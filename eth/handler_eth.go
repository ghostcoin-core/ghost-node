// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// ethHandler implements the eth.Backend interface to handle the various network
// packets that are sent as replies or broadcasts.
type ethHandler handler

func (h *ethHandler) Chain() *core.BlockChain { return h.chain }
func (h *ethHandler) TxPool() eth.TxPool      { return h.txpool }

// RunPeer is invoked when a peer joins on the `eth` protocol.
func (h *ethHandler) RunPeer(peer *eth.Peer, hand eth.Handler) error {
	return (*handler)(h).runEthPeer(peer, hand)
}

// PeerInfo retrieves all known `eth` information about a peer.
func (h *ethHandler) PeerInfo(id enode.ID) interface{} {
	if p := h.peers.peer(id.String()); p != nil {
		return p.info()
	}
	return nil
}

// AcceptTxs retrieves whether transaction processing is enabled on the node
// or if inbound transactions should simply be dropped.
func (h *ethHandler) AcceptTxs() bool {
	return h.synced.Load()
}

// Handle is invoked from a peer's message handler when it receives a new remote
// message that the handler couldn't consume and serve itself.
func (h *ethHandler) Handle(peer *eth.Peer, packet eth.Packet) error {
	// Consume any broadcasts and announces, forwarding the rest to the downloader
	switch packet := packet.(type) {
	case *eth.NewBlockHashesPacket:
		hashes, numbers := packet.Unpack()
		return h.handleBlockAnnounces(peer, hashes, numbers)

	case *eth.NewBlockPacket:
		return h.handleBlockBroadcast(peer, packet.Block, packet.TD)

	case *eth.NewPooledTransactionHashesPacket:
		kinds, sizes, hashes := h.filterRevealAnnounces(peer.ID(), packet.Types, packet.Sizes, packet.Hashes)
		kinds, sizes, hashes = h.filterAccountAnnounces(peer.ID(), kinds, sizes, hashes)
		return h.txFetcher.Notify(peer.ID(), kinds, sizes, hashes)

	case *eth.TransactionsPacket:
		txs, err := packet.Items()
		if err != nil {
			return fmt.Errorf("Transactions: %v", err)
		}
		if err := handleTransactions(peer, txs, true); err != nil {
			return fmt.Errorf("Transactions: %v", err)
		}
		h.addRevealsFromPeer(peer.ID(), txs)
		return h.txFetcher.Enqueue(peer.ID(), txs, false)

	case *eth.PooledTransactionsPacket:
		txs, err := packet.List.Items()
		if err != nil {
			return fmt.Errorf("PooledTransactions: %v", err)
		}
		if err := handleTransactions(peer, txs, false); err != nil {
			return fmt.Errorf("PooledTransactions: %v", err)
		}
		h.addRevealsFromPeer(peer.ID(), txs)
		return h.txFetcher.Enqueue(peer.ID(), txs, true)

	default:
		return fmt.Errorf("unexpected eth packet type: %T", packet)
	}
}

// handleTransactions marks all given transactions as known to the peer
// and performs basic validations.
func handleTransactions(peer *eth.Peer, list []*types.Transaction, directBroadcast bool) error {
	seen := make(map[common.Hash]struct{})
	for _, tx := range list {
		if directBroadcast && tx.Type() == types.BlobTxType {
			return errors.New("disallowed broadcast blob transaction")
		}

		// Check for duplicates.
		hash := tx.Hash()
		if _, exists := seen[hash]; exists {
			return fmt.Errorf("multiple copies of the same hash %v", hash)
		}
		seen[hash] = struct{}{}

		// Mark as known.
		peer.MarkTransaction(hash)
	}
	return nil
}

// filterRevealAnnounces drops from an announcement the reveals the peer's
// budgets do not cover, so that the fetcher never requests them. Other
// transactions pass unchanged.
func (h *ethHandler) filterRevealAnnounces(peer string, kinds []byte, sizes []uint32, hashes []common.Hash) ([]byte, []uint32, []common.Hash) {
	if h.ghostpool == nil || kinds == nil || len(kinds) != len(hashes) || len(sizes) != len(hashes) {
		return kinds, sizes, hashes
	}
	keep := h.ghostpool.FilterAnnounced(peer, kinds, sizes, hashes)
	var (
		fkinds  = make([]byte, 0, len(hashes))
		fsizes  = make([]uint32, 0, len(hashes))
		fhashes = make([]common.Hash, 0, len(hashes))
	)
	for i, hash := range hashes {
		if i < len(keep) && keep[i] {
			fkinds = append(fkinds, kinds[i])
			fsizes = append(fsizes, sizes[i])
			fhashes = append(fhashes, hash)
		}
	}
	return fkinds, fsizes, fhashes
}

// filterAccountAnnounces keeps of an announcement only as many unknown
// account transactions as the peer's signature budget has left, so that the
// fetcher requests no more than the peer may have verified. An announcement
// without types counts every unknown hash against the budget. Other
// transactions pass unchanged.
func (h *ethHandler) filterAccountAnnounces(peer string, kinds []byte, sizes []uint32, hashes []common.Hash) ([]byte, []uint32, []common.Hash) {
	typed := kinds != nil && len(kinds) == len(hashes) && len(sizes) == len(hashes)
	var (
		left    = h.sigBudgets.Get(peer).Available()
		fkinds  []byte
		fsizes  []uint32
		fhashes = make([]common.Hash, 0, len(hashes))
	)
	if typed {
		fkinds = make([]byte, 0, len(hashes))
		fsizes = make([]uint32, 0, len(hashes))
	}
	for i, hash := range hashes {
		if (!typed || kinds[i] == types.GhostAccountTxType) && !h.txpool.Has(hash) {
			if left == 0 {
				continue
			}
			left--
		}
		if typed {
			fkinds = append(fkinds, kinds[i])
			fsizes = append(fsizes, sizes[i])
		}
		fhashes = append(fhashes, hash)
	}
	return fkinds, fsizes, fhashes
}

// addRevealsFromPeer hands the reveals of a delivery to the reveal pool with
// the peer they came from, so that its budgets apply. The whole delivery
// still goes to the fetcher afterwards, which sees each of these reveals as
// already known or refused.
func (h *ethHandler) addRevealsFromPeer(peer string, txs []*types.Transaction) {
	if h.ghostpool == nil {
		return
	}
	var reveals []*types.Transaction
	for _, tx := range txs {
		if tx.IsGhostReveal() {
			reveals = append(reveals, tx)
		}
	}
	if len(reveals) == 0 {
		return
	}
	for i, err := range h.ghostpool.AddFromPeer(peer, reveals) {
		if err != nil {
			log.Debug("Reveal from peer refused", "peer", peer, "hash", reveals[i].Hash(), "err", err)
		}
	}
}

// handleBlockAnnounces is invoked from a peer's message handler when it transmits a
// batch of block announcements for the local node to process.
func (h *ethHandler) handleBlockAnnounces(peer *eth.Peer, hashes []common.Hash, numbers []uint64) error {
	// Drop all incoming block announces from the p2p network if
	// the chain already entered the pos stage and disconnect the
	// remote peer.
	if h.merger.PoSFinalized() {
		return errors.New("disallowed block announcement")
	}
	// Schedule all the unknown hashes for retrieval
	var (
		unknownHashes  = make([]common.Hash, 0, len(hashes))
		unknownNumbers = make([]uint64, 0, len(numbers))
	)
	for i := 0; i < len(hashes); i++ {
		if !h.chain.HasBlock(hashes[i], numbers[i]) {
			unknownHashes = append(unknownHashes, hashes[i])
			unknownNumbers = append(unknownNumbers, numbers[i])
		}
	}
	for i := 0; i < len(unknownHashes); i++ {
		h.blockFetcher.Notify(peer.ID(), unknownHashes[i], unknownNumbers[i], time.Now(), peer.RequestOneHeader, peer.RequestBodies)
	}
	return nil
}

// handleBlockBroadcast is invoked from a peer's message handler when it transmits a
// block broadcast for the local node to process.
func (h *ethHandler) handleBlockBroadcast(peer *eth.Peer, block *types.Block, td *big.Int) error {
	// Drop all incoming block announces from the p2p network if
	// the chain already entered the pos stage and disconnect the
	// remote peer.
	if h.merger.PoSFinalized() {
		return errors.New("disallowed block broadcast")
	}
	// Schedule the block for import
	h.blockFetcher.Enqueue(peer.ID(), block)

	// Assuming the block is importable by the peer, but possibly not yet done so,
	// calculate the head hash and TD that the peer truly must have.
	var (
		trueHead = block.ParentHash()
		trueTD   = new(big.Int).Sub(td, block.Difficulty())
	)
	// Update the peer's total difficulty if better than the previous
	if _, td, _ := peer.Head(); trueTD.Cmp(td) > 0 {
		peer.SetHead(trueHead, trueTD, block.Difficulty())
		h.chainSync.handlePeerEvent()
	}
	return nil
}
