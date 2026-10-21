// Copyright 2026 The Ghost Authors
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
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rlp"
)

// sigcheckHandler is a handler over a real transaction pool, which verifies
// signatures, on a chain where testAddr is funded and has sent one
// transaction (its next nonce is 1). It records the peers dropped for a
// failed signature.
type sigcheckHandler struct {
	handler *handler
	chain   *core.BlockChain
	pool    *txpool.TxPool

	mu      sync.Mutex
	dropped []string
}

func newSigcheckHandler(t *testing.T) *sigcheckHandler {
	t.Helper()
	gspec := &genesisT.Genesis{
		Config: params.TestChainConfig,
		Alloc:  genesisT.GenesisAlloc{testAddr: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)}},
	}
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 1, func(i int, gen *core.BlockGen) {
		signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), gen.PrevBlock(-1).Hash())
		tx, err := types.SignGhostAccountTx(signer, testKey, &types.GhostAccountTx{
			ChainID:   gspec.Config.GetChainID(),
			Nonce:     gen.TxNonce(testAddr),
			GasTipCap: new(big.Int),
			GasFeeCap: gen.BaseFee(),
			Gas:       100000,
			To:        &common.Address{},
			Value:     new(big.Int),
		})
		if err != nil {
			panic(err)
		}
		gen.AddTx(tx)
	})
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	config := legacypool.DefaultConfig
	config.Journal = ""
	pool, err := txpool.New(config.PriceLimit, chain, []txpool.SubPool{legacypool.New(config, chain)})
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(&handlerConfig{
		Database:   db,
		Chain:      chain,
		TxPool:     pool,
		Merger:     consensus.NewMerger(rawdb.NewMemoryDatabase()),
		Network:    1,
		Sync:       downloader.SnapSync,
		BloomCache: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Start(1000)
	s := &sigcheckHandler{handler: h, chain: chain, pool: pool}
	h.sigDropPeer = func(id string) {
		s.mu.Lock()
		s.dropped = append(s.dropped, id)
		s.mu.Unlock()
		h.removePeer(id)
	}
	t.Cleanup(func() {
		h.Stop()
		pool.Close()
		chain.Stop()
	})
	return s
}

func (s *sigcheckHandler) droppedPeers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dropped...)
}

// connect registers a peer with the handler and returns it with the remote
// end of its pipe.
func (s *sigcheckHandler) connect(t *testing.T, id byte) (*eth.Peer, *p2p.MsgPipeRW) {
	t.Helper()
	pipe, remote := p2p.MsgPipe()
	t.Cleanup(func() { pipe.Close(); remote.Close() })
	peer := eth.NewPeer(eth.ETH68, p2p.NewPeerPipe(enode.ID{id}, "", nil, pipe), pipe, s.pool)
	t.Cleanup(peer.Close)
	if err := s.handler.peers.registerPeer(peer, nil); err != nil {
		t.Fatal(err)
	}
	return peer, remote
}

// accountTx signs a transfer from the account of seed for the test chain.
// With badSig a bit of the signature is flipped.
func (s *sigcheckHandler) accountTx(t *testing.T, seed byte, nonce uint64, badSig bool) *types.Transaction {
	t.Helper()
	key, _, _ := testAccount(seed)
	tx := signTestTx(s.chain, key, &types.GhostAccountTx{
		Nonce:     nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1_000_000_000),
		Gas:       100000,
		To:        &common.Address{0x01},
	})
	if !badSig {
		return tx
	}
	scheme, pk, sig, _ := tx.GhostAccountAuth()
	sig[7] ^= 0x01
	return types.NewTx(&types.GhostAccountTx{
		ChainID:   tx.ChainId(),
		Nonce:     tx.Nonce(),
		GasTipCap: tx.GasTipCap(),
		GasFeeCap: tx.GasFeeCap(),
		Gas:       tx.Gas(),
		To:        tx.To(),
		Value:     tx.Value(),
		Scheme:    types.GhostScheme(scheme),
		PublicKey: pk,
		Signature: sig,
	})
}

// broadcast delivers txs from the peer as a transaction broadcast.
func (s *sigcheckHandler) broadcast(t *testing.T, peer *eth.Peer, txs ...*types.Transaction) {
	t.Helper()
	list, err := rlp.EncodeToRawList(txs)
	if err != nil {
		t.Fatal(err)
	}
	if err := (*ethHandler)(s.handler).Handle(peer, &eth.TransactionsPacket{RawList: list}); err != nil {
		t.Fatalf("transactions: %v", err)
	}
}

// pipeClosed reports whether the peer's pipe was closed, which a disconnect
// does to a test peer. Messages the handler still sends are read and
// discarded.
func pipeClosed(remote *p2p.MsgPipeRW) bool {
	done := make(chan error, 1)
	go func() {
		for {
			msg, err := remote.ReadMsg()
			if err != nil {
				done <- err
				return
			}
			msg.Discard()
		}
	}()
	select {
	case err := <-done:
		return errors.Is(err, p2p.ErrPipeClosed)
	case <-time.After(5 * time.Second):
		return false
	}
}

// TestInvalidSignatureDisconnectsPeer checks that a peer that sends an
// account transaction whose signature fails is disconnected, and that a peer
// sending only valid ones is not.
func TestInvalidSignatureDisconnectsPeer(t *testing.T) {
	s := newSigcheckHandler(t)
	honest, _ := s.connect(t, 1)
	liar, liarRemote := s.connect(t, 2)

	good := s.accountTx(t, 1, 1, false) // testKey at its next nonce
	s.broadcast(t, honest, good)
	if !s.pool.Has(good.Hash()) {
		t.Fatal("valid transaction not in the pool")
	}
	if dropped := s.droppedPeers(); len(dropped) != 0 {
		t.Fatalf("peers %v dropped for a valid transaction", dropped)
	}

	bad := s.accountTx(t, 1, 2, true)
	s.broadcast(t, liar, bad)
	if s.pool.Has(bad.Hash()) {
		t.Fatal("transaction with a failed signature in the pool")
	}
	if dropped := s.droppedPeers(); len(dropped) != 1 || dropped[0] != liar.ID() {
		t.Fatalf("dropped %v, want peer %s", dropped, liar.ID())
	}
	if !pipeClosed(liarRemote) {
		t.Fatal("peer that sent a failed signature still connected")
	}

	// The same failing transaction from another peer is refused from the
	// failure cache, and that peer is disconnected too.
	other, _ := s.connect(t, 3)
	s.broadcast(t, other, bad)
	if dropped := s.droppedPeers(); len(dropped) != 2 || dropped[1] != other.ID() {
		t.Fatalf("dropped %v, want peer %s second", dropped, other.ID())
	}
}

// TestStateFailureDoesNotDisconnectPeer checks that a peer is not penalised
// for a correctly signed transaction the state refuses: a stale nonce, a
// balance that does not cover it.
func TestStateFailureDoesNotDisconnectPeer(t *testing.T) {
	s := newSigcheckHandler(t)
	peer, _ := s.connect(t, 1)

	stale := s.accountTx(t, 1, 0, false)    // testKey's nonce 0 is in the chain
	unfunded := s.accountTx(t, 9, 0, false) // an account with no balance
	s.broadcast(t, peer, stale, unfunded)
	for _, tx := range []*types.Transaction{stale, unfunded} {
		if s.pool.Has(tx.Hash()) {
			t.Fatalf("transaction %x the state refuses is in the pool", tx.Hash())
		}
	}
	// The same refusals through the pool are state errors, not signature
	// failures.
	errs := s.pool.Add([]*types.Transaction{stale, unfunded}, false, true)
	if !errors.Is(errs[0], core.ErrNonceTooLow) || !errors.Is(errs[1], core.ErrInsufficientFunds) {
		t.Fatalf("errors %v, want a stale nonce and insufficient funds", errs)
	}
	if dropped := s.droppedPeers(); len(dropped) != 0 {
		t.Fatalf("peers %v dropped for state failures", dropped)
	}
	// The peer is still served: its next valid transaction is admitted.
	good := s.accountTx(t, 1, 1, false)
	s.broadcast(t, peer, good)
	if !s.pool.Has(good.Hash()) {
		t.Fatal("valid transaction after the state failures not in the pool")
	}
	if dropped := s.droppedPeers(); len(dropped) != 0 {
		t.Fatalf("peers %v dropped", dropped)
	}
}

// TestPeerSignatureBudget checks that a peer has no more account
// transactions verified, or fetched from its announcements, than its budget
// per second, that a transaction from an unknown peer is dropped unverified,
// and that the budget is refilled after a second.
func TestPeerSignatureBudget(t *testing.T) {
	handler := newTestHandler()
	defer handler.close()
	var (
		mu  sync.Mutex
		now = time.Unix(1_000_000, 0)
	)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	handler.handler.sigBudgets = txpool.NewSigBudgets(2, 16, clock)

	pipe, remote := p2p.MsgPipe()
	defer pipe.Close()
	defer remote.Close()
	peer := eth.NewPeer(eth.ETH68, p2p.NewPeerPipe(enode.ID{5}, "", nil, pipe), pipe, handler.txpool)
	defer peer.Close()
	if err := handler.handler.peers.registerPeer(peer, nil); err != nil {
		t.Fatal(err)
	}
	txs := make([]*types.Transaction, 4)
	for i := range txs {
		txs[i] = signTestTx(handler.chain, testKey, &types.GhostAccountTx{Nonce: uint64(i), Gas: 100000, To: &common.Address{}})
	}
	// Announcements: only the budget's worth of account transactions passes.
	backend := (*ethHandler)(handler.handler)
	kinds := []byte{types.GhostAccountTxType, types.GhostAccountTxType, types.GhostAccountTxType}
	sizes := []uint32{100, 100, 100}
	hashes := []common.Hash{txs[0].Hash(), txs[1].Hash(), txs[2].Hash()}
	if _, _, kept := backend.filterAccountAnnounces(peer.ID(), kinds, sizes, hashes); len(kept) != 2 {
		t.Fatalf("announcement kept %d hashes, want the budget of 2", len(kept))
	}

	// Deliveries: two are added, the rest dropped unverified.
	errs := handler.handler.addTxsFromPeer(peer.ID(), txs[:3])
	if errs[0] != nil || errs[1] != nil || errs[2] != txpool.ErrSignatureBudget {
		t.Fatalf("errors %v, want two added and the third over the budget", errs)
	}
	if handler.txpool.Has(txs[2].Hash()) {
		t.Fatal("transaction over the budget reached the pool")
	}
	// A known transaction costs nothing, even with the budget used.
	if errs := handler.handler.addTxsFromPeer(peer.ID(), txs[:1]); errs[0] != nil {
		t.Fatalf("known transaction: %v", errs[0])
	}
	// An unknown peer gets nothing verified.
	if errs := handler.handler.addTxsFromPeer("unknown", txs[3:]); errs[0] != txpool.ErrSignaturePeerUnknown {
		t.Fatalf("unknown peer: error %v, want %v", errs[0], txpool.ErrSignaturePeerUnknown)
	}
	// A second later the budget is full again.
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	if errs := handler.handler.addTxsFromPeer(peer.ID(), txs[2:]); errs[0] != nil || errs[1] != nil {
		t.Fatalf("after a second: errors %v, want both added", errs)
	}
}
