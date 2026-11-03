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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/txpool/ghostpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// failingGhostPool is a reveal pool that refuses every transaction with the
// refusal its test sets, recording what it is handed.
type failingGhostPool struct {
	mu      sync.Mutex
	refusal error
	added   map[string]int
}

func (p *failingGhostPool) AddFromPeer(peer string, txs []*types.Transaction) []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.added == nil {
		p.added = make(map[string]int)
	}
	p.added[peer] += len(txs)
	errs := make([]error, len(txs))
	for i := range errs {
		errs[i] = p.refusal
	}
	return errs
}

func (p *failingGhostPool) FilterAnnounced(peer string, kinds []byte, sizes []uint32, hashes []common.Hash) []bool {
	keep := make([]bool, len(hashes))
	for i := range keep {
		keep[i] = true
	}
	return keep
}

func (p *failingGhostPool) DropPeer(peer string) {}

// TestHandlerDropsPeerAtFailedProofLimit checks that the wire path drops a
// peer when the reveal pool reports it at its failed proof limit, for a
// broadcast and for a pooled transaction reply, and keeps a peer whose
// transactions the pool refuses for any other reason, a failed proof below
// the limit among them.
func TestHandlerDropsPeerAtFailedProofLimit(t *testing.T) {
	handler := newTestHandler()
	defer handler.close()
	pool := new(failingGhostPool)
	handler.handler.ghostpool = pool
	backend := (*ethHandler)(handler.handler)

	newAction := func(seed byte) *types.Transaction {
		envelope := make([]byte, types.GhostPolicyActionEnvelopeSize)
		envelope[0] = types.GhostPolicyActionTxType
		envelope[1] = seed
		tx, err := types.NewGhostPolicyActionTx(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	// newPeer registers a peer on a message pipe, and returns it and a
	// channel that is closed once the peer is disconnected, seen as its
	// pipe closing.
	newPeer := func(id byte) (*eth.Peer, chan struct{}) {
		pipe, remote := p2p.MsgPipe()
		t.Cleanup(func() { pipe.Close(); remote.Close() })
		peer := eth.NewPeer(eth.ETH68, p2p.NewPeerPipe(enode.ID{id}, "", nil, pipe), pipe, handler.txpool)
		t.Cleanup(peer.Close)
		if err := handler.handler.peers.registerPeer(peer, nil); err != nil {
			t.Fatal(err)
		}
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			for {
				if _, err := remote.ReadMsg(); err != nil {
					return
				}
			}
		}()
		return peer, closed
	}
	broadcast := func(peer *eth.Peer, txs ...*types.Transaction) {
		t.Helper()
		raw, err := rlp.EncodeToRawList(txs)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Handle(peer, &eth.TransactionsPacket{RawList: raw}); err != nil {
			t.Fatalf("transactions: %v", err)
		}
	}
	reply := func(peer *eth.Peer, txs ...*types.Transaction) {
		t.Helper()
		raw, err := rlp.EncodeToRawList(txs)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Handle(peer, &eth.PooledTransactionsPacket{RequestId: 1, List: raw}); err != nil {
			t.Fatalf("pooled transactions: %v", err)
		}
	}
	dropped := func(closed chan struct{}, wait time.Duration) bool {
		select {
		case <-closed:
			return true
		case <-time.After(wait):
			return false
		}
	}

	// Refusals other than the limit keep the peer: a failed proof below
	// the limit, a budget, a full pool.
	for i, refusal := range []error{
		fmt.Errorf("%w: synthetic test proof", ghostpriv.ErrActionProof),
		ghostpool.ErrPeerBudget,
		ghostpool.ErrPoolFull,
		ghostpool.ErrActionPending,
	} {
		pool.mu.Lock()
		pool.refusal = refusal
		pool.mu.Unlock()
		peer, closed := newPeer(byte(0x10 + i))
		broadcast(peer, newAction(byte(0x10+i)))
		reply(peer, newAction(byte(0x20+i)))
		if dropped(closed, 100*time.Millisecond) {
			t.Fatalf("peer dropped for the refusal %v", refusal)
		}
	}

	// The limit, wrapped as the pool returns it, drops the peer: from a
	// broadcast and from a pooled transaction reply.
	pool.mu.Lock()
	pool.refusal = fmt.Errorf("%w: peer, 3 failed proofs: %w", ghostpool.ErrPeerFailLimit, ghostpriv.ErrActionProof)
	pool.mu.Unlock()
	viaBroadcast, closedBroadcast := newPeer(0x31)
	broadcast(viaBroadcast, newAction(0x31))
	if !dropped(closedBroadcast, 5*time.Second) {
		t.Fatal("peer at the failed proof limit kept after a broadcast")
	}
	viaReply, closedReply := newPeer(0x32)
	reply(viaReply, newAction(0x32))
	if !dropped(closedReply, 5*time.Second) {
		t.Fatal("peer at the failed proof limit kept after a pooled transaction reply")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.added[viaBroadcast.ID()] != 1 || pool.added[viaReply.ID()] != 1 {
		t.Fatalf("pool handed %d and %d transactions, want one from each peer", pool.added[viaBroadcast.ID()], pool.added[viaReply.ID()])
	}
}
