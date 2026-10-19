// Copyright 2026 The go-ethereum Authors
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

package snap

import (
	"bytes"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// TestSnapSyncFix33790 checks that reverting a request (for example after it
// timed out) puts the peer back in the idle pool of that request type, so it
// can be assigned work again, but only while the peer is still registered.
func TestSnapSyncFix33790(t *testing.T) {
	const reqID = 1

	kinds := []struct {
		name   string
		revert func(s *Syncer, peer string) // assigns a request to peer and reverts it
		idlers func(s *Syncer) map[string]struct{}
	}{
		{
			name: "account",
			revert: func(s *Syncer, peer string) {
				req := &accountRequest{peer: peer, id: reqID, stale: make(chan struct{}), timeout: time.AfterFunc(time.Hour, func() {}), task: &accountTask{}}
				s.lock.Lock()
				delete(s.accountIdlers, peer)
				s.accountReqs[reqID] = req
				s.lock.Unlock()
				s.revertAccountRequest(req)
			},
			idlers: func(s *Syncer) map[string]struct{} { return s.accountIdlers },
		},
		{
			name: "bytecode",
			revert: func(s *Syncer, peer string) {
				req := &bytecodeRequest{peer: peer, id: reqID, stale: make(chan struct{}), timeout: time.AfterFunc(time.Hour, func() {}), task: &accountTask{codeTasks: make(map[common.Hash]struct{})}}
				s.lock.Lock()
				delete(s.bytecodeIdlers, peer)
				s.bytecodeReqs[reqID] = req
				s.lock.Unlock()
				s.revertBytecodeRequest(req)
			},
			idlers: func(s *Syncer) map[string]struct{} { return s.bytecodeIdlers },
		},
		{
			name: "storage",
			revert: func(s *Syncer, peer string) {
				req := &storageRequest{peer: peer, id: reqID, stale: make(chan struct{}), timeout: time.AfterFunc(time.Hour, func() {}), subTask: &storageTask{}}
				s.lock.Lock()
				delete(s.storageIdlers, peer)
				s.storageReqs[reqID] = req
				s.lock.Unlock()
				s.revertStorageRequest(req)
			},
			idlers: func(s *Syncer) map[string]struct{} { return s.storageIdlers },
		},
		{
			name: "trienode-heal",
			revert: func(s *Syncer, peer string) {
				req := &trienodeHealRequest{peer: peer, id: reqID, stale: make(chan struct{}), timeout: time.AfterFunc(time.Hour, func() {}), task: &healTask{trieTasks: make(map[string]common.Hash)}}
				s.lock.Lock()
				delete(s.trienodeHealIdlers, peer)
				s.trienodeHealReqs[reqID] = req
				s.lock.Unlock()
				s.revertTrienodeHealRequest(req)
			},
			idlers: func(s *Syncer) map[string]struct{} { return s.trienodeHealIdlers },
		},
		{
			name: "bytecode-heal",
			revert: func(s *Syncer, peer string) {
				req := &bytecodeHealRequest{peer: peer, id: reqID, stale: make(chan struct{}), timeout: time.AfterFunc(time.Hour, func() {}), task: &healTask{codeTasks: make(map[common.Hash]struct{})}}
				s.lock.Lock()
				delete(s.bytecodeHealIdlers, peer)
				s.bytecodeHealReqs[reqID] = req
				s.lock.Unlock()
				s.revertBytecodeHealRequest(req)
			},
			idlers: func(s *Syncer) map[string]struct{} { return s.bytecodeHealIdlers },
		},
	}
	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			// A registered peer whose request is reverted becomes idle again.
			syncer := NewSyncer(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
			peer := newTestPeer("synthetic-peer", t, func() {})
			if err := syncer.Register(peer); err != nil {
				t.Fatalf("failed to register peer: %v", err)
			}
			kind.revert(syncer, peer.ID())
			if _, ok := kind.idlers(syncer)[peer.ID()]; !ok {
				t.Errorf("peer not idle after its %s request was reverted", kind.name)
			}

			// A peer that already left is not brought back by the revert.
			syncer = NewSyncer(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
			if err := syncer.Register(peer); err != nil {
				t.Fatalf("failed to register peer: %v", err)
			}
			if err := syncer.Unregister(peer.ID()); err != nil {
				t.Fatalf("failed to unregister peer: %v", err)
			}
			kind.revert(syncer, peer.ID())
			if _, ok := kind.idlers(syncer)[peer.ID()]; ok {
				t.Errorf("dropped peer marked idle after its %s request was reverted", kind.name)
			}
		})
	}
}

// TestSnapSyncFix33898 checks that account and storage range responses with an
// entry preceding the requested origin are rejected. The proof only covers the
// range from the origin on, so such an entry falls into a part of the rebuilt
// trie that the proof leaves unresolved, where it must not be accepted.
func TestSnapSyncFix33898(t *testing.T) {
	_, sourceTrie, elems := makeAccountTrieNoStorage(1000, rawdb.HashScheme)
	root := sourceTrie.Hash()

	// Build an honest response for a range starting in the middle of the trie,
	// then forge an entry before the origin. The forged entry reuses an existing
	// key with another entry's value, so it decodes as a valid account.
	origin := common.BytesToHash(elems[500].k)
	honest := elems[500:510]
	forged := &kv{k: elems[0].k, v: elems[1].v}
	if bytes.Compare(forged.k, origin[:]) >= 0 {
		t.Fatal("forged key does not precede the origin")
	}
	proof := trienode.NewProofSet()
	if err := sourceTrie.Prove(origin[:], proof); err != nil {
		t.Fatalf("failed to prove origin: %v", err)
	}
	if err := sourceTrie.Prove(honest[len(honest)-1].k, proof); err != nil {
		t.Fatalf("failed to prove last key: %v", err)
	}
	var proofs [][]byte
	for _, blob := range proof.List() {
		proofs = append(proofs, blob)
	}
	response := func(withForged bool) ([]common.Hash, [][]byte) {
		var (
			hashes []common.Hash
			values [][]byte
		)
		if withForged {
			hashes = append(hashes, common.BytesToHash(forged.k))
			values = append(values, forged.v)
		}
		for _, entry := range honest {
			hashes = append(hashes, common.BytesToHash(entry.k))
			values = append(values, entry.v)
		}
		return hashes, values
	}

	newSyncer := func(t *testing.T) (*Syncer, *testPeer) {
		syncer := NewSyncer(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
		peer := newTestPeer("synthetic-peer", t, func() {})
		if err := syncer.Register(peer); err != nil {
			t.Fatalf("failed to register peer: %v", err)
		}
		peer.remote = syncer
		syncer.root = root
		return syncer, peer
	}

	t.Run("account", func(t *testing.T) {
		for _, withForged := range []bool{false, true} {
			syncer, peer := newSyncer(t)
			req := &accountRequest{
				peer:    peer.ID(),
				id:      1,
				time:    time.Now(),
				deliver: make(chan *accountResponse, 1),
				revert:  make(chan *accountRequest, 1),
				cancel:  make(chan struct{}),
				timeout: time.AfterFunc(time.Hour, func() {}),
				stale:   make(chan struct{}),
				origin:  origin,
				limit:   common.MaxHash,
				task:    &accountTask{},
			}
			syncer.accountReqs[req.id] = req

			hashes, values := response(withForged)
			err := syncer.OnAccounts(peer, req.id, hashes, values, proofs)
			switch {
			case !withForged && err != nil:
				t.Fatalf("honest account range rejected: %v", err)
			case !withForged && len(req.deliver) != 1:
				t.Fatal("honest account range not delivered")
			case withForged && err == nil:
				t.Fatal("account range with an entry before the origin accepted")
			case withForged && len(req.deliver) != 0:
				t.Fatal("account range with an entry before the origin delivered")
			}
		}
	})

	t.Run("storage", func(t *testing.T) {
		account := common.HexToHash("0x01")
		for _, withForged := range []bool{false, true} {
			syncer, peer := newSyncer(t)
			req := &storageRequest{
				peer:     peer.ID(),
				id:       1,
				time:     time.Now(),
				deliver:  make(chan *storageResponse, 1),
				revert:   make(chan *storageRequest, 1),
				cancel:   make(chan struct{}),
				timeout:  time.AfterFunc(time.Hour, func() {}),
				stale:    make(chan struct{}),
				accounts: []common.Hash{account},
				roots:    []common.Hash{root},
				origin:   origin,
				limit:    common.MaxHash,
				mainTask: &accountTask{},
				subTask:  &storageTask{},
			}
			syncer.storageReqs[req.id] = req

			hashes, values := response(withForged)
			err := syncer.OnStorage(peer, req.id, [][]common.Hash{hashes}, [][][]byte{values}, proofs)
			switch {
			case !withForged && err != nil:
				t.Fatalf("honest storage range rejected: %v", err)
			case !withForged && len(req.deliver) != 1:
				t.Fatal("honest storage range not delivered")
			case withForged && err == nil:
				t.Fatal("storage range with an entry before the origin accepted")
			case withForged && len(req.deliver) != 0:
				t.Fatal("storage range with an entry before the origin delivered")
			}
		}
	})
}
