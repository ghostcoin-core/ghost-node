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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// newEmptySnapHandler returns a snap sync handler on an empty chain (only its
// genesis) kept in the path-based state database.
func newEmptySnapHandler(t *testing.T) *handler {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	gspec := &genesisT.Genesis{
		Config: params.TestChainConfig,
		Alloc:  genesisT.GenesisAlloc{testAddr: {Balance: big.NewInt(1000000)}},
	}
	chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(rawdb.PathScheme), gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	h, err := newHandler(&handlerConfig{
		Database:   db,
		Chain:      chain,
		TxPool:     newTestTxPool(),
		Merger:     consensus.NewMerger(rawdb.NewMemoryDatabase()),
		Network:    1,
		Sync:       downloader.SnapSync,
		BloomCache: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestStartMiningKeepsSnapSync checks that starting the miner on an empty
// chain marks the node synced but keeps snap sync on, and that the sync hold
// then reports false with no peer ahead and false for good once snap sync
// ends.
func TestStartMiningKeepsSnapSync(t *testing.T) {
	h := newEmptySnapHandler(t)
	if !h.snapSync.Load() {
		t.Fatal("snap sync is off on an empty chain")
	}
	h.startMining()
	if !h.snapSync.Load() {
		t.Error("starting the miner turned snap sync off on an empty chain")
	}
	if !h.synced.Load() {
		t.Error("starting the miner did not mark the node synced")
	}
	if h.snapSyncPending() {
		t.Error("sync hold with no peers and the head's state readable")
	}
	h.enableSyncedFeatures()
	if h.snapSync.Load() || h.snapSyncPending() {
		t.Error("sync hold or snap sync still on after snap sync ended")
	}
}

// TestSnapAbortRestoresState checks that a path-based state database a snap
// sync turned off is turned back on, at the head's root, when the state
// syncer never ran, and stays off when it did; and that the miner's sync hold
// is on while the head's state cannot be read.
func TestSnapAbortRestoresState(t *testing.T) {
	t.Run("state syncer never ran", func(t *testing.T) {
		h := newEmptySnapHandler(t)
		root := h.chain.CurrentBlock().Root
		if err := h.chain.TrieDB().Disable(); err != nil { // as a snap sync does as it starts
			t.Fatal(err)
		}
		if h.chain.HasState(root) {
			t.Fatal("head state readable with the state database off")
		}
		if !h.snapSyncPending() {
			t.Error("no sync hold while the head's state cannot be read")
		}
		h.restoreStateAfterSnapAbort()
		if !h.chain.HasState(root) {
			t.Fatal("state database not turned back on after a snap sync that wrote no state")
		}
		if got := rawdb.ReadSnapSyncStatusFlag(h.database); got != rawdb.StateSyncFinished {
			t.Errorf("snap sync status flag %d, want finished", got)
		}
		if h.snapSyncPending() {
			t.Error("sync hold after the state database came back with no peer ahead")
		}
	})
	t.Run("state syncer ran", func(t *testing.T) {
		h := newEmptySnapHandler(t)
		root := h.chain.CurrentBlock().Root
		if err := h.chain.TrieDB().Disable(); err != nil {
			t.Fatal(err)
		}
		rawdb.WriteSnapshotSyncStatus(h.database, []byte{0x01}) // as the state syncer does when it stops
		h.restoreStateAfterSnapAbort()
		if h.chain.HasState(root) {
			t.Fatal("state database turned back on after the state syncer ran")
		}
	})
}
