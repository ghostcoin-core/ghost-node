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
// genesis) kept in the state database of the given scheme.
func newEmptySnapHandler(t *testing.T, scheme string) *handler {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	gspec := &genesisT.Genesis{
		Config: params.TestChainConfig,
		Alloc:  genesisT.GenesisAlloc{testAddr: {Balance: big.NewInt(1000000)}},
	}
	chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(scheme), gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
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
// chain in the hash-based state database marks the node synced but keeps
// snap sync on; that the sync hold then reports false with no peer ahead,
// and false for good once snap sync ends; and that with the path-based
// database starting the miner turns snap sync off as before.
func TestStartMiningKeepsSnapSync(t *testing.T) {
	h := newEmptySnapHandler(t, rawdb.HashScheme)
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
		t.Error("sync hold with no peers")
	}
	h.enableSyncedFeatures()
	if h.snapSync.Load() || h.snapSyncPending() {
		t.Error("sync hold or snap sync still on after snap sync ended")
	}

	h = newEmptySnapHandler(t, rawdb.PathScheme)
	h.startMining()
	if h.snapSync.Load() || !h.synced.Load() {
		t.Errorf("path-based database: snap sync %v, synced %v after starting the miner, want off and synced", h.snapSync.Load(), h.synced.Load())
	}
}
