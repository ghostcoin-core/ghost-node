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

package miner

import (
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
)

// startPeerGatedWorker starts a mining worker for the chain ID chainID on the
// chain and engine of createMiner, and returns a channel that receives every
// sealing task the worker hands to the sealer. The gate looks at nothing but
// the chain ID and the peer count, so the chain's own rules do not matter.
// With hook, the worker's peer count reads from peers; without, it has none.
// Sealing itself is skipped, so the chain stays at genesis.
func startPeerGatedWorker(t *testing.T, chainID uint64, peers *atomic.Int32, hook bool) (*worker, <-chan *task) {
	t.Helper()
	m, _, cleanup := createMiner(t)
	// Only this test's worker runs on the chain.
	m.Close()
	t.Cleanup(func() { cleanup(true) })

	config := *m.eth.BlockChain().Config().(*goethereum.ChainConfig)
	config.ChainID = new(big.Int).SetUint64(chainID)
	w := newWorker(testConfig, &config, m.engine, m.eth, new(event.TypeMux), nil, false)
	t.Cleanup(w.close)
	w.setEtherbase(common.HexToAddress("0xc0ffee"))
	if hook {
		w.setPeerCount(func() int { return int(peers.Load()) })
	}
	tasks := make(chan *task, 64)
	w.newTaskHook = func(task *task) {
		select {
		case tasks <- task:
		default:
		}
	}
	w.skipSealHook = func(*task) bool { return true }
	w.start()
	return w, tasks
}

// TestMinerWaitsForPeersOnPublicTestNet checks that a mining node on the
// public test network seals nothing while it has no peers, keeps its pending
// block current meanwhile, starts sealing once a peer connects and stops
// again when the last one leaves; and that the internal network, developer
// mode and a worker with no peer source mine with no peers as before.
func TestMinerWaitsForPeersOnPublicTestNet(t *testing.T) {
	t.Run("public test network", func(t *testing.T) {
		var peers atomic.Int32
		w, tasks := startPeerGatedWorker(t, ghost.TestNetChainID, &peers, true)

		// Neither the first work nor new work asked for may reach the sealer.
		time.Sleep(500 * time.Millisecond)
		w.start()
		select {
		case task := <-tasks:
			t.Fatalf("sealed block %d on the public test network with no peers", task.block.NumberU64())
		case <-time.After(2500 * time.Millisecond):
		}
		if !w.isRunning() {
			t.Fatal("the worker stopped running while it waits for peers")
		}
		if block := w.pendingBlock(); block == nil || block.NumberU64() != 1 {
			t.Fatalf("pending block %v while the worker waits for peers, want block 1", block)
		}

		// Nothing new arrives but the peer: the recommit timer seals the work
		// it held back.
		peers.Store(1)
		select {
		case task := <-tasks:
			if got := task.block.NumberU64(); got != 1 {
				t.Fatalf("first sealed block %d, want 1", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the worker did not seal once a peer connected")
		}

		// A node that loses its last peer stops sealing again.
		peers.Store(0)
		time.Sleep(200 * time.Millisecond)
		for len(tasks) > 0 {
			<-tasks
		}
		w.start()
		select {
		case task := <-tasks:
			t.Fatalf("sealed block %d after the last peer left", task.block.NumberU64())
		case <-time.After(2500 * time.Millisecond):
		}
	})

	for _, tc := range []struct {
		name    string
		chainID uint64
		hook    bool
	}{
		{"internal network", ghost.InternalNetChainID, true},
		{"developer mode", ghost.DeveloperChainID, true},
		{"no peer source", ghost.TestNetChainID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var peers atomic.Int32
			_, tasks := startPeerGatedWorker(t, tc.chainID, &peers, tc.hook)
			select {
			case <-tasks:
			case <-time.After(5 * time.Second):
				t.Fatal("the worker did not seal with no peers")
			}
		})
	}
}
