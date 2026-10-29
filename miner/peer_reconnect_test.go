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
	"sync/atomic"
	"testing"
	"time"
)

// publicTestNetChainID is the chain ID of the public test network, the one
// network whose miner waits for a peer. Should it ever drift from the chain's
// own, the worker would seal with no peers and the test below would fail.
const publicTestNetChainID = 6_777_972

// TestMinerResumesAfterPeersReturn checks that a node on the public test
// network that loses its last peer and gets one back starts sealing again on
// its own, with nothing but the returning peer to wake it: every time the
// connection drops and comes back, and also when the last peer leaves while
// the worker is building a block, after it checked for peers.
func TestMinerResumesAfterPeersReturn(t *testing.T) {
	var peers atomic.Int32
	peers.Store(1)
	w, tasks := startPeerGatedWorker(t, publicTestNetChainID, &peers, true)

	// While leaving is set, the next look at the peer count still sees the
	// leaving peer, and every later one sees the count in peers.
	var leaving atomic.Bool
	w.setPeerCount(func() int {
		if leaving.CompareAndSwap(true, false) {
			return 1
		}
		return int(peers.Load())
	})

	select {
	case <-tasks:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not seal with a peer connected")
	}

	// dropAndReturn takes the last peer away, checks that new work is built
	// but not sealed, then brings a peer back and expects the worker to seal
	// again without being started again.
	dropAndReturn := func(name string, midBuild bool) {
		t.Helper()
		peers.Store(0)
		time.Sleep(200 * time.Millisecond)
		for len(tasks) > 0 {
			<-tasks
		}
		leaving.Store(midBuild)
		w.start()
		select {
		case task := <-tasks:
			t.Fatalf("%s: sealed block %d with no peers", name, task.block.NumberU64())
		case <-time.After(2500 * time.Millisecond):
		}
		if midBuild && leaving.Load() {
			t.Fatalf("%s: the worker never looked at the peer count", name)
		}
		if !w.isRunning() {
			t.Fatalf("%s: the worker stopped running while it waits for peers", name)
		}

		peers.Store(1)
		select {
		case <-tasks:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the worker did not seal again once a peer reconnected", name)
		}
	}

	dropAndReturn("first drop", false)
	dropAndReturn("second drop", false)
	dropAndReturn("peer leaves while a block is built", true)
}
