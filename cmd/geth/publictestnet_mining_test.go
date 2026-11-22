// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/internal/reexec"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// testMiningFloor is the difficulty floor of the fast test network: about
// a second or two of RandomX hashing in light mode on one thread, so a
// block reaches every node well before another node seals a competing one.
const testMiningFloor = 64

// A geth run as "geth-test-mining" is a "geth-test-seeds" run on the public
// test network with its difficulty floor lowered to testMiningFloor. The
// genesis stays the test network's: ASERT is at the floor on a chain started
// weeks after the genesis time, so the floor alone sets each block's
// difficulty. Blocks carry real RandomX seals and every node checks them.
// Every node of a test runs as "geth-test-mining" so they all agree on the
// rules.
func init() {
	reexec.Register("geth-test-mining", func() {
		ghost.SetTestNetMinDifficultyForTests(testMiningFloor)
		runWithTestSeeds()
	})
}

// miningNode is a node on the fast test network.
type miningNode struct {
	*testNode
	etherbase common.Address
}

// startMiningNode starts a node on an empty data directory that mines to its
// own address with threads threads, with seeds as its built-in seed list.
func startMiningNode(t *testing.T, name string, account byte, threads int, seeds ...string) *miningNode {
	t.Helper()
	_, _, etherbase := testAccount(account)
	args := append([]string{"--cache", "64", "--datadir.minfreedisk", "0"}, localNetFlags...)
	args = append(args, "--mine", "--miner.threads", fmt.Sprint(threads), "--miner.etherbase", etherbase.Hex())
	n := startNodeAs(t, "geth-test-mining", name, t.TempDir(), seeds, args...)
	checkTestNet(t, n)
	return &miningNode{testNode: n, etherbase: etherbase}
}

// minedBlock is the part of a block the tests read.
type minedBlock struct {
	Number hexutil.Uint64 `json:"number"`
	Hash   common.Hash    `json:"hash"`
	Miner  common.Address `json:"miner"`
}

// head returns the node's current block number.
func (n *miningNode) head(t *testing.T) uint64 {
	t.Helper()
	var number hexutil.Uint64
	if err := n.rpc.Call(&number, "eth_blockNumber"); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	return uint64(number)
}

// block returns the node's canonical block number, or nil if it has none.
func (n *miningNode) block(t *testing.T, number uint64) *minedBlock {
	t.Helper()
	var b *minedBlock
	if err := n.rpc.Call(&b, "eth_getBlockByNumber", hexutil.EncodeUint64(number), false); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	return b
}

// log returns what the node has logged so far.
func (n *miningNode) log() string {
	return n.geth.StderrText()
}

// minedBy returns the miners of blocks from..to on n's canonical chain.
func minedBy(t *testing.T, n *miningNode, from, to uint64) map[common.Address]int {
	t.Helper()
	miners := make(map[common.Address]int)
	for number := from; number <= to; number++ {
		b := n.block(t, number)
		if b == nil {
			t.Fatalf("%s: no block %d", n.name, number)
		}
		miners[b.Miner]++
	}
	return miners
}

// The log lines the tests look for, as the node writes them.
const (
	logMiningKeepsSnap = "Mining with snap sync kept on"
	logSnapPivot       = "Committed new head block" // a snap sync committed its pivot
	logSnapOff         = "Snap sync complete, auto disabling"
	logSealed          = "Successfully sealed new block"
)

// TestPublicTestNetMiningNodeSnapSyncsLongChain checks that a node started
// with mining on, on an empty data directory, joins a long chain by snap
// sync and then mines on it. Two seeds mine a chain well past the snap sync
// pivot distance; the new node must commit a snap sync pivot, seal nothing
// before it, reach the seeds' chain and then get its own blocks into it.
func TestPublicTestNetMiningNodeSnapSyncsLongChain(t *testing.T) {
	if testing.Short() {
		t.Skip("mines a long chain")
	}
	// A snap sync puts its pivot 64 blocks below the peer's head and below
	// that only downloads, so a chain of this length leaves most of it to
	// the snap part. Each seed mines with two threads to build it sooner.
	const length = 160

	seedA := startMiningNode(t, "seed-a", 0xb1, 2, "")
	_, seedAURL := seedA.enode(t)
	seedB := startMiningNode(t, "seed-b", 0xb2, 2, seedAURL)
	_, seedBURL := seedB.enode(t)
	waitForEthPeer(t, seedA.testNode, seedB.testNode)

	start := time.Now()
	waitFor(t, 10*time.Minute, fmt.Sprintf("the seeds to mine %d blocks", length), func() (bool, error) {
		return seedA.head(t) >= length, nil
	})
	t.Logf("result: seeds mined %d blocks in %v", seedA.head(t), time.Since(start).Round(time.Second))

	start = time.Now()
	fresh := startMiningNode(t, "fresh", 0xb3, 1, seedAURL, seedBURL)
	waitFor(t, 5*time.Minute, "the new node to reach the seeds' chain", func() (bool, error) {
		b := fresh.block(t, length)
		return b != nil && *b == *seedA.block(t, length), nil
	})
	t.Logf("result: new mining node synced past block %d in %v", length, time.Since(start).Round(time.Second))

	out := fresh.log()
	if !strings.Contains(out, logMiningKeepsSnap) {
		t.Errorf("starting the miner did not keep snap sync on; the log has no %q", logMiningKeepsSnap)
	}
	pivot := strings.Index(out, logSnapPivot)
	if pivot < 0 {
		t.Fatalf("the new node did not snap sync: its log has no %q", logSnapPivot)
	}
	if sealed := strings.Index(out, logSealed); sealed >= 0 && sealed < pivot {
		t.Errorf("the new node sealed a block before its snap sync committed its pivot")
	}

	// Once synced, the new node mines on the seeds' chain: a block it
	// sealed lands on both seeds' canonical chain.
	from := fresh.head(t) + 1
	waitFor(t, 3*time.Minute, "a block of the new node on the seeds' chain", func() (bool, error) {
		to := seedA.head(t)
		for number := from; number <= to; number++ {
			if b := seedA.block(t, number); b != nil && b.Miner == fresh.etherbase {
				other := seedB.block(t, number)
				return other != nil && *other == *b, nil
			}
		}
		return false, nil
	})
}

// TestPublicTestNetMiningNodesStartTogether checks that several nodes started
// together at genesis, each mining on an empty data directory, build one
// chain: each takes the blocks the others propagate instead of discarding
// them while it has yet to sync, all agree on it, blocks of more than one of
// them are on it, and each has left snap sync once it reached the network's
// head.
func TestPublicTestNetMiningNodesStartTogether(t *testing.T) {
	if testing.Short() {
		t.Skip("mines a chain on three nodes")
	}
	const length = 40

	a := startMiningNode(t, "miner-a", 0xc1, 1, "")
	_, aURL := a.enode(t)
	b := startMiningNode(t, "miner-b", 0xc2, 1, aURL)
	c := startMiningNode(t, "miner-c", 0xc3, 1, aURL)
	nodes := []*miningNode{a, b, c}

	start := time.Now()
	waitFor(t, 5*time.Minute, fmt.Sprintf("every node to pass block %d", length), func() (bool, error) {
		for _, n := range nodes {
			if n.head(t) < length {
				return false, nil
			}
		}
		return true, nil
	})
	t.Logf("result: three miners passed block %d in %v", length, time.Since(start).Round(time.Second))

	// Blocks well below the heads are settled: every node has the same.
	const settled = length - 10
	waitFor(t, time.Minute, fmt.Sprintf("the nodes to agree on block %d", settled), func() (bool, error) {
		want := a.block(t, settled)
		for _, n := range nodes[1:] {
			if got := n.block(t, settled); got == nil || want == nil || *got != *want {
				return false, nil
			}
		}
		return true, nil
	})
	miners := minedBy(t, a, 1, settled)
	t.Logf("result: miners of blocks 1-%d: %v", settled, miners)
	if len(miners) < 2 {
		t.Errorf("one node mined every block of 1-%d; the nodes did not take each other's blocks", settled)
	}
	for addr := range miners {
		if addr != a.etherbase && addr != b.etherbase && addr != c.etherbase {
			t.Errorf("block mined by %x, not one of the three nodes", addr)
		}
	}
	for _, n := range nodes {
		if !strings.Contains(n.log(), logSnapOff) {
			t.Errorf("%s: still in snap sync after reaching the network's head; its log has no %q", n.name, logSnapOff)
		}
	}

	// And they keep going.
	next := a.head(t) + 10
	waitFor(t, 2*time.Minute, fmt.Sprintf("every node to pass block %d", next), func() (bool, error) {
		for _, n := range nodes {
			if n.head(t) < next {
				return false, nil
			}
		}
		return true, nil
	})
}
