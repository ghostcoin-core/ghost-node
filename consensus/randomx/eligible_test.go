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

package randomx

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
)

// leafAt names a block by its coinbase and height.
type leafAt struct {
	coinbase common.Address
	number   uint64
}

// leafEngine appends coin leaf i and data leaf i+500 to the block planned
// for i, so that the block's roots differ from its parent's. Blocks that
// append the same leaves to the same trees carry the same roots.
func leafEngine(t *testing.T, f *sealedChainFixture, plan map[leafAt]int) *treeWriter {
	return &treeWriter{RandomX: f.engine, write: func(h *types.Header, st *state.StateDB) {
		i, ok := plan[leafAt{h.Coinbase, h.Number.Uint64()}]
		if !ok {
			return
		}
		if _, err := ghosttree.Append(st, ghosttree.Coin, h.Number.Uint64(), testTreeLeaf(i)); err != nil {
			t.Errorf("block %d: coin append: %v", h.Number, err)
		}
		if _, err := ghosttree.Append(st, ghosttree.Data, h.Number.Uint64(), testTreeLeaf(i+500)); err != nil {
			t.Errorf("block %d: data append: %v", h.Number, err)
		}
	}}
}

// rootNode is a blockchain on its own database.
type rootNode struct {
	db    ethdb.Database
	chain *core.BlockChain
}

func newRootNode(t *testing.T, f *sealedChainFixture, engine *treeWriter) *rootNode {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, f.gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &rootNode{db: db, chain: chain}
}

func (n *rootNode) mine(t *testing.T, f *sealedChainFixture, engine *treeWriter, coinbase common.Address, count int) types.Blocks {
	t.Helper()
	var blocks types.Blocks
	for i := 0; i < count; i++ {
		blocks = append(blocks, mineOn(t, engine, f.engine, n.chain, coinbase, nil, true))
	}
	return blocks
}

func (n *rootNode) insert(t *testing.T, blocks types.Blocks) {
	t.Helper()
	if _, err := n.chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
}

// rootOf returns a root field of a block.
func rootOf(b *types.Block, kind ghosttree.Kind) common.Hash {
	return *ghosttree.HeaderRoot(b.Header(), kind)
}

// eligibleOn answers EligibleRoot on a node, failing the test on an error.
func eligibleOn(t *testing.T, n *rootNode, parent *types.Block, kind ghosttree.Kind, root common.Hash) bool {
	t.Helper()
	ok, err := ghosttree.EligibleRoot(n.chain, parent.Header(), kind, root)
	if err != nil {
		t.Fatalf("parent %d %x, %v root %x: %v", parent.NumberU64(), parent.Hash(), kind, root, err)
	}
	return ok
}

type kindRoot struct {
	kind ghosttree.Kind
	root common.Hash
}

// rootsOf lists both roots of every block.
func rootsOf(blocks ...*types.Block) []kindRoot {
	var out []kindRoot
	for _, b := range blocks {
		for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
			out = append(out, kindRoot{kind, rootOf(b, kind)})
		}
	}
	return out
}

// answers lists EligibleRoot for every parent and root, errors included.
func answers(n *rootNode, parents types.Blocks, roots []kindRoot) []string {
	var out []string
	for _, p := range parents {
		for _, r := range roots {
			ok, err := ghosttree.EligibleRoot(n.chain, p.Header(), r.kind, r.root)
			out = append(out, fmt.Sprintf("parent %d %x, %v root %x: %v %v", p.NumberU64(), p.Hash().Bytes()[:4], r.kind, r.root.Bytes()[:4], ok, err))
		}
	}
	return out
}

func compareAnswers(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d answers, want %d", what, len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: %s, want %s", what, got[i], want[i])
		}
	}
}

// rootIndex returns every entry of a node's root index and its head.
func rootIndex(t *testing.T, db ethdb.Database) (map[string]uint64, string) {
	t.Helper()
	entries := make(map[string]uint64)
	err := rawdb.IterateGhostRootHeights(db, func(kind uint8, root common.Hash, number uint64) error {
		entries[fmt.Sprintf("%v %x", ghosttree.Kind(kind), root)] = number
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	number, hash, ok, err := rawdb.ReadGhostRootIndexHead(db)
	if err != nil || !ok {
		t.Fatalf("index head: %v %v", ok, err)
	}
	return entries, fmt.Sprintf("%d %x", number, hash)
}

func compareIndexes(t *testing.T, what string, a, b ethdb.Database) {
	t.Helper()
	got, gotHead := rootIndex(t, a)
	want, wantHead := rootIndex(t, b)
	if gotHead != wantHead {
		t.Errorf("%s: index head %s, want %s", what, gotHead, wantHead)
	}
	for k, n := range got {
		if w, ok := want[k]; !ok || w != n {
			t.Errorf("%s: entry %s at %d, other node %d (present %v)", what, k, n, w, ok)
		}
	}
	for k, n := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: entry %s at %d missing", what, k, n)
		}
	}
}

func cat(parts ...types.Blocks) types.Blocks {
	var out types.Blocks
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestDiscardedBranchRootIsRejectedEvenIfSeen imports a branch A whose blocks
// carry new roots, then a heavier branch B without them: once B is canonical,
// A's roots are rejected for blocks on B, although the node imported A and
// followed it.
func TestDiscardedBranchRootIsRejectedEvenIfSeen(t *testing.T) {
	f := sealedChain(t)
	var (
		trunk = common.Address{0x72}
		sideA = common.Address{0xa2}
		sideB = common.Address{0xb2}
	)
	engine := leafEngine(t, f, map[leafAt]int{{trunk, 1}: 1, {sideA, 3}: 2, {sideA, 4}: 3})
	seen := newRootNode(t, f, engine)
	defer seen.chain.Stop()
	onlyB := newRootNode(t, f, engine)
	defer onlyB.chain.Stop()

	trunkBlocks := onlyB.mine(t, f, engine, trunk, 2)
	seen.insert(t, trunkBlocks)
	branchA := seen.mine(t, f, engine, sideA, 2)
	branchB := onlyB.mine(t, f, engine, sideB, 3)

	// Canonical, A's roots are eligible above the blocks carrying them.
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		if !eligibleOn(t, seen, branchA[1], kind, rootOf(branchA[0], kind)) {
			t.Fatalf("%v root of A's first block not eligible while A is canonical", kind)
		}
	}
	seen.insert(t, branchB)
	if seen.chain.CurrentBlock().Hash() != branchB[2].Hash() {
		t.Fatal("the node did not switch to branch B")
	}
	for _, b := range branchA {
		if seen.chain.GetHeader(b.Hash(), b.NumberU64()) == nil {
			t.Fatal("branch A's headers are gone; the test needs them stored")
		}
	}
	for _, node := range []*rootNode{seen, onlyB} {
		for _, parent := range cat(trunkBlocks[1:], branchB) {
			for _, r := range rootsOf(branchA...) {
				if eligibleOn(t, node, parent, r.kind, r.root) {
					t.Errorf("%v root %x of branch A eligible above block %d of B", r.kind, r.root, parent.NumberU64())
				}
			}
			for _, r := range rootsOf(trunkBlocks...) {
				if !eligibleOn(t, node, parent, r.kind, r.root) {
					t.Errorf("trunk %v root %x not eligible above block %d of B", r.kind, r.root, parent.NumberU64())
				}
			}
		}
	}
	// For a block on A itself, its own ancestry still holds them.
	if !eligibleOn(t, seen, branchA[1], ghosttree.Coin, rootOf(branchA[0], ghosttree.Coin)) {
		t.Error("A's root not eligible on A's own branch")
	}
}

// TestSideBranchIsValidatedAgainstItsOwnAncestry builds a branch B whose
// first block carries a new root and imports it on a node that follows the
// heavier branch A: the root is eligible above that block of B while the
// node follows A. Once B overtakes A, the node answers as a node that
// followed B from the start.
func TestSideBranchIsValidatedAgainstItsOwnAncestry(t *testing.T) {
	f := sealedChain(t)
	var (
		trunk = common.Address{0x71}
		sideA = common.Address{0xa1}
		sideB = common.Address{0xb1}
	)
	engine := leafEngine(t, f, map[leafAt]int{{trunk, 1}: 1, {sideA, 3}: 2, {sideB, 3}: 10, {sideB, 5}: 11})
	switched := newRootNode(t, f, engine)
	defer switched.chain.Stop()
	onlyB := newRootNode(t, f, engine)
	defer onlyB.chain.Stop()

	trunkBlocks := onlyB.mine(t, f, engine, trunk, 2)
	switched.insert(t, trunkBlocks)
	branchA := switched.mine(t, f, engine, sideA, 3)
	branchB := onlyB.mine(t, f, engine, sideB, 4)
	rootB := rootOf(branchB[0], ghosttree.Coin)
	if rootB == rootOf(trunkBlocks[1], ghosttree.Coin) || rootB == rootOf(branchA[0], ghosttree.Coin) {
		t.Fatal("B's first block carries no new root")
	}

	// B's first two blocks, lighter than A: stored, not followed.
	switched.insert(t, branchB[:2])
	if switched.chain.CurrentBlock().Hash() != branchA[2].Hash() {
		t.Fatal("the node left branch A")
	}
	if !eligibleOn(t, switched, branchB[1], ghosttree.Coin, rootB) {
		t.Error("B's root not eligible above B's second block while the node follows A")
	}
	if !eligibleOn(t, switched, branchB[0], ghosttree.Data, rootOf(branchB[0], ghosttree.Data)) {
		t.Error("B's data root not eligible above B's first block while the node follows A")
	}
	if eligibleOn(t, switched, trunkBlocks[1], ghosttree.Coin, rootB) {
		t.Error("B's root eligible for B's first block itself")
	}
	if eligibleOn(t, switched, branchA[2], ghosttree.Coin, rootB) {
		t.Error("B's root eligible on branch A")
	}
	if eligibleOn(t, switched, branchB[1], ghosttree.Coin, rootOf(branchA[0], ghosttree.Coin)) {
		t.Error("the canonical branch A's root eligible on branch B")
	}
	roots := rootsOf(cat(trunkBlocks, branchA, branchB)...)
	before := answers(switched, cat(trunkBlocks, branchB[:2]), roots)
	compareAnswers(t, "B's blocks while following A, against the node on B", before, answers(onlyB, cat(trunkBlocks, branchB[:2]), roots))

	// The switch.
	switched.insert(t, branchB[2:])
	if switched.chain.CurrentBlock().Hash() != branchB[3].Hash() {
		t.Fatal("the node did not switch to branch B")
	}
	parents := cat(trunkBlocks, branchB)
	compareAnswers(t, "after the switch, against the node on B", answers(switched, parents, roots), answers(onlyB, parents, roots))
	compareAnswers(t, "after the switch, against the answers before it", answers(switched, cat(trunkBlocks, branchB[:2]), roots), before)
	if eligibleOn(t, switched, branchB[1], ghosttree.Coin, rootOf(branchB[2], ghosttree.Coin)) {
		t.Error("the root of B's third block eligible for that block")
	}
	if !eligibleOn(t, switched, branchB[2], ghosttree.Coin, rootOf(branchB[2], ghosttree.Coin)) {
		t.Error("the root of B's third block not eligible above it")
	}
}

// TestRootInBothBranchesIsEligibleThroughTheAncestor checks roots carried by
// a block of the discarded branch and by a block that stays in the ancestry:
// a trunk root that A's blocks repeat, and a root that A carries first and B
// carries one block higher.
func TestRootInBothBranchesIsEligibleThroughTheAncestor(t *testing.T) {
	f := sealedChain(t)
	var (
		trunk = common.Address{0x74}
		sideA = common.Address{0xa4}
		sideB = common.Address{0xb4}
	)
	// A appends leaf 2 at height 4, B the same leaf at height 5: the same
	// coin root at different heights.
	engine := leafEngine(t, f, map[leafAt]int{{trunk, 1}: 1, {sideA, 4}: 2, {sideB, 5}: 2})
	reorged := newRootNode(t, f, engine)
	defer reorged.chain.Stop()
	onlyB := newRootNode(t, f, engine)
	defer onlyB.chain.Stop()

	trunkBlocks := onlyB.mine(t, f, engine, trunk, 2)
	reorged.insert(t, trunkBlocks)
	branchA := reorged.mine(t, f, engine, sideA, 2)
	branchB := onlyB.mine(t, f, engine, sideB, 3)
	trunkRoot, shared := rootOf(trunkBlocks[0], ghosttree.Coin), rootOf(branchA[1], ghosttree.Coin)
	if rootOf(branchA[0], ghosttree.Coin) != trunkRoot {
		t.Fatal("A's first block does not repeat the trunk root")
	}
	if rootOf(branchB[2], ghosttree.Coin) != shared || rootOf(branchB[1], ghosttree.Coin) == shared {
		t.Fatal("B's third block does not carry A's root first")
	}
	reorged.insert(t, branchB)
	if reorged.chain.CurrentBlock().Hash() != branchB[2].Hash() {
		t.Fatal("the node did not switch to branch B")
	}
	for _, node := range []*rootNode{reorged, onlyB} {
		for _, parent := range branchB {
			if !eligibleOn(t, node, parent, ghosttree.Coin, trunkRoot) {
				t.Errorf("trunk root, also in A, not eligible above block %d of B", parent.NumberU64())
			}
		}
		if eligibleOn(t, node, branchB[1], ghosttree.Coin, shared) {
			t.Error("A's root eligible for the block of B that carries it first")
		}
		if !eligibleOn(t, node, branchB[2], ghosttree.Coin, shared) {
			t.Error("A's root not eligible above the block of B that carries it")
		}
		height, found, err := node.chain.RootFirstHeight(ghosttree.Coin, shared)
		if err != nil || !found || height != 5 {
			t.Errorf("entry of the shared root: %d %v %v, want height 5", height, found, err)
		}
	}
	compareIndexes(t, "after the reorganisation", reorged.db, onlyB.db)
}

// TestEligibilityAfterForcedReorg follows a branch A with new roots, then
// reorganises to a heavier branch B with roots of its own: the index loses
// A's entries, gains B's, and equals that of a node that synced only B, and
// so do the answers. A rewind, a reimport and a restart on a database
// without the index lead to the same index again.
func TestEligibilityAfterForcedReorg(t *testing.T) {
	f := sealedChain(t)
	var (
		trunk = common.Address{0x73}
		sideA = common.Address{0xa3}
		sideB = common.Address{0xb3}
	)
	engine := leafEngine(t, f, map[leafAt]int{{trunk, 1}: 1, {sideA, 3}: 2, {sideA, 4}: 3, {sideB, 3}: 30, {sideB, 5}: 31})
	reorged := newRootNode(t, f, engine)
	onlyB := newRootNode(t, f, engine)
	defer onlyB.chain.Stop()

	trunkBlocks := onlyB.mine(t, f, engine, trunk, 2)
	reorged.insert(t, trunkBlocks)
	branchA := reorged.mine(t, f, engine, sideA, 2)
	branchB := onlyB.mine(t, f, engine, sideB, 3)
	for _, r := range rootsOf(branchA...) {
		if _, found, err := reorged.chain.RootFirstHeight(r.kind, r.root); err != nil || !found {
			t.Fatalf("branch A's %v root %x not indexed while A is canonical: %v", r.kind, r.root, err)
		}
	}

	reorged.insert(t, branchB)
	if reorged.chain.CurrentBlock().Hash() != branchB[2].Hash() {
		t.Fatal("the node did not switch to branch B")
	}
	compareIndexes(t, "after the reorganisation", reorged.db, onlyB.db)
	for _, r := range rootsOf(branchA...) {
		if _, found, err := reorged.chain.RootFirstHeight(r.kind, r.root); err != nil || found {
			t.Errorf("branch A's %v root %x still indexed (%v)", r.kind, r.root, err)
		}
	}
	for i, b := range branchB {
		for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
			want := b.NumberU64()
			if i > 0 && rootOf(b, kind) == rootOf(branchB[i-1], kind) {
				continue
			}
			if height, found, err := reorged.chain.RootFirstHeight(kind, rootOf(b, kind)); err != nil || !found || height != want {
				t.Errorf("branch B's %v root of block %d: %d %v %v", kind, want, height, found, err)
			}
		}
	}
	roots := rootsOf(cat(trunkBlocks, branchA, branchB)...)
	parents := cat(trunkBlocks, branchB)
	compareAnswers(t, "after the reorganisation, against the node that saw only B", answers(reorged, parents, roots), answers(onlyB, parents, roots))

	// A rewind to the trunk and the reimport of B.
	if err := reorged.chain.SetHead(trunkBlocks[1].NumberU64()); err != nil {
		t.Fatal(err)
	}
	head := reorged.chain.CurrentBlock()
	trunkOnly := newRootNode(t, f, engine)
	defer trunkOnly.chain.Stop()
	trunkOnly.insert(t, trunkBlocks[:head.Number.Uint64()])
	compareIndexes(t, "after the rewind, against a node with the trunk only", reorged.db, trunkOnly.db)
	reorged.insert(t, cat(trunkBlocks[head.Number.Uint64():], branchB))
	compareIndexes(t, "after the reimport", reorged.db, onlyB.db)

	// A database whose index is gone rejects, and a restart builds the index
	// from the stored headers.
	reorged.chain.Stop()
	batch := reorged.db.NewBatch()
	err := rawdb.IterateGhostRootHeights(reorged.db, func(kind uint8, root common.Hash, _ uint64) error {
		return rawdb.DeleteGhostRootHeight(batch, kind, root)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rawdb.DeleteGhostRootIndexHead(batch); err != nil {
		t.Fatal(err)
	}
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
	ok, err := ghosttree.EligibleRoot(reorged.chain, branchB[2].Header(), ghosttree.Coin, rootOf(trunkBlocks[0], ghosttree.Coin))
	if ok || !errors.Is(err, ghosttree.ErrIndexNotReady) {
		t.Errorf("without the index: %v %v, want %v", ok, err, ghosttree.ErrIndexNotReady)
	}
	restarted, err := core.NewBlockChain(reorged.db, nil, f.gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	if restarted.CurrentBlock().Hash() != branchB[2].Hash() {
		t.Fatalf("restarted at block %d", restarted.CurrentBlock().Number)
	}
	compareIndexes(t, "after the restart", reorged.db, onlyB.db)
	compareAnswers(t, "after the restart", answers(&rootNode{db: reorged.db, chain: restarted}, parents, roots), answers(onlyB, parents, roots))
}
