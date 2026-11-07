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
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostmmr"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// mmrOver is the header MMR over the given headers, built here leaf by leaf
// rather than read from the engine or the chain.
func mmrOver(t *testing.T, headers []*types.Header) ghostmmr.State {
	t.Helper()
	var s ghostmmr.State
	for _, h := range headers {
		work, err := ghostmmr.WorkFromBig(h.Difficulty)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Push(ghostmmr.Leaf(h.Hash(), work), nil); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func mmrRootOver(t *testing.T, headers []*types.Header) common.Hash {
	t.Helper()
	root, err := mmrOver(t, headers).Root()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// ancestry returns the headers of the chain from genesis to head, oldest
// first.
func ancestry(t *testing.T, chain *core.BlockChain, head *types.Header) []*types.Header {
	t.Helper()
	headers := []*types.Header{head}
	for h := head; h.Number.Sign() > 0; {
		if h = chain.GetHeader(h.ParentHash, h.Number.Uint64()-1); h == nil {
			t.Fatal("missing ancestor")
		}
		headers = append([]*types.Header{h}, headers...)
	}
	return headers
}

// requireMMRFollows checks the header MMR root of every header of the chain
// up to head against the MMR over the headers before it, and the paths of
// every block from head against head's root.
func requireMMRFollows(t *testing.T, name string, chain *core.BlockChain, head *types.Header) {
	t.Helper()
	headers := ancestry(t, chain, head)
	for i, h := range headers[1:] {
		if h.HeaderMmrRoot == nil || *h.HeaderMmrRoot != mmrRootOver(t, headers[:i+1]) {
			t.Fatalf("%s: block %d carries header MMR root %v, not the root over its %d earlier blocks", name, i+1, h.HeaderMmrRoot, i+1)
		}
		state, err := chain.HeaderMMR(h.Hash(), h.Number.Uint64())
		if err != nil {
			t.Fatal(err)
		}
		if root, _ := state.Root(); root != *h.HeaderMmrRoot || state.N != h.Number.Uint64() {
			t.Fatalf("%s: the chain's header MMR of block %d has root %x over %d leaves", name, i+1, root, state.N)
		}
	}
	n := head.Number.Uint64()
	for i := uint64(0); i < n; i++ {
		path, err := chain.HeaderMMRPath(head.Hash(), i)
		if err != nil {
			t.Fatalf("%s: path of block %d: %v", name, i, err)
		}
		work, _ := ghostmmr.WorkFromBig(headers[i].Difficulty)
		before, _, err := ghostmmr.VerifyPath(*head.HeaderMmrRoot, n, i, headers[i].Hash(), work, path)
		if err != nil {
			t.Fatalf("%s: path of block %d does not verify against the head: %v", name, i, err)
		}
		if want := new(big.Int).Mul(testDifficulty, new(big.Int).SetUint64(i)); before.Big().Cmp(want) != 0 {
			t.Errorf("%s: work before block %d is %v, want %v", name, i, before, want)
		}
	}
}

// TestHeaderMMRRootRejected seals blocks whose header MMR root is one bit
// off, the parent's, or missing: VerifyHeader rejects each with
// ErrHeaderMmrRoot, alone and in a batch, InsertChain does not import it,
// and the check comes before the body is executed.
func TestHeaderMMRRootRejected(t *testing.T) {
	f := sealedChain(t)
	chain, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if _, err := chain.InsertChain(f.blocks); err != nil {
		t.Fatal(err)
	}
	head := chain.CurrentBlock()
	requireMMRFollows(t, "sealed chain", chain, head)

	for _, c := range []struct {
		name   string
		change func(h *types.Header)
	}{
		{"lowest bit", func(h *types.Header) { flipBit(h.HeaderMmrRoot, 0) }},
		{"highest bit", func(h *types.Header) { flipBit(h.HeaderMmrRoot, 255) }},
		{"the parent's root", func(h *types.Header) { root := *head.HeaderMmrRoot; h.HeaderMmrRoot = &root }},
		{"the empty root", func(h *types.Header) { root := common.Hash(ghostmmr.EmptyRoot); h.HeaderMmrRoot = &root }},
		{"no root", func(h *types.Header) { h.HeaderMmrRoot = nil }},
		// A wrong coin tree root too: the header check comes first.
		{"and a wrong coin root", func(h *types.Header) { flipBit(h.HeaderMmrRoot, 7); flipBit(h.CoinTreeRoot, 7) }},
	} {
		bad := mineOn(t, f.engine, f.engine, chain, common.Address{0xe1}, c.change, false)
		if err := f.engine.VerifyHeader(chain, bad.Header(), true); !errors.Is(err, ErrHeaderMmrRoot) {
			t.Errorf("%s: VerifyHeader error %v, want %v", c.name, err, ErrHeaderMmrRoot)
		}
		if err := f.engine.VerifyHeader(chain, bad.Header(), false); !errors.Is(err, ErrHeaderMmrRoot) {
			t.Errorf("%s, without the seal check: error %v, want %v", c.name, err, ErrHeaderMmrRoot)
		}
		// In a batch with its good parent and the chain below.
		reader := newTestReader(chain.Config(), f.genesis.Header(), f.headers()...)
		batch := []*types.Header{bad.Header()}
		abort, results := f.engine.VerifyHeaders(reader, batch, []bool{true})
		if err := <-results; !errors.Is(err, ErrHeaderMmrRoot) {
			t.Errorf("%s: VerifyHeaders error %v, want %v", c.name, err, ErrHeaderMmrRoot)
		}
		close(abort)
		_, err := chain.InsertChain(types.Blocks{bad})
		if !errors.Is(err, ErrHeaderMmrRoot) || strings.Contains(err.Error(), "coinTreeRoot") {
			t.Errorf("%s: InsertChain error %v, want %v before the body", c.name, err, ErrHeaderMmrRoot)
		}
		if chain.CurrentBlock().Hash() != head.Hash() || chain.HasBlock(bad.Hash(), bad.NumberU64()) {
			t.Errorf("%s: the block was imported", c.name)
		}
	}
	// The same block with its true root is accepted, and the root is sealed.
	good := mineOn(t, f.engine, f.engine, chain, common.Address{0xe1}, nil, true)
	h := good.Header()
	if *h.HeaderMmrRoot != mmrRootOver(t, ancestry(t, chain, head)) {
		t.Fatal("the assembled block does not carry the root over the earlier blocks")
	}
	moved := types.CopyHeader(h)
	flipBit(moved.HeaderMmrRoot, 100)
	if f.engine.SealHash(moved) == f.engine.SealHash(h) {
		t.Error("the header MMR root is not in the seal hash")
	}
}

// TestHeaderMMRVerifyHeadersBatch checks a batch of headers whose parents are
// in the batch: each header's root is checked against the state of its
// parent in the batch, and a wrong root in the middle fails that header only.
func TestHeaderMMRVerifyHeadersBatch(t *testing.T) {
	f := sealedChain(t)
	engine := newTestEngine(t, testParams()) // nothing remembered
	reader := newTestReader(testConfig(), f.genesis.Header())
	headers := f.headers()
	seals := make([]bool, len(headers))
	abort, results := engine.VerifyHeaders(reader, headers, seals)
	for i := range headers {
		if err := <-results; err != nil {
			t.Fatalf("header %d of the batch: %v", i+1, err)
		}
	}
	close(abort)

	engine = newTestEngine(t, testParams())
	wrong := append([]*types.Header{}, headers...)
	wrong[9] = types.CopyHeader(headers[9])
	flipBit(wrong[9].HeaderMmrRoot, 3)
	abort, results = engine.VerifyHeaders(reader, wrong[:10], seals[:10])
	for i := 0; i < 10; i++ {
		err := <-results
		if i == 9 && !errors.Is(err, ErrHeaderMmrRoot) {
			t.Errorf("the wrong header: %v, want %v", err, ErrHeaderMmrRoot)
		}
		if i != 9 && err != nil {
			t.Errorf("header %d: %v", i+1, err)
		}
	}
	close(abort)
}

// TestHeaderMMRFollowsReorg builds a branch A and a heavier branch B on the
// sealed chain: after the reorganisation every header of the new chain
// carries the root over its own ancestry, the chain's MMR state of the head
// is that of a node that only saw B, every path from the head verifies, and
// a header of A does not verify where B's stands. A heavier A brings the MMR
// back to A.
func TestHeaderMMRFollowsReorg(t *testing.T) {
	f := sealedChain(t)
	reorged, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer reorged.Stop()
	onlyB, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer onlyB.Stop()
	onlyA, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer onlyA.Stop()
	for _, c := range []*core.BlockChain{reorged, onlyB, onlyA} {
		if _, err := c.InsertChain(f.blocks); err != nil {
			t.Fatal(err)
		}
	}
	ancestor := reorged.CurrentBlock()

	var branchA, branchB types.Blocks
	for i := 0; i < 2; i++ {
		branchA = append(branchA, mineOn(t, f.engine, f.engine, reorged, common.Address{0xa1}, nil, true))
	}
	if _, err := onlyA.InsertChain(branchA); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		branchB = append(branchB, mineOn(t, f.engine, f.engine, onlyB, common.Address{0xb1}, nil, true))
	}
	headA := reorged.CurrentBlock()
	requireMMRFollows(t, "branch A", reorged, headA)

	if _, err := reorged.InsertChain(branchB); err != nil {
		t.Fatal(err)
	}
	head := reorged.CurrentBlock()
	if head.Hash() != branchB[2].Hash() {
		t.Fatal("the node did not reorganise to branch B")
	}
	requireMMRFollows(t, "after the reorganisation", reorged, head)
	ours, err := reorged.HeaderMMR(head.Hash(), head.Number.Uint64())
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := onlyB.HeaderMMR(head.Hash(), head.Number.Uint64())
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := ours.Root(); a != mustRoot(t, theirs) || ours.N != theirs.N {
		t.Fatal("the reorganised node's header MMR differs from the node that only saw B")
	}
	// The first block of A in place of the first block of B does not verify.
	n, i := head.Number.Uint64(), ancestor.Number.Uint64()+1
	path, err := reorged.HeaderMMRPath(head.Hash(), i)
	if err != nil {
		t.Fatal(err)
	}
	work, _ := ghostmmr.WorkFromBig(testDifficulty)
	if _, _, err := ghostmmr.VerifyPath(*head.HeaderMmrRoot, n, i, branchA[0].Hash(), work, path); !errors.Is(err, ghostmmr.ErrRootMismatch) {
		t.Errorf("branch A's block %d verifies in branch B: %v", i, err)
	}
	if _, _, err := ghostmmr.VerifyPath(*head.HeaderMmrRoot, n, i, branchB[0].Hash(), work, path); err != nil {
		t.Errorf("branch B's block %d: %v", i, err)
	}
	// Branch A's states are still those of A.
	stateA, err := reorged.HeaderMMR(headA.Hash(), headA.Number.Uint64())
	if err != nil || mustRoot(t, stateA) != *headA.HeaderMmrRoot {
		t.Fatalf("branch A's head state after the reorganisation: %v", err)
	}
	// The next block on B carries the root over B's chain.
	next := mineOn(t, f.engine, f.engine, reorged, common.Address{0xb2}, nil, true)
	if *next.Header().HeaderMmrRoot != mmrRootOver(t, ancestry(t, reorged, head)) {
		t.Fatal("a block built after the reorganisation does not carry B's root")
	}

	// A grows heavier than B, on a node that follows A: the MMR goes back to
	// A's chain.
	var moreA types.Blocks
	for i := 0; i < 3; i++ {
		moreA = append(moreA, mineOn(t, f.engine, f.engine, onlyA, common.Address{0xa2}, nil, true))
	}
	if _, err := reorged.InsertChain(moreA); err != nil {
		t.Fatal(err)
	}
	if reorged.CurrentBlock().Hash() != moreA[2].Hash() {
		t.Fatal("the node did not reorganise back to A")
	}
	requireMMRFollows(t, "back on A", reorged, reorged.CurrentBlock())
}

func mustRoot(t *testing.T, s ghostmmr.State) common.Hash {
	t.Helper()
	root, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestHeaderMMRWithoutChainStore checks that the engine computes the state
// a header commits to from the headers alone, for a chain that keeps no
// header MMR, and gets the chain's answer.
func TestHeaderMMRWithoutChainStore(t *testing.T) {
	f := sealedChain(t)
	chain, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if _, err := chain.InsertChain(f.blocks); err != nil {
		t.Fatal(err)
	}
	reader := newTestReader(testConfig(), f.genesis.Header(), f.headers()...)
	for _, h := range f.headers() {
		engine := newTestEngine(t, testParams())
		got, err := engine.headerMMROf(reader, reader.GetHeader, h)
		if err != nil {
			t.Fatal(err)
		}
		want, err := chain.HeaderMMR(h.Hash(), h.Number.Uint64())
		if err != nil {
			t.Fatal(err)
		}
		if mustRoot(t, got) != mustRoot(t, want) || got.N != h.Number.Uint64() {
			t.Fatalf("block %d: the engine's state differs from the chain's", h.Number)
		}
	}
	// A header whose ancestry is unknown has no state.
	orphan := types.CopyHeader(f.blocks[5].Header())
	orphan.ParentHash = common.Hash{0x0f}
	if _, err := newTestEngine(t, testParams()).headerMMROf(reader, reader.GetHeader, orphan); err == nil {
		t.Error("a header with an unknown parent has a header MMR state")
	}
}

// TestHeaderMMRWorkOverflow checks the 2^128 bound on a chain's total
// difficulty with the block's own: reaching it is ErrWorkOverflow, with the
// reason work-overflow, and one below is accepted.
func TestHeaderMMRWorkOverflow(t *testing.T) {
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	near := func(total *big.Int) ghostmmr.State {
		w, err := ghostmmr.WorkFromBig(total)
		if err != nil {
			t.Fatal(err)
		}
		return ghostmmr.State{N: 1, Peaks: []ghostmmr.Entry{{Work: w}}}
	}
	header := &types.Header{Difficulty: big.NewInt(16)}
	if err := checkHeaderMMR(header, near(new(big.Int).Sub(two128, big.NewInt(16)))); !errors.Is(err, ErrWorkOverflow) || !errors.Is(err, ghostmmr.ErrWorkOverflow) || !strings.Contains(err.Error(), "work-overflow") {
		t.Errorf("total difficulty of 2^128: %v", err)
	}
	if err := checkHeaderMMR(header, near(new(big.Int).Sub(two128, big.NewInt(17)))); err != nil {
		t.Errorf("total difficulty of 2^128 - 1: %v", err)
	}
	// A difficulty of 2^128 itself is no leaf.
	if _, err := headerMMRLeaf(&types.Header{Difficulty: two128, Number: big.NewInt(1)}); !errors.Is(err, ErrWorkOverflow) {
		t.Errorf("a difficulty of 2^128: %v", err)
	}
	// A child of a parent that would take the chain to 2^128 has no state.
	parent := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(16)}
	if _, err := childMMR(near(new(big.Int).Sub(two128, big.NewInt(16))), parent); !errors.Is(err, ErrWorkOverflow) {
		t.Errorf("a parent leaf to 2^128: %v", err)
	}
	// A root on a header without tree roots is refused, and a header without
	// tree roots needs none.
	root := common.Hash{1}
	if err := checkHeaderMMR(&types.Header{Difficulty: big.NewInt(1), HeaderMmrRoot: &root}, ghostmmr.State{}); !errors.Is(err, errUnsupportedField) {
		t.Errorf("a header MMR root without tree roots: %v", err)
	}
	if err := checkHeaderMMR(&types.Header{Difficulty: big.NewInt(1)}, ghostmmr.State{}); err != nil {
		t.Errorf("a base header: %v", err)
	}
}

// TestHeaderMMRGenesis checks that the Ghost genesis blocks carry the root of
// the empty MMR in the Ghost layout, and that the internal network's first
// blocks carry the root over the genesis.
func TestHeaderMMRGenesis(t *testing.T) {
	empty := common.HexToHash("b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac")
	for name, g := range map[string]*genesisT.Genesis{
		"internal network":      ghost.InternalNetGenesis(),
		"public test network":   ghost.TestNetGenesis(),
		"developer mode":        params.DeveloperGenesisBlock(11_500_000, nil),
		"another configuration": testGenesis(),
	} {
		h := core.GenesisToBlock(g, nil).Header()
		if name == "another configuration" {
			if h.HeaderMmrRoot != nil {
				t.Errorf("%s: genesis has a header MMR root", name)
			}
			continue
		}
		if h.HeaderMmrRoot == nil || *h.HeaderMmrRoot != empty {
			t.Errorf("%s: genesis header MMR root %v, want the empty root %x", name, h.HeaderMmrRoot, empty)
		}
	}
	engine, err := New(Config{Params: ghost.InternalNetParams()})
	if err != nil {
		t.Fatal(err)
	}
	engine.SetThreads(1)
	chain, err := newTestBlockChain(engine, ghost.InternalNetGenesis())
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	for i := 0; i < 2; i++ {
		parent := chain.CurrentBlock()
		block := mineOn(t, engine, engine, chain, common.Address{0x01}, nil, true)
		if *block.Header().HeaderMmrRoot != mmrRootOver(t, ancestry(t, chain, parent)) {
			t.Fatalf("block %d on the internal network: header MMR root %x", i+1, *block.Header().HeaderMmrRoot)
		}
	}
}
