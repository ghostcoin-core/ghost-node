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

package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/ghostmmr"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

// mmrFakeEngine accepts every header and seals nothing. Its difficulty
// varies with the height, so that the leaves of the header MMR carry
// different work, and is the same at every height on every branch, so the
// longer branch is the heavier one.
type mmrFakeEngine struct{}

func (mmrFakeEngine) Author(h *types.Header) (common.Address, error) { return h.Coinbase, nil }
func (mmrFakeEngine) VerifyHeader(consensus.ChainHeaderReader, *types.Header, bool) error {
	return nil
}
func (mmrFakeEngine) VerifyHeaders(_ consensus.ChainHeaderReader, headers []*types.Header, _ []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))
	for range headers {
		results <- nil
	}
	return abort, results
}
func (mmrFakeEngine) VerifyUncles(consensus.ChainReader, *types.Block) error { return nil }
func (e mmrFakeEngine) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Difficulty = mmrTestDifficulty(header.Number.Uint64())
	return nil
}
func (mmrFakeEngine) Finalize(consensus.ChainHeaderReader, *types.Header, *state.StateDB, []*types.Transaction, []*types.Header, []*types.Withdrawal) {
}
func (mmrFakeEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, _ []*types.Withdrawal) (*types.Block, error) {
	header.Root = st.IntermediateRoot(chain.Config().IsEnabled(chain.Config().GetEIP161dTransition, header.Number))
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}
func (mmrFakeEngine) Seal(_ consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, _ <-chan struct{}) error {
	results <- block
	return nil
}
func (mmrFakeEngine) SealHash(header *types.Header) common.Hash { return header.Hash() }
func (mmrFakeEngine) CalcDifficulty(_ consensus.ChainHeaderReader, _ uint64, parent *types.Header) *big.Int {
	return mmrTestDifficulty(parent.Number.Uint64() + 1)
}
func (mmrFakeEngine) APIs(consensus.ChainHeaderReader) []rpc.API { return nil }
func (mmrFakeEngine) Close() error                               { return nil }

func mmrTestDifficulty(number uint64) *big.Int { return big.NewInt(1000 + int64(number%7)*13) }

// mmrTestChain is an empty chain on a fresh genesis.
func mmrTestChain(t *testing.T) (*BlockChain, *genesisT.Genesis) {
	t.Helper()
	_, genesis, chain, err := newCanonical(mmrFakeEngine{}, 0, true, rawdb.HashScheme)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	return chain, genesis
}

// headerAncestry returns the headers from genesis to head, oldest first.
func headerAncestry(t *testing.T, chain *BlockChain, head *types.Header) []*types.Header {
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

// refMMR is the header MMR over headers, built leaf by leaf here.
func refMMR(t *testing.T, headers []*types.Header) ghostmmr.State {
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

func rootOf(t *testing.T, s ghostmmr.State) [ghostmmr.HashSize]byte {
	t.Helper()
	root, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// requireHeaderMMR checks the stored header MMR state of every block from
// genesis to head against the MMR over the blocks before it, and the path of
// every block from head against head's state, with the work before it.
func requireHeaderMMR(t *testing.T, name string, chain *BlockChain, head *types.Header) {
	t.Helper()
	headers := headerAncestry(t, chain, head)
	for i, h := range headers {
		state, err := chain.HeaderMMR(h.Hash(), h.Number.Uint64())
		if err != nil {
			t.Fatalf("%s: header MMR of block %d: %v", name, i, err)
		}
		if state.N != uint64(i) || rootOf(t, state) != rootOf(t, refMMR(t, headers[:i])) {
			t.Fatalf("%s: header MMR of block %d is not the MMR over the %d blocks before it", name, i, i)
		}
	}
	n := head.Number.Uint64()
	root := rootOf(t, refMMR(t, headers[:n]))
	before := new(big.Int)
	for i := uint64(0); i < n; i++ {
		path, err := chain.HeaderMMRPath(head.Hash(), i)
		if err != nil {
			t.Fatalf("%s: path of block %d: %v", name, i, err)
		}
		work, _ := ghostmmr.WorkFromBig(headers[i].Difficulty)
		got, total, err := ghostmmr.VerifyPath(root, n, i, headers[i].Hash(), work, path)
		if err != nil {
			t.Fatalf("%s: path of block %d of %d does not verify: %v", name, i, n, err)
		}
		if got.Big().Cmp(before) != 0 {
			t.Fatalf("%s: work before block %d is %v, want %v", name, i, got, before)
		}
		before.Add(before, headers[i].Difficulty)
		if i == n-1 && total.Big().Cmp(before) != 0 {
			t.Fatalf("%s: total work %v, want %v", name, total, before)
		}
	}
	if _, err := chain.HeaderMMRPath(head.Hash(), n); !errors.Is(err, ghostmmr.ErrIndex) {
		t.Fatalf("%s: a path for the head itself: %v", name, err)
	}
}

// generate makes n blocks on parent with coinbases of the given seed.
func generate(genesis *genesisT.Genesis, parent *types.Block, db ethdb.Database, n int, seed byte) []*types.Block {
	blocks, _ := GenerateChain(genesis.Config, parent, mmrFakeEngine{}, db, n, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: seed, 19: byte(i)})
	})
	return blocks
}

// TestHeaderMMRStoredPerBlock imports a chain and checks every block's
// stored header MMR state, keyed by its hash, and the path of every block
// from the head.
func TestHeaderMMRStoredPerBlock(t *testing.T) {
	chain, genesis := mmrTestChain(t)
	_, blocks, _ := GenerateChainWithGenesis(genesis, mmrFakeEngine{}, 40, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 1, 19: byte(i)})
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	requireHeaderMMR(t, "imported chain", chain, chain.CurrentBlock())
	for _, b := range blocks {
		enc, err := rawdb.ReadHeaderMMRState(chain.db, b.Hash())
		if err != nil || enc == nil {
			t.Fatalf("block %d: no stored header MMR state (%v)", b.NumberU64(), err)
		}
		s, err := ghostmmr.DecodeState(enc)
		if err != nil || s.N != b.NumberU64() {
			t.Fatalf("block %d: stored state of %d leaves (%v)", b.NumberU64(), s.N, err)
		}
	}
	// The genesis commits to the empty MMR.
	if s, err := chain.HeaderMMR(chain.Genesis().Hash(), 0); err != nil || s.N != 0 || rootOf(t, s) != ghostmmr.EmptyRoot {
		t.Errorf("genesis header MMR %v (%v)", s, err)
	}
	if _, err := chain.HeaderMMRPath(common.Hash{1}, 0); err == nil {
		t.Error("a path from an unknown tip")
	}
}

// TestHeaderMMRFollowsReorg imports a branch A, then a heavier branch B from
// block 10, then A again made heavier: after each reorganisation the head's
// header MMR is the MMR over the new chain, its paths verify, a block of the
// other branch does not verify in its place, and nothing of the other
// branch was rewritten.
func TestHeaderMMRFollowsReorg(t *testing.T) {
	chain, genesis := mmrTestChain(t)
	db, branchA, _ := GenerateChainWithGenesis(genesis, mmrFakeEngine{}, 20, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 0xa, 19: byte(i)})
	})
	if _, err := chain.InsertChain(branchA); err != nil {
		t.Fatal(err)
	}
	headA := chain.CurrentBlock()
	requireHeaderMMR(t, "branch A", chain, headA)
	stateA, err := rawdb.ReadHeaderMMRState(chain.db, headA.Hash())
	if err != nil || stateA == nil {
		t.Fatal("no state for A's head")
	}

	branchB := generate(genesis, branchA[9], db, 15, 0xb)
	if _, err := chain.InsertChain(branchB); err != nil {
		t.Fatal(err)
	}
	headB := chain.CurrentBlock()
	if headB.Hash() != branchB[len(branchB)-1].Hash() {
		t.Fatal("no reorganisation to branch B")
	}
	requireHeaderMMR(t, "after the reorganisation to B", chain, headB)

	// Block 12 of A does not verify where block 12 of B stands.
	n := headB.Number.Uint64()
	root := rootOf(t, refMMR(t, headerAncestry(t, chain, headB)[:n]))
	path, err := chain.HeaderMMRPath(headB.Hash(), 12)
	if err != nil {
		t.Fatal(err)
	}
	a12, b12 := branchA[11].Header(), branchB[1].Header()
	if a12.Number.Uint64() != 12 || b12.Number.Uint64() != 12 {
		t.Fatal("test blocks at the wrong height")
	}
	work, _ := ghostmmr.WorkFromBig(a12.Difficulty)
	if _, _, err := ghostmmr.VerifyPath(root, n, 12, a12.Hash(), work, path); !errors.Is(err, ghostmmr.ErrRootMismatch) {
		t.Errorf("A's block 12 verifies in B: %v", err)
	}
	if _, _, err := ghostmmr.VerifyPath(root, n, 12, b12.Hash(), work, path); err != nil {
		t.Errorf("B's block 12: %v", err)
	}
	// A's blocks keep their states, untouched by the reorganisation.
	if again, _ := rawdb.ReadHeaderMMRState(chain.db, headA.Hash()); string(again) != string(stateA) {
		t.Error("the reorganisation rewrote the state of A's head")
	}
	sA, err := chain.HeaderMMR(headA.Hash(), headA.Number.Uint64())
	if err != nil || rootOf(t, sA) != rootOf(t, refMMR(t, headerAncestry(t, chain, headA)[:headA.Number.Uint64()])) {
		t.Fatalf("A's head state after the reorganisation (%v)", err)
	}

	// A, made heavier, takes the chain back.
	moreA := generate(genesis, branchA[len(branchA)-1], db, 10, 0xc)
	if _, err := chain.InsertChain(moreA); err != nil {
		t.Fatal(err)
	}
	if chain.CurrentBlock().Hash() != moreA[len(moreA)-1].Hash() {
		t.Fatal("no reorganisation back to A")
	}
	requireHeaderMMR(t, "back on A", chain, chain.CurrentBlock())
}

// TestHeaderMMRHeaderChain imports headers only: the header chain stores the
// states and inner nodes, and paths are served from them.
func TestHeaderMMRHeaderChain(t *testing.T) {
	chain, genesis := mmrTestChain(t)
	_, blocks, _ := GenerateChainWithGenesis(genesis, mmrFakeEngine{}, 33, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 2, 19: byte(i)})
	})
	headers := make([]*types.Header, len(blocks))
	for i, b := range blocks {
		headers[i] = b.Header()
	}
	if _, err := chain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatal(err)
	}
	requireHeaderMMR(t, "header chain", chain, chain.CurrentHeader())
}

// TestHeaderMMRRebuildsMissingStates removes stored states, as a database
// from before the store has none, and checks that the node computes them
// again from the nearest ancestor that has one, and stores them.
func TestHeaderMMRRebuildsMissingStates(t *testing.T) {
	chain, genesis := mmrTestChain(t)
	_, blocks, _ := GenerateChainWithGenesis(genesis, mmrFakeEngine{}, 30, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 3, 19: byte(i)})
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	head := chain.CurrentBlock()
	want := rootOf(t, refMMR(t, headerAncestry(t, chain, head)[:head.Number.Uint64()]))
	db := chain.db
	for _, b := range blocks[4:] {
		if err := rawdb.DeleteHeaderMMRState(db, b.Hash()); err != nil {
			t.Fatal(err)
		}
	}
	chain.hc.mmrCache.Purge() // as after a restart
	s, err := chain.HeaderMMR(head.Hash(), head.Number.Uint64())
	if err != nil || rootOf(t, s) != want {
		t.Fatalf("rebuilt state (%v)", err)
	}
	for _, b := range blocks {
		if enc, _ := rawdb.ReadHeaderMMRState(db, b.Hash()); enc == nil {
			t.Fatalf("block %d: the rebuilt state was not stored", b.NumberU64())
		}
	}
	requireHeaderMMR(t, "rebuilt", chain, head)
}

// TestHeaderMMRSetHead rewinds the chain: the states of the removed blocks go
// with their headers, those below stay, and importing the blocks again gives
// the same states.
func TestHeaderMMRSetHead(t *testing.T) {
	chain, genesis := mmrTestChain(t)
	_, blocks, _ := GenerateChainWithGenesis(genesis, mmrFakeEngine{}, 24, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 4, 19: byte(i)})
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	if err := chain.SetHead(10); err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		enc, err := rawdb.ReadHeaderMMRState(chain.db, b.Hash())
		if err != nil {
			t.Fatal(err)
		}
		if kept := b.NumberU64() <= 10; kept != (enc != nil) {
			t.Fatalf("block %d after the rewind to 10: state stored %v", b.NumberU64(), enc != nil)
		}
	}
	requireHeaderMMR(t, "rewound", chain, chain.CurrentBlock())
	if _, err := chain.InsertChain(blocks[10:]); err != nil {
		t.Fatal(err)
	}
	requireHeaderMMR(t, "imported again", chain, chain.CurrentBlock())
}

// TestHeaderMMRGhostGenesis checks that the Ghost genesis headers carry the
// root of the empty header MMR, as the last item of the Ghost layout.
func TestHeaderMMRGhostGenesis(t *testing.T) {
	for name, g := range map[string]*genesisT.Genesis{
		"internal network":    ghost.InternalNetGenesis(),
		"public test network": ghost.TestNetGenesis(),
	} {
		h := GenesisToBlock(g, nil).Header()
		if h.HeaderMmrRoot == nil || *h.HeaderMmrRoot != common.Hash(ghostmmr.EmptyRoot) {
			t.Errorf("%s: genesis header MMR root %v", name, h.HeaderMmrRoot)
		}
		enc, err := rlp.EncodeToBytes(h)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := types.DecodeGhostHeader(enc)
		if err != nil || dec.HeaderMmrRoot == nil || *dec.HeaderMmrRoot != *h.HeaderMmrRoot {
			t.Errorf("%s: strict decode %v", name, err)
		}
	}
	if GenesisToBlock(ghost.TestNetGenesis(), nil).Hash() != ghost.TestNetGenesisHash {
		t.Error("the public test network's genesis hash is not TestNetGenesisHash")
	}
}
