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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestSeedHeight checks the key rule against the table in the RandomX survey.
func TestSeedHeight(t *testing.T) {
	for h := uint64(1); h <= 2112; h++ {
		if got := SeedHeight(h, 2048, 64); got != 0 {
			t.Fatalf("E=2048 L=64: height %d gives %d, want 0", h, got)
		}
	}
	for _, c := range []struct{ e, l, h, want uint64 }{
		{2048, 64, 0, 0},
		{2048, 64, 2113, 2048},
		{2048, 64, 4160, 2048},
		{2048, 64, 4161, 4096},
		{2048, 64, 6209, 6144},
		{8192, 256, 8448, 0},
		{8192, 256, 8449, 8192},
		{8192, 256, 16640, 8192},
		{8192, 256, 16641, 16384},
		{8192, 256, 24833, 24576},
	} {
		if got := SeedHeight(c.h, c.e, c.l); got != c.want {
			t.Errorf("E=%d L=%d: height %d gives %d, want %d", c.e, c.l, c.h, got, c.want)
		}
	}

	// The engine's defaults are the survey's E = 8192 and L = 256.
	engine, err := New(Config{Params: testParams()})
	if err != nil {
		t.Fatal(err)
	}
	if engine.epochLength != 8192 || engine.keyLag != 256 {
		t.Errorf("defaults E=%d L=%d, want 8192 and 256", engine.epochLength, engine.keyLag)
	}
	if got := engine.seedHeight(16641); got != 16384 {
		t.Errorf("default engine: height 16641 gives %d, want 16384", got)
	}

	for _, c := range []struct {
		e, l uint64
		want error
	}{
		{3000, 256, errBadEpoch},
		{8191, 256, errBadEpoch},
		{2048, 100, errBadKeyLag},
	} {
		if _, err := New(Config{Params: testParams(), EpochLength: c.e, KeyLag: c.l}); !errors.Is(err, c.want) {
			t.Errorf("E=%d L=%d: New returned %v, want %v", c.e, c.l, err, c.want)
		}
	}
	if _, err := New(Config{EpochLength: 8, KeyLag: 4}); !errors.Is(err, errMissingParams) {
		t.Errorf("New without parameters returned %v, want %v", err, errMissingParams)
	}
}

// branch returns n headers on parent, numbered on from it, marked by tag.
func branch(parent *types.Header, n int, tag string) []*types.Header {
	headers := make([]*types.Header, n)
	for i := range headers {
		headers[i] = &types.Header{
			ParentHash: parent.Hash(),
			Number:     new(big.Int).Add(parent.Number, common.Big1),
			Time:       parent.Time + testBlockTime,
			Difficulty: big.NewInt(16),
			Extra:      []byte(tag),
		}
		parent = headers[i]
	}
	return headers
}

// TestKeyLookupOnSideBranch checks that the key of a block on a side branch
// is that branch's own block at the seed height, found by parent hashes and
// never by number, and that results are remembered per header hash.
func TestKeyLookupOnSideBranch(t *testing.T) {
	engine := newTestEngine(t, testParams())
	genesis := &types.Header{Number: big.NewInt(0), Time: testGenesisAt, Difficulty: big.NewInt(16)}

	// main: heights 1..20; side forks after 5 (6..20); late forks after 10.
	main := branch(genesis, 20, "main")
	side := branch(main[4], 15, "side")
	late := branch(main[9], 6, "late")
	at := func(headers []*types.Header, height uint64) *types.Header {
		return headers[height-headers[0].Number.Uint64()]
	}
	reader := newTestReader(testConfig(), genesis, main...)
	reader.add(side...)
	reader.add(late...)

	lookup := chainLookup(reader)
	for _, c := range []struct {
		name   string
		header *types.Header
		want   common.Hash
	}{
		{"main 12", at(main, 12), genesis.Hash()},
		{"side 12", at(side, 12), genesis.Hash()},
		{"main 13", at(main, 13), at(main, 8).Hash()},
		{"side 13", at(side, 13), at(side, 8).Hash()},
		{"side 20", at(side, 20), at(side, 8).Hash()},
		{"main 20", at(main, 20), at(main, 8).Hash()},
		{"late 16", at(late, 16), at(main, 8).Hash()},
	} {
		got, err := engine.keyOf(lookup, c.header)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: key %x, want %x", c.name, got, c.want)
		}
	}
	if at(side, 8).Hash() == at(main, 8).Hash() {
		t.Fatal("the branches share the key block; the test proves nothing")
	}
	if n := reader.byNumber.Load(); n != 0 {
		t.Errorf("key lookup read %d headers by number", n)
	}

	// A header whose ancestry is missing has no key.
	orphan := branch(&types.Header{Number: big.NewInt(15), ParentHash: common.Hash{0xff}}, 1, "orphan")[0]
	if _, err := engine.keyOf(lookup, orphan); !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Errorf("orphan: error %v, want %v", err, consensus.ErrUnknownAncestor)
	}

	// Remembered keys need no headers: a fresh header on the side branch
	// finds its key through its parent's remembered result.
	next := branch(at(side, 19), 1, "side, again")[0]
	empty := newTestReader(testConfig(), genesis)
	got, err := engine.keyOf(chainLookup(empty), next)
	if err != nil || got != at(side, 8).Hash() {
		t.Errorf("remembered key: got %x, %v; want %x", got, err, at(side, 8).Hash())
	}
}

// TestFalseNumberLeavesNoWrongKey sends a header that names a real parent but
// claims a number in a neighbouring key period, through every path that
// looks keys up, and checks that the parent's real child still gets the key
// of its own period. The reader answers by hash alone, as the chain's header
// cache does, and the engine starts with nothing remembered, as after a
// restart.
func TestFalseNumberLeavesNoWrongKey(t *testing.T) {
	genesis := &types.Header{Number: big.NewInt(0), Time: testGenesisAt, Difficulty: big.NewInt(16)}
	main := branch(genesis, 20, "main")
	reader := cacheReader{newTestReader(testConfig(), genesis, main...)}

	for _, c := range []struct {
		name    string
		parent  uint64 // the real parent's height
		claimed uint64 // the number the false header claims
	}{
		// Blocks 13..20 are keyed by block 8, 21..28 by block 16.
		{"next key period", 19, 22},
		{"previous key period", 15, 12},
	} {
		parent, child := main[c.parent-1], main[c.parent]
		if SeedHeight(c.claimed, testEpoch, testLag) == SeedHeight(child.Number.Uint64(), testEpoch, testLag) {
			t.Fatalf("%s: the claimed number shares the child's key; the test proves nothing", c.name)
		}
		want := main[SeedHeight(child.Number.Uint64(), testEpoch, testLag)-1].Hash()
		forged := &types.Header{
			ParentHash: parent.Hash(),
			Number:     new(big.Int).SetUint64(c.claimed),
			Time:       parent.Time + testBlockTime,
			Difficulty: big.NewInt(16),
			Extra:      []byte("forged"),
		}

		engine := newTestEngine(t, testParams())
		if err := engine.VerifyHeader(reader, forged, true); !errors.Is(err, consensus.ErrInvalidNumber) {
			t.Errorf("%s: single: error %v, want %v", c.name, err, consensus.ErrInvalidNumber)
		}
		_, results := engine.VerifyHeaders(reader, []*types.Header{forged}, []bool{true})
		if err := <-results; !errors.Is(err, consensus.ErrInvalidNumber) {
			t.Errorf("%s: batch: error %v, want %v", c.name, err, consensus.ErrInvalidNumber)
		}
		// The key lookup itself refuses the parent at the wrong number,
		// through the chain and through a batch.
		if _, err := engine.keyOf(chainLookup(reader), forged); !errors.Is(err, consensus.ErrUnknownAncestor) {
			t.Errorf("%s: chain key lookup: error %v, want %v", c.name, err, consensus.ErrUnknownAncestor)
		}
		if _, err := engine.keyOf(batchLookup(reader, []*types.Header{parent, forged}), forged); !errors.Is(err, consensus.ErrUnknownAncestor) {
			t.Errorf("%s: batch key lookup: error %v, want %v", c.name, err, consensus.ErrUnknownAncestor)
		}
		if key, ok := engine.keys.Get(parent.Hash()); ok {
			t.Errorf("%s: a key %x is remembered for the real parent", c.name, key)
		}
		got, err := engine.keyOf(chainLookup(reader), child)
		if err != nil || got != want {
			t.Errorf("%s: the real child's key: got %x, %v; want %x", c.name, got, err, want)
		}
	}
}
