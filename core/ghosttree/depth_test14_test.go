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

//go:build ghosttreetest14

package ghosttree

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestTestDepthBuildIsFourteen(t *testing.T) {
	if Release.Depth != 14 {
		t.Fatalf("test build depth %d, want 14", Release.Depth)
	}
	if got := Release.capacity(); got != 16384 {
		t.Fatalf("test build capacity %d, want 16384", got)
	}
	if got := Release.pagesPerTree(); got != 4 {
		t.Errorf("test build pages per tree %d, want 4", got)
	}
	if err := Release.Check(); err != nil {
		t.Fatalf("test build parameters refused: %v", err)
	}
	for _, d := range []int{0, 13, 15, 32} {
		if err := (Params{Depth: d}).Check(); !errors.Is(err, ErrDepth) {
			t.Errorf("depth %d: Check %v, want %v", d, err, ErrDepth)
		}
	}
	if got, want := EmptyRoot(Coin), zeros(Coin, 14)[14]; got != want {
		t.Errorf("empty coin root %x, want Z_14 %x", got, want)
	}

	// Fill coin tree 0 to 16,384 leaves in block 5 through Append.
	st := newState(t)
	leaves := make([]common.Hash, 0, 16384)
	for i := 0; i < 16384; i++ {
		leaf := testLeaf(i)
		res, err := Append(st, Coin, 5, leaf)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if res.TreeIndex != 0 || res.Position != uint32(i) {
			t.Fatalf("append %d went to %+v", i, res)
		}
		leaves = append(leaves, leaf)
	}
	if got := getUint(t, st, Coin, SlotLeafCount); got != 16384 {
		t.Fatalf("leaf count %d, want 16384", got)
	}
	full, err := Root(st, Coin)
	if err != nil {
		t.Fatal(err)
	}
	if want := naiveRoot(Coin, 14, leaves); full != want {
		t.Fatalf("full tree root %x, want %x", full, want)
	}
	if got := st.GetState(TreeAccount(Coin), Slot(SlotFinalRoot)); got != full {
		t.Errorf("final root %x, want %x", got, full)
	}
	var pageRoots []common.Hash
	for pg := 0; pg < 4; pg++ {
		pageRoots = append(pageRoots, PageRoot(Coin, leaves[pg*PageLeaves:(pg+1)*PageLeaves]))
	}
	if got := RootFromPageRoots(Coin, pageRoots); got != full {
		t.Errorf("root from the four page roots %x, want %x", got, full)
	}

	// The next append in the filling block is refused; in the next block it
	// rolls over to tree index 1.
	leaf := testLeaf(16384)
	if _, err := Append(st, Coin, 5, leaf); !errors.Is(err, ErrFillingBlock) {
		t.Fatalf("append in the filling block: %v, want %v", err, ErrFillingBlock)
	}
	res, err := Append(st, Coin, 6, leaf)
	if err != nil {
		t.Fatalf("rollover append: %v", err)
	}
	if res != (AppendResult{Kind: Coin, TreeIndex: 1, Position: 0, Leaf: leaf}) {
		t.Fatalf("rollover went to %+v", res)
	}
	if got := getUint(t, st, Coin, SlotTreeIndex); got != 1 {
		t.Errorf("tree index %d, want 1", got)
	}
	if got := getUint(t, st, Coin, SlotLeafCount); got != 1 {
		t.Errorf("leaf count %d, want 1", got)
	}
	if got, want := mustRoot(t, Release, st, Coin), naiveRoot(Coin, 14, []common.Hash{leaf}); got != want {
		t.Errorf("root of tree 1 %x, want %x", got, want)
	}
	if got := st.GetState(TreeAccount(Coin), Slot(SlotFinalRoot)); got != (common.Hash{}) {
		t.Errorf("final root not cleared: %x", got)
	}
}
