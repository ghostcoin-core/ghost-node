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

package ghosttree

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// pagesOf splits leaves into pages.
func pagesOf(leaves []common.Hash) [][]common.Hash {
	var pages [][]common.Hash
	for first := 0; first < len(leaves); first += PageLeaves {
		pages = append(pages, leaves[first:min(len(leaves), first+PageLeaves)])
	}
	return pages
}

func pageRootsOf(kind Kind, leaves []common.Hash) []common.Hash {
	var roots []common.Hash
	for _, page := range pagesOf(leaves) {
		roots = append(roots, PageRoot(kind, page))
	}
	return roots
}

func TestPageRootVectors(t *testing.T) {
	// coin-page-two-leaves of spec 05, section 11.
	leaves := []common.Hash{
		common.HexToHash("562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458"),
		common.HexToHash("93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15"),
	}
	var (
		wantPage  = common.HexToHash("06d032e35a1f30a5773c38d9631f5e4ec069786f4d22131ef0bbba75acf2b717")
		wantEmpty = common.HexToHash("b50ae40977b91a1a10c7965cd40294eac6f63cbc40b5e57b9d4aa215956142d4")
		wantRoot  = common.HexToHash("142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5")
	)
	page := PageRoot(Coin, leaves)
	if page != wantPage {
		t.Errorf("page root %x, want %x", page, wantPage)
	}
	if got := PageRoot(Coin, nil); got != wantEmpty {
		t.Errorf("empty page root %x, want %x", got, wantEmpty)
	}
	if got := zeros(Coin, 32)[PageLevels]; got != wantEmpty {
		t.Errorf("Z_12 %x, want %x", got, wantEmpty)
	}
	if got := RootFromPageRoots(Coin, []common.Hash{page}); got != wantRoot {
		t.Errorf("root from the page-root list %x, want %x", got, wantRoot)
	}
	// Listing the empty pages explicitly changes nothing.
	if got := RootFromPageRoots(Coin, []common.Hash{page, wantEmpty, wantEmpty}); got != wantRoot {
		t.Errorf("root with explicit empty pages %x, want %x", got, wantRoot)
	}
	if got := naiveRoot(Coin, 32, leaves); got != wantRoot {
		t.Errorf("naive root %x, want %x", got, wantRoot)
	}
	// The same leaves in a data page give another root.
	if PageRoot(Data, leaves) == wantPage {
		t.Error("the data page root equals the coin page root")
	}

	// A full page of 4,096 leaves against a naive recomputation.
	for _, kind := range []Kind{Coin, Data} {
		full := make([]common.Hash, PageLeaves)
		for i := range full {
			full[i] = testLeaf(i)
		}
		want := naiveLevels(kind, PageLevels, full)[PageLevels]
		if len(want) != 1 {
			t.Fatalf("%v: naive page has %d nodes on top", kind, len(want))
		}
		if got := PageRoot(kind, full); got != want[0] {
			t.Errorf("%v: full page root %x, want %x", kind, got, want[0])
		}
		if got, want := RootFromPageRoots(kind, []common.Hash{want[0]}), naiveRoot(kind, 32, full); got != want {
			t.Errorf("%v: tree root of a full page %x, want %x", kind, got, want)
		}
		// Every leaf counts.
		changed := append([]common.Hash(nil), full...)
		changed[PageLeaves-1] = testLeaf(PageLeaves)
		if PageRoot(kind, changed) == want[0] {
			t.Errorf("%v: changing the last leaf keeps the page root", kind)
		}
		// More than a page is no page.
		if got := PageRoot(kind, append(full, testLeaf(PageLeaves))); got != (common.Hash{}) {
			t.Errorf("%v: page root of 4,097 leaves %x", kind, got)
		}
	}
	if got := PageRoot(Kind(2), leaves); got != (common.Hash{}) {
		t.Errorf("page root of an unknown kind %x", got)
	}
}

func TestRootFromPageRootsMatchesTree(t *testing.T) {
	counts := []int{0, 1, 2, 4095, 4096, 4097, 8192, 10000}
	for _, kind := range []Kind{Coin, Data} {
		st := newState(t)
		var leaves []common.Hash
		for _, n := range counts {
			for len(leaves) < n {
				leaf := testLeaf(len(leaves))
				if _, err := Append(st, kind, 1, leaf); err != nil {
					t.Fatal(err)
				}
				leaves = append(leaves, leaf)
			}
			want := mustRoot(t, Release, st, kind)
			roots := pageRootsOf(kind, leaves)
			if len(roots) != (n+PageLeaves-1)/PageLeaves {
				t.Fatalf("%v, %d leaves: %d pages", kind, n, len(roots))
			}
			if got := RootFromPageRoots(kind, roots); got != want {
				t.Errorf("%v, %d leaves: root from page roots %x, tree root %x", kind, n, got, want)
			}
		}
	}
	// A list longer than a tree has pages is no list.
	if got := RootFromPageRoots(Coin, make([]common.Hash, 1<<20+1)); got != (common.Hash{}) {
		t.Errorf("root of an overlong list %x", got)
	}
	if got := RootFromPageRoots(Kind(2), nil); got != (common.Hash{}) {
		t.Errorf("root of an unknown kind %x", got)
	}
}

func TestWitnessVerifiesAgainstHeaderRoot(t *testing.T) {
	const n = 10000
	st := newState(t)
	var leaves []common.Hash
	for i := 0; i < n; i++ {
		leaves = append(leaves, testLeaf(i))
		if _, err := Append(st, Coin, 1, leaves[i]); err != nil {
			t.Fatal(err)
		}
	}
	coinRoot, dataRoot := mustRoot(t, Release, st, Coin), mustRoot(t, Release, st, Data)
	header := &types.Header{Number: big.NewInt(1), CoinTreeRoot: &coinRoot, DataTreeRoot: &dataRoot}

	pages, roots := pagesOf(leaves), pageRootsOf(Coin, leaves)
	for _, pos := range []uint32{0, 1, 4095, 4096, 4097, 8191, 8192, n - 1} {
		page := pages[pos/PageLeaves]
		path, err := Witness(Coin, pos, page, roots)
		if err != nil {
			t.Fatalf("position %d: %v", pos, err)
		}
		if !VerifyMembership(header, Coin, pos, leaves[pos], path) {
			t.Errorf("position %d: the wallet's witness does not verify", pos)
		}
		if path != naivePath(Coin, leaves, int(pos)) {
			t.Errorf("position %d: witness differs from the full tree's path", pos)
		}
		for l := 0; l < 32; l++ {
			bad := path
			bad[l][0] ^= 0x80
			if VerifyMembership(header, Coin, pos, leaves[pos], bad) {
				t.Errorf("position %d: verifies with sibling %d changed", pos, l)
			}
		}
		if VerifyMembership(header, Coin, pos, testLeaf(n), path) {
			t.Errorf("position %d: another leaf verifies", pos)
		}
	}

	// The wallet refuses to build a path from data that does not check.
	tampered := append([]common.Hash(nil), pages[1]...)
	tampered[7] = testLeaf(n + 1)
	if _, err := Witness(Coin, 4096+3, tampered, roots); !errors.Is(err, ErrPageMismatch) {
		t.Errorf("tampered page: %v, want %v", err, ErrPageMismatch)
	}
	if _, err := Witness(Coin, 3*PageLeaves, pages[2], roots); !errors.Is(err, ErrNotInPage) {
		t.Errorf("page past the list: %v, want %v", err, ErrNotInPage)
	}
	if _, err := Witness(Coin, n, pages[2], roots); !errors.Is(err, ErrNotInPage) {
		t.Errorf("unfilled position: %v, want %v", err, ErrNotInPage)
	}
	if _, err := Witness(Kind(2), 0, pages[0], roots); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: %v, want %v", err, ErrUnknownKind)
	}
}
