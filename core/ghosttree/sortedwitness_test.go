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
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

func sortedTag(i int) LookupTag {
	var t LookupTag
	copy(t[:], K("ghost/test-sorted-tag", []byte{byte(i), byte(i >> 8)}).Bytes())
	return t
}

// TestSortedWitnessesAreTheSetWitnesses fills every indexed tree, some
// leaves with a repeated tag and some without a tag, and checks that the
// sorted witnesses are exactly the witnesses the set gives leaf by leaf, in
// ascending key order, folding to the set's root.
func TestSortedWitnessesAreTheSetWitnesses(t *testing.T) {
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		tag := sortedTag(i % 97) // repeated tags
		if i%11 == 0 {
			tag = LookupTag{} // no entry
		}
		if _, err := AppendTagged(st, Coin, 1, K("ghost/test-sorted-leaf", []byte{byte(i), byte(i >> 8)}), tag); err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			if _, err := AppendTagged(st, Data, 1, K("ghost/test-sorted-data", []byte{byte(i), byte(i >> 8)}), sortedTag(1000+i)); err != nil {
				t.Fatal(err)
			}
		}
		if i%2 == 0 {
			if err := MarkSpent(st, Coin, 1, K("ghost/test-sorted-coin-marker", []byte{byte(i), byte(i >> 8)}), uint64(i)); err != nil {
				t.Fatal(err)
			}
		}
		if i%5 == 0 {
			if err := MarkSpent(st, Data, 1, K("ghost/test-sorted-data-marker", []byte{byte(i), byte(i >> 8)}), 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, set := range IndexedSets {
		sp, _ := set.spec()
		ws, keys, root, err := SortedWitnesses(st, set)
		if err != nil {
			t.Fatalf("%v: %v", set, err)
		}
		want, _ := set.SetRoot(st)
		if root != want {
			t.Fatalf("%v: root %x, stored %x", set, root, want)
		}
		s := newISet(sp, st)
		for r, w := range ws {
			if len(w) != set.WitnessSize() {
				t.Fatalf("%v: witness %d of %d bytes", set, r, len(w))
			}
			key, pos, ok := set.WitnessKey(w)
			if !ok || key != keys[r] {
				t.Fatalf("%v: rank %d key", set, r)
			}
			if r > 0 && bytes.Compare(keys[r-1][:], key[:]) >= 0 {
				t.Fatalf("%v: rank %d out of order", set, r)
			}
			ref, err := s.witness(pos)
			if err != nil || !bytes.Equal(ref, w) {
				t.Fatalf("%v: rank %d differs from the set's own witness (%v)", set, r, err)
			}
			if k, ok := VerifySetWitness(set, root, w); !ok || k != key {
				t.Fatalf("%v: rank %d does not verify", set, r)
			}
		}
		switch set {
		case CoinLookupSet:
			if len(ws) != 1+300-28 {
				t.Errorf("coin lookup: %d leaves", len(ws))
			}
		case CoinMarkerSet:
			if len(ws) != 1+150 {
				t.Errorf("coin markers: %d leaves", len(ws))
			}
		}
	}

	// The low leaf a wallet finds by key proves first entry and absence.
	ws, keys, root, _ := SortedWitnesses(st, CoinLookupSet)
	low := func(q common.Hash) []byte {
		r := 0
		for r+1 < len(keys) && bytes.Compare(keys[r+1][:], q[:]) < 0 {
			r++
		}
		return ws[r]
	}
	tag := sortedTag(5)
	if !VerifyLookupFirst(Coin, root, tag, 5, low(LookupQueryKey(tag))) {
		t.Error("the low leaf of a present tag does not prove its first entry")
	}
	absent := sortedTag(5000)
	if !VerifyLookupAbsence(Coin, root, absent, low(LookupQueryKey(absent))) {
		t.Error("the low leaf of an absent tag does not prove its absence")
	}
}

// TestSortedWitnessesOfEmptySets reads the genesis sets: the sentinel alone,
// folding to the empty roots.
func TestSortedWitnessesOfEmptySets(t *testing.T) {
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	g := GenesisHeaderFields()
	for set, want := range map[IndexedSet]common.Hash{
		CoinLookupSet: g.CoinLookupRoot, DataLookupSet: g.DataLookupRoot,
		CoinMarkerSet: g.CoinMarkerRoot, DataMarkerSet: g.DataMarkerRoot,
	} {
		ws, _, root, err := SortedWitnesses(st, set)
		if err != nil || len(ws) != 1 || root != want {
			t.Errorf("%v: %d witnesses, root %x want %x, %v", set, len(ws), root, want, err)
		}
	}
	if _, _, _, err := SortedWitnesses(st, IndexedSet(9)); err == nil {
		t.Error("unknown set read")
	}
}
