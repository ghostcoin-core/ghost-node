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
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
)

// withLeaves builds a child of parent that appends the given leaves of one
// kind, in order, with the header roots of real tree state.
func (c *testChain) withLeaves(parent *testBlock, tag byte, kind Kind, leaves []common.Hash) *testBlock {
	c.t.Helper()
	st := parent.st.Copy()
	number := parent.header.Number.Uint64() + 1
	var records []Record
	for _, leaf := range leaves {
		res, err := Append(st, kind, number, leaf)
		if err != nil {
			c.t.Fatal(err)
		}
		records = append(records, Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: leaf, Note: testNote(leaf)})
	}
	coinRoot, dataRoot := mustRoot(c.t, Release, st, Coin), mustRoot(c.t, Release, st, Data)
	markerRoot, err := DataMarkerRoot(st)
	if err != nil {
		c.t.Fatal(err)
	}
	header := &types.Header{
		ParentHash:     parent.hash(),
		Number:         new(big.Int).SetUint64(number),
		Difficulty:     big.NewInt(1),
		BaseFee:        big.NewInt(1),
		Extra:          []byte{tag},
		CoinTreeRoot:   &coinRoot,
		DataTreeRoot:   &dataRoot,
		DataMarkerRoot: &markerRoot,
	}
	return &testBlock{header: header, records: records, st: st}
}

// restoreChain is a chain whose block 1 appends one coin leaf and block 2
// 39,999 more coin leaves (10 pages) and 10,000 data leaves (3 pages): at
// block 1 the coin tree has one leaf and the data tree none.
func restoreChain(t *testing.T) *testChain {
	t.Helper()
	c := newTestChain(t)
	c.extend(1, 1, 0)
	c.extend(2, 39999, 10000)
	return c
}

// sideBlock stores a block off the canonical chain at height 1.
func sideBlock(c *testChain) *testBlock {
	c.t.Helper()
	b := c.next(c.blocks[0], 0xee, 1, 0)
	rawdb.WriteHeader(c.db, b.header)
	return b
}

func entryCount(pages []*TreePage) int {
	n := 0
	for _, p := range pages {
		n += len(p.Entries)
	}
	return n
}

func TestPageRootTailMatchesTheSpecVectors(t *testing.T) {
	// Vector witness-extension-same-page: two coin leaves in one block and a
	// third in the next, all in page 0.
	c := newTestChain(t)
	leaves := []common.Hash{
		common.HexToHash("562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458"),
		common.HexToHash("93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15"),
		common.HexToHash("c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"),
	}
	early := c.withLeaves(c.head(), 1, Coin, leaves[:2])
	c.insert(early)
	late := c.withLeaves(early, 1, Coin, leaves[2:])
	c.insert(late)

	if want := common.HexToHash("142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5"); *early.header.CoinTreeRoot != want {
		t.Fatalf("root after two leaves %x, want %x", *early.header.CoinTreeRoot, want)
	}
	if want := common.HexToHash("ad00a34b5bee7b1021456d5986d76aa73885f342df270a60a4c44e2627b1e195"); *late.header.CoinTreeRoot != want {
		t.Fatalf("root after three leaves %x, want %x", *late.header.CoinTreeRoot, want)
	}

	tail, err := c.h.PageRootTail(Coin, 0, 0, late.hash())
	if err != nil {
		t.Fatal(err)
	}
	if want := []common.Hash{common.HexToHash("96c579df26776fc1392c499d35702a7b33accf42d5087edacc22fa70dd3cfaea")}; !reflect.DeepEqual(tail, want) {
		t.Fatalf("tail at the later anchor %x, want %x", tail, want)
	}
	if got := RootFromPageRoots(Coin, tail); got != *late.header.CoinTreeRoot {
		t.Errorf("tail at the later anchor gives %x, header %x", got, *late.header.CoinTreeRoot)
	}
	tail, err = c.h.PageRootTail(Coin, 0, 0, early.hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 1 || RootFromPageRoots(Coin, tail) != *early.header.CoinTreeRoot {
		t.Errorf("tail at the earlier anchor: %x", tail)
	}

	set, err := c.h.PageSet(Coin, 0, []uint32{0}, late.hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || set[0].Page != 0 || set[0].Filled != 3 || len(set[0].Entries) != 3 {
		t.Fatalf("page set of the vector: %+v", set)
	}
	for i, e := range set[0].Entries {
		if e.Leaf != leaves[i] || e.Note != testNote(leaves[i]) {
			t.Errorf("position %d: leaf %x, want %x", i, e.Leaf, leaves[i])
		}
	}

	// Vector witness-extension-new-pages, as far as a node serves it: a tree
	// of 10,000 leaves in 3 pages; the tail from 0 is the page-root list, and
	// a tail with one root changed does not match the header root.
	wide := newTestChain(t)
	head := wide.extend(1, 10000, 0)
	tail, err = wide.h.PageRootTail(Coin, 0, 0, head.hash())
	if err != nil {
		t.Fatal(err)
	}
	roots, err := wide.h.PageRoots(Coin, 0, head.hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 3 || !reflect.DeepEqual(tail, roots) {
		t.Fatalf("tail of %d roots, page roots %d", len(tail), len(roots))
	}
	if RootFromPageRoots(Coin, tail) != *head.header.CoinTreeRoot {
		t.Fatal("the tail does not match the header root")
	}
	for i := range tail {
		bad := append([]common.Hash(nil), tail...)
		bad[i][0] ^= 1
		if RootFromPageRoots(Coin, bad) == *head.header.CoinTreeRoot {
			t.Errorf("tail with root %d changed still matches the header", i)
		}
	}
}

func TestPageRootTailRefusesOtherStarts(t *testing.T) {
	c := newTestChain(t)
	head := c.extend(1, 10000, 0)
	side := sideBlock(c)
	before := historyContents(t, c.db)
	unchanged := func(name string) {
		t.Helper()
		if !reflect.DeepEqual(before, historyContents(t, c.db)) {
			t.Fatalf("%s: the store changed", name)
		}
	}
	for _, start := range []uint32{1, 4096, 65535, 65537, 1 << 20} {
		if got, err := c.h.PageRootTail(Coin, 0, start, head.hash()); !errors.Is(err, ErrTailStart) {
			t.Errorf("start %d: %d roots, %v, want %v", start, len(got), err, ErrTailStart)
		}
		unchanged("bad start")
	}
	tail, err := c.h.PageRootTail(Coin, 0, TailPages, head.hash())
	if err != nil || tail == nil || len(tail) != 0 {
		t.Errorf("start 65536 on a 3-page tree: %v, %v, want an empty list", tail, err)
	}
	unchanged("start past the last page")
	for _, w := range []struct {
		name   string
		kind   Kind
		anchor common.Hash
		want   error
	}{
		{"coin marker kind", CoinMarkers, head.hash(), ErrUnknownKind},
		{"data marker kind", DataMarkers, head.hash(), ErrUnknownKind},
		{"unknown anchor", Coin, common.Hash{1}, ErrUnknownAnchor},
		{"non-canonical anchor", Coin, side.hash(), ErrNotCanonical},
	} {
		if got, err := c.h.PageRootTail(w.kind, 0, 0, w.anchor); !errors.Is(err, w.want) {
			t.Errorf("%s: %d roots, %v, want %v", w.name, len(got), err, w.want)
		}
		unchanged(w.name)
	}
}

func TestPageSetServesEightPagesOrAllOfASmallTree(t *testing.T) {
	c := restoreChain(t)
	small, full := c.blocks[1], c.head()
	for _, w := range []struct {
		name   string
		kind   Kind
		anchor *testBlock
		pages  []uint32
	}{
		{"3-page tree", Data, full, []uint32{0, 1, 2}},
		{"10-page tree", Coin, full, []uint32{0, 1, 2, 3, 4, 5, 6, 9}},
		{"one-leaf tree", Coin, small, []uint32{0}},
	} {
		set, err := c.h.PageSet(w.kind, 0, w.pages, w.anchor.hash())
		if err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if len(set) != len(w.pages) {
			t.Fatalf("%s: %d pages, want %d", w.name, len(set), len(w.pages))
		}
		for i, p := range w.pages {
			want, err := c.h.Page(w.kind, 0, p, w.anchor.hash())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(set[i], want) {
				t.Errorf("%s: page %d differs from Page", w.name, p)
			}
		}
		if n := entryCount(set); n > PageSetPages*PageLeaves {
			t.Errorf("%s: %d entries", w.name, n)
		}
	}
	// The 10-page set: seven full pages and the last, partial one.
	set, _ := c.h.PageSet(Coin, 0, []uint32{0, 1, 2, 3, 4, 5, 6, 9}, full.hash())
	if n := entryCount(set); n != 7*PageLeaves+40000-9*PageLeaves {
		t.Errorf("10-page set: %d entries", n)
	}
	want := c.expected(Coin, 0, 2)
	if !reflect.DeepEqual(set[7].Entries, want[9*PageLeaves:]) || !reflect.DeepEqual(set[3].Entries, want[3*PageLeaves:4*PageLeaves]) {
		t.Error("10-page set: entries differ from the chain's records")
	}
}

func TestPageSetRefusesAnyOtherShape(t *testing.T) {
	c := restoreChain(t)
	full, genesis := c.head(), c.blocks[0]
	before := historyContents(t, c.db)
	for _, w := range []struct {
		name   string
		kind   Kind
		anchor *testBlock
		pages  []uint32
	}{
		{"7 pages", Coin, full, []uint32{0, 1, 2, 3, 4, 5, 6}},
		{"9 pages", Coin, full, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		{"a duplicate", Coin, full, []uint32{0, 1, 2, 3, 4, 5, 6, 6}},
		{"descending", Coin, full, []uint32{9, 6, 5, 4, 3, 2, 1, 0}},
		{"page 10", Coin, full, []uint32{0, 1, 2, 3, 4, 5, 6, 10}},
		{"empty list", Coin, full, []uint32{}},
		{"nil list", Coin, full, nil},
		{"two of three pages", Data, full, []uint32{0, 1}},
		{"pages 1 to 3 of three", Data, full, []uint32{1, 2, 3}},
		{"a duplicate of a small tree", Data, full, []uint32{0, 0, 1}},
		{"an empty tree", Data, genesis, []uint32{0}},
		{"an empty coin tree", Coin, genesis, []uint32{0}},
	} {
		if got, err := c.h.PageSet(w.kind, 0, w.pages, w.anchor.hash()); !errors.Is(err, ErrPageSetShape) {
			t.Errorf("%s: %d pages, %v, want %v", w.name, len(got), err, ErrPageSetShape)
		}
	}
	if _, err := c.h.PageSet(CoinMarkers, 0, []uint32{0}, full.hash()); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("marker kind: %v, want %v", err, ErrUnknownKind)
	}
	if !reflect.DeepEqual(before, historyContents(t, c.db)) {
		t.Error("a refused page set changed the store")
	}
}

// decoy is the decoy marker i of the spec vectors: Keccak-256 of "decoy" and
// the byte i.
func decoy(i int) common.Hash {
	return crypto.Keccak256Hash([]byte("decoy"), []byte{byte(i)})
}

func spend(b *testBlock, kind Kind, markers ...common.Hash) {
	for _, m := range markers {
		b.records = append(b.records, Record{Kind: kind, Leaf: m})
	}
}

// markerKeys returns the keys of the spent-marker index.
func markerKeys(t *testing.T, db ethdb.Database) [][]byte {
	t.Helper()
	var out [][]byte
	it := db.NewIterator([]byte("ghost-tree-marker-"), nil)
	defer it.Release()
	for it.Next() {
		out = append(out, common.CopyBytes(it.Key()))
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	return out
}

func markerAt(t *testing.T, db ethdb.Database, kind Kind, m common.Hash) (uint64, uint32, bool) {
	t.Helper()
	index, position, ok, err := rawdb.ReadGhostTreeMarker(db, uint8(kind), m)
	if err != nil {
		t.Fatal(err)
	}
	return index, position, ok
}

// indexedAt checks that the index holds marker m of a list at the list index
// and position of the record that spent it in block number, or, for number 0,
// that it does not hold m.
func indexedAt(t *testing.T, h *History, kind Kind, m common.Hash, number uint64) {
	t.Helper()
	index, position, ok := markerAt(t, h.db, kind, m)
	if number == 0 {
		if ok {
			t.Errorf("%v marker %x indexed at %d %d, want absent", kind, m, index, position)
		}
		return
	}
	if !ok {
		t.Errorf("%v marker %x not indexed, want spent in block %d", kind, m, number)
		return
	}
	rec, err := h.read(slot{kind, index, position})
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil || rec.leaf != m || rec.number != number {
		t.Errorf("%v marker %x indexed at %d %d, holding %+v; want its spend in block %d", kind, m, index, position, rec, number)
	}
}

func TestMarkerIndexFollowsRevertAndSync(t *testing.T) {
	// RevertBlock: block 2 spends new markers and, again, one of block 1;
	// the index keeps the first spend and drops only what block 2 indexed.
	c := newTestChain(t)
	b1 := c.next(c.head(), 1, 2, 1)
	spend(b1, CoinMarkers, decoy(1), decoy(2))
	spend(b1, DataMarkers, decoy(1))
	c.insert(b1)
	b2 := c.next(b1, 2, 1, 1)
	spend(b2, CoinMarkers, decoy(3), decoy(1))
	spend(b2, DataMarkers, decoy(4))
	c.insert(b2)
	if n := len(markerKeys(t, c.db)); n != 5 {
		t.Fatalf("%d index keys, want one per distinct marker of a list", n)
	}
	for _, k := range markerKeys(t, c.db) {
		if len(k) != 51 {
			t.Errorf("index key of %d bytes", len(k))
		}
	}
	if index, position, ok := markerAt(t, c.db, CoinMarkers, decoy(1)); !ok || index != 0 || position != 0 {
		t.Errorf("a marker spent twice is indexed at %d %d %v, want its first spend", index, position, ok)
	}
	c.rewind(1)
	if _, _, ok := markerAt(t, c.db, CoinMarkers, decoy(3)); ok {
		t.Error("a marker of the reverted block is still indexed")
	}
	if _, _, ok := markerAt(t, c.db, DataMarkers, decoy(4)); ok {
		t.Error("a data marker of the reverted block is still indexed")
	}
	if _, _, ok := markerAt(t, c.db, CoinMarkers, decoy(1)); !ok {
		t.Error("reverting a second spend removed the first")
	}
	other := c.next(b1, 3, 1, 0)
	spend(other, CoinMarkers, decoy(6))
	c.insert(other)
	ref := newTestChain(t)
	for _, b := range c.blocks[1:] {
		ref.insert(b)
	}
	if got, want := historyContents(t, c.db), historyContents(t, ref.db); !reflect.DeepEqual(got, want) {
		t.Errorf("after the revert: %d keys, a store of the branch alone %d", len(got), len(want))
	}

	// Sync: a reorganisation leaves the store of a node that only saw the
	// new branch, and a marker of the removed branch is not spent.
	s := newSyncChain(t)
	base := s.branch(s.genesis, 1, 2, 5, 1, 3, 2)
	old := s.branch(base[1], 2, 2, 5, 1, 3, 2)
	spend(old[0], DataMarkers, decoy(7))
	s.setHead(old[1])
	indexedAt(t, s.h, DataMarkers, decoy(7), 3)
	fork := s.branch(base[1], 3, 3, 4, 0, 2, 1)
	s.setHead(fork[2])
	sref := newSyncChain(t)
	for _, b := range s.ancestry(fork[2]) {
		sref.add(b)
	}
	sref.setHead(fork[2])
	if got, want := historyContents(t, s.db), historyContents(t, sref.db); !reflect.DeepEqual(got, want) {
		t.Errorf("after the reorganising sync: %d keys, a store of the branch alone %d", len(got), len(want))
	}
	var oldCoin, baseData, forkCoin common.Hash
	for _, r := range old[1].records {
		if r.Kind == CoinMarkers {
			oldCoin = r.Leaf
		}
	}
	for _, r := range base[0].records {
		if r.Kind == DataMarkers {
			baseData = r.Leaf
		}
	}
	for _, r := range fork[1].records {
		if r.Kind == CoinMarkers {
			forkCoin = r.Leaf
		}
	}
	checkIndex := func() {
		t.Helper()
		indexedAt(t, s.h, CoinMarkers, oldCoin, 0)
		indexedAt(t, s.h, CoinMarkers, forkCoin, 4)
		indexedAt(t, s.h, DataMarkers, decoy(7), 0)
		indexedAt(t, s.h, DataMarkers, baseData, 1)
	}
	checkIndex()
	if n := len(markerKeys(t, s.db)); n != 2*(3+2)+3*(2+1) {
		t.Errorf("%d index keys after the sync, want one per marker of the branch", n)
	}

	// A store with a head and records but without the marker of the index,
	// as built before it, is built again by Sync.
	built := historyContents(t, s.db)
	keys := len(markerKeys(t, s.db))
	if err := rawdb.DeleteGhostTreeMarked(s.db); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.DeleteGhostTreeMarkers(s.db, s.db, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n := len(markerKeys(t, s.db)); n != 0 {
		t.Fatalf("%d index keys left", n)
	}
	if marked, err := rawdb.ReadGhostTreeMarked(s.db); err != nil || marked {
		t.Fatalf("index marker after the delete: %v, %v", marked, err)
	}
	s.setHead(fork[2])
	if marked, err := rawdb.ReadGhostTreeMarked(s.db); err != nil || !marked {
		t.Errorf("index marker after the rebuilding sync: %v, %v", marked, err)
	}
	if n := len(markerKeys(t, s.db)); n != keys {
		t.Errorf("%d index keys after the rebuilding sync, want %d", n, keys)
	}
	if got := historyContents(t, s.db); !reflect.DeepEqual(got, built) {
		t.Errorf("rebuilt history: %d keys, %d index keys; want %d", len(got), len(markerKeys(t, s.db)), len(built))
	}
	checkIndex()
	s.checkServed(fork[2])

	// reset takes the whole index and its marker.
	if err := s.h.reset(); err != nil {
		t.Fatal(err)
	}
	if n := len(markerKeys(t, s.db)); n != 0 {
		t.Errorf("%d index keys after reset", n)
	}
	if marked, err := rawdb.ReadGhostTreeMarked(s.db); err != nil || marked {
		t.Errorf("index marker after reset: %v, %v", marked, err)
	}
}
