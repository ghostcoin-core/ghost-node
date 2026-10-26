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

// realMarker is the real marker of vector marker-query-one-real.
var realMarker = common.BytesToHash(bytes.Repeat([]byte{0x88}, common.HashLength))

// oneRealQuery is the query of vector marker-query-one-real: decoys 0 to 36,
// the real marker, decoys 37 to 62.
func oneRealQuery() []common.Hash {
	q := make([]common.Hash, 0, StatusMarkers)
	for i := 0; i <= 36; i++ {
		q = append(q, decoy(i))
	}
	q = append(q, realMarker)
	for i := 37; i <= 62; i++ {
		q = append(q, decoy(i))
	}
	return q
}

// statusQuery is a query of the given markers first and decoys after.
func statusQuery(markers ...common.Hash) []common.Hash {
	q := append([]common.Hash(nil), markers...)
	for i := 100; len(q) < StatusMarkers; i++ {
		q = append(q, decoy(i))
	}
	return q
}

// checkStatus asks a query and compares the answers with the spent ones,
// by query position.
func checkStatus(t *testing.T, h *History, kind Kind, q []common.Hash, anchor common.Hash, spent map[int]uint64) {
	t.Helper()
	got, err := h.MarkerStatus(kind, q, anchor)
	if err != nil {
		t.Fatalf("%v status: %v", kind, err)
	}
	if len(got) != len(q) {
		t.Fatalf("%v status: %d answers for %d markers", kind, len(got), len(q))
	}
	for i, s := range got {
		block, ok := spent[i]
		if want := (MarkerStatus{Spent: ok, Block: block}); s != want {
			t.Errorf("%v status of marker %d (%x): %+v, want %+v", kind, i, q[i], s, want)
		}
	}
}

func spend(b *testBlock, kind Kind, markers ...common.Hash) {
	for _, m := range markers {
		b.records = append(b.records, Record{Kind: kind, Leaf: m})
	}
}

func TestMarkerStatusAnswersAsOfTheAnchor(t *testing.T) {
	q := oneRealQuery()
	if len(q) != StatusMarkers {
		t.Fatalf("query of %d markers", len(q))
	}
	if want := common.HexToHash("5a5972a2ed527a3d3e8a844c7dc51475add0d52f8aba4cd1a17a277216cdeec2"); q[0] != want {
		t.Fatalf("decoy 0 %x, want %x", q[0], want)
	}
	if want := common.HexToHash("b0c48d43efdf1668e8e3f912e3369b062ad00f37d33b188a421f83e211dd247c"); q[63] != want {
		t.Fatalf("decoy 62 %x, want %x", q[63], want)
	}

	// Block 1 spends other markers of both kinds; block 2 spends decoy 5 as
	// a data marker and the real marker's value as a coin marker; block 3
	// spends decoy 20 as a data marker.
	s := newSyncChain(t)
	b1 := s.child(s.genesis, 1, 3, 2, 40, 40)
	b2 := s.child(b1, 1, 1, 1, 1, 1)
	spend(b2, DataMarkers, decoy(5))
	spend(b2, CoinMarkers, realMarker)
	b3 := s.child(b2, 1, 0, 0, 0, 0)
	spend(b3, DataMarkers, decoy(20))
	s.setHead(b3)

	// As the vector's answers line says: nothing in the query is spent on a
	// store with other markers spent.
	for _, kind := range []Kind{Coin, Data} {
		checkStatus(t, s.h, kind, q, b1.hash(), nil)
		checkStatus(t, s.h, kind, q, s.genesis.hash(), nil)
	}
	// The markers spent in block 1 are spent in it, and found.
	var spentInB1 []common.Hash
	for _, r := range b1.records {
		if r.Kind == DataMarkers {
			spentInB1 = append(spentInB1, r.Leaf)
		}
	}
	checkStatus(t, s.h, Data, statusQuery(spentInB1[0], spentInB1[39]), b3.hash(), map[int]uint64{0: 1, 1: 1})
	checkStatus(t, s.h, Coin, statusQuery(spentInB1[0], spentInB1[39]), b3.hash(), nil)

	// Decoy 5 is query position 5, decoy 20 position 20, the real marker
	// position 37.
	checkStatus(t, s.h, Data, q, b2.hash(), map[int]uint64{5: 2})
	checkStatus(t, s.h, Data, q, b3.hash(), map[int]uint64{5: 2, 20: 3})
	checkStatus(t, s.h, Data, q, b1.hash(), nil)
	// The coin list is separate: the real marker's value is spent as a coin
	// marker and not as a data marker, decoy 5 the other way round.
	checkStatus(t, s.h, Coin, q, b2.hash(), map[int]uint64{37: 2})
	checkStatus(t, s.h, Coin, q, b3.hash(), map[int]uint64{37: 2})

	// 32 zero bytes is a valid query value, never spent.
	zero := statusQuery(common.Hash{}, decoy(5), realMarker)
	checkStatus(t, s.h, Data, zero, b3.hash(), map[int]uint64{1: 2})
}

func TestMarkerStatusRefusesWrongQueries(t *testing.T) {
	s := newSyncChain(t)
	b1 := s.child(s.genesis, 1, 2, 2, 5, 5)
	spend(b1, DataMarkers, decoy(5))
	s.setHead(b1)
	side := s.child(s.genesis, 2, 1, 0, 0, 0)
	before := historyContents(t, s.db)

	q := oneRealQuery()
	repeated := append([]common.Hash(nil), q...)
	repeated[63] = repeated[10]
	for _, w := range []struct {
		name    string
		kind    Kind
		markers []common.Hash
		anchor  common.Hash
		want    error
	}{
		{"63 markers", Data, q[:63], b1.hash(), ErrStatusQuery},
		{"65 markers", Data, append(append([]common.Hash(nil), q...), decoy(63)), b1.hash(), ErrStatusQuery},
		{"a repeated marker", Data, repeated, b1.hash(), ErrStatusQuery},
		{"no markers", Data, nil, b1.hash(), ErrStatusQuery},
		{"an empty list", Coin, []common.Hash{}, b1.hash(), ErrStatusQuery},
		{"coin marker kind", CoinMarkers, q, b1.hash(), ErrUnknownKind},
		{"data marker kind", DataMarkers, q, b1.hash(), ErrUnknownKind},
		{"unknown anchor", Data, q, common.Hash{1}, ErrUnknownAnchor},
		{"non-canonical anchor", Data, q, side.hash(), ErrNotCanonical},
	} {
		if got, err := s.h.MarkerStatus(w.kind, w.markers, w.anchor); !errors.Is(err, w.want) {
			t.Errorf("%s: %v, %v, want %v", w.name, got, err, w.want)
		}
		if !reflect.DeepEqual(before, historyContents(t, s.db)) {
			t.Fatalf("%s: the store changed", w.name)
		}
	}
	// The vector's query of 64 is answered.
	checkStatus(t, s.h, Data, q, b1.hash(), map[int]uint64{5: 1})
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
	checkStatus(t, s.h, Data, statusQuery(decoy(7)), old[1].hash(), map[int]uint64{0: 3})
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
	coinQuery := statusQuery(oldCoin, forkCoin)
	dataQuery := statusQuery(decoy(7), baseData)
	checkStatus(t, s.h, Coin, coinQuery, fork[2].hash(), map[int]uint64{1: 4})
	checkStatus(t, s.h, Data, dataQuery, fork[2].hash(), map[int]uint64{1: 1})
	if n := len(markerKeys(t, s.db)); n != 2*(3+2)+3*(2+1) {
		t.Errorf("%d index keys after the sync, want one per marker of the branch", n)
	}

	// A store with a head and records but without the marker of the index,
	// as built before it, is not served and is built again by Sync.
	built := historyContents(t, s.db)
	if err := rawdb.DeleteGhostTreeMarked(s.db); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.DeleteGhostTreeMarkers(s.db, s.db, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n := len(markerKeys(t, s.db)); n != 0 {
		t.Fatalf("%d index keys left", n)
	}
	if _, err := s.h.MarkerStatus(Coin, coinQuery, fork[2].hash()); !errors.Is(err, ErrHistoryNotReady) {
		t.Errorf("history without the index: %v, want %v", err, ErrHistoryNotReady)
	}
	s.setHead(fork[2])
	if got := historyContents(t, s.db); !reflect.DeepEqual(got, built) {
		t.Errorf("rebuilt history: %d keys, %d index keys; want %d", len(got), len(markerKeys(t, s.db)), len(built))
	}
	checkStatus(t, s.h, Coin, coinQuery, fork[2].hash(), map[int]uint64{1: 4})
	checkStatus(t, s.h, Data, dataQuery, fork[2].hash(), map[int]uint64{1: 1})
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
