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
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// testNote is a note that differs for every leaf.
func testNote(leaf common.Hash) (note [NoteBytes]byte) {
	for i := 0; i < NoteBytes; i += common.HashLength {
		copy(note[i:], leaf[:])
	}
	note[NoteBytes-1] ^= 0x5a
	return note
}

// testBlock is a header with the records its block appended and the tree
// state after it.
type testBlock struct {
	header  *types.Header
	records []Record
	st      *state.StateDB
}

func (b *testBlock) hash() common.Hash { return b.header.Hash() }

// testChain is a header chain in a database with its tree history, the
// canonical blocks by number. Leaves are appended to real tree state, so the
// header roots are those core/ghosttree computes.
type testChain struct {
	t      *testing.T
	db     ethdb.Database
	h      *History
	blocks []*testBlock
	seq    uint64
}

func newTestChain(t *testing.T) *testChain {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	c := &testChain{t: t, db: db, h: NewHistory(db)}
	coin, data := EmptyRoot(Coin), EmptyRoot(Data)
	c.insert(&testBlock{
		header: &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data},
		st:     newState(t),
	})
	return c
}

func (c *testChain) head() *testBlock { return c.blocks[len(c.blocks)-1] }

// next builds a child of parent that appends coin and data leaves; tag tells
// the blocks of different branches apart.
func (c *testChain) next(parent *testBlock, tag byte, coin, data int) *testBlock {
	c.t.Helper()
	st := parent.st.Copy()
	number := parent.header.Number.Uint64() + 1
	var records []Record
	for _, k := range []struct {
		kind Kind
		n    int
	}{{Coin, coin}, {Data, data}} {
		for i := 0; i < k.n; i++ {
			c.seq++
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], c.seq)
			leaf := K("ghost/test-history-leaf", []byte{tag}, b[:])
			res, err := Append(st, k.kind, number, leaf)
			if err != nil {
				c.t.Fatal(err)
			}
			records = append(records, Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: leaf, Note: testNote(leaf)})
		}
	}
	coinRoot, dataRoot := mustRoot(c.t, Release, st, Coin), mustRoot(c.t, Release, st, Data)
	header := &types.Header{
		ParentHash:   parent.hash(),
		Number:       new(big.Int).SetUint64(number),
		Difficulty:   big.NewInt(1),
		BaseFee:      big.NewInt(1),
		Extra:        []byte{tag},
		CoinTreeRoot: &coinRoot,
		DataTreeRoot: &dataRoot,
	}
	return &testBlock{header: header, records: records, st: st}
}

// insert makes b the canonical block at its height and applies it.
func (c *testChain) insert(b *testBlock) {
	c.t.Helper()
	number := b.header.Number.Uint64()
	if number != uint64(len(c.blocks)) {
		c.t.Fatalf("inserting block %d on a chain of %d", number, len(c.blocks))
	}
	rawdb.WriteHeader(c.db, b.header)
	rawdb.WriteCanonicalHash(c.db, b.hash(), number)
	if err := c.h.ApplyBlock(b.hash(), number, b.records); err != nil {
		c.t.Fatalf("apply block %d: %v", number, err)
	}
	c.blocks = append(c.blocks, b)
}

func (c *testChain) extend(tag byte, coin, data int) *testBlock {
	c.t.Helper()
	b := c.next(c.head(), tag, coin, data)
	c.insert(b)
	return b
}

// rewind reverts the canonical blocks above number, newest first, as a
// reorganisation does.
func (c *testChain) rewind(number uint64) {
	c.t.Helper()
	for uint64(len(c.blocks)) > number+1 {
		b := c.head()
		if err := c.h.RevertBlock(b.hash()); err != nil {
			c.t.Fatalf("revert block %d: %v", b.header.Number, err)
		}
		rawdb.DeleteCanonicalHash(c.db, b.header.Number.Uint64())
		c.blocks = c.blocks[:len(c.blocks)-1]
	}
}

// expected returns the leaves, notes and salts of a tree up to and including
// block number on the canonical chain.
func (c *testChain) expected(kind Kind, treeIndex, number uint64) []PageEntry {
	entries := []PageEntry{}
	for _, b := range c.blocks[:number+1] {
		for _, r := range b.records {
			if r.Kind == kind && r.TreeIndex == treeIndex {
				entries = append(entries, PageEntry{Leaf: r.Leaf, Note: r.Note, Salt: r.Salt})
			}
		}
	}
	return entries
}

// walletScan fetches a tree as of anchor the way a wallet does: the page-root
// list, checked against the header root, then every page, each checked
// against its page root, and the first page past the list, which is empty.
func walletScan(t *testing.T, h *History, kind Kind, treeIndex uint64, anchor *types.Header) ([]common.Hash, []PageEntry) {
	t.Helper()
	roots, err := h.PageRoots(kind, treeIndex, anchor.Hash())
	if err != nil {
		t.Fatalf("%v tree %d page roots at %d: %v", kind, treeIndex, anchor.Number, err)
	}
	if got := RootFromPageRoots(kind, roots); got != *HeaderRoot(anchor, kind) {
		t.Fatalf("%v tree %d at %d: page roots give %x, header %x", kind, treeIndex, anchor.Number, got, *HeaderRoot(anchor, kind))
	}
	entries := []PageEntry{}
	for p := 0; p <= len(roots); p++ {
		page, err := h.Page(kind, treeIndex, uint32(p), anchor.Hash())
		if err != nil {
			t.Fatalf("%v tree %d page %d at %d: %v", kind, treeIndex, p, anchor.Number, err)
		}
		if int(page.Filled) != len(page.Entries) {
			t.Fatalf("page %d: %d filled, %d entries", p, page.Filled, len(page.Entries))
		}
		if p == len(roots) {
			if page.Filled != 0 {
				t.Fatalf("page %d past the list has %d entries", p, page.Filled)
			}
			break
		}
		if p < len(roots)-1 && page.Filled != PageLeaves {
			t.Fatalf("page %d before the last has %d entries", p, page.Filled)
		}
		leaves := make([]common.Hash, len(page.Entries))
		for i, e := range page.Entries {
			leaves[i] = e.Leaf
		}
		if PageRoot(kind, leaves) != roots[p] {
			t.Fatalf("page %d does not match its page root", p)
		}
		entries = append(entries, page.Entries...)
	}
	return roots, entries
}

// checkServed scans both trees of index 0 at every canonical anchor and
// compares them with the chain's records.
func (c *testChain) checkServed() {
	c.t.Helper()
	for _, b := range c.blocks {
		for _, kind := range []Kind{Coin, Data} {
			_, got := walletScan(c.t, c.h, kind, 0, b.header)
			if want := c.expected(kind, 0, b.header.Number.Uint64()); !reflect.DeepEqual(got, want) {
				c.t.Errorf("%v at block %d: %d entries served, want %d", kind, b.header.Number, len(got), len(want))
			}
		}
	}
}

// historyContents returns every key and value of the tree history.
func historyContents(t *testing.T, db ethdb.Database) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	it := db.NewIterator([]byte("ghost-tree-"), nil)
	defer it.Release()
	for it.Next() {
		out[string(it.Key())] = common.CopyBytes(it.Value())
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHistoryAfterReorg(t *testing.T) {
	c := newTestChain(t)
	c.extend(1, 4000, 3)
	c.extend(2, 200, 1) // completes coin page 0
	c.extend(3, 5, 4097)
	old := append([]*testBlock(nil), c.blocks[2:]...)
	oldHead := c.head().header
	c.checkServed()

	// Reverting a block under a newer one that wrote the same tree is
	// refused and changes nothing.
	before := historyContents(t, c.db)
	if err := c.h.RevertBlock(old[0].hash()); !errors.Is(err, ErrRevertOrder) {
		t.Fatalf("reverting under the head: %v, want %v", err, ErrRevertOrder)
	}
	if !reflect.DeepEqual(before, historyContents(t, c.db)) {
		t.Fatal("a refused revert changed the history")
	}

	// The reorganisation: back to block 1, then a branch of three blocks.
	c.rewind(1)
	c.extend(4, 96, 0) // completes coin page 0 with other leaves
	c.extend(5, 10, 2)
	c.extend(6, 0, 0)
	c.checkServed()

	// A store that only ever saw the second branch.
	ref := newTestChain(t)
	for _, b := range c.blocks[1:] {
		ref.insert(b)
	}
	if got, want := historyContents(t, c.db), historyContents(t, ref.db); !reflect.DeepEqual(got, want) {
		t.Errorf("history after the reorganisation has %d entries, a store of the branch alone %d", len(got), len(want))
		for k, v := range got {
			if !bytes.Equal(want[k], v) {
				t.Errorf("differs at key %x", k)
			}
		}
	}
	for _, b := range c.blocks {
		for _, kind := range []Kind{Coin, Data} {
			gotRoots, gotEntries := walletScan(t, c.h, kind, 0, b.header)
			wantRoots, wantEntries := walletScan(t, ref.h, kind, 0, b.header)
			if !reflect.DeepEqual(gotRoots, wantRoots) || !reflect.DeepEqual(gotEntries, wantEntries) {
				t.Errorf("%v at block %d: served data differs from a store of the branch alone", kind, b.header.Number)
			}
		}
	}

	// The removed branch is not an anchor any more, and is gone.
	if _, err := c.h.PageRoots(Coin, 0, oldHead.Hash()); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("anchor on the removed branch: %v, want %v", err, ErrNotCanonical)
	}
	if _, err := c.h.Page(Coin, 0, 0, oldHead.Hash()); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("page anchored on the removed branch: %v, want %v", err, ErrNotCanonical)
	}
	if _, err := ref.h.Page(Coin, 0, 0, oldHead.Hash()); !errors.Is(err, ErrUnknownAnchor) {
		t.Errorf("unknown anchor: %v, want %v", err, ErrUnknownAnchor)
	}
	for _, b := range old {
		if err := c.h.RevertBlock(b.hash()); !errors.Is(err, ErrBlockUnknown) {
			t.Errorf("reverting a removed block again: %v, want %v", err, ErrBlockUnknown)
		}
	}
	if err := c.h.ApplyBlock(c.head().hash(), c.head().header.Number.Uint64(), nil); !errors.Is(err, ErrBlockApplied) {
		t.Errorf("applying a block twice: %v, want %v", err, ErrBlockApplied)
	}

	// Reverting the whole branch, empty block included, gives back block 1.
	c.rewind(1)
	ref = newTestChain(t)
	ref.insert(c.blocks[1])
	if !reflect.DeepEqual(historyContents(t, c.db), historyContents(t, ref.db)) {
		t.Error("history after reverting to block 1 differs from a store of block 1 alone")
	}
}

func TestFilledPositionsAreAsOfAnchor(t *testing.T) {
	c := newTestChain(t)
	c.extend(1, 10, 1)
	c.extend(2, 5, 0)
	c.extend(3, 4100, 2)
	c.extend(4, 0, 0)

	for _, w := range []struct {
		number      uint64
		page        uint32
		filled      uint32
		pageRoots   int
		coinEntries int
	}{
		{0, 0, 0, 0, 0},
		{1, 0, 10, 1, 10},
		{2, 0, 15, 1, 15},
		{2, 1, 0, 1, 15},
		{3, 0, PageLeaves, 2, 4115},
		{3, 1, 19, 2, 4115},
		{4, 1, 19, 2, 4115},
	} {
		anchor := c.blocks[w.number].header
		page, err := c.h.Page(Coin, 0, w.page, anchor.Hash())
		if err != nil {
			t.Fatalf("block %d page %d: %v", w.number, w.page, err)
		}
		if page.Filled != w.filled || len(page.Entries) != int(w.filled) {
			t.Errorf("block %d page %d: %d filled, %d entries, want %d", w.number, w.page, page.Filled, len(page.Entries), w.filled)
		}
		want := c.expected(Coin, 0, w.number)
		first := int(w.page) * PageLeaves
		if first < len(want) && !reflect.DeepEqual(page.Entries, want[first:min(len(want), first+PageLeaves)]) {
			t.Errorf("block %d page %d: entries differ from the records up to the anchor", w.number, w.page)
		}
		roots, entries := walletScan(t, c.h, Coin, 0, anchor)
		if len(roots) != w.pageRoots || len(entries) != w.coinEntries {
			t.Errorf("block %d: %d page roots and %d entries, want %d and %d", w.number, len(roots), len(entries), w.pageRoots, w.coinEntries)
		}
	}
	// A page beyond any tree is out of range, not empty.
	if _, err := c.h.Page(Coin, 0, 1<<20, c.head().hash()); !errors.Is(err, ErrPageRange) {
		t.Errorf("page 2^20: %v, want %v", err, ErrPageRange)
	}
	// A tree index with no leaf at the anchor does not exist.
	if _, err := c.h.PageRoots(Coin, 1, c.head().hash()); !errors.Is(err, ErrNoTree) {
		t.Errorf("tree 1: %v, want %v", err, ErrNoTree)
	}
	if _, err := c.h.Page(Kind(2), 0, 0, c.head().hash()); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: %v, want %v", err, ErrUnknownKind)
	}
}

func TestWrongPageIsCaught(t *testing.T) {
	c := newTestChain(t)
	c.extend(1, 5000, 7)
	anchor := c.head().header
	roots, entries := walletScan(t, c.h, Coin, 0, anchor)
	page1, err := c.h.Page(Coin, 0, 1, anchor.Hash())
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]common.Hash, len(page1.Entries))
	for i, e := range page1.Entries {
		leaves[i] = e.Leaf
	}
	if PageRoot(Coin, leaves) != roots[1] {
		t.Fatal("the honest page does not match")
	}

	// The wallet's side: a page with one leaf changed fails its page root, a
	// list with one root changed fails the header root.
	for i := range leaves {
		if i%311 != 0 {
			continue
		}
		bad := append([]common.Hash(nil), leaves...)
		bad[i][5] ^= 1
		if PageRoot(Coin, bad) == roots[1] {
			t.Errorf("leaf %d of page 1 changed: the page still matches", i)
		}
	}
	if short := leaves[:len(leaves)-1]; PageRoot(Coin, short) == roots[1] {
		t.Error("page 1 with a leaf left out still matches")
	}
	for i := range roots {
		bad := append([]common.Hash(nil), roots...)
		bad[i][31] ^= 1
		if RootFromPageRoots(Coin, bad) == *anchor.CoinTreeRoot {
			t.Errorf("page root %d changed: the list still matches the header", i)
		}
	}
	if RootFromPageRoots(Coin, roots[:1]) == *anchor.CoinTreeRoot {
		t.Error("the list with its last page left out still matches the header")
	}
	if RootFromPageRoots(Data, roots) == *anchor.CoinTreeRoot {
		t.Error("the coin list matches as a data list")
	}

	// The node's side: corrupted history is refused, never served.
	for _, corrupt := range []struct {
		name   string
		damage func()
		repair func()
	}{
		{"leaf of the partial page", func() {
			rec := stored{number: 1, leaf: testLeaf(1), note: entries[4100].Note}
			rawdb.WriteGhostTreeLeaf(c.db, uint8(Coin), 0, 4100, rec.encode())
		}, func() {
			rec := stored{number: 1, leaf: entries[4100].Leaf, note: entries[4100].Note}
			rawdb.WriteGhostTreeLeaf(c.db, uint8(Coin), 0, 4100, rec.encode())
		}},
		{"stored root of the full page", func() {
			rawdb.WriteGhostTreePageRoot(c.db, uint8(Coin), 0, 0, testLeaf(2))
		}, func() {
			rawdb.WriteGhostTreePageRoot(c.db, uint8(Coin), 0, 0, roots[0])
		}},
		{"truncated record", func() {
			rawdb.WriteGhostTreeLeaf(c.db, uint8(Coin), 0, 4999, []byte{1, 2, 3})
		}, func() {
			rec := stored{number: 1, leaf: entries[4999].Leaf, note: entries[4999].Note}
			rawdb.WriteGhostTreeLeaf(c.db, uint8(Coin), 0, 4999, rec.encode())
		}},
		{"missing record", func() {
			rawdb.DeleteGhostTreeLeaf(c.db, uint8(Coin), 0, 4500)
		}, func() {
			rec := stored{number: 1, leaf: entries[4500].Leaf, note: entries[4500].Note}
			rawdb.WriteGhostTreeLeaf(c.db, uint8(Coin), 0, 4500, rec.encode())
		}},
	} {
		corrupt.damage()
		if r, err := c.h.PageRoots(Coin, 0, anchor.Hash()); err == nil {
			t.Errorf("%s: page roots served: %d", corrupt.name, len(r))
		}
		for p := uint32(0); p < 3; p++ {
			if pg, err := c.h.Page(Coin, 0, p, anchor.Hash()); err == nil {
				t.Errorf("%s: page %d served with %d entries", corrupt.name, p, pg.Filled)
			}
		}
		corrupt.repair()
		walletScan(t, c.h, Coin, 0, anchor)
	}
	// A header without the root of the kind is no anchor.
	h := types.CopyHeader(anchor)
	h.CoinTreeRoot, h.DataTreeRoot, h.ParentHash = nil, nil, common.Hash{1}
	rawdb.WriteHeader(c.db, h)
	rawdb.WriteCanonicalHash(c.db, h.Hash(), 1)
	if _, err := c.h.PageRoots(Coin, 0, h.Hash()); !errors.Is(err, ErrNoHeaderRoot) {
		t.Errorf("header without roots: %v, want %v", err, ErrNoHeaderRoot)
	}
}

func TestApplyBlockRefusesBrokenRecords(t *testing.T) {
	c := newTestChain(t)
	c.extend(1, 3, 1)
	c.extend(2, 0, 0)
	leaf := testLeaf(77)
	ok := Record{Kind: Coin, TreeIndex: 0, Position: 3, Leaf: leaf}
	for _, b := range []struct {
		name    string
		number  uint64
		records []Record
	}{
		{"gap", 3, []Record{{Kind: Coin, Position: 4, Leaf: leaf}}},
		{"position stored", 3, []Record{{Kind: Coin, Position: 2, Leaf: leaf}}},
		{"duplicate in the block", 3, []Record{ok, ok}},
		{"zero leaf", 3, []Record{{Kind: Coin, Position: 3}}},
		{"unknown kind", 3, []Record{{Kind: Kind(9), Position: 0, Leaf: leaf}}},
		{"below the block before", 0, []Record{ok}},
		{"next index before the tree is full", 3, []Record{{Kind: Data, TreeIndex: 1, Position: 0, Leaf: leaf}}},
		{"good then bad", 3, []Record{ok, {Kind: Coin, Position: 5, Leaf: leaf}}},
	} {
		before := historyContents(t, c.db)
		hash := common.Hash{byte(len(b.name))}
		if err := c.h.ApplyBlock(hash, b.number, b.records); !errors.Is(err, ErrBadRecord) {
			t.Errorf("%s: %v, want %v", b.name, err, ErrBadRecord)
		}
		if !reflect.DeepEqual(before, historyContents(t, c.db)) {
			t.Errorf("%s: a refused block wrote to the history", b.name)
		}
	}
}

// TestHistoryServesFullTrees fills a small tree of two pages and starts the
// next index: the full tree is checked against the header of the block that
// filled it, the next against the anchor.
func TestHistoryServesFullTrees(t *testing.T) {
	p := Params{Depth: PageLevels + 1}
	db := rawdb.NewMemoryDatabase()
	h := &History{p: p, db: db}
	var tree0, tree1 []common.Hash
	var parent common.Hash
	block := func(number uint64, records []Record) *types.Header {
		t.Helper()
		coin := naiveRoot(Coin, p.Depth, tree1)
		if len(tree1) == 0 {
			coin = naiveRoot(Coin, p.Depth, tree0)
		}
		data := zeros(Data, p.Depth)[p.Depth]
		header := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data}
		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, header.Hash(), number)
		if err := h.ApplyBlock(header.Hash(), number, records); err != nil {
			t.Fatalf("block %d: %v", number, err)
		}
		parent = header.Hash()
		return header
	}
	block(0, nil)
	var records []Record
	for i := 0; i < 2*PageLeaves; i++ {
		tree0 = append(tree0, testLeaf(i))
		records = append(records, Record{Kind: Coin, Position: uint32(i), Leaf: tree0[i]})
	}
	// The next index cannot start in the block that fills the tree.
	next := Record{Kind: Coin, TreeIndex: 1, Position: 0, Leaf: testLeaf(-1)}
	if err := h.ApplyBlock(common.Hash{9}, 1, append(append([]Record(nil), records...), next)); !errors.Is(err, ErrBadRecord) {
		t.Fatalf("next index in the filling block: %v, want %v", err, ErrBadRecord)
	}
	filled := block(1, records)
	block(2, nil)
	tree1 = []common.Hash{next.Leaf}
	head := block(3, []Record{next})

	for _, anchor := range []*types.Header{filled, head} {
		roots, err := h.PageRoots(Coin, 0, anchor.Hash())
		if err != nil {
			t.Fatalf("tree 0 at %d: %v", anchor.Number, err)
		}
		if len(roots) != 2 || rootFromPageRoots(p, Coin, roots) != *filled.CoinTreeRoot {
			t.Errorf("tree 0 at %d: %d page roots not matching the filling block", anchor.Number, len(roots))
		}
		pg, err := h.Page(Coin, 0, 2, anchor.Hash())
		if !errors.Is(err, ErrPageRange) {
			t.Errorf("page past a full small tree: %+v, %v", pg, err)
		}
	}
	if _, err := h.PageRoots(Coin, 1, filled.Hash()); !errors.Is(err, ErrNoTree) {
		t.Errorf("tree 1 before it started: %v, want %v", err, ErrNoTree)
	}
	pg, err := h.Page(Coin, 1, 0, head.Hash())
	if err != nil || pg.Filled != 1 || pg.Entries[0].Leaf != next.Leaf {
		t.Errorf("tree 1 at the head: %+v, %v", pg, err)
	}
	// The filling block cannot be reverted under the next index.
	if err := h.RevertBlock(filled.Hash()); !errors.Is(err, ErrRevertOrder) {
		t.Errorf("reverting the filling block: %v, want %v", err, ErrRevertOrder)
	}
}

// testSalt is a synthetic salt that differs for every seed.
func testSalt(seed byte) *[SaltBytes]byte {
	var s [SaltBytes]byte
	for i := range s {
		s[i] = seed ^ byte(0x30+i)
	}
	return &s
}

// TestHistoryKeepsTheSaltWithTheLeaf applies a block whose salted commits
// carry a salt beside leaves without one: each salted record is stored 16
// bytes longer with the salt after the note, every other record keeps the old
// length, and the pages serve each salt with its leaf and note. A marker
// never keeps a salt, a record of the old length still decodes without one,
// and reverting the block removes the salts with their leaves.
func TestHistoryKeepsTheSaltWithTheLeaf(t *testing.T) {
	c := newTestChain(t)
	c.extend(1, 2, 1) // leaves without a salt: version 1 commits
	before := historyContents(t, c.db)

	// Block 2 appends coin positions 2 to 4 and data positions 1 and 2; coin
	// 2, coin 4 and data 1 are salted commits.
	salted := c.next(c.head(), 2, 3, 2)
	salted.records[0].Salt = testSalt(1)
	salted.records[2].Salt = testSalt(2)
	salted.records[3].Salt = testSalt(3)
	salted.records = append(salted.records, Record{Kind: CoinMarkers, Leaf: testLeaf(900), Salt: testSalt(4)})
	c.insert(salted)

	layout := []struct {
		kind Kind
		pos  uint32
		salt *[SaltBytes]byte
	}{
		{Coin, 0, nil}, {Coin, 1, nil}, {Coin, 2, testSalt(1)}, {Coin, 3, nil}, {Coin, 4, testSalt(2)},
		{Data, 0, nil}, {Data, 1, testSalt(3)}, {Data, 2, nil},
		{CoinMarkers, 0, nil},
	}
	checkStored := func(when string) {
		t.Helper()
		for _, w := range layout {
			enc, err := rawdb.ReadGhostTreeLeaf(c.db, uint8(w.kind), 0, w.pos)
			if err != nil || enc == nil {
				t.Fatalf("%s: %v position %d not stored: %v", when, w.kind, w.pos, err)
			}
			want := storedSize
			if w.salt != nil {
				want = storedSize + SaltBytes
			}
			if len(enc) != want {
				t.Errorf("%s: %v position %d stored in %d bytes, want %d", when, w.kind, w.pos, len(enc), want)
				continue
			}
			if w.salt != nil && !bytes.Equal(enc[storedSize:], w.salt[:]) {
				t.Errorf("%s: %v position %d stored salt %x, want %x", when, w.kind, w.pos, enc[storedSize:], w.salt[:])
			}
		}
	}
	checkStored("applied")

	// The pages serve each salt with its leaf and note, and none where the
	// leaf has none.
	c.checkServed()
	for _, w := range layout[:8] {
		page, err := c.h.Page(w.kind, 0, 0, salted.hash())
		if err != nil {
			t.Fatal(err)
		}
		e := page.Entries[w.pos]
		if !reflect.DeepEqual(e.Salt, w.salt) {
			t.Errorf("%v position %d served salt %v, want %v", w.kind, w.pos, e.Salt, w.salt)
		}
	}
	if page, err := c.h.Page(Coin, 0, 0, salted.hash()); err != nil || page.Entries[2].Note != salted.records[0].Note || page.Entries[2].Leaf != salted.records[0].Leaf {
		t.Fatalf("the salted leaf lost its leaf or note: %v", err)
	}

	// The old length decodes with no salt; the salted length with its salt;
	// any other length is corrupt.
	plain := stored{number: 7, leaf: testLeaf(5), note: testNote(testLeaf(5))}
	dec, err := decodeStored(plain.encode())
	if err != nil || dec.salt != nil || dec.leaf != plain.leaf || dec.note != plain.note || dec.number != 7 {
		t.Fatalf("old-length record: %+v, %v", dec, err)
	}
	withSalt := plain
	withSalt.salt = testSalt(6)
	enc := withSalt.encode()
	if len(enc) != len(plain.encode())+SaltBytes {
		t.Fatalf("salted record of %d bytes", len(enc))
	}
	if dec, err := decodeStored(enc); err != nil || !reflect.DeepEqual(dec, &withSalt) {
		t.Fatalf("salted record: %+v, %v", dec, err)
	}
	for _, n := range []int{storedSize - 1, storedSize + 1, storedSize + SaltBytes - 1, storedSize + SaltBytes + 1} {
		if _, err := decodeStored(make([]byte, n)); !errors.Is(err, ErrCorruptHistory) {
			t.Errorf("record of %d bytes: %v, want %v", n, err, ErrCorruptHistory)
		}
	}

	// Reverting the block removes the salted records with the rest of it.
	c.rewind(1)
	if !reflect.DeepEqual(before, historyContents(t, c.db)) {
		t.Fatal("reverting the salted block left something in the history")
	}
	for _, w := range layout[2:] {
		if w.kind == Data && w.pos == 0 {
			continue
		}
		if enc, err := rawdb.ReadGhostTreeLeaf(c.db, uint8(w.kind), 0, w.pos); err != nil || enc != nil {
			t.Errorf("%v position %d still stored after the revert: %x, %v", w.kind, w.pos, enc, err)
		}
	}
	c.checkServed()

	// The same block applied again keeps its salts; a block of the other
	// branch at the same positions has none.
	c.insert(salted)
	checkStored("applied again")
	c.checkServed()
	c.rewind(1)
	other := c.extend(3, 3, 2)
	for _, kind := range []Kind{Coin, Data} {
		page, err := c.h.Page(kind, 0, 0, other.hash())
		if err != nil {
			t.Fatal(err)
		}
		for i, e := range page.Entries {
			if e.Salt != nil {
				t.Errorf("%v position %d of the other branch served salt %x", kind, i, e.Salt[:])
			}
		}
	}
	c.checkServed()
}
