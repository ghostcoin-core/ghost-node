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
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// syncChain is a block tree in a database whose canonical chain is set by
// setHead, with the history kept by Sync from the records of each block, as
// a node keeps it.
type syncChain struct {
	t       *testing.T
	db      ethdb.Database
	h       *History
	blocks  map[common.Hash]*testBlock
	failing map[common.Hash]bool // blocks whose records cannot be read
	seq     uint64
	genesis *testBlock
}

func newSyncChain(t *testing.T) *syncChain {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	c := &syncChain{t: t, db: db, h: NewHistory(db), blocks: make(map[common.Hash]*testBlock), failing: make(map[common.Hash]bool)}
	coin, data := EmptyRoot(Coin), EmptyRoot(Data)
	c.genesis = &testBlock{
		header: &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data},
		st:     newState(t),
	}
	c.add(c.genesis)
	return c
}

func (c *syncChain) add(b *testBlock) {
	rawdb.WriteHeader(c.db, b.header)
	c.blocks[b.hash()] = b
}

// child stores a child of parent that appends coin and data leaves and
// spends coin and data markers; tag tells the branches apart.
func (c *syncChain) child(parent *testBlock, tag byte, coin, data, coinMarkers, dataMarkers int) *testBlock {
	c.t.Helper()
	tc := &testChain{t: c.t, seq: c.seq}
	b := tc.next(parent, tag, coin, data)
	c.seq = tc.seq
	for _, k := range []struct {
		kind Kind
		n    int
	}{{CoinMarkers, coinMarkers}, {DataMarkers, dataMarkers}} {
		for i := 0; i < k.n; i++ {
			c.seq++
			var s [8]byte
			binary.BigEndian.PutUint64(s[:], c.seq)
			b.records = append(b.records, Record{Kind: k.kind, Leaf: K("ghost/test-sync-marker", []byte{tag}, s[:])})
		}
	}
	c.add(b)
	return b
}

// branch builds n children on parent, each with the given records.
func (c *syncChain) branch(parent *testBlock, tag byte, n, coin, data, coinMarkers, dataMarkers int) []*testBlock {
	c.t.Helper()
	var out []*testBlock
	for i := 0; i < n; i++ {
		parent = c.child(parent, tag, coin, data, coinMarkers, dataMarkers)
		out = append(out, parent)
	}
	return out
}

// ancestry returns b's chain from genesis.
func (c *syncChain) ancestry(b *testBlock) []*testBlock {
	var out []*testBlock
	for {
		out = append([]*testBlock{b}, out...)
		if b.header.Number.Sign() == 0 {
			return out
		}
		b = c.blocks[b.header.ParentHash]
	}
}

func (c *syncChain) records(header *types.Header) ([]Record, error) {
	if c.failing[header.Hash()] {
		return nil, errors.New("receipts unreadable")
	}
	b, ok := c.blocks[header.Hash()]
	if !ok {
		return nil, errors.New("unknown block")
	}
	return append([]Record(nil), b.records...), nil
}

// setCanonical makes b's ancestry the canonical chain, without syncing.
func (c *syncChain) setCanonical(b *testBlock) {
	chain := c.ancestry(b)
	for n := uint64(len(chain)); rawdb.ReadCanonicalHash(c.db, n) != (common.Hash{}); n++ {
		rawdb.DeleteCanonicalHash(c.db, n)
	}
	for _, a := range chain {
		rawdb.WriteCanonicalHash(c.db, a.hash(), a.header.Number.Uint64())
	}
}

// setHead makes b's ancestry the canonical chain and syncs the history to b.
func (c *syncChain) setHead(b *testBlock) {
	c.t.Helper()
	c.setCanonical(b)
	if err := c.h.Sync(b.header, c.records); err != nil {
		c.t.Fatalf("sync to block %d: %v", b.header.Number, err)
	}
}

// expected returns the leaves of a tree or the markers of a list, index 0, up
// to and including anchor on its chain.
func (c *syncChain) expected(kind Kind, anchor *testBlock) []common.Hash {
	out := []common.Hash{}
	for _, b := range c.ancestry(anchor) {
		for _, r := range b.records {
			if r.Kind == kind && r.TreeIndex == 0 {
				out = append(out, r.Leaf)
			}
		}
	}
	return out
}

// markerScan fetches a marker list as of anchor page by page, up to the first
// page that is not full.
func markerScan(t *testing.T, h *History, kind Kind, anchor common.Hash) []common.Hash {
	t.Helper()
	out := []common.Hash{}
	for p := uint32(0); ; p++ {
		page, err := h.MarkerPage(kind, 0, p, anchor)
		if err != nil {
			t.Fatalf("%v page %d: %v", kind, p, err)
		}
		out = append(out, page.Markers...)
		if len(page.Markers) < PageLeaves {
			return out
		}
	}
}

// checkServed scans both trees and both marker lists at every block of b's
// ancestry and compares them with the chain's records.
func (c *syncChain) checkServed(head *testBlock) {
	c.t.Helper()
	for _, a := range c.ancestry(head) {
		for _, kind := range []Kind{Coin, Data} {
			_, entries := walletScan(c.t, c.h, kind, 0, a.header)
			got := []common.Hash{}
			for _, e := range entries {
				got = append(got, e.Leaf)
			}
			if want := c.expected(kind, a); !reflect.DeepEqual(got, want) {
				c.t.Errorf("%v at block %d: %d leaves served, want %d", kind, a.header.Number, len(got), len(want))
			}
		}
		for _, kind := range []Kind{CoinMarkers, DataMarkers} {
			if got, want := markerScan(c.t, c.h, kind, a.hash()), c.expected(kind, a); !reflect.DeepEqual(got, want) {
				c.t.Errorf("%v at block %d: %d markers served, want %d", kind, a.header.Number, len(got), len(want))
			}
		}
	}
}

func TestSyncBackfillsAnExistingChain(t *testing.T) {
	c := newSyncChain(t)
	chain := c.branch(c.genesis, 1, 3, 1500, 2, 2000, 1)
	chain = append(chain, c.child(chain[len(chain)-1], 1, 0, 0, 0, 0))
	head := chain[len(chain)-1]

	// The chain is there before the history: nothing is served yet.
	c.setCanonical(head)
	if _, err := c.h.MarkerPage(CoinMarkers, 0, 0, head.hash()); !errors.Is(err, ErrHistoryNotReady) {
		t.Errorf("marker page before the first sync: %v, want %v", err, ErrHistoryNotReady)
	}
	if _, err := c.h.PageRoots(Coin, 0, head.hash()); !errors.Is(err, ErrRootMismatch) {
		t.Errorf("page roots before the first sync: %v, want %v", err, ErrRootMismatch)
	}
	// The first sync builds it from genesis.
	c.setHead(head)
	c.checkServed(head)
	if got := len(c.expected(CoinMarkers, head)); got != 6000 {
		t.Fatalf("%d coin markers in the chain", got)
	}
	// A second sync to the same head writes nothing.
	before := historyContents(t, c.db)
	c.setHead(head)
	if !reflect.DeepEqual(before, historyContents(t, c.db)) {
		t.Error("a sync to the stored head changed the history")
	}
}

func TestSyncFollowsReorgs(t *testing.T) {
	c := newSyncChain(t)
	base := c.branch(c.genesis, 1, 2, 10, 3, 4, 1)
	old := c.branch(base[1], 2, 3, 4000, 1, 3000, 2)
	for _, b := range old {
		c.setHead(b)
	}
	c.checkServed(old[2])

	// A longer branch from block 2 replaces it.
	fork := c.branch(base[1], 3, 4, 100, 0, 1500, 0)
	c.setHead(fork[3])
	c.checkServed(fork[3])

	// The removed branch is no anchor, and leaves nothing behind: the store
	// equals that of a node that only ever saw the new branch.
	if _, err := c.h.MarkerPage(CoinMarkers, 0, 0, old[2].hash()); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("marker page on the removed branch: %v, want %v", err, ErrNotCanonical)
	}
	ref := newSyncChain(t)
	for _, b := range c.ancestry(fork[3]) {
		ref.add(b)
	}
	ref.setHead(fork[3])
	if got, want := historyContents(t, c.db), historyContents(t, ref.db); !reflect.DeepEqual(got, want) {
		t.Errorf("history after the reorganisation has %d entries, a store of the branch alone %d", len(got), len(want))
	}

	// And back to the first branch, made longer.
	more := c.child(old[2], 2, 1, 1, 1, 1)
	c.setHead(more)
	c.checkServed(more)

	// A shorter head: a rewind.
	c.setHead(base[0])
	c.checkServed(base[0])
	if _, err := c.h.MarkerPage(CoinMarkers, 0, 0, more.hash()); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("marker page above the head: %v, want %v", err, ErrNotCanonical)
	}
}

func TestSyncStopsBelowUnreadableBlock(t *testing.T) {
	c := newSyncChain(t)
	chain := c.branch(c.genesis, 1, 4, 5, 5, 5, 5)
	c.setHead(chain[0])
	c.failing[chain[2].hash()] = true
	c.setCanonical(chain[3])
	if err := c.h.Sync(chain[3].header, c.records); err == nil {
		t.Fatal("sync over an unreadable block succeeded")
	}
	// The history holds block 2 and nothing above; above it, nothing is
	// answered.
	c.checkServed(chain[1])
	for _, b := range chain[2:] {
		if _, err := c.h.MarkerPage(DataMarkers, 0, 0, b.hash()); !errors.Is(err, ErrHistoryNotReady) {
			t.Errorf("marker page at unsynced block %d: %v, want %v", b.header.Number, err, ErrHistoryNotReady)
		}
		if _, err := c.h.PageRoots(Coin, 0, b.hash()); !errors.Is(err, ErrRootMismatch) {
			t.Errorf("page roots at unsynced block %d: %v, want %v", b.header.Number, err, ErrRootMismatch)
		}
	}
	// Once the block reads, the next sync catches up.
	delete(c.failing, chain[2].hash())
	c.setHead(chain[3])
	c.checkServed(chain[3])
}

func TestSyncRebuildsStaleHistory(t *testing.T) {
	c := newSyncChain(t)
	chain := c.branch(c.genesis, 1, 3, 20, 20, 20, 20)
	c.setHead(chain[2])

	// The stored head's header is gone, as after a rewind the history did
	// not see: the history is built again for the new head.
	side := c.branch(c.genesis, 2, 2, 7, 0, 3, 3)
	rawdb.DeleteHeader(c.db, chain[2].hash(), 3)
	c.setHead(side[1])
	c.checkServed(side[1])

	// Records written without a head, by ApplyBlock alone, are replaced too.
	db := rawdb.NewMemoryDatabase()
	h := NewHistory(db)
	for _, b := range c.ancestry(chain[1]) {
		rawdb.WriteHeader(db, b.header)
		rawdb.WriteCanonicalHash(db, b.hash(), b.header.Number.Uint64())
		if err := h.ApplyBlock(b.hash(), b.header.Number.Uint64(), b.records); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.MarkerPage(CoinMarkers, 0, 0, chain[1].hash()); !errors.Is(err, ErrHistoryNotReady) {
		t.Errorf("marker page without a head: %v, want %v", err, ErrHistoryNotReady)
	}
	for _, b := range c.ancestry(side[1]) {
		rawdb.WriteHeader(db, b.header)
	}
	for n := uint64(0); n <= 3; n++ {
		rawdb.DeleteCanonicalHash(db, n)
	}
	for _, b := range c.ancestry(side[1]) {
		rawdb.WriteCanonicalHash(db, b.hash(), b.header.Number.Uint64())
	}
	if err := h.Sync(side[1].header, c.records); err != nil {
		t.Fatal(err)
	}
	c.h, c.db = h, db
	c.checkServed(side[1])
}

func TestUnwindRevertsOnlyTheHead(t *testing.T) {
	c := newSyncChain(t)
	chain := c.branch(c.genesis, 1, 3, 3, 3, 3, 3)
	c.setHead(chain[2])
	before := historyContents(t, c.db)
	for _, other := range []common.Hash{chain[1].hash(), chain[0].hash(), {7}} {
		if err := c.h.Unwind(other); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, historyContents(t, c.db)) {
		t.Fatal("unwinding a block that is not the head changed the history")
	}
	for i := 2; i >= 0; i-- {
		if err := c.h.Unwind(chain[i].hash()); err != nil {
			t.Fatal(err)
		}
	}
	c.setCanonical(c.genesis)
	c.checkServed(c.genesis)
	ref := newSyncChain(t)
	ref.setHead(ref.genesis)
	if !reflect.DeepEqual(historyContents(t, c.db), historyContents(t, ref.db)) {
		t.Error("history unwound to genesis differs from a history of genesis alone")
	}
}

func TestMarkerPagesAreAsOfAnchor(t *testing.T) {
	c := newSyncChain(t)
	b1 := c.child(c.genesis, 1, 0, 0, 10, 0)
	b2 := c.child(b1, 1, 0, 0, 4100, 1)
	b3 := c.child(b2, 1, 0, 0, 0, 0)
	c.setHead(b3)
	for _, w := range []struct {
		anchor *testBlock
		page   uint32
		count  int
	}{
		{c.genesis, 0, 0},
		{b1, 0, 10},
		{b1, 1, 0},
		{b2, 0, PageLeaves},
		{b2, 1, 14},
		{b3, 1, 14},
		{b3, 2, 0},
	} {
		page, err := c.h.MarkerPage(CoinMarkers, 0, w.page, w.anchor.hash())
		if err != nil {
			t.Fatalf("block %d page %d: %v", w.anchor.header.Number, w.page, err)
		}
		if len(page.Markers) != w.count {
			t.Errorf("block %d page %d: %d markers, want %d", w.anchor.header.Number, w.page, len(page.Markers), w.count)
		}
		want := c.expected(CoinMarkers, w.anchor)
		first := int(w.page) * PageLeaves
		if first < len(want) && !reflect.DeepEqual(page.Markers, want[first:min(len(want), first+PageLeaves)]) {
			t.Errorf("block %d page %d: markers differ from the chain's", w.anchor.header.Number, w.page)
		}
	}
	for _, c2 := range []struct {
		name string
		kind Kind
		idx  uint64
		page uint32
		want error
	}{
		{"tree kind", Coin, 0, 0, ErrUnknownKind},
		{"unknown kind", Kind(9), 0, 0, ErrUnknownKind},
		{"page beyond a list", CoinMarkers, 0, 1 << 20, ErrPageRange},
		{"list that does not exist", CoinMarkers, 1, 0, ErrNoTree},
	} {
		if _, err := c.h.MarkerPage(c2.kind, c2.idx, c2.page, b3.hash()); !errors.Is(err, c2.want) {
			t.Errorf("%s: %v, want %v", c2.name, err, c2.want)
		}
	}
	if _, err := c.h.MarkerPage(CoinMarkers, 0, 0, common.Hash{1}); !errors.Is(err, ErrUnknownAnchor) {
		t.Errorf("unknown anchor: %v, want %v", err, ErrUnknownAnchor)
	}
	// A missing marker below the count is refused, never skipped.
	rawdb.DeleteGhostTreeLeaf(c.db, uint8(CoinMarkers), 0, 5)
	if _, err := c.h.MarkerPage(CoinMarkers, 0, 0, b3.hash()); err == nil {
		t.Error("a page with a missing marker was served")
	}
}

// TestMarkerListsRollOver fills a small marker list and goes on in the next
// index within the same block, which a tree may not do.
func TestMarkerListsRollOver(t *testing.T) {
	c := newSyncChain(t)
	c.h.p = Params{Depth: PageLevels}
	b1 := c.child(c.genesis, 1, 0, 0, PageLeaves-3, 0)
	b2 := c.child(b1, 1, 0, 0, 10, 0)
	c.setHead(b2)
	all := c.expected(CoinMarkers, b2)
	for _, w := range []struct {
		index uint64
		want  []common.Hash
	}{{0, all[:PageLeaves]}, {1, all[PageLeaves:]}} {
		page, err := c.h.MarkerPage(CoinMarkers, w.index, 0, b2.hash())
		if err != nil {
			t.Fatalf("list %d: %v", w.index, err)
		}
		if !reflect.DeepEqual(page.Markers, w.want) {
			t.Errorf("list %d: %d markers, want %d", w.index, len(page.Markers), len(w.want))
		}
	}
	if _, err := c.h.MarkerPage(CoinMarkers, 1, 0, b1.hash()); !errors.Is(err, ErrNoTree) {
		t.Errorf("list 1 before it started: %v, want %v", err, ErrNoTree)
	}
	// A reorg back to block 1 removes list 1 and the end of list 0.
	c.setHead(c.child(b1, 2, 0, 0, 0, 1))
	if page, err := c.h.MarkerPage(CoinMarkers, 0, 0, b1.hash()); err != nil || len(page.Markers) != PageLeaves-3 {
		t.Errorf("list 0 after the reorg: %v, %v", page, err)
	}
	if enc, err := rawdb.ReadGhostTreeLeaf(c.db, uint8(CoinMarkers), 1, 0); err != nil || enc != nil {
		t.Errorf("list 1 after the reorg: %x, %v", enc, err)
	}
}
