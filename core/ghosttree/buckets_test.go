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
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// The spec vector tags of spec 01 section 14.
const (
	vectorTagA = 0x4d6c00
	vectorTagB = 0x7c28b7
)

// bucketTag is the tag given to the note at position i of a test tree: the
// two spec vectors at positions 17 and 8500, the edges of the two halves
// around them, and otherwise a spread of values.
func bucketTag(i int) uint32 {
	switch i {
	case 17:
		return vectorTagA
	case 8500:
		return vectorTagB
	case 3:
		return 0x7fffff
	case 4:
		return 0x800000
	case 5:
		return 0
	case 6:
		return 0xffffff
	}
	return uint32(i) * 2654435761 >> 8 & 0xffffff
}

// setTag makes a note start with tag.
func setTag(note *[NoteBytes]byte, tag uint32) {
	note[0], note[1], note[2] = byte(tag>>16), byte(tag>>8), byte(tag)
}

// taggedBlock builds a child of the chain's head appending coin and data
// leaves whose notes start with bucketTag of their position, every seventh
// one a salted commit.
func (c *testChain) taggedBlock(tag byte, coin, data int) *testBlock {
	c.t.Helper()
	b := c.next(c.head(), tag, coin, data)
	for i := range b.records {
		r := &b.records[i]
		setTag(&r.Note, bucketTag(int(r.Position)))
		if r.Position%7 == 0 {
			r.Salt = testSalt(byte(r.Position))
		}
	}
	return b
}

// treeEntries returns the leaves of tree 0 of a kind in the given blocks, in
// position order.
func treeEntries(blocks []*testBlock, kind Kind) []PageEntry {
	var out []PageEntry
	for _, b := range blocks {
		for _, r := range b.records {
			if r.Kind == kind && r.TreeIndex == 0 {
				out = append(out, PageEntry{Leaf: r.Leaf, Note: r.Note, Salt: r.Salt})
			}
		}
	}
	return out
}

// wantBucket picks from the leaves of a tree, by position, those whose tag
// starts with the prefix, reading the tag from the note bytes directly.
func wantBucket(entries []PageEntry, bits, prefix uint32) []BucketEntry {
	out := []BucketEntry{}
	for i, e := range entries {
		tag := uint32(e.Note[0])<<16 | uint32(e.Note[1])<<8 | uint32(e.Note[2])
		if tag>>(24-bits) == prefix {
			out = append(out, BucketEntry{Position: uint32(i), PageEntry: e})
		}
	}
	return out
}

// tagKeys returns the tag index keys of a store.
func tagKeys(t *testing.T, db ethdb.Database) []string {
	t.Helper()
	var out []string
	for k := range historyContents(t, db) {
		if strings.HasPrefix(k, "ghost-tree-tag-") {
			out = append(out, k)
		}
	}
	return out
}

// checkBuckets reads every bucket of tree 0 of both kinds at an anchor and
// compares them with the leaves of the tree.
func checkBuckets(t *testing.T, h *History, anchor common.Hash, want map[Kind][]PageEntry) {
	t.Helper()
	for _, kind := range []Kind{Coin, Data} {
		entries := want[kind]
		bits := BucketBits(uint64(len(entries)))
		total := 0
		for prefix := uint32(0); prefix < 1<<bits; prefix++ {
			got, err := ReadNoteBucket(h, kind, 0, bits, prefix, anchor)
			if err != nil {
				t.Fatalf("%v bucket %d/%d: %v", kind, prefix, bits, err)
			}
			if w := wantBucket(entries, bits, prefix); !reflect.DeepEqual(got.Entries, w) {
				t.Errorf("%v bucket %d/%d: %d entries, want %d", kind, prefix, bits, len(got.Entries), len(w))
			}
			total += len(got.Entries)
		}
		if total != len(entries) {
			t.Errorf("%v: buckets hold %d leaves, the tree %d", kind, total, len(entries))
		}
	}
}

func TestBucketBitsMatchesTheSpecRule(t *testing.T) {
	for _, v := range []struct {
		notes uint64
		bits  uint32
	}{
		{0, 0},              // bucket-rule-0
		{8191, 0},           // bucket-rule-1
		{8192, 1},           // bucket-rule-2
		{1048576, 8},        // bucket-rule-3
		{3650000000, 19},    // bucket-rule-4
		{1099511627776, 24}, // bucket-rule-5
		{4095, 0},
		{4096, 0},
		{16383, 1},
		{16384, 2},
		{1<<36 - 1, 23},
		{1 << 36, 24},
		{^uint64(0), 24},
	} {
		if got := BucketBits(v.notes); got != v.bits {
			t.Errorf("BucketBits(%d) = %d, want %d", v.notes, got, v.bits)
		}
	}
}

func TestNoteBucketReturnsTheTagPrefixInPositionOrder(t *testing.T) {
	c := newTestChain(t)
	c.insert(c.taggedBlock(1, 6000, 5))
	c.insert(c.taggedBlock(2, 3000, 0))
	anchor := c.head().hash()
	coin := treeEntries(c.blocks, Coin)
	if len(coin) != 9000 || BucketBits(9000) != 1 {
		t.Fatalf("%d coin leaves", len(coin))
	}
	checkBuckets(t, c.h, anchor, map[Kind][]PageEntry{Coin: coin, Data: treeEntries(c.blocks, Data)})

	// The two halves at m = 1, each in increasing position order, with the
	// leaf, note and salt as stored.
	low, err := ReadNoteBucket(c.h, Coin, 0, 1, 0, anchor)
	if err != nil {
		t.Fatal(err)
	}
	high, err := ReadNoteBucket(c.h, Coin, 0, 1, 1, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(low.Entries) == 0 || len(high.Entries) == 0 || len(low.Entries)+len(high.Entries) != len(coin) {
		t.Fatalf("halves of %d and %d leaves", len(low.Entries), len(high.Entries))
	}
	found := map[uint32]uint32{}
	salted := 0
	for half, b := range []*NoteBucket{low, high} {
		for i, e := range b.Entries {
			if i > 0 && e.Position <= b.Entries[i-1].Position {
				t.Fatalf("half %d: position %d after %d", half, e.Position, b.Entries[i-1].Position)
			}
			if got := tagNumber(noteTag(&e.Note)) >> 23; got != uint32(half) {
				t.Errorf("half %d: position %d has tag bit %d", half, e.Position, got)
			}
			if !reflect.DeepEqual(e.PageEntry, coin[e.Position]) {
				t.Errorf("half %d: position %d differs from the stored leaf", half, e.Position)
			}
			if e.Salt != nil {
				salted++
			}
			found[e.Position] = uint32(half)
		}
	}
	if salted == 0 {
		t.Error("no salt served")
	}
	for pos, half := range map[uint32]uint32{3: 0, 4: 1, 5: 0, 6: 1, 17: 0, 8500: 0} {
		if got, ok := found[pos]; !ok || got != half {
			t.Errorf("position %d in half %d (%v), want %d", pos, got, ok, half)
		}
	}

	// The spec vectors through the range logic: 4d6c00 is prefix 0x4d at
	// m = 8 and 0x26b60 at m = 19, 7c28b7 is 0x7c and 0x3e145.
	for _, v := range []struct {
		tag, bits, prefix uint32
	}{
		{vectorTagA, 8, 0x4d}, {vectorTagA, 19, 0x26b60}, {vectorTagA, 1, 0}, {vectorTagA, 24, vectorTagA},
		{vectorTagB, 8, 0x7c}, {vectorTagB, 19, 0x3e145}, {vectorTagB, 1, 0}, {vectorTagB, 0, 0},
	} {
		if got := bucketOf(v.tag, v.bits); got != v.prefix {
			t.Errorf("tag %06x at %d bits: prefix %#x, want %#x", v.tag, v.bits, got, v.prefix)
		}
		first, last := tagRange(v.bits, v.prefix)
		if v.tag < first || v.tag > last || last-first+1 != 1<<(24-v.bits) {
			t.Errorf("tag %06x outside the range %06x to %06x of prefix %#x at %d bits", v.tag, first, last, v.prefix, v.bits)
		}
		if v.prefix > 0 {
			if _, prev := tagRange(v.bits, v.prefix-1); prev+1 != first {
				t.Errorf("prefix %#x at %d bits does not follow the one before", v.prefix, v.bits)
			}
		}
	}
	// Bits 8 and 19 are served only on trees of that size: the rule gives
	// them for 1,048,576 and 3,650,000,000 leaves, and this tree refuses
	// them.
	if BucketBits(1048576) != 8 || BucketBits(3650000000) != 19 {
		t.Error("the rule does not give 8 and 19 bits")
	}
	for _, v := range []struct{ bits, prefix uint32 }{{8, 0x4d}, {19, 0x26b60}, {8, 0x7c}, {19, 0x3e145}} {
		if _, err := ReadNoteBucket(c.h, Coin, 0, v.bits, v.prefix, anchor); !errors.Is(err, ErrBucketBits) {
			t.Errorf("%d bits on a tree of 9000 leaves: %v, want %v", v.bits, err, ErrBucketBits)
		}
	}

	// The read follows the tag index: a position whose tag key is gone is
	// not in its bucket.
	tag := noteTag(&coin[17].Note)
	if err := rawdb.DeleteGhostTreeTag(c.db, uint8(Coin), 0, tag, 17); err != nil {
		t.Fatal(err)
	}
	b, err := ReadNoteBucket(c.h, Coin, 0, 1, 0, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) != len(low.Entries)-1 {
		t.Errorf("without its tag key: %d entries, want %d", len(b.Entries), len(low.Entries)-1)
	}
	for _, e := range b.Entries {
		if e.Position == 17 {
			t.Error("position 17 served without its tag key")
		}
	}
	// A tag key under a tag the note does not start with is corrupt.
	if err := rawdb.WriteGhostTreeTag(c.db, uint8(Coin), 0, [TagBytes]byte{0, 0, 1}, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNoteBucket(c.h, Coin, 0, 1, 0, anchor); !errors.Is(err, ErrCorruptHistory) {
		t.Errorf("tag key under another tag: %v, want %v", err, ErrCorruptHistory)
	}
}

func TestNoteBucketIsAsOfTheAnchor(t *testing.T) {
	c := newTestChain(t)
	early := c.taggedBlock(1, 8000, 2)
	c.insert(early)
	late := c.taggedBlock(2, 600, 1)
	c.insert(late)
	if BucketBits(8000) != 0 || BucketBits(8600) != 1 {
		t.Fatal("the chain does not cross 8192 leaves")
	}
	checkBuckets(t, c.h, early.hash(), map[Kind][]PageEntry{Coin: treeEntries(c.blocks[:2], Coin), Data: treeEntries(c.blocks[:2], Data)})
	checkBuckets(t, c.h, late.hash(), map[Kind][]PageEntry{Coin: treeEntries(c.blocks, Coin), Data: treeEntries(c.blocks, Data)})

	// Position 8500 (7c28b7) is appended by the later block.
	has := func(b *NoteBucket, pos uint32) bool {
		for _, e := range b.Entries {
			if e.Position == pos {
				return true
			}
		}
		return false
	}
	at, err := ReadNoteBucket(c.h, Coin, 0, 0, 0, early.hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(at.Entries) != 8000 || has(at, 8500) || !has(at, 17) {
		t.Errorf("at the early anchor: %d entries, position 8500 %v", len(at.Entries), has(at, 8500))
	}
	after, err := ReadNoteBucket(c.h, Coin, 0, 1, 0, late.hash())
	if err != nil {
		t.Fatal(err)
	}
	if !has(after, 8500) || !has(after, 17) {
		t.Error("the later anchor does not serve positions 17 and 8500")
	}
	// The rule uses the leaf count at the anchor.
	if _, err := ReadNoteBucket(c.h, Coin, 0, 1, 0, early.hash()); !errors.Is(err, ErrBucketBits) {
		t.Errorf("the later block's bits at the early anchor: %v, want %v", err, ErrBucketBits)
	}
	if _, err := ReadNoteBucket(c.h, Coin, 0, 0, 0, late.hash()); !errors.Is(err, ErrBucketBits) {
		t.Errorf("the early block's bits at the later anchor: %v, want %v", err, ErrBucketBits)
	}
	// Genesis has an empty tree 0 with one empty bucket.
	if b, err := ReadNoteBucket(c.h, Coin, 0, 0, 0, c.blocks[0].hash()); err != nil || len(b.Entries) != 0 {
		t.Errorf("genesis bucket: %v, %v", b, err)
	}
}

func TestNoteBucketRefusesAnyOtherRequest(t *testing.T) {
	c := newTestChain(t)
	c.insert(c.taggedBlock(1, 9000, 3))
	anchor := c.head().hash()
	side := c.next(c.blocks[0], 9, 1, 0)
	rawdb.WriteHeader(c.db, side.header)
	// A block whose header is known but not applied, on the canonical chain
	// above the history.
	unapplied := c.next(c.head(), 3, 1, 0)
	rawdb.WriteHeader(c.db, unapplied.header)
	rawdb.WriteCanonicalHash(c.db, unapplied.hash(), 2)

	before := historyContents(t, c.db)
	for _, r := range []struct {
		name   string
		kind   Kind
		index  uint64
		bits   uint32
		prefix uint32
		anchor common.Hash
		want   error
	}{
		{"one bit below the rule", Coin, 0, 0, 0, anchor, ErrBucketBits},
		{"one bit above the rule", Coin, 0, 2, 0, anchor, ErrBucketBits},
		{"one bit above the rule, data", Data, 0, 1, 0, anchor, ErrBucketBits},
		{"25 bits", Coin, 0, 25, 0, anchor, ErrBucketBits},
		{"prefix 2^bits", Coin, 0, 1, 2, anchor, ErrBucketPrefix},
		{"prefix 2^24 at 24 bits", Coin, 0, 24, 1 << 24, anchor, ErrBucketPrefix},
		{"prefix at 0 bits", Data, 0, 0, 1, anchor, ErrBucketPrefix},
		{"coin marker kind", CoinMarkers, 0, 0, 0, anchor, ErrUnknownKind},
		{"data marker kind", DataMarkers, 0, 0, 0, anchor, ErrUnknownKind},
		{"unknown kind", Kind(9), 0, 1, 0, anchor, ErrUnknownKind},
		{"unknown anchor", Coin, 0, 1, 0, common.Hash{1}, ErrUnknownAnchor},
		{"non-canonical anchor", Coin, 0, 0, 0, side.hash(), ErrNotCanonical},
		{"anchor not applied", Coin, 0, 1, 0, unapplied.hash(), ErrHistoryNotReady},
		{"tree that does not exist", Coin, 1, 0, 0, anchor, ErrNoTree},
		{"data tree that does not exist", Data, 7, 0, 0, anchor, ErrNoTree},
	} {
		b, err := ReadNoteBucket(c.h, r.kind, r.index, r.bits, r.prefix, r.anchor)
		if !errors.Is(err, r.want) {
			t.Errorf("%s: %v, %v, want %v", r.name, b, err, r.want)
		}
		if !reflect.DeepEqual(before, historyContents(t, c.db)) {
			t.Fatalf("%s: a refused read changed the store", r.name)
		}
	}
	// The rule's own request is served.
	if _, err := ReadNoteBucket(c.h, Coin, 0, 1, 1, anchor); err != nil {
		t.Errorf("the rule's request: %v", err)
	}
}

func TestNoteBucketIndexFollowsRevertAndSync(t *testing.T) {
	// RevertBlock: a reorganisation leaves the tag keys of a store of the
	// new branch alone.
	c := newTestChain(t)
	c.insert(c.taggedBlock(1, 3000, 4))
	c.insert(c.taggedBlock(2, 2000, 1))
	c.insert(c.taggedBlock(3, 10, 5000))
	if n := len(tagKeys(t, c.db)); n != 3000+4+2000+1+10+5000 {
		t.Fatalf("%d tag keys", n)
	}
	c.rewind(1)
	c.insert(c.taggedBlock(4, 7, 9))
	c.insert(c.taggedBlock(5, 0, 0))
	ref := newTestChain(t)
	for _, b := range c.blocks[1:] {
		ref.insert(b)
	}
	if got, want := historyContents(t, c.db), historyContents(t, ref.db); !reflect.DeepEqual(got, want) {
		t.Errorf("after the revert: %d keys, %d tag keys; a store of the branch alone %d and %d", len(got), len(tagKeys(t, c.db)), len(want), len(tagKeys(t, ref.db)))
	}
	if n := len(tagKeys(t, c.db)); n != 3000+4+7+9 {
		t.Errorf("%d tag keys after the revert", n)
	}
	for _, b := range c.blocks {
		n := b.header.Number.Uint64()
		checkBuckets(t, c.h, b.hash(), map[Kind][]PageEntry{Coin: treeEntries(c.blocks[:n+1], Coin), Data: treeEntries(c.blocks[:n+1], Data)})
	}
	c.rewind(0)
	if n := len(tagKeys(t, c.db)); n != 0 {
		t.Errorf("%d tag keys after reverting to genesis", n)
	}

	// Sync: a reorganisation leaves the store of a node that only saw the
	// new branch, and marker records write no tag key.
	s := newSyncChain(t)
	base := s.branch(s.genesis, 1, 2, 30, 4, 10, 3)
	old := s.branch(base[1], 2, 2, 5000, 2, 20, 1)
	s.setHead(old[1])
	fork := s.branch(base[1], 3, 3, 40, 6, 1, 1)
	s.setHead(fork[2])
	sref := newSyncChain(t)
	for _, b := range s.ancestry(fork[2]) {
		sref.add(b)
	}
	sref.setHead(fork[2])
	if got, want := historyContents(t, s.db), historyContents(t, sref.db); !reflect.DeepEqual(got, want) {
		t.Errorf("after the reorganising sync: %d keys, a store of the branch alone %d", len(got), len(want))
	}
	if n := len(tagKeys(t, s.db)); n != 2*(30+4)+3*(40+6) {
		t.Errorf("%d tag keys after the sync, want one per tree leaf", n)
	}
	chain := s.ancestry(fork[2])
	served := map[Kind][]PageEntry{Coin: treeEntries(chain, Coin), Data: treeEntries(chain, Data)}
	checkBuckets(t, s.h, fork[2].hash(), served)

	markers := newSyncChain(t)
	only := markers.branch(markers.genesis, 1, 2, 0, 0, 50, 7)
	markers.setHead(only[1])
	if n := len(tagKeys(t, markers.db)); n != 0 {
		t.Errorf("marker records wrote %d tag keys", n)
	}

	// A store with a head and records but without the marker, as built
	// before the tag index, is not served and is built again by Sync.
	built := historyContents(t, s.db)
	if err := rawdb.DeleteGhostTreeTagged(s.db); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.DeleteGhostTreeTags(s.db, s.db, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n := len(tagKeys(t, s.db)); n != 0 {
		t.Fatalf("%d tag keys left", n)
	}
	if _, err := ReadNoteBucket(s.h, Coin, 0, 0, 0, fork[2].hash()); !errors.Is(err, ErrHistoryNotReady) {
		t.Errorf("history without the tag index: %v, want %v", err, ErrHistoryNotReady)
	}
	s.setHead(fork[2])
	if got := historyContents(t, s.db); !reflect.DeepEqual(got, built) {
		t.Errorf("rebuilt history: %d keys, %d tag keys; want %d", len(got), len(tagKeys(t, s.db)), len(built))
	}
	checkBuckets(t, s.h, fork[2].hash(), served)
	s.checkServed(fork[2])
}
