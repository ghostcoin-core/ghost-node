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
	"testing"
)

// floodTag is the one tag a committer gives many notes, to make its bucket
// (prefix 1 at one bucket bit) far larger than the rule's.
const floodTag = 0xabcdef

// floodedBlock builds a child of the chain's head appending coin leaves
// whose notes start with floodTag at two positions in three and with
// bucketTag of their position, below 0x800000, at every third one.
func (c *testChain) floodedBlock(tag byte, coin int) *testBlock {
	c.t.Helper()
	b := c.next(c.head(), tag, coin, 0)
	for i := range b.records {
		r := &b.records[i]
		if r.Position%3 != 0 {
			setTag(&r.Note, floodTag)
		} else {
			setTag(&r.Note, bucketTag(int(r.Position))&0x7fffff)
		}
		if r.Position%7 == 0 {
			r.Salt = testSalt(byte(r.Position))
		}
	}
	return b
}

// readPages reads a bucket in pages of limit entries from position 0,
// following Next, and returns the pages.
func readPages(t *testing.T, h *History, anchor [32]byte, bits, prefix uint32, limit int) []*NoteBucket {
	t.Helper()
	var pages []*NoteBucket
	start := uint32(0)
	for {
		p, err := ReadNoteBucketPage(h, Coin, 0, bits, prefix, anchor, start, limit)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, p)
		if !p.More {
			return pages
		}
		if len(pages) > 1000 {
			t.Fatal("bucket pages never end")
		}
		start = p.Next
	}
}

func TestNoteBucketFarOverTheCapIsPaged(t *testing.T) {
	c := newTestChain(t)
	c.insert(c.floodedBlock(1, 9000))
	anchor := c.head().hash()
	coin := treeEntries(c.blocks, Coin)
	if BucketBits(uint64(len(coin))) != 1 {
		t.Fatalf("%d coin leaves are not one bucket bit", len(coin))
	}
	want := wantBucket(coin, 1, 1)
	const limit = 64
	if len(want) < 50*limit {
		t.Fatalf("flooded bucket of %d entries is not far over the cap of %d", len(want), limit)
	}

	// Every page but the last is full and points past its last entry; the
	// pages together are the whole bucket in position order, each once.
	pages := readPages(t, c.h, anchor, 1, 1, limit)
	var got []BucketEntry
	for i, p := range pages {
		last := i == len(pages)-1
		if !last && (len(p.Entries) != limit || p.Next != p.Entries[limit-1].Position+1) {
			t.Fatalf("page %d: %d entries, next %d", i, len(p.Entries), p.Next)
		}
		if last && (len(p.Entries) == 0 || len(p.Entries) > limit || p.More) {
			t.Fatalf("last page %d: %d entries, more %v", i, len(p.Entries), p.More)
		}
		got = append(got, p.Entries...)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paged bucket of %d entries differs from the %d of the tree", len(got), len(want))
	}

	// A start inside the bucket begins at the first position at or after
	// it; a start past the tree is an empty, final page.
	mid := want[len(want)/2].Position - 1
	p, err := ReadNoteBucketPage(c.h, Coin, 0, 1, 1, anchor, mid, limit)
	if err != nil {
		t.Fatal(err)
	}
	if p.Entries[0].Position != mid+1 {
		t.Fatalf("page from %d starts at %d, want %d", mid, p.Entries[0].Position, mid+1)
	}
	p, err = ReadNoteBucketPage(c.h, Coin, 0, 1, 1, anchor, 1<<32-1, limit)
	if err != nil || len(p.Entries) != 0 || p.More {
		t.Fatalf("page past the tree: %v, %+v", err, p)
	}

	// The default reply cap holds an honest bucket whole.
	if MaxBucketEntries < 2*MinBucketNotes {
		t.Fatalf("reply cap %d below an honest bucket's %d", MaxBucketEntries, 2*MinBucketNotes)
	}
	honest := readPages(t, c.h, anchor, 1, 0, MaxBucketEntries)
	if len(honest) != 1 || !reflect.DeepEqual(honest[0].Entries, wantBucket(coin, 1, 0)) {
		t.Fatalf("honest bucket in %d pages", len(honest))
	}
}

func TestNoteBucketTooLargeToScanIsRefused(t *testing.T) {
	c := newTestChain(t)
	c.insert(c.floodedBlock(1, 9000))
	anchor := c.head().hash()
	coin := treeEntries(c.blocks, Coin)
	honest := len(wantBucket(coin, 1, 0))

	saved := bucketScan
	bucketScan = honest + 100
	defer func() { bucketScan = saved }()

	// The honest half fits the scan; the flooded half does not, and is
	// refused before any record is read, from any start.
	if p, err := ReadNoteBucketPage(c.h, Coin, 0, 1, 0, anchor, 0, 0); err != nil || len(p.Entries) != honest {
		t.Fatalf("honest bucket: %v", err)
	}
	for _, start := range []uint32{0, 8000} {
		if _, err := ReadNoteBucketPage(c.h, Coin, 0, 1, 1, anchor, start, 16); !errors.Is(err, ErrBucketTooLarge) {
			t.Fatalf("flooded bucket from %d: %v, want %v", start, err, ErrBucketTooLarge)
		}
	}
	if _, err := ReadNoteBucket(c.h, Coin, 0, 1, 1, anchor); !errors.Is(err, ErrBucketTooLarge) {
		t.Fatalf("whole flooded bucket: %v, want %v", err, ErrBucketTooLarge)
	}
}
