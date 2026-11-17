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

package ghostpir

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
)

// The indexed trees of decision 0004 are served by PIR, so that a wallet
// proves where its tag sits in a lookup index, and whether its marker is
// spent, without any server learning the tag or the marker:
//
//   - an index database (IndexTable) holds the witness of every used leaf
//     of the tree in ascending key order, record r the r-th leaf, the
//     sentinel at 0: 1,332 bytes for a lookup index, 1,359 for the coin
//     marker set, 1,354 for the data marker set. Every record is the
//     tree's own witness of its leaf and verifies against the anchor
//     header's root of the tree;
//   - a bucket database (IndexBucketTable) of 2^b records, b the bits of
//     IndexBucketBits for the tree's leaf count: record k gives the ranks
//     [start, end) of the leaves whose key starts with the b bits of k.
//
// A wallet looking for the low leaf of a query key q (LookupQueryKey of its
// tag, or its marker) reads the bucket of q, then searches the ranks from
// start - 1 to end by halving, reading one index record a step. The leaf at
// start - 1 is below q and the leaf at end above it, so the search ends at
// the last leaf at or below q: a lookup witness that proves the tag's first
// entry or its absence, or a marker's membership or absence witness. The
// bucket table is not believed; a wrong one only costs the wallet queries,
// because every index record is checked against the header's root.

// IndexBucketRecordSize is a bucket record: the first rank of the bucket and
// the rank after its last, 5 big-endian bytes each.
const IndexBucketRecordSize = 5 + 5

// maxIndexBucketBits bounds the bucket table at 2^24 records.
const maxIndexBucketBits = 24

// ErrIndexBucket is returned for a bucket record that does not decode.
var ErrIndexBucket = errors.New("ghostpir: malformed index bucket record")

// IndexBucketBits is the bits of the bucket table of an indexed tree with
// leaves used leaves, the sentinel included: the least b with 2^b at least
// the leaves past the sentinel, at least 1 and at most 24. A wallet reads it
// from the record count of the bucket table, 2^b.
func IndexBucketBits(leaves int) int {
	n := max(leaves-1, 2)
	return min(bits.Len(uint(n-1)), maxIndexBucketBits)
}

// IndexBucketOf is the bucket of a key in a table of b bits: its first b
// bits.
func IndexBucketOf(b int, key common.Hash) uint32 {
	return binary.BigEndian.Uint32(key[:4]) >> (32 - b)
}

// DecodeIndexBucket reads a bucket record: the ranks [start, end) of the
// leaves of the bucket.
func DecodeIndexBucket(rec []byte) (start, end uint64, err error) {
	if len(rec) != IndexBucketRecordSize {
		return 0, 0, fmt.Errorf("%w: %d bytes", ErrIndexBucket, len(rec))
	}
	start, end = read5(rec[:5]), read5(rec[5:])
	if start == 0 || end < start {
		return 0, 0, fmt.Errorf("%w: ranks %d to %d", ErrIndexBucket, start, end)
	}
	return start, end, nil
}

func put5(dst []byte, v uint64) {
	dst[0], dst[1], dst[2], dst[3], dst[4] = byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func read5(b []byte) uint64 {
	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
}

// IndexSet is the records of one indexed tree as of an anchor.
type IndexSet struct {
	Set       ghosttree.IndexedSet
	Kind      ghosttree.Kind // Coin or Data for a lookup index, CoinMarkers or DataMarkers for a marker set
	Root      common.Hash    // the anchor header's root of the tree
	Witnesses [][]byte       // the witness of every used leaf, by key
	Keys      []common.Hash  // the key of every used leaf, by key
}

// BucketRecords returns the bucket table of the set.
func (s *IndexSet) BucketRecords() [][]byte {
	b := IndexBucketBits(len(s.Keys))
	out := make([][]byte, 1<<b)
	r := uint64(1) // past the sentinel
	for k := range out {
		start := r
		for r < uint64(len(s.Keys)) && IndexBucketOf(b, s.Keys[r]) == uint32(k) {
			r++
		}
		rec := make([]byte, IndexBucketRecordSize)
		put5(rec[:5], start)
		put5(rec[5:], r)
		out[k] = rec
	}
	return out
}

// IndexSetKind is the kind a snapshot entry of an indexed tree carries.
func IndexSetKind(set ghosttree.IndexedSet) ghosttree.Kind {
	switch set {
	case ghosttree.CoinLookupSet:
		return ghosttree.Coin
	case ghosttree.DataLookupSet:
		return ghosttree.Data
	case ghosttree.CoinMarkerSet:
		return ghosttree.CoinMarkers
	}
	return ghosttree.DataMarkers
}

// IndexSetOf is the indexed tree of a snapshot entry's kind.
func IndexSetOf(kind ghosttree.Kind) (ghosttree.IndexedSet, bool) {
	for _, set := range ghosttree.IndexedSets {
		if IndexSetKind(set) == kind {
			return set, true
		}
	}
	return 0, false
}

// IndexHeaderRoot is the anchor header's root of an indexed tree, nil when
// the header has none.
func IndexHeaderRoot(header *types.Header, set ghosttree.IndexedSet) *common.Hash {
	switch set {
	case ghosttree.CoinLookupSet:
		return header.CoinLookupRoot
	case ghosttree.DataLookupSet:
		return header.DataLookupRoot
	case ghosttree.CoinMarkerSet:
		return header.CoinMarkerRoot
	case ghosttree.DataMarkerSet:
		return header.DataMarkerRoot
	}
	return nil
}

// BuildIndexSets reads the four indexed trees from the state after the
// anchor block and checks each against the anchor header's root of it.
func BuildIndexSets(st ghosttree.StateDB, anchor *types.Header) ([]*IndexSet, error) {
	var out []*IndexSet
	for _, set := range ghosttree.IndexedSets {
		want := IndexHeaderRoot(anchor, set)
		if want == nil {
			return nil, fmt.Errorf("%w: block %d has no %v root", ErrSnapshotAnchor, anchor.Number, set)
		}
		ws, keys, root, err := ghosttree.SortedWitnesses(st, set)
		if err != nil {
			return nil, fmt.Errorf("%v: %w", set, err)
		}
		if root != *want {
			return nil, fmt.Errorf("%w: %v root %x at block %d, header %x", ErrSnapshotRoots, set, root, anchor.Number, *want)
		}
		out = append(out, &IndexSet{Set: set, Kind: IndexSetKind(set), Root: root, Witnesses: ws, Keys: keys})
	}
	return out, nil
}
