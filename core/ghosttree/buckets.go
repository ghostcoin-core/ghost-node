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
	"fmt"
	"math/bits"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
)

// A note bucket is the leaves of one tree, as of an anchor, whose note
// starts with a tag in one bit prefix. The tag is the first TagBytes bytes
// of the note (its nonce), read as a big-endian number; the node never
// derives one, it only reads those bytes. A wallet that knows its tags reads
// its buckets instead of every page. The number of prefix bits is fixed by
// the tree's leaf count at the anchor (BucketBits), so that every bucket
// holds about the same number of notes whatever a wallet asks for.

const (
	// TagBytes is the length of a note's lookup tag.
	TagBytes = rawdb.GhostTreeTagBytes

	// MaxBucketBits is the most prefix bits a bucket has: the whole tag.
	MaxBucketBits = 8 * TagBytes

	// MinBucketNotes is the number of notes a bucket holds at least once a
	// tree has that many.
	MinBucketNotes = 4096
)

var (
	// ErrBucketBits is returned for prefix bits other than those of the
	// tree's leaf count at the anchor.
	ErrBucketBits = errors.New("bucket bits do not match the tree")

	// ErrBucketPrefix is returned for a prefix wider than its bits.
	ErrBucketPrefix = errors.New("bucket prefix beyond its bits")
)

// BucketBits returns the prefix bits of the buckets of a tree of count
// leaves: floor(log2(count / 4096)), clamped to 0 to 24.
func BucketBits(count uint64) uint32 {
	q := count / MinBucketNotes
	if q == 0 {
		return 0
	}
	return min(uint32(bits.Len64(q)-1), MaxBucketBits)
}

// BucketEntry is one leaf of a bucket at its position.
type BucketEntry struct {
	Position uint32
	PageEntry
}

// NoteBucket is the leaves of a bucket in increasing position order.
type NoteBucket struct {
	Entries []BucketEntry
}

// tagLevel is the level of the tag index a position is kept in: the bucket
// bits of the tree once the position is filled. A tree whose bucket bits are
// m has its positions in levels 0 to m, and level m ends below twice its
// leaf count (below 8,192 for m = 0), so a read as of an anchor visits no
// later level and at most about as many positions past the anchor as before
// it, however far the tree has grown since.
func tagLevel(position uint32) uint8 {
	return uint8(BucketBits(uint64(position) + 1))
}

// noteTag returns the tag a note starts with.
func noteTag(note *[NoteBytes]byte) (tag [TagBytes]byte) {
	copy(tag[:], note[:TagBytes])
	return tag
}

// tagNumber is a tag as a big-endian number.
func tagNumber(tag [TagBytes]byte) uint32 {
	return uint32(tag[0])<<16 | uint32(tag[1])<<8 | uint32(tag[2])
}

// bucketOf returns the prefix of a tag with the given bits.
func bucketOf(tag uint32, bits uint32) uint32 {
	return tag >> (MaxBucketBits - bits)
}

// tagRange returns the first and last tag of a bucket.
func tagRange(bits, prefix uint32) (first, last uint32) {
	shift := MaxBucketBits - bits
	return prefix << shift, (prefix+1)<<shift - 1
}

// ReadNoteBucket returns the leaves of tree treeIndex of a kind (Coin or
// Data) as of the anchor block whose note's tag starts with the bits-bit
// prefix, each with its position, leaf, note and salt, in position order. It
// refuses bits other than BucketBits of the tree's leaf count at the anchor
// and a prefix of 2^bits or more. The anchor must be canonical and applied to
// the history, and a tree index other than 0 must have a leaf at it. The
// bucket is not checked against a header root.
func ReadNoteBucket(h *History, kind Kind, treeIndex uint64, bits uint32, prefix uint32, anchor common.Hash) (*NoteBucket, error) {
	if !kind.valid() {
		return nil, ErrUnknownKind
	}
	if bits > MaxBucketBits {
		return nil, fmt.Errorf("%w: %d bits, at most %d", ErrBucketBits, bits, MaxBucketBits)
	}
	if uint64(prefix) >= uint64(1)<<bits {
		return nil, fmt.Errorf("%w: prefix %#x of %d bits", ErrBucketPrefix, prefix, bits)
	}
	if err := h.p.pageable(); err != nil {
		return nil, err
	}
	h.lock.RLock()
	defer h.lock.RUnlock()

	number, _, err := h.canonicalHeader(anchor)
	if err != nil {
		return nil, err
	}
	if err := h.tagged(anchor, number); err != nil {
		return nil, err
	}
	count, err := h.countAt(kind, treeIndex, number)
	if err != nil {
		return nil, err
	}
	if count == 0 && treeIndex > 0 {
		return nil, fmt.Errorf("%w: %v tree %d at block %d", ErrNoTree, kind, treeIndex, number)
	}
	if want := BucketBits(count); bits != want {
		return nil, fmt.Errorf("%w: %d bits, %v tree %d of %d leaves at block %d has %d", ErrBucketBits, bits, kind, treeIndex, count, number, want)
	}
	out := &NoteBucket{Entries: []BucketEntry{}}
	if count == 0 {
		return out, nil
	}
	// The positions below count are in levels 0 to bits; no later level is
	// read, and the positions past the anchor in level bits are passed over.
	first, last := tagRange(bits, prefix)
	var positions []uint32
	for level := uint32(0); level <= bits; level++ {
		tagged, err := rawdb.ReadGhostTreeTagRange(h.db, uint8(kind), uint8(level), treeIndex, first, last, count)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCorruptHistory, err)
		}
		for _, t := range tagged {
			positions = append(positions, t.Position)
		}
	}
	slices.Sort(positions)

	out.Entries = make([]BucketEntry, 0, len(positions))
	for _, pos := range positions {
		rec, err := h.mustRead(slot{kind, treeIndex, pos})
		if err != nil {
			return nil, err
		}
		if t := tagNumber(noteTag(&rec.note)); t < first || t > last {
			return nil, fmt.Errorf("%w: %v tree %d position %d indexed under another tag", ErrCorruptHistory, kind, treeIndex, pos)
		}
		out.Entries = append(out.Entries, BucketEntry{Position: pos, PageEntry: PageEntry{Leaf: rec.leaf, Note: rec.note, Salt: rec.salt}})
	}
	return out, nil
}

// tagged checks that the history holds the anchor at number and keeps the
// tag index: the anchor is applied, and a history with a head has the
// marker of the index.
func (h *History) tagged(anchor common.Hash, number uint64) error {
	enc, err := rawdb.ReadGhostTreeBlock(h.db, anchor)
	if err != nil {
		return err
	}
	if enc == nil {
		return fmt.Errorf("%w: anchor %x not applied", ErrHistoryNotReady, anchor)
	}
	if applied, _, err := decodeBlock(enc); err != nil {
		return err
	} else if applied != number {
		return fmt.Errorf("%w: anchor %x applied at %d", ErrCorruptHistory, anchor, applied)
	}
	_, _, ok, err := h.readHead()
	if err != nil || !ok {
		return err
	}
	if tagged, err := rawdb.ReadGhostTreeTagged(h.db); err != nil {
		return err
	} else if !tagged {
		return fmt.Errorf("%w: history without the tag index", ErrHistoryNotReady)
	}
	return nil
}
