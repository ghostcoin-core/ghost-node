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

package rawdb

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/ethdb"
)

// The tag index of the commitment tree history: for each leaf of a tree, a
// key made of its level, the first bytes of its note and its position, with
// no value, so that the positions of one tag range in one level are one
// ordered key range. The level of a position is the bucket bits of the tree
// once the position is filled; a level holds positions below about twice the
// leaf count of any tree whose bucket bits are that level, so a read as of an
// anchor visits no level above the anchor's and few positions past it. It is
// kept by core/ghosttree next to the records.

// GhostTreeTagged is a position of a tree with the tag of its note.
type GhostTreeTagged struct {
	Tag      uint32 // the tag as a big-endian number
	Position uint32
}

// WriteGhostTreeTag stores the tag of the note at a position of a tree
// (kind 0 or 1) in its level.
func WriteGhostTreeTag(db ethdb.KeyValueWriter, kind, level uint8, treeIndex uint64, tag [GhostTreeTagBytes]byte, position uint32) error {
	return db.Put(ghostTreeTagKey(kind, level, treeIndex, tag, position), []byte{})
}

// DeleteGhostTreeTag removes the tag of the note at a position of a tree.
func DeleteGhostTreeTag(db ethdb.KeyValueWriter, kind, level uint8, treeIndex uint64, tag [GhostTreeTagBytes]byte, position uint32) error {
	return db.Delete(ghostTreeTagKey(kind, level, treeIndex, tag, position))
}

// ErrGhostTreeTagScan is returned by ScanGhostTreeTagRange when a range holds
// more keys than the scan may read.
var ErrGhostTreeTagScan = errors.New("tag range holds more keys than one read may scan")

// ReadGhostTreeTagRange returns the stored positions below count of one
// level of a tree whose tag lies in first to last, both included, in tag
// order and, within a tag, in position order. Positions at or above count
// are passed over and never kept.
func ReadGhostTreeTagRange(db ethdb.Iteratee, kind, level uint8, treeIndex uint64, first, last uint32, count uint64) ([]GhostTreeTagged, error) {
	var out []GhostTreeTagged
	_, err := ScanGhostTreeTagRange(db, kind, level, treeIndex, first, last, count, -1, func(t GhostTreeTagged) {
		out = append(out, t)
	})
	return out, err
}

// ScanGhostTreeTagRange calls keep, in the order of ReadGhostTreeTagRange,
// for each stored position below count of one level of a tree whose tag
// lies in first to last. It reads at most maxKeys keys of the range (no
// limit when negative), counting the positions passed over, and returns
// ErrGhostTreeTagScan once the range holds more. It returns the number of
// keys read.
func ScanGhostTreeTagRange(db ethdb.Iteratee, kind, level uint8, treeIndex uint64, first, last uint32, count uint64, maxKeys int, keep func(GhostTreeTagged)) (int, error) {
	if first > last || last >= 1<<(8*GhostTreeTagBytes) {
		return 0, fmt.Errorf("tag range %#x to %#x", first, last)
	}
	if count == 0 {
		return 0, nil
	}
	prefix := ghostTreeTagTreeKey(kind, level, treeIndex)
	start := []byte{byte(first >> 16), byte(first >> 8), byte(first)}
	it := db.NewIterator(prefix, start)
	defer it.Release()

	read := 0
	for it.Next() {
		rest := it.Key()[len(prefix):]
		if len(rest) != GhostTreeTagBytes+4 {
			return read, fmt.Errorf("tag key of %d bytes", len(it.Key()))
		}
		tag := uint32(rest[0])<<16 | uint32(rest[1])<<8 | uint32(rest[2])
		if tag > last {
			break
		}
		if maxKeys >= 0 && read >= maxKeys {
			return read, ErrGhostTreeTagScan
		}
		read++
		if position := binary.BigEndian.Uint32(rest[GhostTreeTagBytes:]); uint64(position) < count {
			keep(GhostTreeTagged{Tag: tag, Position: position})
		}
	}
	return read, it.Error()
}

// DeleteGhostTreeTags removes every tag key of every tree, writing to batch
// and passing it to flush after each removal, so a caller can write it out in
// pieces.
func DeleteGhostTreeTags(db ethdb.Iteratee, batch ethdb.KeyValueWriter, flush func() error) error {
	it := db.NewIterator(ghostTreeTagPrefix, nil)
	defer it.Release()
	for it.Next() {
		if err := batch.Delete(it.Key()); err != nil {
			return err
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return it.Error()
}

// ReadGhostTreeTagged reports whether the history keeps the tag index.
func ReadGhostTreeTagged(db ethdb.KeyValueReader) (bool, error) {
	data, err := readOptional(db, ghostTreeTaggedKey)
	if err != nil || data == nil {
		return false, err
	}
	if len(data) != 1 || data[0] != 1 {
		return false, fmt.Errorf("tag index marker %x", data)
	}
	return true, nil
}

// WriteGhostTreeTagged records that the history keeps the tag index.
func WriteGhostTreeTagged(db ethdb.KeyValueWriter) error {
	return db.Put(ghostTreeTaggedKey, []byte{1})
}

// DeleteGhostTreeTagged removes the record that the history keeps the tag
// index.
func DeleteGhostTreeTagged(db ethdb.KeyValueWriter) error {
	return db.Delete(ghostTreeTaggedKey)
}
