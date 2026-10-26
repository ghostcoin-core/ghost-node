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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// The spent-marker index of the commitment tree history: for each marker of
// a marker list (kind 2 or 3), the tree index and position of the record that
// spent it, so that the status of a marker is one lookup and never a scan of
// a list. It is kept by core/ghosttree next to the records. The key is 51
// bytes long.

const ghostTreeMarkerValueSize = 8 + 4

// ReadGhostTreeMarker returns the list index and position of the record that
// spent a marker of a list, and false if the index has none.
func ReadGhostTreeMarker(db ethdb.KeyValueReader, kind uint8, marker common.Hash) (uint64, uint32, bool, error) {
	data, err := readOptional(db, ghostTreeMarkerKey(kind, marker))
	if err != nil || data == nil {
		return 0, 0, false, err
	}
	if len(data) != ghostTreeMarkerValueSize {
		return 0, 0, false, fmt.Errorf("marker index entry of %d bytes", len(data))
	}
	return binary.BigEndian.Uint64(data), binary.BigEndian.Uint32(data[8:]), true, nil
}

// WriteGhostTreeMarker stores the list index and position of the record that
// spent a marker.
func WriteGhostTreeMarker(db ethdb.KeyValueWriter, kind uint8, marker common.Hash, index uint64, position uint32) error {
	value := make([]byte, ghostTreeMarkerValueSize)
	binary.BigEndian.PutUint64(value, index)
	binary.BigEndian.PutUint32(value[8:], position)
	return db.Put(ghostTreeMarkerKey(kind, marker), value)
}

// DeleteGhostTreeMarker removes the index entry of a marker.
func DeleteGhostTreeMarker(db ethdb.KeyValueWriter, kind uint8, marker common.Hash) error {
	return db.Delete(ghostTreeMarkerKey(kind, marker))
}

// DeleteGhostTreeMarkers removes every entry of the spent-marker index,
// writing to batch and passing it to flush after each removal, so a caller
// can write it out in pieces.
func DeleteGhostTreeMarkers(db ethdb.Iteratee, batch ethdb.KeyValueWriter, flush func() error) error {
	it := db.NewIterator(ghostTreeMarkerPrefix, nil)
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

// ReadGhostTreeMarked reports whether the history keeps the spent-marker
// index.
func ReadGhostTreeMarked(db ethdb.KeyValueReader) (bool, error) {
	data, err := readOptional(db, ghostTreeMarkedKey)
	if err != nil || data == nil {
		return false, err
	}
	if len(data) != 1 || data[0] != 1 {
		return false, fmt.Errorf("marker index marker %x", data)
	}
	return true, nil
}

// WriteGhostTreeMarked records that the history keeps the spent-marker index.
func WriteGhostTreeMarked(db ethdb.KeyValueWriter) error {
	return db.Put(ghostTreeMarkedKey, []byte{1})
}

// DeleteGhostTreeMarked removes the record that the history keeps the
// spent-marker index.
func DeleteGhostTreeMarked(db ethdb.KeyValueWriter) error {
	return db.Delete(ghostTreeMarkedKey)
}
