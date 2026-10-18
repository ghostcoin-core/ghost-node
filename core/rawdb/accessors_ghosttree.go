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

// The accessors of the tree-root index return the database's errors instead
// of logging them, as those of the tree history do: an unreadable entry must
// never read as a missing one. The index is kept by core/ghosttree.

// ReadGhostRootIndexHead returns the block whose ancestry the tree-root index
// holds, and false if there is no index.
func ReadGhostRootIndexHead(db ethdb.KeyValueReader) (uint64, common.Hash, bool, error) {
	data, err := readOptional(db, ghostRootIndexHeadKey)
	if err != nil || data == nil {
		return 0, common.Hash{}, false, err
	}
	if len(data) != 8+common.HashLength {
		return 0, common.Hash{}, false, fmt.Errorf("root index head of %d bytes", len(data))
	}
	return binary.BigEndian.Uint64(data), common.BytesToHash(data[8:]), true, nil
}

// WriteGhostRootIndexHead stores the block whose ancestry the tree-root index
// holds.
func WriteGhostRootIndexHead(db ethdb.KeyValueWriter, number uint64, hash common.Hash) error {
	data := make([]byte, 8+common.HashLength)
	binary.BigEndian.PutUint64(data, number)
	copy(data[8:], hash[:])
	return db.Put(ghostRootIndexHeadKey, data)
}

// DeleteGhostRootIndexHead removes the head of the tree-root index, which
// marks the index as not ready.
func DeleteGhostRootIndexHead(db ethdb.KeyValueWriter) error {
	return db.Delete(ghostRootIndexHeadKey)
}

// ReadGhostRootHeight returns the height of the first canonical header that
// carries root as its root of the kind, and false if the index has no entry.
func ReadGhostRootHeight(db ethdb.KeyValueReader, kind uint8, root common.Hash) (uint64, bool, error) {
	data, err := readOptional(db, ghostRootIndexKey(kind, root))
	if err != nil || data == nil {
		return 0, false, err
	}
	if len(data) != 8 {
		return 0, false, fmt.Errorf("root index entry of %d bytes", len(data))
	}
	return binary.BigEndian.Uint64(data), true, nil
}

// WriteGhostRootHeight stores the height of the first canonical header that
// carries root as its root of the kind.
func WriteGhostRootHeight(db ethdb.KeyValueWriter, kind uint8, root common.Hash, number uint64) error {
	return db.Put(ghostRootIndexKey(kind, root), encodeBlockNumber(number))
}

// DeleteGhostRootHeight removes the entry of a root of the kind.
func DeleteGhostRootHeight(db ethdb.KeyValueWriter, kind uint8, root common.Hash) error {
	return db.Delete(ghostRootIndexKey(kind, root))
}

// IterateGhostRootHeights calls fn for every entry of the tree-root index, in
// key order, and stops at the first error.
func IterateGhostRootHeights(db ethdb.Iteratee, fn func(kind uint8, root common.Hash, number uint64) error) error {
	it := db.NewIterator(ghostRootIndexPrefix, nil)
	defer it.Release()

	for it.Next() {
		key, value := it.Key(), it.Value()
		if len(key) != len(ghostRootIndexPrefix)+1+common.HashLength || len(value) != 8 {
			return fmt.Errorf("root index entry with a key of %d bytes and a value of %d bytes", len(key), len(value))
		}
		kind := key[len(ghostRootIndexPrefix)]
		root := common.BytesToHash(key[len(ghostRootIndexPrefix)+1:])
		if err := fn(kind, root, binary.BigEndian.Uint64(value)); err != nil {
			return err
		}
	}
	return it.Error()
}
