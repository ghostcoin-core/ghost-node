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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// The accessors of the commitment tree history return the database's errors
// instead of logging them: a reader of the history must tell a missing entry
// from an unreadable one. The values are encoded by core/ghosttree.

// readOptional returns the value at key, nil if there is none.
func readOptional(db ethdb.KeyValueReader, key []byte) ([]byte, error) {
	ok, err := db.Has(key)
	if err != nil || !ok {
		return nil, err
	}
	return db.Get(key)
}

// ReadGhostTreeLeaf returns the stored record at a position of a tree, nil if
// the position is not stored.
func ReadGhostTreeLeaf(db ethdb.KeyValueReader, kind uint8, treeIndex uint64, position uint32) ([]byte, error) {
	return readOptional(db, ghostTreeLeafKey(kind, treeIndex, position))
}

// WriteGhostTreeLeaf stores the record at a position of a tree.
func WriteGhostTreeLeaf(db ethdb.KeyValueWriter, kind uint8, treeIndex uint64, position uint32, value []byte) error {
	return db.Put(ghostTreeLeafKey(kind, treeIndex, position), value)
}

// DeleteGhostTreeLeaf removes the record at a position of a tree.
func DeleteGhostTreeLeaf(db ethdb.KeyValueWriter, kind uint8, treeIndex uint64, position uint32) error {
	return db.Delete(ghostTreeLeafKey(kind, treeIndex, position))
}

// ReadGhostTreeBlock returns the list of tree positions a block wrote, nil
// if the block was not applied.
func ReadGhostTreeBlock(db ethdb.KeyValueReader, hash common.Hash) ([]byte, error) {
	return readOptional(db, ghostTreeBlockKey(hash))
}

// WriteGhostTreeBlock stores the list of tree positions a block wrote.
func WriteGhostTreeBlock(db ethdb.KeyValueWriter, hash common.Hash, value []byte) error {
	return db.Put(ghostTreeBlockKey(hash), value)
}

// DeleteGhostTreeBlock removes the list of tree positions a block wrote.
func DeleteGhostTreeBlock(db ethdb.KeyValueWriter, hash common.Hash) error {
	return db.Delete(ghostTreeBlockKey(hash))
}

// ReadGhostTreePageRoot returns the stored root of a full page, and false if
// none is stored.
func ReadGhostTreePageRoot(db ethdb.KeyValueReader, kind uint8, treeIndex uint64, page uint32) (common.Hash, bool, error) {
	data, err := readOptional(db, ghostTreePageRootKey(kind, treeIndex, page))
	if err != nil || data == nil {
		return common.Hash{}, false, err
	}
	if len(data) != common.HashLength {
		return common.Hash{}, false, fmt.Errorf("page root of %d bytes", len(data))
	}
	return common.BytesToHash(data), true, nil
}

// WriteGhostTreePageRoot stores the root of a full page.
func WriteGhostTreePageRoot(db ethdb.KeyValueWriter, kind uint8, treeIndex uint64, page uint32, root common.Hash) error {
	return db.Put(ghostTreePageRootKey(kind, treeIndex, page), root.Bytes())
}

// DeleteGhostTreePageRoot removes the stored root of a page.
func DeleteGhostTreePageRoot(db ethdb.KeyValueWriter, kind uint8, treeIndex uint64, page uint32) error {
	return db.Delete(ghostTreePageRootKey(kind, treeIndex, page))
}
