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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// The header MMR store (core/ghostmmr, docs/trees-and-headers.md) is content
// addressed, so blocks of different forks never share or overwrite an entry:
//
//   - the state of a block, its leaf count and peaks, keyed by the block hash;
//   - the children of an inner node, keyed by the node's own hash.
//
// The values are the encodings of core/ghostmmr; these accessors keep them as
// bytes. Like those of the tree history, they return the database's errors
// instead of logging them, so an unreadable entry never reads as a missing
// one.

// ReadHeaderMMRState returns the stored header MMR state of the block with
// the given hash, nil if none is stored.
func ReadHeaderMMRState(db ethdb.KeyValueReader, hash common.Hash) ([]byte, error) {
	return readOptional(db, headerMMRStateKey(hash))
}

// WriteHeaderMMRState stores the header MMR state of a block.
func WriteHeaderMMRState(db ethdb.KeyValueWriter, hash common.Hash, state []byte) error {
	return db.Put(headerMMRStateKey(hash), state)
}

// DeleteHeaderMMRState removes the header MMR state of a block.
func DeleteHeaderMMRState(db ethdb.KeyValueWriter, hash common.Hash) error {
	return db.Delete(headerMMRStateKey(hash))
}

// ReadHeaderMMRNode returns the stored children of the inner node with the
// given hash, nil if none are stored.
func ReadHeaderMMRNode(db ethdb.KeyValueReader, hash common.Hash) ([]byte, error) {
	return readOptional(db, headerMMRNodeKey(hash))
}

// WriteHeaderMMRNode stores the children of an inner node.
func WriteHeaderMMRNode(db ethdb.KeyValueWriter, hash common.Hash, children []byte) error {
	return db.Put(headerMMRNodeKey(hash), children)
}
