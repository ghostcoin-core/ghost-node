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

package ethapi

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// GhostBucketAPI serves the note buckets of the commitment trees in the ghost
// namespace, beside GhostAPI: the leaves of one tree as of an anchor whose
// note's tag starts with a bit prefix.
type GhostBucketAPI struct {
	history *ghosttree.History
}

// NewGhostBucketAPI returns the note bucket reads over a tree history.
func NewGhostBucketAPI(history *ghosttree.History) *GhostBucketAPI {
	return &GhostBucketAPI{history: history}
}

// RPCBucketEntry is one leaf of a bucket at its position. Salt is left out
// for a leaf without one, as in RPCPageEntry.
type RPCBucketEntry struct {
	Position hexutil.Uint64 `json:"position"`
	Leaf     common.Hash    `json:"leaf"`
	Note     hexutil.Bytes  `json:"note"`
	Salt     hexutil.Bytes  `json:"salt,omitempty"`
}

// RPCNoteBucket is one bucket of a tree as of an anchor: its entries in
// position order, and their number.
type RPCNoteBucket struct {
	Kind      TreeKind         `json:"kind"`
	TreeIndex hexutil.Uint64   `json:"treeIndex"`
	Bits      hexutil.Uint64   `json:"bits"`
	Prefix    hexutil.Uint64   `json:"prefix"`
	Count     hexutil.Uint64   `json:"count"`
	Entries   []RPCBucketEntry `json:"entries"`
}

// GetNoteBucket returns the leaves of a tree ("coin" or "data") as of the
// anchor block whose note's tag starts with the bits-bit prefix, each as
// position, leaf, note and salt, in position order. Bits must be those of
// the tree's leaf count at the anchor and the prefix below 2^bits; anything
// else, and a marker kind, is refused. The bucket is not checked against a
// header root.
func (api *GhostBucketAPI) GetNoteBucket(kind TreeKind, treeIndex hexutil.Uint64, bits hexutil.Uint64, prefix hexutil.Uint64, anchorHash common.Hash) (*RPCNoteBucket, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	if bits > ghosttree.MaxBucketBits {
		return nil, fmt.Errorf("%w: %d bits", ghosttree.ErrBucketBits, uint64(bits))
	}
	if prefix >= 1<<bits {
		return nil, fmt.Errorf("%w: prefix %#x of %d bits", ghosttree.ErrBucketPrefix, uint64(prefix), uint64(bits))
	}
	b, err := ghosttree.ReadNoteBucket(api.history, ghosttree.Kind(kind), uint64(treeIndex), uint32(bits), uint32(prefix), anchorHash)
	if err != nil {
		return nil, err
	}
	out := &RPCNoteBucket{
		Kind:      kind,
		TreeIndex: treeIndex,
		Bits:      bits,
		Prefix:    prefix,
		Count:     hexutil.Uint64(len(b.Entries)),
		Entries:   make([]RPCBucketEntry, len(b.Entries)),
	}
	for i, e := range b.Entries {
		out.Entries[i] = RPCBucketEntry{Position: hexutil.Uint64(e.Position), Leaf: e.Leaf, Note: append(hexutil.Bytes(nil), e.Note[:]...)}
		if e.Salt != nil {
			out.Entries[i].Salt = append(hexutil.Bytes(nil), e.Salt[:]...)
		}
	}
	return out, nil
}
