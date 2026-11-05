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
	"encoding/binary"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The block lookup digest of decision 0004: K(TagBlockLookupDigest,
// encoding), the encoding being
//
//	coinStart (5) | coinTagCount (4) | coinTags (16 each) |
//	dataStart (5) | dataTagCount (4) | dataTags (16 each) |
//	coinMarkerCount (4) | coinMarkers (32 each) |
//	dataMarkerCount (4) | dataMarkers (32 each)
//
// over the leaves the block appended to each tree, in order from the global
// position coinStart or dataStart, and the markers it spent of each kind, in
// order. A leaf without a lookup entry is listed with 16 zero bytes, a tag
// no transaction may carry, so the i-th tag is always that of the leaf at
// start + i. A list without leaves starts at the position the next leaf of
// the tree would take.
//
// The node reads the lists from the state after the block. Each list keeps
// a record in the account of its tree or set: the height of the last block
// that changed it plus one, and the position the block's first leaf or
// marker took. Append and MarkSpent write it with the first change of a
// block, so a block that changes nothing writes nothing.

// TagBlockLookupDigest is the hash tag of the block lookup digest, and
// TagBlockLookupSlot that of the storage keys of the block records.
const (
	TagBlockLookupDigest = "ghost/block-lookup-digest/v1"
	TagBlockLookupSlot   = "ghost/block-lookup-slot/v1"
)

// The lists of a block and their records.
const (
	listCoinLeaves = iota
	listDataLeaves
	listCoinMarkers
	listDataMarkers
)

// Words of a block record.
const (
	recordHeight = 0 // the height plus one, zero for none
	recordStart  = 1
)

func listAccount(list byte) common.Address {
	switch list {
	case listCoinLeaves:
		return ghost.CoinTreeAccount
	case listDataLeaves:
		return ghost.DataTreeAccount
	case listCoinMarkers:
		return ghost.CoinMarkerAccount
	}
	return ghost.DataMarkerAccount
}

func leafList(kind Kind) byte {
	if kind == Data {
		return listDataLeaves
	}
	return listCoinLeaves
}

func markerList(kind Kind) byte {
	if kind == Data {
		return listDataMarkers
	}
	return listCoinMarkers
}

func recordKey(list, field byte) common.Hash {
	return K(TagBlockLookupSlot, []byte{list, field})
}

// noteBlockStart writes the record of a list with the first change of the
// block at height: start is the position that change takes.
func noteBlockStart(st StateDB, list byte, height, start uint64) {
	addr := listAccount(list)
	if st.GetState(addr, recordKey(list, recordHeight)) == word(height+1) {
		return
	}
	ensureAccount(st, addr)
	st.SetState(addr, recordKey(list, recordHeight), word(height+1))
	st.SetState(addr, recordKey(list, recordStart), word(start))
}

// blockStart returns the start of a list in the block at height, and false
// when the block did not change the list.
func blockStart(st StateDB, list byte, height uint64) (uint64, bool, error) {
	addr := listAccount(list)
	h, ok := readUint(st.GetState(addr, recordKey(list, recordHeight)))
	if !ok {
		return 0, false, fmt.Errorf("%w: block record %d height out of range", ErrCorruptTreeState, list)
	}
	if h == 0 || h-1 != height {
		return 0, false, nil
	}
	start, ok := readUint(st.GetState(addr, recordKey(list, recordStart)))
	if !ok {
		return 0, false, fmt.Errorf("%w: block record %d start out of range", ErrCorruptTreeState, list)
	}
	return start, true, nil
}

// BlockLookup is what the block lookup digest covers.
type BlockLookup struct {
	CoinStart   uint64
	CoinTags    []LookupTag
	DataStart   uint64
	DataTags    []LookupTag
	CoinMarkers []common.Hash
	DataMarkers []common.Hash
}

// Encode returns the encoding of the lists the digest hashes.
func (b *BlockLookup) Encode() []byte {
	out := make([]byte, 0, 26+LookupTagSize*(len(b.CoinTags)+len(b.DataTags))+32*(len(b.CoinMarkers)+len(b.DataMarkers)))
	out = append(out, index5(b.CoinStart)...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.CoinTags)))
	for _, t := range b.CoinTags {
		out = append(out, t[:]...)
	}
	out = append(out, index5(b.DataStart)...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.DataTags)))
	for _, t := range b.DataTags {
		out = append(out, t[:]...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.CoinMarkers)))
	for _, m := range b.CoinMarkers {
		out = append(out, m[:]...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.DataMarkers)))
	for _, m := range b.DataMarkers {
		out = append(out, m[:]...)
	}
	return out
}

// Digest returns the block lookup digest of the lists.
func (b *BlockLookup) Digest() common.Hash {
	return K(TagBlockLookupDigest, b.Encode())
}

// EmptyLookupDigest is the digest of empty lists starting at position 0,
// the lookupDigest of every Ghost genesis.
var EmptyLookupDigest = (&BlockLookup{}).Digest()

// ReadBlockLookup returns the lists of the block at height from the state
// after it.
func ReadBlockLookup(st StateDB, height uint64) (*BlockLookup, error) {
	if err := Release.Check(); err != nil {
		return nil, err
	}
	b := new(BlockLookup)
	var err error
	if b.CoinStart, b.CoinTags, err = blockLeaves(Release, st, Coin, height); err != nil {
		return nil, err
	}
	if b.DataStart, b.DataTags, err = blockLeaves(Release, st, Data, height); err != nil {
		return nil, err
	}
	if b.CoinMarkers, err = blockMarkers(st, Coin, height); err != nil {
		return nil, err
	}
	if b.DataMarkers, err = blockMarkers(st, Data, height); err != nil {
		return nil, err
	}
	return b, nil
}

// LookupDigest returns the block lookup digest of the block at height from
// the state after it.
func LookupDigest(st StateDB, height uint64) (common.Hash, error) {
	b, err := ReadBlockLookup(st, height)
	if err != nil {
		return common.Hash{}, err
	}
	return b.Digest(), nil
}

// blockLeaves returns the start and the tags of the leaves the block at
// height appended to the tree of a kind. A block appends to one tree only,
// as a tree that fills takes no more leaves in its block.
func blockLeaves(p Params, st StateDB, kind Kind, height uint64) (uint64, []LookupTag, error) {
	s, err := load(p, st, kind)
	if err != nil {
		return 0, nil, err
	}
	start, changed, err := blockStart(st, leafList(kind), height)
	if err != nil {
		return 0, nil, err
	}
	if !changed {
		index, pos := s.index, s.count
		if s.count == p.capacity() {
			if s.index == math.MaxUint64 {
				return 0, nil, fmt.Errorf("%w: %v tree", ErrGlobalPosition, kind)
			}
			index, pos = s.index+1, 0
		}
		g, err := GlobalPosition(index, uint32(pos))
		return g, nil, err
	}
	end := s.index<<32 + s.count
	if s.index > 0xff || start>>32 != s.index || start > end {
		return 0, nil, fmt.Errorf("%w: %v block record starts at %#x, tree %d holds %d", ErrCorruptTreeState, kind, start, s.index, s.count)
	}
	tags := make([]LookupTag, 0, end-start)
	for g := start; g < end; g++ {
		tag, _, err := LookupEntry(st, kind, g)
		if err != nil {
			return 0, nil, err
		}
		tags = append(tags, tag)
	}
	return start, tags, nil
}

// blockMarkers returns the markers the block at height spent of a kind, in
// the order it spent them.
func blockMarkers(st StateDB, kind Kind, height uint64) ([]common.Hash, error) {
	start, changed, err := blockStart(st, markerList(kind), height)
	if err != nil || !changed {
		return nil, err
	}
	s := newISet(markerSpec(kind), st)
	n, err := s.count()
	if err != nil {
		return nil, err
	}
	if start == 0 || start > n {
		return nil, fmt.Errorf("%w: %s block record starts at %d of %d", ErrCorruptTreeState, s.sp.name, start, n)
	}
	out := make([]common.Hash, 0, n-start)
	for pos := start; pos < n; pos++ {
		out = append(out, s.get(s.leafKey(pos, leafValue)))
	}
	return out, nil
}
