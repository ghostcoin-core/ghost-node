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
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/ghost"
	"golang.org/x/crypto/sha3"
)

// The lookup indices of decision 0004 (docs/trees-and-headers.md): for each
// of the coin tree and the data tree an indexed tree of depth 40
// (indexedset.go) whose used leaves
//
//	tag (16) | position (5) | nextTag (16) | nextPosition (5) | nextIndex (5)
//
// link the lookup entries in ascending order of (tag, position) from the
// sentinel of 47 zero bytes at index position 0. The entry of the leaf at
// global position g sits at index position g + 1. A leaf whose transaction
// carries no lookup tag has no entry, and its index position stays the
// empty leaf.
//
// The coin lookup index lives in the coin tree account, the data lookup
// index in the data tree account, under keys of their own slot tags.

// LookupTagSize is the length of a lookup tag.
const LookupTagSize = 16

// LookupTag is the lookup tag of a leaf: the first 16 bytes of
// S(TagNoteLookup, k_note, i). The zero tag is the sentinel's and no
// transaction may carry it.
type LookupTag [LookupTagSize]byte

// IsZero reports whether the tag is 16 zero bytes.
func (t LookupTag) IsZero() bool { return t == LookupTag{} }

// The hash tags of the lookup tag and of the two lookup indices.
const (
	TagNoteLookup = "ghost/note-lookup/v1"

	TagCoinLookupLeaf = "ghost/coin-lookup-leaf/v1"
	TagCoinLookupNode = "ghost/coin-lookup-node/v1"
	TagCoinLookupSlot = "ghost/coin-lookup-slot/v1"
	TagDataLookupLeaf = "ghost/data-lookup-leaf/v1"
	TagDataLookupNode = "ghost/data-lookup-node/v1"
	TagDataLookupSlot = "ghost/data-lookup-slot/v1"
)

// LookupWitnessSize is the length of a lookup witness: the leaf (16 + 5 +
// 16 + 5 + 5), its index position (5) and 40 siblings, 1,332 bytes.
const LookupWitnessSize = 2*lookupKeySize + markerIndexSize + markerIndexSize + MarkerSetDepth*32

// Global positions: tree index (1 byte) and position (4 bytes), 5 bytes
// big-endian. The last position of tree 255 is not usable, so that every
// entry's index position g + 1 fits in 40 bits; NoGlobalPosition marks no
// leaf.
const (
	MaxGlobalPosition = uint64(0xfffffffffe)
	NoGlobalPosition  = uint64(0xffffffffff)
)

var (
	// ErrZeroLookupTag is returned for a lookup tag of 16 zero bytes.
	ErrZeroLookupTag = errors.New("zero lookup tag")

	// ErrGlobalPosition is returned for a leaf without a usable global
	// position: a tree index above 255, or the last position of tree 255.
	ErrGlobalPosition = errors.New("leaf has no usable global position")
)

// S is the tagged SHA3-256 hash: FIPS 202 SHA3-256 over the tag's length as
// one byte, the tag's ASCII bytes and the inputs in order.
func S(tag string, inputs ...[]byte) common.Hash {
	h := sha3.New256()
	h.Write([]byte{byte(len(tag))})
	h.Write([]byte(tag))
	for _, in := range inputs {
		h.Write(in)
	}
	var out common.Hash
	h.Sum(out[:0])
	return out
}

// DeriveLookupTag returns the lookup tag of the i-th note of the lookup key
// kNote: the first 16 bytes of S(TagNoteLookup, kNote, i as 8 bytes).
func DeriveLookupTag(kNote common.Hash, i uint64) LookupTag {
	var n [8]byte
	for j := 7; j >= 0; j-- {
		n[j] = byte(i)
		i >>= 8
	}
	h := S(TagNoteLookup, kNote[:], n[:])
	var t LookupTag
	copy(t[:], h[:LookupTagSize])
	return t
}

// GlobalPosition returns the global position of the leaf at position of
// tree treeIndex: the index in the first byte and the position in the next
// four. ErrGlobalPosition for a tree index above 255 and for position
// 2^32 - 1 of tree 255.
func GlobalPosition(treeIndex uint64, position uint32) (uint64, error) {
	if treeIndex > 0xff {
		return 0, fmt.Errorf("%w: tree index %d", ErrGlobalPosition, treeIndex)
	}
	g := treeIndex<<32 | uint64(position)
	if g > MaxGlobalPosition {
		return 0, fmt.Errorf("%w: tree %d, position %d", ErrGlobalPosition, treeIndex, position)
	}
	return g, nil
}

// EncodeGlobalPosition returns g as 5 bytes big-endian.
func EncodeGlobalPosition(g uint64) []byte { return index5(g) }

var (
	coinLookupSpec = newSetSpec(setSpec{
		name:    "coin lookup index",
		account: func() common.Address { return ghost.CoinTreeAccount },
		slotTag: TagCoinLookupSlot,
		leafTag: TagCoinLookupLeaf,
		nodeTag: TagCoinLookupNode,
		layout:  layoutLookup,
	})
	dataLookupSpec = newSetSpec(setSpec{
		name:    "data lookup index",
		account: func() common.Address { return ghost.DataTreeAccount },
		slotTag: TagDataLookupSlot,
		leafTag: TagDataLookupLeaf,
		nodeTag: TagDataLookupNode,
		layout:  layoutLookup,
	})
)

func lookupSpec(kind Kind) *setSpec {
	if kind == Data {
		return dataLookupSpec
	}
	return coinLookupSpec
}

// lookupKey is the key of the entry (tag, g): the tag and g in 5 bytes, then
// zeros.
func lookupKey(tag LookupTag, g uint64) common.Hash {
	var k common.Hash
	copy(k[:LookupTagSize], tag[:])
	copy(k[LookupTagSize:lookupKeySize], index5(g))
	return k
}

// splitLookupKey returns the tag and the global position of a key.
func splitLookupKey(k common.Hash) (LookupTag, uint64) {
	var t LookupTag
	copy(t[:], k[:LookupTagSize])
	return t, read5(k[LookupTagSize:lookupKeySize])
}

// planLookup plans the entry of the leaf at global position g with tag
// into the lookup index of a kind, at index position g + 1. It writes
// nothing to the state.
func planLookup(st StateDB, kind Kind, g uint64, tag LookupTag) (*iset, error) {
	if tag.IsZero() {
		return nil, ErrZeroLookupTag
	}
	if g > MaxGlobalPosition {
		return nil, fmt.Errorf("%w: %#x", ErrGlobalPosition, g)
	}
	s := newISet(lookupSpec(kind), st)
	at := g + 1
	if s.get(s.leafKey(at, leafValue)) != (common.Hash{}) {
		return nil, s.corrupt("index position %d already used", at)
	}
	if err := s.plan(lookupKey(tag, g), 0, at); err != nil {
		return nil, err
	}
	return s, nil
}

// EmptyLookupRoot returns the root of the empty lookup index of a kind, the
// tree of the sentinel alone: decision 0004 vectors coin-lookup-empty and
// data-lookup-empty, the coinLookupRoot and dataLookupRoot of every Ghost
// genesis.
func EmptyLookupRoot(kind Kind) common.Hash {
	return lookupSpec(kind).sentinel[MarkerSetDepth]
}

// LookupRoot returns the root of the lookup index of a kind: its stored root
// node, or EmptyLookupRoot while it has no entry.
func LookupRoot(st StateDB, kind Kind) (common.Hash, error) {
	if err := Release.Check(); err != nil {
		return common.Hash{}, err
	}
	if !kind.valid() {
		return common.Hash{}, ErrUnknownKind
	}
	return newISet(lookupSpec(kind), st).root(), nil
}

// LookupEntry returns the tag of the leaf at global position g of a kind,
// and false when that leaf has no entry.
func LookupEntry(st StateDB, kind Kind, g uint64) (LookupTag, bool, error) {
	if !kind.valid() {
		return LookupTag{}, false, ErrUnknownKind
	}
	if g > MaxGlobalPosition {
		return LookupTag{}, false, fmt.Errorf("%w: %#x", ErrGlobalPosition, g)
	}
	s := newISet(lookupSpec(kind), st)
	k := s.get(s.leafKey(g+1, leafValue))
	if k == (common.Hash{}) {
		return LookupTag{}, false, nil
	}
	tag, pos := splitLookupKey(k)
	if pos != g || tag.IsZero() {
		return LookupTag{}, false, s.corrupt("entry at index position %d holds position %d", g+1, pos)
	}
	return tag, true, nil
}

// LookupLeaf returns the used leaf at an index position of the lookup index
// of a kind: its tag and position, and the tag, position and index position
// of the next entry.
func LookupLeaf(st StateDB, kind Kind, indexPosition uint64) (tag LookupTag, position uint64, nextTag LookupTag, nextPosition, nextIndex uint64, err error) {
	if !kind.valid() {
		return LookupTag{}, 0, LookupTag{}, 0, 0, ErrUnknownKind
	}
	if indexPosition >= markerSetCapacity {
		return LookupTag{}, 0, LookupTag{}, 0, 0, fmt.Errorf("index position %d beyond the index", indexPosition)
	}
	s := newISet(lookupSpec(kind), st)
	l, err := s.leaf(indexPosition)
	if err != nil {
		return LookupTag{}, 0, LookupTag{}, 0, 0, err
	}
	if indexPosition != 0 && l.key == (common.Hash{}) {
		return LookupTag{}, 0, LookupTag{}, 0, 0, fmt.Errorf("index position %d has no entry", indexPosition)
	}
	tag, position = splitLookupKey(l.key)
	nextTag, nextPosition = splitLookupKey(l.nextKey)
	return tag, position, nextTag, nextPosition, l.nextIndex, nil
}

// LookupMembershipWitness returns the 1,332-byte witness of the entry of
// the leaf at global position g of a kind: the entry, its index position
// g + 1 and the 40 siblings of its path. A leaf without an entry is an
// error.
func LookupMembershipWitness(st StateDB, kind Kind, g uint64) ([]byte, error) {
	if _, ok, err := LookupEntry(st, kind, g); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%v leaf at global position %#x has no lookup entry", kind, g)
	}
	return newISet(lookupSpec(kind), st).witness(g + 1)
}

// LookupLowWitness returns the witness of the entry just below every entry
// of tag in the lookup index of a kind: the entry with the largest key
// below (tag, 0), the sentinel for the smallest tag. Its next entry is the
// first entry of tag, which VerifyLookupFirst checks, or an entry of a
// larger tag or none, which VerifyLookupAbsence checks.
func LookupLowWitness(st StateDB, kind Kind, tag LookupTag) ([]byte, error) {
	if !kind.valid() {
		return nil, ErrUnknownKind
	}
	if tag.IsZero() {
		return nil, ErrZeroLookupTag
	}
	s := newISet(lookupSpec(kind), st)
	pos, err := s.below(lookupKey(tag, 0))
	if err != nil {
		return nil, err
	}
	return s.witness(pos)
}

// foldLookup checks a lookup witness against root and returns its leaf;
// ok is false for any other length or root, and for a leaf that does not
// sit at its own index position: the sentinel at 0, the entry of g at
// g + 1.
func foldLookup(kind Kind, root common.Hash, witness []byte) (l setLeaf, ok bool) {
	if !kind.valid() {
		return setLeaf{}, false
	}
	l, pos, got, ok := lookupSpec(kind).foldWitness(witness)
	if !ok || got != root {
		return setLeaf{}, false
	}
	if l.key == (common.Hash{}) {
		return l, pos == 0
	}
	tag, g := splitLookupKey(l.key)
	return l, !tag.IsZero() && g <= MaxGlobalPosition && pos == g+1
}

// VerifyLookupMembership reports whether witness shows that the leaf at
// global position g of a kind has the lookup tag tag in the index whose
// root is root. Anything else, the zero tag included, is false.
func VerifyLookupMembership(kind Kind, root common.Hash, tag LookupTag, g uint64, witness []byte) bool {
	if tag.IsZero() {
		return false
	}
	l, ok := foldLookup(kind, root, witness)
	return ok && l.key == lookupKey(tag, g)
}

// VerifyLookupFirst reports whether witness shows that g is the first
// global position with tag in the index of a kind whose root is root: the
// witness leaf has a smaller tag and its next entry is (tag, g) at index
// position g + 1.
func VerifyLookupFirst(kind Kind, root common.Hash, tag LookupTag, g uint64, witness []byte) bool {
	if tag.IsZero() || g > MaxGlobalPosition {
		return false
	}
	l, ok := foldLookup(kind, root, witness)
	if !ok {
		return false
	}
	low, _ := splitLookupKey(l.key)
	return bytes.Compare(low[:], tag[:]) < 0 && l.nextKey == lookupKey(tag, g) && l.nextIndex == g+1
}

// VerifyLookupAbsence reports whether witness shows that no leaf of a kind
// has tag in the index whose root is root: the witness leaf has a smaller
// tag and its next entry has a larger one, or it is the last entry, whose
// next fields are all zero.
func VerifyLookupAbsence(kind Kind, root common.Hash, tag LookupTag, witness []byte) bool {
	if tag.IsZero() {
		return false
	}
	l, ok := foldLookup(kind, root, witness)
	if !ok {
		return false
	}
	low, _ := splitLookupKey(l.key)
	if bytes.Compare(low[:], tag[:]) >= 0 {
		return false
	}
	if l.nextKey == (common.Hash{}) {
		return l.nextIndex == 0
	}
	next, _ := splitLookupKey(l.nextKey)
	return bytes.Compare(next[:], tag[:]) > 0
}
