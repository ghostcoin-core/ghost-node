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
)

// The data marker-set tree of spec 05, section 6: an append-only indexed
// tree of depth 40 whose used leaves (value, nextValue, nextIndex) link the
// spent data markers in ascending order, starting from the sentinel leaf
// (0, 0, 0) at position 0.
//
// It lives in the storage of the data marker account, beside the marker
// slots, under keys K(TagMarkerSetSlot, ...), which no marker (a Keccak
// output used directly as a key) can be:
//
//   - the leaf count, where zero means 1, the genesis set of the sentinel
//     alone;
//   - for each used position the three words value, nextValue and
//     nextIndex;
//   - every node (level, index), the leaves at level 0, where zero means the
//     default node: Z_l, except on the path of position 0, whose default is
//     the node over the sentinel leaf;
//   - an ordered index of the used values, a crit-bit tree, so that the low
//     leaf of an insert is found in at most 256 steps without a scan.
//
// The genesis set writes no slot, so the account does not exist at genesis
// and the genesis state root is unchanged.

// MarkerSetDepth is the depth of the data marker-set tree.
const MarkerSetDepth = 40

// The hash tags of the data marker-set tree, and the tag of its storage
// keys.
const (
	TagMarkerSetLeaf = "ghost/data-marker-set-leaf/v1"
	TagMarkerSetNode = "ghost/data-marker-set-node/v1"
	TagMarkerSetSlot = "ghost/data-marker-set-slot/v1"
)

// MarkerAbsenceWitnessSize is the length of an absence witness: the low
// leaf (32 + 32 + 5), its position (5) and 40 siblings.
const MarkerAbsenceWitnessSize = 32 + 32 + markerIndexSize + markerIndexSize + MarkerSetDepth*32

// markerIndexSize is the width of a nextIndex or a position, big-endian.
const markerIndexSize = 5

// markerSetCapacity is the number of leaf positions, 2^40.
const markerSetCapacity = uint64(1) << MarkerSetDepth

var (
	// ErrZeroMarker is returned for the data marker of 32 zero bytes, the
	// sentinel's value, which no data reveal may spend.
	ErrZeroMarker = errors.New("zero data marker")

	// ErrMarkerSetFull is returned for an insert into a set whose 2^40
	// positions are all used.
	ErrMarkerSetFull = errors.New("data marker set full")
)

// Kinds of storage keys of the set.
const (
	keyCount     = 0
	keyLeaf      = 1
	keyNode      = 2
	keyIndexRoot = 3
	keyIndexNode = 4
)

// Words of a used leaf and of a crit-bit node.
const (
	leafValue     = 0
	leafNextValue = 1
	leafNextIndex = 2

	critBit   = 0
	critChild = 1 // the children at critChild and critChild+1
)

func index5(v uint64) []byte {
	return []byte{byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func read5(b []byte) uint64 {
	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
}

func setKey(kind byte, parts ...[]byte) common.Hash {
	return K(TagMarkerSetSlot, append([][]byte{{kind}}, parts...)...)
}

func countKey() common.Hash                     { return setKey(keyCount) }
func leafKey(pos uint64, field byte) common.Hash { return setKey(keyLeaf, index5(pos), []byte{field}) }
func nodeKey(level int, i uint64) common.Hash    { return setKey(keyNode, []byte{byte(level)}, index5(i)) }
func indexRootKey() common.Hash                  { return setKey(keyIndexRoot) }
func indexNodeKey(id uint64, field byte) common.Hash {
	return setKey(keyIndexNode, index5(id), []byte{field})
}

// markerLeaf is the hash of the leaf (value, nextValue, nextIndex).
func markerLeaf(value, nextValue common.Hash, nextIndex uint64) common.Hash {
	return K(TagMarkerSetLeaf, value[:], nextValue[:], index5(nextIndex))
}

func markerNode(level int, left, right common.Hash) common.Hash {
	return K(TagMarkerSetNode, []byte{byte(level)}, left[:], right[:])
}

// markerZeros are Z_0 to Z_40 of the set, and markerSentinel the nodes of
// the genesis set on the path of position 0, its root last.
var markerZeros, markerSentinel = func() ([]common.Hash, []common.Hash) {
	z := make([]common.Hash, MarkerSetDepth+1)
	s := make([]common.Hash, MarkerSetDepth+1)
	z[0], s[0] = EmptyLeaf, markerLeaf(common.Hash{}, common.Hash{}, 0)
	for l := 0; l < MarkerSetDepth; l++ {
		z[l+1] = markerNode(l, z[l], z[l])
		s[l+1] = markerNode(l, s[l], z[l])
	}
	return z, s
}()

func defaultMarkerNode(level int, i uint64) common.Hash {
	if i == 0 {
		return markerSentinel[level]
	}
	return markerZeros[level]
}

// markerSet reads and writes the set of one state.
type markerSet struct {
	st     StateDB
	writes map[common.Hash]common.Hash // planned writes, read back before the state
	order  []common.Hash
}

func newMarkerSet(st StateDB) *markerSet {
	return &markerSet{st: st, writes: make(map[common.Hash]common.Hash)}
}

func (s *markerSet) get(key common.Hash) common.Hash {
	if v, ok := s.writes[key]; ok {
		return v
	}
	return s.st.GetState(ghost.DataMarkerAccount, key)
}

func (s *markerSet) set(key, value common.Hash) {
	if _, ok := s.writes[key]; !ok {
		s.order = append(s.order, key)
	}
	s.writes[key] = value
}

// commit writes the planned slots in the order they were first planned.
func (s *markerSet) commit() {
	if len(s.order) == 0 {
		return
	}
	ensureAccount(s.st, ghost.DataMarkerAccount)
	for _, key := range s.order {
		s.st.SetState(ghost.DataMarkerAccount, key, s.writes[key])
	}
}

func (s *markerSet) uint(key common.Hash, what string) (uint64, error) {
	v, ok := readUint(s.get(key))
	if !ok {
		return 0, fmt.Errorf("%w: data marker set %s out of range", ErrCorruptTreeState, what)
	}
	return v, nil
}

func (s *markerSet) count() (uint64, error) {
	n, err := s.uint(countKey(), "leaf count")
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 1, nil
	}
	if n == 1 || n > markerSetCapacity {
		return 0, fmt.Errorf("%w: data marker set leaf count %d", ErrCorruptTreeState, n)
	}
	return n, nil
}

type markerSetLeaf struct {
	value, nextValue common.Hash
	nextIndex        uint64
}

func (s *markerSet) leaf(pos uint64) (markerSetLeaf, error) {
	l := markerSetLeaf{value: s.get(leafKey(pos, leafValue)), nextValue: s.get(leafKey(pos, leafNextValue))}
	var err error
	if l.nextIndex, err = s.uint(leafKey(pos, leafNextIndex), "next index"); err != nil {
		return markerSetLeaf{}, err
	}
	if l.nextIndex >= markerSetCapacity {
		return markerSetLeaf{}, fmt.Errorf("%w: data marker set next index %d", ErrCorruptTreeState, l.nextIndex)
	}
	return l, nil
}

func (s *markerSet) setLeaf(pos uint64, l markerSetLeaf) {
	s.set(leafKey(pos, leafValue), l.value)
	s.set(leafKey(pos, leafNextValue), l.nextValue)
	s.set(leafKey(pos, leafNextIndex), word(l.nextIndex))
}

func (s *markerSet) node(level int, i uint64) common.Hash {
	if h := s.get(nodeKey(level, i)); h != (common.Hash{}) {
		return h
	}
	return defaultMarkerNode(level, i)
}

// updatePath writes the leaf hash at pos and the nodes above it.
func (s *markerSet) updatePath(pos uint64, l markerSetLeaf) {
	cur := markerLeaf(l.value, l.nextValue, l.nextIndex)
	s.set(nodeKey(0, pos), cur)
	for level := 0; level < MarkerSetDepth; level++ {
		sib := s.node(level, pos^1)
		if pos&1 == 1 {
			cur = markerNode(level, sib, cur)
		} else {
			cur = markerNode(level, cur, sib)
		}
		pos >>= 1
		s.set(nodeKey(level+1, pos), cur)
	}
}

// siblings returns the 40 siblings of the path of pos.
func (s *markerSet) siblings(pos uint64) []common.Hash {
	sib := make([]common.Hash, MarkerSetDepth)
	for level := 0; level < MarkerSetDepth; level++ {
		sib[level] = s.node(level, pos^1)
		pos >>= 1
	}
	return sib
}

// A reference of the crit-bit index is 2p for the used leaf at position p
// and 2id+1 for the crit-bit node id. The zero word, the root of the
// genesis index, is the sentinel leaf.
func leafRef(pos uint64) uint64 { return pos << 1 }
func nodeRef(id uint64) uint64  { return id<<1 | 1 }

// bitAt is bit k of v, 0 the most significant.
func bitAt(v common.Hash, k uint64) uint64 { return uint64(v[k/8]>>(7-k%8)) & 1 }

// critStep is one crit-bit node on the path a search takes.
type critStep struct {
	id, crit uint64
	dir      uint64      // the child the search took
	at       common.Hash // the key of the reference to this node
}

// lowLeaf finds the position of the used leaf with the largest value below
// marker, through the crit-bit index of the set of count used leaves. With
// it, it returns the index change an insert of marker at position count
// makes; apply plans that change. A marker in the set is ErrMarkerSpent.
func (s *markerSet) lowLeaf(marker common.Hash, count uint64) (low uint64, apply func(), err error) {
	refAt := indexRootKey()
	ref, err := s.uint(refAt, "index root")
	if err != nil {
		return 0, nil, err
	}
	// The path the bits of marker take, to the leaf that shares most of its
	// prefix.
	var path []critStep
	for ref&1 == 1 {
		id := ref >> 1
		if id == 0 || id >= count || len(path) == 256 {
			return 0, nil, fmt.Errorf("%w: data marker set index node %d", ErrCorruptTreeState, id)
		}
		crit, err := s.uint(indexNodeKey(id, critBit), "index bit")
		if err != nil {
			return 0, nil, err
		}
		if crit > 255 || (len(path) > 0 && crit <= path[len(path)-1].crit) {
			return 0, nil, fmt.Errorf("%w: data marker set index bit %d", ErrCorruptTreeState, crit)
		}
		dir := bitAt(marker, crit)
		path = append(path, critStep{id: id, crit: crit, dir: dir, at: refAt})
		refAt = indexNodeKey(id, critChild+byte(dir))
		if ref, err = s.uint(refAt, "index child"); err != nil {
			return 0, nil, err
		}
	}
	best := ref >> 1
	if best >= count {
		return 0, nil, fmt.Errorf("%w: data marker set index leaf %d", ErrCorruptTreeState, best)
	}
	value := s.get(leafKey(best, leafValue))
	if value == marker {
		return 0, nil, ErrMarkerSpent
	}
	// The first bit where marker leaves every value of the set.
	var d uint64
	for bitAt(value, d) == bitAt(marker, d) {
		d++
	}
	// The new node goes above the first node of the path whose bit is
	// below d, or above the leaf.
	k := 0
	for k < len(path) && path[k].crit < d {
		k++
	}
	subAt := refAt
	if k < len(path) {
		subAt = path[k].at
	}
	sub, err := s.uint(subAt, "index reference")
	if err != nil {
		return 0, nil, err
	}
	// Every value in the subtree there agrees with marker before bit d and
	// differs at d: below marker when marker's bit d is 1. Otherwise the low
	// leaf is the largest value left of the last turn right above it.
	if bitAt(marker, d) == 1 {
		if low, err = s.maxLeaf(sub, count); err != nil {
			return 0, nil, err
		}
	} else {
		j := k - 1
		for j >= 0 && path[j].dir == 0 {
			j--
		}
		if j < 0 {
			return 0, nil, fmt.Errorf("%w: data marker set has no value below %x", ErrCorruptTreeState, marker)
		}
		left, err := s.uint(indexNodeKey(path[j].id, critChild), "index child")
		if err != nil {
			return 0, nil, err
		}
		if low, err = s.maxLeaf(left, count); err != nil {
			return 0, nil, err
		}
	}
	// The new node takes the position of the new leaf as its id.
	apply = func() {
		n, dir := count, bitAt(marker, d)
		s.set(indexNodeKey(n, critBit), word(d))
		s.set(indexNodeKey(n, critChild+byte(dir)), word(leafRef(n)))
		s.set(indexNodeKey(n, critChild+byte(1-dir)), word(sub))
		s.set(subAt, word(nodeRef(n)))
	}
	return low, apply, nil
}

// maxLeaf returns the position of the largest value under ref.
func (s *markerSet) maxLeaf(ref, count uint64) (uint64, error) {
	for steps := 0; ref&1 == 1; steps++ {
		id := ref >> 1
		if id == 0 || id >= count || steps == 256 {
			return 0, fmt.Errorf("%w: data marker set index node %d", ErrCorruptTreeState, id)
		}
		var err error
		if ref, err = s.uint(indexNodeKey(id, critChild+1), "index child"); err != nil {
			return 0, err
		}
	}
	if ref>>1 >= count {
		return 0, fmt.Errorf("%w: data marker set index leaf %d", ErrCorruptTreeState, ref>>1)
	}
	return ref >> 1, nil
}

// plan plans the insert of marker: the new leaf at position n, the low
// leaf rewritten to point at it, the count, both paths and the index. It
// writes nothing to the state.
func (s *markerSet) plan(marker common.Hash) error {
	if marker == (common.Hash{}) {
		return ErrZeroMarker
	}
	n, err := s.count()
	if err != nil {
		return err
	}
	if n == markerSetCapacity {
		return ErrMarkerSetFull
	}
	lowPos, apply, err := s.lowLeaf(marker, n)
	if err != nil {
		return err
	}
	low, err := s.leaf(lowPos)
	if err != nil {
		return err
	}
	if bytes.Compare(low.value[:], marker[:]) >= 0 || (low.nextValue != (common.Hash{}) && bytes.Compare(marker[:], low.nextValue[:]) >= 0) {
		return fmt.Errorf("%w: data marker set low leaf %d does not hold %x", ErrCorruptTreeState, lowPos, marker)
	}
	added := markerSetLeaf{value: marker, nextValue: low.nextValue, nextIndex: low.nextIndex}
	low.nextValue, low.nextIndex = marker, n
	s.setLeaf(n, added)
	s.set(leafKey(lowPos, leafNextValue), low.nextValue)
	s.set(leafKey(lowPos, leafNextIndex), word(low.nextIndex))
	s.set(countKey(), word(n+1))
	s.updatePath(lowPos, low)
	s.updatePath(n, added)
	apply()
	return nil
}

// MarkerSetCount returns the number of used leaves of the data marker set,
// the sentinel included: 1 at genesis. A corrupt count reads as 0, which no
// set has.
func MarkerSetCount(st StateDB) uint64 {
	n, err := newMarkerSet(st).count()
	if err != nil {
		return 0
	}
	return n
}

// MarkerSetLeaf returns the used leaf at position of the data marker set.
func MarkerSetLeaf(st StateDB, position uint64) (value, nextValue common.Hash, nextIndex uint64, err error) {
	s := newMarkerSet(st)
	n, err := s.count()
	if err != nil {
		return common.Hash{}, common.Hash{}, 0, err
	}
	if position >= n {
		return common.Hash{}, common.Hash{}, 0, fmt.Errorf("data marker set position %d not below the leaf count %d", position, n)
	}
	l, err := s.leaf(position)
	if err != nil {
		return common.Hash{}, common.Hash{}, 0, err
	}
	return l.value, l.nextValue, l.nextIndex, nil
}

// MarkerAbsenceWitness returns the 1,354-byte witness that marker is not in
// the data marker set of the state (spec 05, section 6): the low leaf, its
// position and the 40 siblings of its path. The zero marker is
// ErrZeroMarker, a marker in the set ErrMarkerSpent.
func MarkerAbsenceWitness(st StateDB, marker common.Hash) ([]byte, error) {
	if marker == (common.Hash{}) {
		return nil, ErrZeroMarker
	}
	s := newMarkerSet(st)
	n, err := s.count()
	if err != nil {
		return nil, err
	}
	pos, _, err := s.lowLeaf(marker, n)
	if err != nil {
		return nil, err
	}
	low, err := s.leaf(pos)
	if err != nil {
		return nil, err
	}
	w := make([]byte, 0, MarkerAbsenceWitnessSize)
	w = append(w, low.value[:]...)
	w = append(w, low.nextValue[:]...)
	w = append(w, index5(low.nextIndex)...)
	w = append(w, index5(pos)...)
	for _, h := range s.siblings(pos) {
		w = append(w, h[:]...)
	}
	return w, nil
}

// VerifyMarkerAbsence reports whether witness shows that marker is not in
// the data marker set whose root is root: it is exactly 1,354 bytes, the
// marker is not zero, the low leaf folded along its position's bits with the
// siblings gives root, the low leaf's value is below marker, and marker is
// below its nextValue or the nextValue is zero. Anything else is false.
func VerifyMarkerAbsence(root, marker common.Hash, witness []byte) bool {
	if len(witness) != MarkerAbsenceWitnessSize || marker == (common.Hash{}) {
		return false
	}
	value := common.BytesToHash(witness[0:32])
	nextValue := common.BytesToHash(witness[32:64])
	nextIndex := read5(witness[64:69])
	pos := read5(witness[69:74])
	cur := markerLeaf(value, nextValue, nextIndex)
	sib := witness[74:]
	for level := 0; level < MarkerSetDepth; level++ {
		h := common.BytesToHash(sib[32*level : 32*level+32])
		if pos>>level&1 == 1 {
			cur = markerNode(level, h, cur)
		} else {
			cur = markerNode(level, cur, h)
		}
	}
	if cur != root {
		return false
	}
	if bytes.Compare(value[:], marker[:]) >= 0 {
		return false
	}
	return nextValue == (common.Hash{}) || bytes.Compare(marker[:], nextValue[:]) < 0
}
