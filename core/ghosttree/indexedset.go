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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// An indexed tree is an append-only tree of depth 40 whose used leaves
// (key, nextKey, nextIndex) link their keys in ascending order from the
// sentinel leaf at position 0, whose key is zero. The data and coin
// spent-marker sets (markerset.go) and the coin and data lookup indices
// (lookup.go) are indexed trees; they differ in their hash tags, in what a
// leaf hashes and in how a new leaf finds its position:
//
//   - a marker set takes the next position, its leaf count;
//   - a lookup index takes the position its caller names, the global
//     position of the indexed leaf plus one.
//
// Each lives in the storage of one reserved account, under keys
// K(slotTag, ...), which no other slot of that account can be:
//
//   - 0x00: the leaf count of a marker set, where zero means 1 (the sentinel
//     alone); a lookup index has none;
//   - 0x01, position (5), field (1): a word of a used leaf;
//   - 0x02, level (1), index (5): a node, the leaves at level 0, where zero
//     means the default node: Z_l, except on the path of position 0, whose
//     default is the node over the sentinel leaf;
//   - 0x03: the root reference of an ordered index of the used keys, a
//     crit-bit tree, so that the low leaf of an insert is found in at most
//     256 steps without a scan;
//   - 0x04, id (5), field (1): a word of a crit-bit node.
//
// The empty tree writes no slot, so nothing exists at genesis.

// MarkerSetDepth is the depth of every indexed tree: the spent-marker sets
// and the lookup indices.
const MarkerSetDepth = 40

// markerIndexSize is the width of a nextIndex or a position, big-endian.
const markerIndexSize = 5

// markerSetCapacity is the number of leaf positions, 2^40.
const markerSetCapacity = uint64(1) << MarkerSetDepth

// Kinds of storage keys of an indexed tree.
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
	leafExtra     = 3 // the appended position of a coin marker-set leaf

	critBit   = 0
	critChild = 1 // the children at critChild and critChild+1
)

// The leaf layouts of the indexed trees.
const (
	layoutMarker     = iota // value (32), nextValue (32), nextIndex (5)
	layoutCoinMarker        // value (32), nextValue (32), nextIndex (5), appended (5)
	layoutLookup            // tag (16), position (5), nextTag (16), nextPosition (5), nextIndex (5)
)

// lookupKeySize is the length of a lookup key: the tag and the global
// position. It sits at the front of a 32-byte word, the rest zero.
const lookupKeySize = LookupTagSize + markerIndexSize

func index5(v uint64) []byte {
	return []byte{byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func read5(b []byte) uint64 {
	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
}

// setSpec is one indexed tree: where it lives and how it hashes.
type setSpec struct {
	name       string // for errors
	account    func() common.Address
	slotTag    string
	leafTag    string
	nodeTag    string
	layout     int
	sequential bool   // a marker set: positions in order, with a count
	sentinelX  uint64 // the extra word of the sentinel leaf

	zeros, sentinel []common.Hash // Z_0 to Z_40, and the genesis path of position 0
}

// newSetSpec fills in the default nodes of a spec.
func newSetSpec(sp setSpec) *setSpec {
	sp.zeros = make([]common.Hash, MarkerSetDepth+1)
	sp.sentinel = make([]common.Hash, MarkerSetDepth+1)
	sp.zeros[0], sp.sentinel[0] = EmptyLeaf, sp.hashLeaf(setLeaf{extra: sp.sentinelX})
	for l := 0; l < MarkerSetDepth; l++ {
		sp.zeros[l+1] = sp.hashNode(l, sp.zeros[l], sp.zeros[l])
		sp.sentinel[l+1] = sp.hashNode(l, sp.sentinel[l], sp.zeros[l])
	}
	return &sp
}

// setLeaf is a used leaf. A key is a 32-byte word: a marker, or a lookup
// key (tag and position) followed by zeros.
type setLeaf struct {
	key, nextKey common.Hash
	nextIndex    uint64
	extra        uint64
}

// fields returns the leaf as its hash inputs and its witness carry it.
func (sp *setSpec) fields(l setLeaf) []byte {
	switch sp.layout {
	case layoutLookup:
		b := make([]byte, 0, 2*lookupKeySize+markerIndexSize)
		b = append(b, l.key[:lookupKeySize]...)
		b = append(b, l.nextKey[:lookupKeySize]...)
		return append(b, index5(l.nextIndex)...)
	case layoutCoinMarker:
		b := make([]byte, 0, 64+2*markerIndexSize)
		b = append(b, l.key[:]...)
		b = append(b, l.nextKey[:]...)
		b = append(b, index5(l.nextIndex)...)
		return append(b, index5(l.extra)...)
	}
	b := make([]byte, 0, 64+markerIndexSize)
	b = append(b, l.key[:]...)
	b = append(b, l.nextKey[:]...)
	return append(b, index5(l.nextIndex)...)
}

// fieldsSize is the length of fields.
func (sp *setSpec) fieldsSize() int {
	switch sp.layout {
	case layoutLookup:
		return 2*lookupKeySize + markerIndexSize
	case layoutCoinMarker:
		return 64 + 2*markerIndexSize
	}
	return 64 + markerIndexSize
}

// parseFields reads a leaf from its fields.
func (sp *setSpec) parseFields(b []byte) setLeaf {
	var l setLeaf
	switch sp.layout {
	case layoutLookup:
		copy(l.key[:], b[:lookupKeySize])
		copy(l.nextKey[:], b[lookupKeySize:2*lookupKeySize])
		l.nextIndex = read5(b[2*lookupKeySize:])
	default:
		l.key = common.BytesToHash(b[0:32])
		l.nextKey = common.BytesToHash(b[32:64])
		l.nextIndex = read5(b[64:69])
		if sp.layout == layoutCoinMarker {
			l.extra = read5(b[69:74])
		}
	}
	return l
}

func (sp *setSpec) hashLeaf(l setLeaf) common.Hash {
	return K(sp.leafTag, sp.fields(l))
}

func (sp *setSpec) hashNode(level int, left, right common.Hash) common.Hash {
	return K(sp.nodeTag, []byte{byte(level)}, left[:], right[:])
}

func (sp *setSpec) defaultNode(level int, i uint64) common.Hash {
	if i == 0 {
		return sp.sentinel[level]
	}
	return sp.zeros[level]
}

// witnessSize is the length of a witness of a leaf: its fields, its
// position and the 40 siblings of its path.
func (sp *setSpec) witnessSize() int {
	return sp.fieldsSize() + markerIndexSize + MarkerSetDepth*32
}

// foldWitness reads a witness of the spec's layout and folds its leaf along
// its position with its siblings. ok is false for a witness of another
// length.
func (sp *setSpec) foldWitness(witness []byte) (l setLeaf, pos uint64, root common.Hash, ok bool) {
	if len(witness) != sp.witnessSize() {
		return setLeaf{}, 0, common.Hash{}, false
	}
	n := sp.fieldsSize()
	l = sp.parseFields(witness[:n])
	pos = read5(witness[n : n+markerIndexSize])
	cur := sp.hashLeaf(l)
	sib := witness[n+markerIndexSize:]
	for level := 0; level < MarkerSetDepth; level++ {
		h := common.BytesToHash(sib[32*level : 32*level+32])
		if pos>>level&1 == 1 {
			cur = sp.hashNode(level, h, cur)
		} else {
			cur = sp.hashNode(level, cur, h)
		}
	}
	return l, pos, cur, true
}

// iset reads and writes one indexed tree of one state.
type iset struct {
	sp     *setSpec
	st     StateDB
	writes map[common.Hash]common.Hash // planned writes, read back before the state
	order  []common.Hash
}

func newISet(sp *setSpec, st StateDB) *iset {
	return &iset{sp: sp, st: st, writes: make(map[common.Hash]common.Hash)}
}

func (s *iset) key(kind byte, parts ...[]byte) common.Hash {
	return K(s.sp.slotTag, append([][]byte{{kind}}, parts...)...)
}

func (s *iset) countKey() common.Hash { return s.key(keyCount) }

func (s *iset) leafKey(pos uint64, field byte) common.Hash {
	return s.key(keyLeaf, index5(pos), []byte{field})
}

func (s *iset) nodeKey(level int, i uint64) common.Hash {
	return s.key(keyNode, []byte{byte(level)}, index5(i))
}

func (s *iset) indexRootKey() common.Hash { return s.key(keyIndexRoot) }

func (s *iset) indexNodeKey(id uint64, field byte) common.Hash {
	return s.key(keyIndexNode, index5(id), []byte{field})
}

func (s *iset) get(key common.Hash) common.Hash {
	if v, ok := s.writes[key]; ok {
		return v
	}
	return s.st.GetState(s.sp.account(), key)
}

func (s *iset) set(key, value common.Hash) {
	if _, ok := s.writes[key]; !ok {
		s.order = append(s.order, key)
	}
	s.writes[key] = value
}

// commit writes the planned slots in the order they were first planned.
func (s *iset) commit() {
	if len(s.order) == 0 {
		return
	}
	addr := s.sp.account()
	ensureAccount(s.st, addr)
	for _, key := range s.order {
		s.st.SetState(addr, key, s.writes[key])
	}
}

func (s *iset) corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s %s", ErrCorruptTreeState, s.sp.name, fmt.Sprintf(format, args...))
}

func (s *iset) uint(key common.Hash, what string) (uint64, error) {
	v, ok := readUint(s.get(key))
	if !ok {
		return 0, s.corrupt("%s out of range", what)
	}
	return v, nil
}

// count is the number of used leaves of a marker set, the sentinel
// included.
func (s *iset) count() (uint64, error) {
	n, err := s.uint(s.countKey(), "leaf count")
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 1, nil
	}
	if n == 1 || n > markerSetCapacity {
		return 0, s.corrupt("leaf count %d", n)
	}
	return n, nil
}

// limit is the bound of the positions an index may name: the count of a
// marker set, every position of a lookup index.
func (s *iset) limit() (uint64, error) {
	if s.sp.sequential {
		return s.count()
	}
	return markerSetCapacity, nil
}

func (s *iset) leaf(pos uint64) (setLeaf, error) {
	l := setLeaf{key: s.get(s.leafKey(pos, leafValue)), nextKey: s.get(s.leafKey(pos, leafNextValue))}
	var err error
	if l.nextIndex, err = s.uint(s.leafKey(pos, leafNextIndex), "next index"); err != nil {
		return setLeaf{}, err
	}
	if l.nextIndex >= markerSetCapacity {
		return setLeaf{}, s.corrupt("next index %d", l.nextIndex)
	}
	if s.sp.layout == layoutCoinMarker {
		if pos == 0 {
			l.extra = s.sp.sentinelX
		} else if l.extra, err = s.uint(s.leafKey(pos, leafExtra), "appended position"); err != nil {
			return setLeaf{}, err
		}
	}
	return l, nil
}

// setLeaf plans every word of a new leaf.
func (s *iset) setLeaf(pos uint64, l setLeaf) {
	s.set(s.leafKey(pos, leafValue), l.key)
	s.set(s.leafKey(pos, leafNextValue), l.nextKey)
	s.set(s.leafKey(pos, leafNextIndex), word(l.nextIndex))
	if s.sp.layout == layoutCoinMarker {
		s.set(s.leafKey(pos, leafExtra), word(l.extra))
	}
}

func (s *iset) node(level int, i uint64) common.Hash {
	if h := s.get(s.nodeKey(level, i)); h != (common.Hash{}) {
		return h
	}
	return s.sp.defaultNode(level, i)
}

func (s *iset) root() common.Hash { return s.node(MarkerSetDepth, 0) }

// updatePath plans the leaf hash at pos and the nodes above it.
func (s *iset) updatePath(pos uint64, l setLeaf) {
	cur := s.sp.hashLeaf(l)
	s.set(s.nodeKey(0, pos), cur)
	for level := 0; level < MarkerSetDepth; level++ {
		sib := s.node(level, pos^1)
		if pos&1 == 1 {
			cur = s.sp.hashNode(level, sib, cur)
		} else {
			cur = s.sp.hashNode(level, cur, sib)
		}
		pos >>= 1
		s.set(s.nodeKey(level+1, pos), cur)
	}
}

// siblings returns the 40 siblings of the path of pos.
func (s *iset) siblings(pos uint64) []common.Hash {
	sib := make([]common.Hash, MarkerSetDepth)
	for level := 0; level < MarkerSetDepth; level++ {
		sib[level] = s.node(level, pos^1)
		pos >>= 1
	}
	return sib
}

// witness returns the leaf at pos, its position and its 40 siblings.
func (s *iset) witness(pos uint64) ([]byte, error) {
	l, err := s.leaf(pos)
	if err != nil {
		return nil, err
	}
	w := make([]byte, 0, s.sp.witnessSize())
	w = append(w, s.sp.fields(l)...)
	w = append(w, index5(pos)...)
	for _, h := range s.siblings(pos) {
		w = append(w, h[:]...)
	}
	return w, nil
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

// lowLeaf finds the position of the used leaf with the largest key below
// key, through the crit-bit index of the tree whose positions are below
// limit. With it, it returns the index change an insert of key at position
// at makes; apply plans that change. A key in the tree is ErrMarkerSpent.
func (s *iset) lowLeaf(key common.Hash, limit, at uint64) (low uint64, apply func(), err error) {
	refAt := s.indexRootKey()
	ref, err := s.uint(refAt, "index root")
	if err != nil {
		return 0, nil,err
	}
	// The path the bits of key take, to the leaf that shares most of its
	// prefix.
	var path []critStep
	for ref&1 == 1 {
		id := ref >> 1
		if id == 0 || id >= limit || len(path) == 256 {
			return 0, nil,s.corrupt("index node %d", id)
		}
		crit, err := s.uint(s.indexNodeKey(id, critBit), "index bit")
		if err != nil {
			return 0, nil,err
		}
		if crit > 255 || (len(path) > 0 && crit <= path[len(path)-1].crit) {
			return 0, nil,s.corrupt("index bit %d", crit)
		}
		dir := bitAt(key, crit)
		path = append(path, critStep{id: id, crit: crit, dir: dir, at: refAt})
		refAt = s.indexNodeKey(id, critChild+byte(dir))
		if ref, err = s.uint(refAt, "index child"); err != nil {
			return 0, nil,err
		}
	}
	best := ref >> 1
	if best >= limit {
		return 0, nil,s.corrupt("index leaf %d", best)
	}
	value := s.get(s.leafKey(best, leafValue))
	if value == key {
		return 0, nil, ErrMarkerSpent
	}
	// The first bit where key leaves every key of the tree.
	var d uint64
	for bitAt(value, d) == bitAt(key, d) {
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
		return 0, nil,err
	}
	// Every key in the subtree there agrees with key before bit d and
	// differs at d: below key when key's bit d is 1. Otherwise the low leaf
	// is the largest key left of the last turn right above it.
	if bitAt(key, d) == 1 {
		if low, err = s.maxLeaf(sub, limit); err != nil {
			return 0, nil,err
		}
	} else {
		if low, err = s.leftOfLastRight(path[:k], limit, key); err != nil {
			return 0, nil,err
		}
	}
	// The new node takes the position of the new leaf as its id.
	apply = func() {
		dir := bitAt(key, d)
		s.set(s.indexNodeKey(at, critBit), word(d))
		s.set(s.indexNodeKey(at, critChild+byte(dir)), word(leafRef(at)))
		s.set(s.indexNodeKey(at, critChild+byte(1-dir)), word(sub))
		s.set(subAt, word(nodeRef(at)))
	}
	return low, apply, nil
}

// leftOfLastRight returns the largest key left of the last node of path
// where the search turned right.
func (s *iset) leftOfLastRight(path []critStep, limit uint64, key common.Hash) (uint64, error) {
	j := len(path) - 1
	for j >= 0 && path[j].dir == 0 {
		j--
	}
	if j < 0 {
		return 0, s.corrupt("has no key below %x", key)
	}
	left, err := s.uint(s.indexNodeKey(path[j].id, critChild), "index child")
	if err != nil {
		return 0, err
	}
	return s.maxLeaf(left, limit)
}

// below returns the position of the used leaf with the largest key below
// key, whether or not key is in the tree. It plans nothing.
func (s *iset) below(key common.Hash) (uint64, error) {
	limit, err := s.limit()
	if err != nil {
		return 0, err
	}
	low, _, err := s.lowLeaf(key, limit, 0)
	if err != ErrMarkerSpent {
		return low, err
	}
	// key is in the tree: its predecessor is the largest key left of the
	// last turn right on its path, the path its own bits take.
	refAt := s.indexRootKey()
	ref, err := s.uint(refAt, "index root")
	if err != nil {
		return 0, err
	}
	var path []critStep
	for ref&1 == 1 {
		id := ref >> 1
		if id == 0 || id >= limit || len(path) == 256 {
			return 0, s.corrupt("index node %d", id)
		}
		crit, err := s.uint(s.indexNodeKey(id, critBit), "index bit")
		if err != nil {
			return 0, err
		}
		if crit > 255 {
			return 0, s.corrupt("index bit %d", crit)
		}
		dir := bitAt(key, crit)
		path = append(path, critStep{id: id, crit: crit, dir: dir})
		if ref, err = s.uint(s.indexNodeKey(id, critChild+byte(dir)), "index child"); err != nil {
			return 0, err
		}
	}
	return s.leftOfLastRight(path, limit, key)
}

// maxLeaf returns the position of the largest key under ref.
func (s *iset) maxLeaf(ref, limit uint64) (uint64, error) {
	for steps := 0; ref&1 == 1; steps++ {
		id := ref >> 1
		if id == 0 || id >= limit || steps == 256 {
			return 0, s.corrupt("index node %d", id)
		}
		var err error
		if ref, err = s.uint(s.indexNodeKey(id, critChild+1), "index child"); err != nil {
			return 0, err
		}
	}
	if ref>>1 >= limit {
		return 0, s.corrupt("index leaf %d", ref>>1)
	}
	return ref >> 1, nil
}

// plan plans the insert of key with the extra word at position at: the new
// leaf, the low leaf rewritten to point at it, the count of a marker set,
// both paths and the index. It writes nothing to the state. The key is not
// zero and at is a free position; the callers check both.
func (s *iset) plan(key common.Hash, extra, at uint64) error {
	limit, err := s.limit()
	if err != nil {
		return err
	}
	if s.sp.sequential {
		at = limit
	}
	lowPos, apply, err := s.lowLeaf(key, limit, at)
	if err != nil {
		return err
	}
	low, err := s.leaf(lowPos)
	if err != nil {
		return err
	}
	if bytes.Compare(low.key[:], key[:]) >= 0 || (low.nextKey != (common.Hash{}) && bytes.Compare(key[:], low.nextKey[:]) >= 0) {
		return s.corrupt("low leaf %d does not hold %x", lowPos, key)
	}
	added := setLeaf{key: key, nextKey: low.nextKey, nextIndex: low.nextIndex, extra: extra}
	low.nextKey, low.nextIndex = key, at
	s.setLeaf(at, added)
	s.set(s.leafKey(lowPos, leafNextValue), low.nextKey)
	s.set(s.leafKey(lowPos, leafNextIndex), word(low.nextIndex))
	if s.sp.sequential {
		s.set(s.countKey(), word(at+1))
	}
	s.updatePath(lowPos, low)
	s.updatePath(at, added)
	apply()
	return nil
}
