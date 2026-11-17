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
)

// The witnesses of an indexed tree in key order serve a private restore: a
// restore server lays them out as a PIR database, record r the witness of
// the r-th used leaf by key (the sentinel at 0), and a wallet searches it
// for the low leaf of its tag or marker without telling the server which
// one. Each record is the very witness LookupLowWitness,
// LookupMembershipWitness, CoinMarkerWitness or MarkerAbsenceWitness would
// give for that leaf, so it verifies against the set's root in the header.

// IndexedSet names one of the four indexed trees of decision 0004.
type IndexedSet uint8

const (
	CoinLookupSet IndexedSet = iota + 1 // the coin lookup index, under coinLookupRoot
	DataLookupSet                       // the data lookup index, under dataLookupRoot
	CoinMarkerSet                       // the coin marker set, under coinMarkerRoot
	DataMarkerSet                       // the data marker set, under dataMarkerRoot
)

// IndexedSets is every indexed tree, in the order a snapshot lists them.
var IndexedSets = []IndexedSet{CoinLookupSet, DataLookupSet, CoinMarkerSet, DataMarkerSet}

func (s IndexedSet) String() string {
	switch s {
	case CoinLookupSet:
		return "coin-lookup"
	case DataLookupSet:
		return "data-lookup"
	case CoinMarkerSet:
		return "coin-marker-set"
	case DataMarkerSet:
		return "data-marker-set"
	}
	return fmt.Sprintf("indexed-set-%d", uint8(s))
}

// ErrUnknownSet is returned for an IndexedSet that names no tree.
var ErrUnknownSet = errors.New("unknown indexed set")

func (s IndexedSet) spec() (*setSpec, error) {
	switch s {
	case CoinLookupSet:
		return coinLookupSpec, nil
	case DataLookupSet:
		return dataLookupSpec, nil
	case CoinMarkerSet:
		return coinMarkerSpec, nil
	case DataMarkerSet:
		return dataMarkerSpec, nil
	}
	return nil, ErrUnknownSet
}

// WitnessSize is the length of every witness of the set: 1,332 bytes for a
// lookup index, 1,359 for the coin marker set, 1,354 for the data marker
// set. Zero for an unknown set.
func (s IndexedSet) WitnessSize() int {
	sp, err := s.spec()
	if err != nil {
		return 0
	}
	return sp.witnessSize()
}

// SetRoot returns the root of the set in the state.
func (s IndexedSet) SetRoot(st StateDB) (common.Hash, error) {
	sp, err := s.spec()
	if err != nil {
		return common.Hash{}, err
	}
	return newISet(sp, st).root(), nil
}

// WitnessKey returns the key of the leaf a witness of the set carries, as a
// 32-byte word that sorts as the set orders its leaves: a marker, or a
// lookup key (the tag, the global position in 5 bytes, then zeros). It
// returns the leaf's position too. ok is false for a witness of another
// length. Nothing is checked against a root.
func (s IndexedSet) WitnessKey(witness []byte) (key common.Hash, position uint64, ok bool) {
	sp, err := s.spec()
	if err != nil || len(witness) != sp.witnessSize() {
		return common.Hash{}, 0, false
	}
	n := sp.fieldsSize()
	return sp.parseFields(witness[:n]).key, read5(witness[n : n+markerIndexSize]), true
}

// LookupQueryKey is the key a wallet searches a lookup index for: the low
// leaf of tag is the last leaf whose key is below it.
func LookupQueryKey(tag LookupTag) common.Hash { return lookupKey(tag, 0) }

// sortedLimit bounds the leaves a sorted read walks, the most an index of
// MarkerSetDepth holds.
const sortedLimit = markerSetCapacity

// SortedWitnesses returns the witness of every used leaf of the set in the
// state, in ascending key order from the sentinel, with the keys and the
// root they fold to. It reads each leaf once and computes every path in
// memory, and fails when the leaves do not link up in ascending order or
// the paths do not reproduce the set's stored root.
func SortedWitnesses(st StateDB, set IndexedSet) (witnesses [][]byte, keys []common.Hash, root common.Hash, err error) {
	if err := Release.Check(); err != nil {
		return nil, nil, common.Hash{}, err
	}
	sp, err := set.spec()
	if err != nil {
		return nil, nil, common.Hash{}, err
	}
	s := newISet(sp, st)
	var count uint64
	if sp.sequential {
		if count, err = s.count(); err != nil {
			return nil, nil, common.Hash{}, err
		}
	}

	// Walk the links from the sentinel: every used leaf, by key.
	var (
		positions []uint64
		leaves    []setLeaf
		seen      = make(map[uint64]struct{})
	)
	pos := uint64(0)
	for {
		if uint64(len(leaves)) >= sortedLimit {
			return nil, nil, common.Hash{}, s.corrupt("more than %d linked leaves", sortedLimit)
		}
		if _, dup := seen[pos]; dup {
			return nil, nil, common.Hash{}, s.corrupt("leaf %d linked twice", pos)
		}
		seen[pos] = struct{}{}
		l, err := s.leaf(pos)
		if err != nil {
			return nil, nil, common.Hash{}, err
		}
		if pos != 0 && l.key == (common.Hash{}) {
			return nil, nil, common.Hash{}, s.corrupt("link to unused leaf %d", pos)
		}
		if n := len(leaves); n > 0 && bytes.Compare(leaves[n-1].key[:], l.key[:]) >= 0 {
			return nil, nil, common.Hash{}, s.corrupt("leaf %d out of key order", pos)
		}
		positions = append(positions, pos)
		leaves = append(leaves, l)
		if l.nextKey == (common.Hash{}) {
			if l.nextIndex != 0 {
				return nil, nil, common.Hash{}, s.corrupt("last leaf %d links to %d", pos, l.nextIndex)
			}
			break
		}
		if sp.sequential && l.nextIndex >= count {
			return nil, nil, common.Hash{}, s.corrupt("leaf %d links past the count %d", pos, count)
		}
		pos = l.nextIndex
	}
	if sp.sequential && uint64(len(leaves)) != count {
		return nil, nil, common.Hash{}, s.corrupt("%d linked leaves, count %d", len(leaves), count)
	}

	// Every level of the tree over the used positions; the rest are the
	// default nodes.
	levels := make([]map[uint64]common.Hash, MarkerSetDepth+1)
	levels[0] = make(map[uint64]common.Hash, len(leaves))
	for i, l := range leaves {
		levels[0][positions[i]] = sp.hashLeaf(l)
	}
	nodeAt := func(level int, i uint64) common.Hash {
		if h, ok := levels[level][i]; ok {
			return h
		}
		return sp.defaultNode(level, i)
	}
	for level := 0; level < MarkerSetDepth; level++ {
		up := make(map[uint64]common.Hash, len(levels[level])/2+1)
		for i := range levels[level] {
			p := i >> 1
			if _, done := up[p]; done {
				continue
			}
			up[p] = sp.hashNode(level, nodeAt(level, p<<1), nodeAt(level, p<<1|1))
		}
		levels[level+1] = up
	}
	root = nodeAt(MarkerSetDepth, 0)
	if stored := s.root(); stored != root {
		return nil, nil, common.Hash{}, s.corrupt("leaves fold to %x, stored root %x", root, stored)
	}

	witnesses = make([][]byte, len(leaves))
	keys = make([]common.Hash, len(leaves))
	for i, l := range leaves {
		w := make([]byte, 0, sp.witnessSize())
		w = append(w, sp.fields(l)...)
		w = append(w, index5(positions[i])...)
		p := positions[i]
		for level := 0; level < MarkerSetDepth; level++ {
			h := nodeAt(level, p^1)
			w = append(w, h[:]...)
			p >>= 1
		}
		witnesses[i], keys[i] = w, l.key
	}
	return witnesses, keys, root, nil
}

// VerifySetWitness reports whether witness is a witness of the set that
// folds to root, and returns the key of its leaf.
func VerifySetWitness(set IndexedSet, root common.Hash, witness []byte) (common.Hash, bool) {
	sp, err := set.spec()
	if err != nil {
		return common.Hash{}, false
	}
	l, _, got, ok := sp.foldWitness(witness)
	if !ok || got != root {
		return common.Hash{}, false
	}
	return l.key, true
}
