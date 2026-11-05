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

// The spent-marker set trees, indexed trees of depth 40 (indexedset.go):
//
//   - the data marker-set tree of spec 05, section 6, whose used leaves
//     (value, nextValue, nextIndex) link the spent data markers in ascending
//     order from the sentinel leaf (0, 0, 0), in the data marker account;
//   - the coin marker-set tree of decision 0004, whose used leaves (value,
//     nextValue, nextIndex, appended) link the spent coin markers the same
//     way, appended being the global position of the leaf the spending
//     reveal appended, NoGlobalPosition for none; the sentinel is (0, 0, 0,
//     NoGlobalPosition). It lives in the coin marker account.
//
// Both take the next position for each marker, and the genesis set of each
// writes no slot.

// The hash tags of the data marker-set tree, and the tag of its storage
// keys.
const (
	TagMarkerSetLeaf = "ghost/data-marker-set-leaf/v1"
	TagMarkerSetNode = "ghost/data-marker-set-node/v1"
	TagMarkerSetSlot = "ghost/data-marker-set-slot/v1"
)

// The hash tags of the coin marker-set tree, and the tag of its storage
// keys.
const (
	TagCoinMarkerSetLeaf = "ghost/coin-marker-set-leaf/v1"
	TagCoinMarkerSetNode = "ghost/coin-marker-set-node/v1"
	TagCoinMarkerSetSlot = "ghost/coin-marker-set-slot/v1"
)

// MarkerAbsenceWitnessSize is the length of an absence witness of the data
// marker set: the low leaf (32 + 32 + 5), its position (5) and 40 siblings.
const MarkerAbsenceWitnessSize = 32 + 32 + markerIndexSize + markerIndexSize + MarkerSetDepth*32

// CoinMarkerWitnessSize is the length of a witness of the coin marker set:
// the leaf (32 + 32 + 5 + 5), its position (5) and 40 siblings, 1,359 bytes.
const CoinMarkerWitnessSize = 32 + 32 + 3*markerIndexSize + MarkerSetDepth*32

var (
	// ErrZeroMarker is returned for the marker of 32 zero bytes, the
	// sentinel's value, which no reveal may spend.
	ErrZeroMarker = errors.New("zero data marker")

	// ErrMarkerSetFull is returned for an insert into a set whose 2^40
	// positions are all used.
	ErrMarkerSetFull = errors.New("data marker set full")
)

var (
	dataMarkerSpec = newSetSpec(setSpec{
		name:       "data marker set",
		account:    func() common.Address { return ghost.DataMarkerAccount },
		slotTag:    TagMarkerSetSlot,
		leafTag:    TagMarkerSetLeaf,
		nodeTag:    TagMarkerSetNode,
		layout:     layoutMarker,
		sequential: true,
	})
	coinMarkerSpec = newSetSpec(setSpec{
		name:       "coin marker set",
		account:    func() common.Address { return ghost.CoinMarkerAccount },
		slotTag:    TagCoinMarkerSetSlot,
		leafTag:    TagCoinMarkerSetLeaf,
		nodeTag:    TagCoinMarkerSetNode,
		layout:     layoutCoinMarker,
		sequential: true,
		sentinelX:  NoGlobalPosition,
	})
)

// markerSpec is the marker-set tree of a kind.
func markerSpec(kind Kind) *setSpec {
	if kind == Data {
		return dataMarkerSpec
	}
	return coinMarkerSpec
}

func newMarkerSet(st StateDB) *iset { return newISet(dataMarkerSpec, st) }

// planMarker plans the insert of marker into the marker set of a kind, with
// appended the extra word of a coin marker-set leaf. It returns the
// position the marker takes.
func planMarker(s *iset, marker common.Hash, appended uint64) (uint64, error) {
	if marker == (common.Hash{}) {
		return 0, ErrZeroMarker
	}
	n, err := s.count()
	if err != nil {
		return 0, err
	}
	if n == markerSetCapacity {
		return 0, ErrMarkerSetFull
	}
	if s.sp.layout == layoutCoinMarker && appended != NoGlobalPosition && appended > MaxGlobalPosition {
		return 0, fmt.Errorf("%w: appended position %#x", ErrGlobalPosition, appended)
	}
	return n, s.plan(marker, appended, n)
}

// MarkerSetCount returns the number of used leaves of the data marker set,
// the sentinel included: 1 at genesis. A corrupt count reads as 0, which no
// set has.
func MarkerSetCount(st StateDB) uint64 { return markerCount(st, Data) }

// CoinMarkerSetCount is MarkerSetCount for the coin marker set.
func CoinMarkerSetCount(st StateDB) uint64 { return markerCount(st, Coin) }

func markerCount(st StateDB, kind Kind) uint64 {
	n, err := newISet(markerSpec(kind), st).count()
	if err != nil {
		return 0
	}
	return n
}

// MarkerSetLeaf returns the used leaf at position of the data marker set.
func MarkerSetLeaf(st StateDB, position uint64) (value, nextValue common.Hash, nextIndex uint64, err error) {
	l, err := markerLeafAt(st, Data, position)
	return l.key, l.nextKey, l.nextIndex, err
}

// CoinMarkerSetLeaf returns the used leaf at position of the coin marker
// set, with the global position the spending reveal appended.
func CoinMarkerSetLeaf(st StateDB, position uint64) (value, nextValue common.Hash, nextIndex, appended uint64, err error) {
	l, err := markerLeafAt(st, Coin, position)
	return l.key, l.nextKey, l.nextIndex, l.extra, err
}

func markerLeafAt(st StateDB, kind Kind, position uint64) (setLeaf, error) {
	s := newISet(markerSpec(kind), st)
	n, err := s.count()
	if err != nil {
		return setLeaf{}, err
	}
	if position >= n {
		return setLeaf{}, fmt.Errorf("%s position %d not below the leaf count %d", s.sp.name, position, n)
	}
	return s.leaf(position)
}

// MarkerAbsenceWitness returns the 1,354-byte witness that marker is not in
// the data marker set of the state (spec 05, section 6): the low leaf, its
// position and the 40 siblings of its path. The zero marker is
// ErrZeroMarker, a marker in the set ErrMarkerSpent.
func MarkerAbsenceWitness(st StateDB, marker common.Hash) ([]byte, error) {
	return markerAbsenceWitness(st, Data, marker)
}

// CoinMarkerAbsenceWitness is MarkerAbsenceWitness for the coin marker set,
// a witness of CoinMarkerWitnessSize bytes.
func CoinMarkerAbsenceWitness(st StateDB, marker common.Hash) ([]byte, error) {
	return markerAbsenceWitness(st, Coin, marker)
}

func markerAbsenceWitness(st StateDB, kind Kind, marker common.Hash) ([]byte, error) {
	if marker == (common.Hash{}) {
		return nil, ErrZeroMarker
	}
	s := newISet(markerSpec(kind), st)
	n, err := s.count()
	if err != nil {
		return nil, err
	}
	pos, _, err := s.lowLeaf(marker, n, n)
	if err != nil {
		return nil, err
	}
	return s.witness(pos)
}

// CoinMarkerWitness returns the witness of the used leaf at position of the
// coin marker set: the leaf, its position and its 40 siblings.
func CoinMarkerWitness(st StateDB, position uint64) ([]byte, error) {
	s := newISet(coinMarkerSpec, st)
	n, err := s.count()
	if err != nil {
		return nil, err
	}
	if position >= n {
		return nil, fmt.Errorf("coin marker set position %d not below the leaf count %d", position, n)
	}
	return s.witness(position)
}

// VerifyMarkerAbsence reports whether witness shows that marker is not in
// the data marker set whose root is root: it is exactly 1,354 bytes, the
// marker is not zero, the low leaf folded along its position's bits with the
// siblings gives root, the low leaf's value is below marker, and marker is
// below its nextValue or the nextValue is zero. Anything else is false.
func VerifyMarkerAbsence(root, marker common.Hash, witness []byte) bool {
	return verifyMarkerAbsence(dataMarkerSpec, root, marker, witness)
}

// VerifyCoinMarkerAbsence is VerifyMarkerAbsence for the coin marker set and
// its 1,359-byte witness.
func VerifyCoinMarkerAbsence(root, marker common.Hash, witness []byte) bool {
	return verifyMarkerAbsence(coinMarkerSpec, root, marker, witness)
}

func verifyMarkerAbsence(sp *setSpec, root, marker common.Hash, witness []byte) bool {
	if marker == (common.Hash{}) {
		return false
	}
	low, _, got, ok := sp.foldWitness(witness)
	if !ok || got != root {
		return false
	}
	if bytes.Compare(low.key[:], marker[:]) >= 0 {
		return false
	}
	return low.nextKey == (common.Hash{}) || bytes.Compare(marker[:], low.nextKey[:]) < 0
}

// VerifyCoinMarker reports whether witness shows that marker is in the coin
// marker set whose root is root, spent by a reveal that appended the leaf at
// global position appended (NoGlobalPosition for none): the witness is
// exactly 1,359 bytes, its leaf holds marker and appended, and the leaf
// folded along its position gives root. Anything else is false.
func VerifyCoinMarker(root, marker common.Hash, appended uint64, witness []byte) bool {
	if marker == (common.Hash{}) {
		return false
	}
	l, _, got, ok := coinMarkerSpec.foldWitness(witness)
	return ok && got == root && l.key == marker && l.extra == appended
}
