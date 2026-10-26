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
	"encoding/hex"
	"errors"
	"math/rand"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// refSet is a reference model of the data marker set, written from spec 05,
// section 6 alone: a sorted slice of the values, the leaves in position
// order, and a sparse in-memory tree that holds every node it has computed,
// a missing node being the empty subtree Z_l.
type refSet struct {
	sorted []common.Hash
	pos    map[common.Hash]uint64
	leaves []refLeaf
	nodes  map[[2]uint64]common.Hash
	zeros  []common.Hash
}

type refLeaf struct {
	value, nextValue common.Hash
	nextIndex        uint64
}

func refHash(tag string, in ...[]byte) common.Hash {
	data := append([][]byte{{byte(len(tag))}, []byte(tag)}, in...)
	return crypto.Keccak256Hash(data...)
}

func refIndex(v uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b[3:]
}

func refLeafHash(l refLeaf) common.Hash {
	return refHash("ghost/data-marker-set-leaf/v1", l.value[:], l.nextValue[:], refIndex(l.nextIndex))
}

func refNode(level int, a, b common.Hash) common.Hash {
	return refHash("ghost/data-marker-set-node/v1", []byte{byte(level)}, a[:], b[:])
}

func newRefSet() *refSet {
	r := &refSet{pos: map[common.Hash]uint64{}, nodes: map[[2]uint64]common.Hash{}}
	z := refHash("ghost/empty-leaf/v1")
	for l := 0; l <= 40; l++ {
		r.zeros = append(r.zeros, z)
		z = refNode(l, z, z)
	}
	r.sorted = []common.Hash{{}}
	r.pos[common.Hash{}] = 0
	r.leaves = []refLeaf{{}}
	r.write(0)
	return r
}

func (r *refSet) get(level int, i uint64) common.Hash {
	if h, ok := r.nodes[[2]uint64{uint64(level), i}]; ok {
		return h
	}
	return r.zeros[level]
}

// write recomputes the path of the leaf at p.
func (r *refSet) write(p uint64) {
	cur := refLeafHash(r.leaves[p])
	r.nodes[[2]uint64{0, p}] = cur
	for l := 0; l < 40; l++ {
		if p%2 == 1 {
			cur = refNode(l, r.get(l, p-1), cur)
		} else {
			cur = refNode(l, cur, r.get(l, p+1))
		}
		p /= 2
		r.nodes[[2]uint64{uint64(l + 1), p}] = cur
	}
}

func (r *refSet) root() common.Hash { return r.get(40, 0) }

// lowOf returns the position of the largest value below m.
func (r *refSet) lowOf(m common.Hash) uint64 {
	i := sort.Search(len(r.sorted), func(i int) bool { return bytes.Compare(r.sorted[i][:], m[:]) >= 0 })
	return r.pos[r.sorted[i-1]]
}

// insert adds m and returns the position of its low leaf.
func (r *refSet) insert(m common.Hash) uint64 {
	low := r.lowOf(m)
	n := uint64(len(r.leaves))
	r.leaves = append(r.leaves, refLeaf{m, r.leaves[low].nextValue, r.leaves[low].nextIndex})
	r.leaves[low].nextValue, r.leaves[low].nextIndex = m, n
	r.write(low)
	r.write(n)
	i := sort.Search(len(r.sorted), func(i int) bool { return bytes.Compare(r.sorted[i][:], m[:]) >= 0 })
	r.sorted = append(r.sorted, common.Hash{})
	copy(r.sorted[i+1:], r.sorted[i:])
	r.sorted[i] = m
	r.pos[m] = n
	return low
}

func (r *refSet) has(m common.Hash) bool {
	_, ok := r.pos[m]
	return ok
}

func markData(t *testing.T, st StateDB, m common.Hash) {
	t.Helper()
	if err := MarkSpent(st, Data, m); err != nil {
		t.Fatalf("marking %x: %v", m, err)
	}
}

func checkLeaf(t *testing.T, st StateDB, pos uint64, want refLeaf) {
	t.Helper()
	v, nv, ni, err := MarkerSetLeaf(st, pos)
	if err != nil {
		t.Fatalf("leaf %d: %v", pos, err)
	}
	if v != want.value || nv != want.nextValue || ni != want.nextIndex {
		t.Fatalf("leaf %d is (%x, %x, %d), want (%x, %x, %d)", pos, v, nv, ni, want.value, want.nextValue, want.nextIndex)
	}
}

func markerRoot(t *testing.T, st StateDB) common.Hash {
	t.Helper()
	root, err := DataMarkerRoot(st)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

var (
	vectorMarker1 = common.HexToHash("c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b")
	vectorMarker2 = common.HexToHash("40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8")
	vectorRoot1   = common.HexToHash("7ae4f1311ba5ecc3ca3b0c0bbef0e4882aea294a01756ee6cd469ce3e596d0d4")
	vectorRoot2   = common.HexToHash("f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f")
)

func TestMarkerSetGenesisIsEmpty(t *testing.T) {
	st := newState(t)
	if st.Exist(ghost.DataMarkerAccount) {
		t.Fatal("a fresh state has the data marker account")
	}
	if n := MarkerSetCount(st); n != 1 {
		t.Errorf("count %d, want 1", n)
	}
	if got := markerRoot(t, st); got != EmptyMarkerSetRoot {
		t.Errorf("root %x, want %x", got, EmptyMarkerSetRoot)
	}
	if got := newRefSet().root(); got != EmptyMarkerSetRoot {
		t.Errorf("the reference empty root %x, want %x", got, EmptyMarkerSetRoot)
	}
	checkLeaf(t, st, 0, refLeaf{})
	if _, _, _, err := MarkerSetLeaf(st, 1); err == nil {
		t.Error("leaf 1 of the genesis set reads")
	}
	if st.Exist(ghost.DataMarkerAccount) || st.IntermediateRoot(true) != types.EmptyRootHash {
		t.Error("reading the genesis set changed the state")
	}
}

func TestMarkerSetMatchesTheSpecVectors(t *testing.T) {
	st := newState(t)
	markData(t, st, vectorMarker1)
	if n := MarkerSetCount(st); n != 2 {
		t.Errorf("count after one marker %d, want 2", n)
	}
	if got := markerRoot(t, st); got != vectorRoot1 {
		t.Errorf("root after one marker %x, want %x", got, vectorRoot1)
	}
	checkLeaf(t, st, 0, refLeaf{common.Hash{}, vectorMarker1, 1})
	checkLeaf(t, st, 1, refLeaf{vectorMarker1, common.Hash{}, 0})

	// The second marker is smaller: the sentinel is the low leaf.
	markData(t, st, vectorMarker2)
	if n := MarkerSetCount(st); n != 3 {
		t.Errorf("count after two markers %d, want 3", n)
	}
	if got := markerRoot(t, st); got != vectorRoot2 {
		t.Errorf("root after two markers %x, want %x", got, vectorRoot2)
	}
	checkLeaf(t, st, 0, refLeaf{common.Hash{}, vectorMarker2, 2})
	checkLeaf(t, st, 1, refLeaf{vectorMarker1, common.Hash{}, 0})
	checkLeaf(t, st, 2, refLeaf{vectorMarker2, vectorMarker1, 1})
}

func TestMarkerSetAbsenceWitnessVector(t *testing.T) {
	st := newState(t)
	markData(t, st, vectorMarker1)
	markData(t, st, vectorMarker2)
	marker := common.HexToHash("8888888888888888888888888888888888888888888888888888888888888888")
	w, err := MarkerAbsenceWitness(st, marker)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 1354 {
		t.Fatalf("witness of %d bytes", len(w))
	}
	head := "40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8" +
		"c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b" + "0000000001" + "0000000002"
	if got := hex.EncodeToString(w[:74]); got != head {
		t.Errorf("witness begins %s, want %s", got, head)
	}
	if got, want := crypto.Keccak256Hash(w), common.HexToHash("e0019752573b22d754bbbfae50852f927e5b42cfd92711bcdab824f6c9612b44"); got != want {
		t.Errorf("witness hash %x, want %x", got, want)
	}
	if !VerifyMarkerAbsence(vectorRoot2, marker, w) {
		t.Fatal("the vector witness does not verify")
	}
	for name, m := range map[string]common.Hash{
		"equal to the low leaf":      vectorMarker2,
		"below the low leaf":         common.HexToHash("1111111111111111111111111111111111111111111111111111111111111111"),
		"above the non-zero next":    common.HexToHash("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
		"the zero marker":            {},
		"equal to the next value":    vectorMarker1,
		"one above the next value":   common.HexToHash("c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3c"),
		"the largest value there is": common.HexToHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	} {
		if VerifyMarkerAbsence(vectorRoot2, m, w) {
			t.Errorf("marker %s (%x) verifies", name, m)
		}
	}
	if !VerifyMarkerAbsence(vectorRoot2, common.HexToHash("40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc9"), w) {
		t.Error("the marker one above the low leaf does not verify")
	}
	if VerifyMarkerAbsence(vectorRoot1, marker, w) || VerifyMarkerAbsence(EmptyMarkerSetRoot, marker, w) {
		t.Error("the witness verifies against another root")
	}
	if VerifyMarkerAbsence(vectorRoot2, marker, w[:len(w)-1]) || VerifyMarkerAbsence(vectorRoot2, marker, append(common.CopyBytes(w), 0)) {
		t.Error("a witness one byte short or long verifies")
	}
	for i := range w {
		bad := common.CopyBytes(w)
		bad[i] ^= 0x01
		if VerifyMarkerAbsence(vectorRoot2, marker, bad) {
			t.Errorf("a witness with byte %d flipped verifies", i)
		}
	}
	for _, m := range []common.Hash{vectorMarker1, vectorMarker2} {
		if _, err := MarkerAbsenceWitness(st, m); !errors.Is(err, ErrMarkerSpent) {
			t.Errorf("witness for %x in the set: %v, want %v", m, err, ErrMarkerSpent)
		}
	}
	if _, err := MarkerAbsenceWitness(st, common.Hash{}); !errors.Is(err, ErrZeroMarker) {
		t.Errorf("witness for the zero marker: %v, want %v", err, ErrZeroMarker)
	}
}

// referenceMarkers returns n distinct non-zero markers from a fixed seed:
// random ones, ascending and descending runs, groups sharing 250 leading
// bits, and the smallest and largest values.
func referenceMarkers(n int) []common.Hash {
	rng := rand.New(rand.NewSource(3607))
	seen := map[common.Hash]bool{{}: true}
	var out []common.Hash
	add := func(m common.Hash) {
		if !seen[m] && len(out) < n {
			seen[m] = true
			out = append(out, m)
		}
	}
	random := func() common.Hash {
		var h common.Hash
		rng.Read(h[:])
		return h
	}
	add(common.Hash{31: 1})
	add(common.HexToHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
	for len(out) < n {
		switch rng.Intn(4) {
		case 0:
			add(random())
		case 1: // ascending run
			base := random()
			for i := 0; i < 40; i++ {
				base[31]++
				add(base)
			}
		case 2: // descending run
			base := random()
			for i := 0; i < 40; i++ {
				base[30]--
				add(base)
			}
		case 3: // sharing the top 250 bits, in random order
			base := random()
			for _, i := range rng.Perm(64) {
				m := base
				m[31] = m[31]&0xc0 | byte(i)
				add(m)
			}
		}
	}
	return out
}

func TestMarkerSetMatchesReferenceModel(t *testing.T) {
	st := newState(t)
	ref := newRefSet()
	markers := referenceMarkers(3000)
	if len(markers) != 3000 {
		t.Fatalf("%d markers", len(markers))
	}
	for i, m := range markers {
		markData(t, st, m)
		low := ref.insert(m)
		n := uint64(len(ref.leaves) - 1)
		checkLeaf(t, st, n, ref.leaves[n])
		checkLeaf(t, st, low, ref.leaves[low])
		if (i+1)%250 == 0 {
			if got, want := markerRoot(t, st), ref.root(); got != want {
				t.Fatalf("after %d inserts: root %x, reference %x", i+1, got, want)
			}
			if got := MarkerSetCount(st); got != uint64(len(ref.leaves)) {
				t.Fatalf("after %d inserts: count %d, reference %d", i+1, got, len(ref.leaves))
			}
		}
	}
	root := markerRoot(t, st)
	rng := rand.New(rand.NewSource(7))
	for checked := 0; checked < 50; {
		var m common.Hash
		rng.Read(m[:])
		if checked%5 == 0 {
			// Next to a marker of the set, inside a run.
			m = markers[rng.Intn(len(markers))]
			m[31] ^= 0x80
		}
		if ref.has(m) || m == (common.Hash{}) {
			continue
		}
		w, err := MarkerAbsenceWitness(st, m)
		if err != nil {
			t.Fatalf("witness for %x: %v", m, err)
		}
		if !VerifyMarkerAbsence(root, m, w) {
			t.Fatalf("the witness for %x does not verify", m)
		}
		if low := ref.lowOf(m); read5(w[69:74]) != low {
			t.Fatalf("the witness for %x is of position %d, the reference low leaf %d", m, read5(w[69:74]), low)
		}
		checked++
	}
}

func TestMarkerSetRefusesZeroAndRepeat(t *testing.T) {
	st := newState(t)
	if err := MarkSpent(st, Data, common.Hash{}); !errors.Is(err, ErrZeroMarker) {
		t.Errorf("zero marker in the genesis set: %v, want %v", err, ErrZeroMarker)
	}
	if st.Exist(ghost.DataMarkerAccount) || st.IntermediateRoot(true) != types.EmptyRootHash {
		t.Error("the refused zero marker changed the genesis state")
	}
	m := testMarker(1)
	markData(t, st, m)
	stateRoot, setRoot := st.IntermediateRoot(true), markerRoot(t, st)
	if err := MarkSpent(st, Data, common.Hash{}); !errors.Is(err, ErrZeroMarker) {
		t.Errorf("zero marker: %v, want %v", err, ErrZeroMarker)
	}
	if err := MarkSpent(st, Data, m); !errors.Is(err, ErrMarkerSpent) {
		t.Errorf("repeat: %v, want %v", err, ErrMarkerSpent)
	}
	if st.IntermediateRoot(true) != stateRoot || markerRoot(t, st) != setRoot || MarkerSetCount(st) != 2 {
		t.Error("a refused marker changed the state")
	}
}

func TestMarkerSetRollsBackWithTheState(t *testing.T) {
	sdb := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(types.EmptyRootHash, sdb, nil)
	if err != nil {
		t.Fatal(err)
	}
	markData(t, st, testMarker(1))
	stateRoot, setRoot, count := st.IntermediateRoot(true), markerRoot(t, st), MarkerSetCount(st)

	snap := st.Snapshot()
	markData(t, st, testMarker(2))
	markData(t, st, testMarker(3))
	if markerRoot(t, st) == setRoot || MarkerSetCount(st) != count+2 {
		t.Fatal("the two inserts changed nothing")
	}
	st.RevertToSnapshot(snap)
	if markerRoot(t, st) != setRoot || MarkerSetCount(st) != count || st.IntermediateRoot(true) != stateRoot {
		t.Fatal("reverting the snapshot did not restore the set")
	}

	markData(t, st, testMarker(4))
	setRoot, count = markerRoot(t, st), MarkerSetCount(st)
	absent := testMarker(5)
	witness, err := MarkerAbsenceWitness(st, absent)
	if err != nil {
		t.Fatal(err)
	}
	st = commitAndReopen(t, sdb, st, 1)
	if markerRoot(t, st) != setRoot || MarkerSetCount(st) != count {
		t.Error("the set changed across the commit")
	}
	again, err := MarkerAbsenceWitness(st, absent)
	if err != nil || !bytes.Equal(again, witness) {
		t.Errorf("the witness changed across the commit: %v", err)
	}
	if !VerifyMarkerAbsence(setRoot, absent, again) {
		t.Error("the witness does not verify after the commit")
	}
	// A reverted marker is not in the set after the commit.
	if _, err := MarkerAbsenceWitness(st, testMarker(2)); err != nil {
		t.Errorf("a reverted marker: %v", err)
	}
}

// countingState counts the storage reads and writes of the set.
type countingState struct {
	*state.StateDB
	reads, writes int
}

func (c *countingState) GetState(addr common.Address, key common.Hash) common.Hash {
	c.reads++
	return c.StateDB.GetState(addr, key)
}

func (c *countingState) SetState(addr common.Address, key, value common.Hash) {
	c.writes++
	c.StateDB.SetState(addr, key, value)
}

func TestMarkerSetInsertWorkIsBounded(t *testing.T) {
	st := newState(t)
	markers := referenceMarkers(1001)
	for _, m := range markers[:1000] {
		markData(t, st, m)
	}
	c := &countingState{StateDB: st}
	if err := MarkSpent(c, Data, markers[1000]); err != nil {
		t.Fatal(err)
	}
	if c.reads > 2000 || c.writes > 400 {
		t.Errorf("one insert into 1,000 markers: %d reads and %d writes, at most 2,000 and 400", c.reads, c.writes)
	}
	if c.writes == 0 || MarkerSetCount(st) != 1002 {
		t.Error("the counted insert did not insert")
	}
	c.reads = 0
	if _, err := DataMarkerRoot(c); err != nil || c.reads != 1 {
		t.Errorf("DataMarkerRoot made %d reads (%v), want 1", c.reads, err)
	}
}

func TestMarkSpentInsertsDataMarkersOnly(t *testing.T) {
	st := newState(t)
	m := testMarker(1)
	if err := MarkSpent(st, Coin, m); err != nil {
		t.Fatal(err)
	}
	if markerRoot(t, st) != EmptyMarkerSetRoot || MarkerSetCount(st) != 1 {
		t.Error("a coin marker changed the data marker set")
	}
	if st.Exist(ghost.DataMarkerAccount) {
		t.Error("a coin marker wrote to the data marker account")
	}
	if err := MarkSpent(st, Coin, common.Hash{}); err != nil {
		t.Errorf("the coin set refuses the zero marker: %v", err)
	}
	markData(t, st, m)
	ref := newRefSet()
	ref.insert(m)
	if got, want := markerRoot(t, st), ref.root(); got != want {
		t.Errorf("root of {m} %x, reference %x", got, want)
	}
	if got := st.GetState(ghost.DataMarkerAccount, m); got != (common.Hash{31: 1}) {
		t.Errorf("data marker slot %x, want 1", got)
	}
	if !IsSpent(st, Data, m) || !IsSpent(st, Coin, m) {
		t.Error("a marker is not spent")
	}
}
