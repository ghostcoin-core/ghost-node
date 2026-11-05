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
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// vectors0004 reads testdata/decision_0004_vectors.txt: one map of fields
// per [name] block.
func vectors0004(t testing.TB) map[string]map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "decision_0004_vectors.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]map[string]string{}
	var block map[string]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			block = map[string]string{}
			out[line[1:len(line)-1]] = block
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || block == nil {
				t.Fatalf("vector line %q", line)
			}
			block[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// vecHex returns the bytes of a vector field, its space-separated parts
// joined.
func vecHex(t testing.TB, v map[string]map[string]string, block, field string) []byte {
	t.Helper()
	s, ok := v[block][field]
	if !ok {
		t.Fatalf("vector %s.%s missing", block, field)
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("vector %s.%s: %v", block, field, err)
	}
	return b
}

func vecHash(t testing.TB, v map[string]map[string]string, block, field string) common.Hash {
	t.Helper()
	b := vecHex(t, v, block, field)
	if len(b) != 32 {
		t.Fatalf("vector %s.%s has %d bytes", block, field, len(b))
	}
	return common.BytesToHash(b)
}

func vecTag(t testing.TB, v map[string]map[string]string, block, field string) LookupTag {
	t.Helper()
	b := vecHex(t, v, block, field)
	if len(b) != LookupTagSize {
		t.Fatalf("vector %s.%s has %d bytes", block, field, len(b))
	}
	var tag LookupTag
	copy(tag[:], b)
	return tag
}

func vec5(t testing.TB, v map[string]map[string]string, block, field string) uint64 {
	t.Helper()
	b := vecHex(t, v, block, field)
	if len(b) != 5 {
		t.Fatalf("vector %s.%s has %d bytes", block, field, len(b))
	}
	return read5(b)
}

func lookupRoot(t testing.TB, st StateDB, kind Kind) common.Hash {
	t.Helper()
	root, err := LookupRoot(st, kind)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func appendTagged(t testing.TB, st StateDB, kind Kind, height uint64, leaf common.Hash, tag LookupTag) uint64 {
	t.Helper()
	res, err := AppendTagged(st, kind, height, leaf, tag)
	if err != nil {
		t.Fatalf("append %x with tag %x: %v", leaf, tag, err)
	}
	g, err := GlobalPositionOf(res)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// copiedTagState is the state of vector coin-lookup-copied-tag: tag(0) at
// global position 0, tag(1) at 1 and tag(0) again at 2.
func copiedTagState(t *testing.T, v map[string]map[string]string) StateDB {
	t.Helper()
	st := newState(t)
	tag0, tag1 := vecTag(t, v, "lookup-tag", "tag0"), vecTag(t, v, "lookup-tag", "tag1")
	for i, tag := range []LookupTag{tag0, tag1, tag0} {
		if g := appendTagged(t, st, Coin, 1, testLeaf(i), tag); g != uint64(i) {
			t.Fatalf("leaf %d at global position %d", i, g)
		}
	}
	return st
}

func TestLookupTagGolden(t *testing.T) {
	v := vectors0004(t)
	k := vecHash(t, v, "lookup-tag", "k_note")
	for i, field := range []string{"tag0", "tag1", "tag2"} {
		if got, want := DeriveLookupTag(k, uint64(i)), vecTag(t, v, "lookup-tag", field); got != want {
			t.Errorf("tag(%d) = %x, want %x", i, got, want)
		}
	}
	dk := vecHash(t, v, "data-lookup-tag", "k_note")
	if got, want := DeriveLookupTag(dk, 0), vecTag(t, v, "data-lookup-tag", "tag0"); got != want {
		t.Errorf("data tag(0) = %x, want %x", got, want)
	}
	// S is SHA3-256, not Keccak-256: the same input under K differs.
	if s, k := S(TagNoteLookup, k[:]), K(TagNoteLookup, k[:]); s == k {
		t.Error("S and K agree")
	}
	if DeriveLookupTag(k, 0).IsZero() || !(LookupTag{}).IsZero() {
		t.Error("IsZero is wrong")
	}

	// Global positions.
	for _, c := range []struct {
		index uint64
		pos   uint32
		field string
	}{{0, 0, "tree0_pos0"}, {1, 0, "tree1_pos0"}, {255, 4294967294, "tree255_pos4294967294"}} {
		g, err := GlobalPosition(c.index, c.pos)
		if err != nil {
			t.Fatalf("tree %d position %d: %v", c.index, c.pos, err)
		}
		if want := vec5(t, v, "global-positions", c.field); g != want {
			t.Errorf("tree %d position %d is %#x, want %#x", c.index, c.pos, g, want)
		}
		if got := hex.EncodeToString(EncodeGlobalPosition(g)); got != v["global-positions"][c.field] {
			t.Errorf("tree %d position %d encodes as %s", c.index, c.pos, got)
		}
	}
	if v["global-positions"]["tree255_pos4294967295"] != "rejected" {
		t.Fatal("vector tree255_pos4294967295 is not a rejection")
	}
	if _, err := GlobalPosition(255, 4294967295); !errors.Is(err, ErrGlobalPosition) {
		t.Errorf("tree 255 position 2^32-1: %v, want %v", err, ErrGlobalPosition)
	}
	if _, err := GlobalPosition(256, 0); !errors.Is(err, ErrGlobalPosition) {
		t.Errorf("tree 256: %v, want %v", err, ErrGlobalPosition)
	}
	if want := vec5(t, v, "global-positions", "none"); NoGlobalPosition != want || MaxGlobalPosition != want-1 {
		t.Errorf("none %#x and last usable %#x, want %#x", NoGlobalPosition, MaxGlobalPosition, want)
	}
}

func TestLookupIndexGolden(t *testing.T) {
	v := vectors0004(t)
	st := newState(t)
	if got, want := EmptyLookupRoot(Coin), vecHash(t, v, "coin-lookup-empty", "root"); got != want || lookupRoot(t, st, Coin) != want {
		t.Errorf("empty coin lookup root %x, want %x", got, want)
	}
	if got, want := EmptyLookupRoot(Data), vecHash(t, v, "data-lookup-empty", "root"); got != want || lookupRoot(t, st, Data) != want {
		t.Errorf("empty data lookup root %x, want %x", got, want)
	}
	if st.IntermediateRoot(true) != newState(t).IntermediateRoot(true) {
		t.Error("reading the empty indices changed the state")
	}

	tag0, tag1 := vecTag(t, v, "lookup-tag", "tag0"), vecTag(t, v, "lookup-tag", "tag1")
	appendTagged(t, st, Coin, 1, testLeaf(0), tag0)
	if got, want := lookupRoot(t, st, Coin), vecHash(t, v, "coin-lookup-one-leaf", "root"); got != want {
		t.Errorf("one leaf: %x, want %x", got, want)
	}
	appendTagged(t, st, Coin, 1, testLeaf(1), tag1)
	if got, want := lookupRoot(t, st, Coin), vecHash(t, v, "coin-lookup-two-leaves", "root"); got != want {
		t.Errorf("two leaves: %x, want %x", got, want)
	}
	appendTagged(t, st, Coin, 1, testLeaf(2), tag0)
	if got, want := lookupRoot(t, st, Coin), vecHash(t, v, "coin-lookup-copied-tag", "root"); got != want {
		t.Errorf("copied tag: %x, want %x", got, want)
	}
	for i := uint64(0); i < 4; i++ {
		want := vecHex(t, v, "coin-lookup-copied-tag", "leaf"+string(rune('0'+i)))
		tag, pos, nextTag, nextPos, nextIndex, err := LookupLeaf(st, Coin, i)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		var got []byte
		got = append(got, tag[:]...)
		got = append(got, index5(pos)...)
		got = append(got, nextTag[:]...)
		got = append(got, index5(nextPos)...)
		got = append(got, index5(nextIndex)...)
		if !bytes.Equal(got, want) {
			t.Errorf("index leaf %d is %x, want %x", i, got, want)
		}
	}
	if tag, ok, err := LookupEntry(st, Coin, 2); err != nil || !ok || tag != tag0 {
		t.Errorf("entry of position 2: %x %v %v", tag, ok, err)
	}
	if lookupRoot(t, st, Data) != EmptyLookupRoot(Data) {
		t.Error("coin leaves changed the data lookup index")
	}

	// A leaf without a tag takes its position but no entry.
	before := lookupRoot(t, st, Coin)
	if g := appendTagged(t, st, Coin, 1, testLeaf(3), LookupTag{}); g != 3 {
		t.Fatalf("untagged leaf at %d", g)
	}
	if lookupRoot(t, st, Coin) != before {
		t.Error("an untagged leaf changed the coin lookup root")
	}
	if _, ok, err := LookupEntry(st, Coin, 3); ok || err != nil {
		t.Errorf("untagged leaf has an entry (%v)", err)
	}
	if _, err := planLookup(st, Coin, 4, LookupTag{}); !errors.Is(err, ErrZeroLookupTag) {
		t.Errorf("zero tag: %v, want %v", err, ErrZeroLookupTag)
	}
	if _, err := planLookup(st, Coin, 2, tag1); !errors.Is(err, ErrCorruptTreeState) {
		t.Errorf("a second entry at a used position: %v", err)
	}

	data := newState(t)
	appendTagged(t, data, Data, 1, testLeaf(0), vecTag(t, v, "data-lookup-tag", "tag0"))
	if got, want := lookupRoot(t, data, Data), vecHash(t, v, "data-lookup-one-leaf", "root"); got != want {
		t.Errorf("data one leaf: %x, want %x", got, want)
	}
	if lookupRoot(t, data, Coin) != EmptyLookupRoot(Coin) {
		t.Error("a data leaf changed the coin lookup index")
	}
}

// flipEachByte reports the first offset of w at which a witness with that
// byte changed still verifies, or -1.
func flipEachByte(w []byte, verify func([]byte) bool) int {
	c := bytes.Clone(w)
	for i := range c {
		c[i] ^= 0x01
		ok := verify(c)
		c[i] ^= 0x01
		if ok {
			return i
		}
	}
	return -1
}

func TestLookupWitnessGolden(t *testing.T) {
	v := vectors0004(t)
	st := copiedTagState(t, v)
	root := vecHash(t, v, "coin-lookup-copied-tag", "root")
	if lookupRoot(t, st, Coin) != root {
		t.Fatal("the copied-tag state does not have the vector root")
	}
	tag0, tag1, tag2 := vecTag(t, v, "lookup-tag", "tag0"), vecTag(t, v, "lookup-tag", "tag1"), vecTag(t, v, "lookup-tag", "tag2")
	tags := []LookupTag{tag0, tag1, tag0}

	// Membership: the entry of each leaf.
	for g, tag := range tags {
		w, err := LookupMembershipWitness(st, Coin, uint64(g))
		if err != nil {
			t.Fatal(err)
		}
		if len(w) != LookupWitnessSize || LookupWitnessSize != 1332 {
			t.Fatalf("witness of %d bytes, want 1,332", len(w))
		}
		want := append(vecHex(t, v, "coin-lookup-copied-tag", "leaf"+string(rune('1'+g))), index5(uint64(g)+1)...)
		if !bytes.Equal(w[:52], want) {
			t.Errorf("membership witness of %d begins %x, want %x", g, w[:52], want)
		}
		if !VerifyLookupMembership(Coin, root, tag, uint64(g), w) {
			t.Fatalf("membership of %d does not verify", g)
		}
		other := tag1
		if tag == tag1 {
			other = tag0
		}
		switch {
		case VerifyLookupMembership(Coin, root, other, uint64(g), w):
			t.Errorf("membership of %d verifies for another tag", g)
		case VerifyLookupMembership(Coin, root, tag, uint64(g)+3, w):
			t.Errorf("membership of %d verifies for another position", g)
		case VerifyLookupMembership(Data, root, tag, uint64(g), w):
			t.Errorf("membership of %d verifies as a data entry", g)
		case VerifyLookupMembership(Coin, EmptyLookupRoot(Coin), tag, uint64(g), w):
			t.Errorf("membership of %d verifies against another root", g)
		case VerifyLookupMembership(Coin, root, tag, uint64(g), w[:len(w)-1]), VerifyLookupMembership(Coin, root, tag, uint64(g), append(bytes.Clone(w), 0)):
			t.Errorf("membership of %d verifies at another length", g)
		}
		if i := flipEachByte(w, func(c []byte) bool { return VerifyLookupMembership(Coin, root, tag, uint64(g), c) }); i >= 0 {
			t.Errorf("membership of %d verifies with byte %d changed", g, i)
		}
	}
	if _, err := LookupMembershipWitness(st, Coin, 3); err == nil {
		t.Error("a membership witness for a position without an entry")
	}

	// First entry: the low leaf of a tag points at its first position.
	for _, c := range []struct {
		tag   LookupTag
		first uint64
		low   string // the vector leaf of the low entry
		at    uint64
	}{{tag0, 0, "leaf0", 0}, {tag1, 1, "leaf3", 3}} {
		w, err := LookupLowWitness(st, Coin, c.tag)
		if err != nil {
			t.Fatal(err)
		}
		want := append(vecHex(t, v, "coin-lookup-copied-tag", c.low), index5(c.at)...)
		if !bytes.Equal(w[:52], want) {
			t.Errorf("low witness of %x begins %x, want %x", c.tag, w[:52], want)
		}
		if !VerifyLookupFirst(Coin, root, c.tag, c.first, w) {
			t.Fatalf("first entry %d of %x does not verify", c.first, c.tag)
		}
		if VerifyLookupFirst(Coin, root, c.tag, c.first+2, w) {
			t.Errorf("first entry of %x verifies at %d", c.tag, c.first+2)
		}
		if VerifyLookupAbsence(Coin, root, c.tag, w) {
			t.Errorf("a present tag %x verifies as absent", c.tag)
		}
		if i := flipEachByte(w, func(b []byte) bool { return VerifyLookupFirst(Coin, root, c.tag, c.first, b) }); i >= 0 {
			t.Errorf("first entry of %x verifies with byte %d changed", c.tag, i)
		}
	}
	// The second entry of tag(0), at 2, is not the first: its predecessor
	// has the same tag.
	if w, err := LookupMembershipWitness(st, Coin, 0); err != nil || VerifyLookupFirst(Coin, root, tag0, 2, w) {
		t.Errorf("position 2 verifies as the first entry of tag(0) (%v)", err)
	}

	// Absence: a tag above every entry, and one below every entry.
	low := LookupTag{0x01}
	for _, c := range []struct {
		tag LookupTag
		at  uint64
	}{{tag2, 2}, {low, 0}} {
		w, err := LookupLowWitness(st, Coin, c.tag)
		if err != nil {
			t.Fatal(err)
		}
		if got := read5(w[47:52]); got != c.at {
			t.Errorf("absence of %x proved by index position %d, want %d", c.tag, got, c.at)
		}
		if !VerifyLookupAbsence(Coin, root, c.tag, w) {
			t.Fatalf("absence of %x does not verify", c.tag)
		}
		if VerifyLookupAbsence(Coin, EmptyLookupRoot(Coin), c.tag, w) {
			t.Errorf("absence of %x verifies against another root", c.tag)
		}
		if i := flipEachByte(w, func(b []byte) bool { return VerifyLookupAbsence(Coin, root, c.tag, b) }); i >= 0 {
			t.Errorf("absence of %x verifies with byte %d changed", c.tag, i)
		}
	}
	// The empty index proves every tag absent with its sentinel.
	empty := newState(t)
	w, err := LookupLowWitness(empty, Coin, tag0)
	if err != nil || !VerifyLookupAbsence(Coin, EmptyLookupRoot(Coin), tag0, w) {
		t.Errorf("absence in the empty index (%v)", err)
	}
	if _, err := LookupLowWitness(st, Coin, LookupTag{}); !errors.Is(err, ErrZeroLookupTag) {
		t.Errorf("low witness of the zero tag: %v", err)
	}
	if VerifyLookupAbsence(Coin, EmptyLookupRoot(Coin), LookupTag{}, w) {
		t.Error("the zero tag verifies as absent")
	}
}

func TestCoinMarkerSetGolden(t *testing.T) {
	v := vectors0004(t)
	st := newState(t)
	m0, m1 := vecHash(t, v, "coin-marker-set-markers", "m0"), vecHash(t, v, "coin-marker-set-markers", "m1")
	a0, a1 := vec5(t, v, "coin-marker-set-markers", "m0_appended"), vec5(t, v, "coin-marker-set-markers", "m1_appended")
	if vec5(t, v, "coin-marker-set-markers", "sentinel_appended") != NoGlobalPosition {
		t.Fatal("the sentinel's appended position is not NoGlobalPosition")
	}
	coinRoot := func() common.Hash {
		t.Helper()
		r, err := CoinMarkerRoot(st)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if got, want := coinRoot(), vecHash(t, v, "coin-marker-set-empty", "root"); got != want || EmptyCoinMarkerSetRoot != want {
		t.Errorf("empty coin marker set %x, want %x", got, want)
	}
	if err := MarkSpent(st, Coin, 1, m0, a0); err != nil {
		t.Fatal(err)
	}
	if got, want := coinRoot(), vecHash(t, v, "coin-marker-set-one-marker", "root"); got != want {
		t.Errorf("one marker %x, want %x", got, want)
	}
	if err := MarkSpent(st, Coin, 1, m1, a1); err != nil {
		t.Fatal(err)
	}
	root := coinRoot()
	if want := vecHash(t, v, "coin-marker-set-two-markers", "root"); root != want {
		t.Errorf("two markers %x, want %x", root, want)
	}
	for pos, want := range []struct {
		value, next         common.Hash
		nextIndex, appended uint64
	}{{common.Hash{}, m0, 1, NoGlobalPosition}, {m0, m1, 2, a0}, {m1, common.Hash{}, 0, a1}} {
		value, next, nextIndex, appended, err := CoinMarkerSetLeaf(st, uint64(pos))
		if err != nil || value != want.value || next != want.next || nextIndex != want.nextIndex || appended != want.appended {
			t.Errorf("leaf %d is (%x, %x, %d, %#x) %v", pos, value, next, nextIndex, appended, err)
		}
	}
	if markerRoot(t, st) != EmptyMarkerSetRoot {
		t.Error("coin markers changed the data marker set")
	}

	// Membership of a spent marker, with its appended position.
	w, err := CoinMarkerWitness(st, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != CoinMarkerWitnessSize || CoinMarkerWitnessSize != 1359 {
		t.Fatalf("witness of %d bytes, want 1,359", len(w))
	}
	head := append(append(append(append(m0.Bytes(), m1.Bytes()...), index5(2)...), index5(a0)...), index5(1)...)
	if !bytes.Equal(w[:79], head) {
		t.Errorf("witness begins %x, want %x", w[:79], head)
	}
	if !VerifyCoinMarker(root, m0, a0, w) {
		t.Fatal("the marker witness does not verify")
	}
	if VerifyCoinMarker(root, m0, a1, w) || VerifyCoinMarker(root, m1, a0, w) || VerifyCoinMarker(EmptyCoinMarkerSetRoot, m0, a0, w) {
		t.Error("the marker witness verifies for another marker, appended position or root")
	}
	if i := flipEachByte(w, func(b []byte) bool { return VerifyCoinMarker(root, m0, a0, b) }); i >= 0 {
		t.Errorf("the marker witness verifies with byte %d changed", i)
	}

	// Absence of an unspent marker.
	absent := common.HexToHash("e000000000000000000000000000000000000000000000000000000000000000")
	aw, err := CoinMarkerAbsenceWitness(st, absent)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCoinMarkerAbsence(root, absent, aw) || read5(aw[74:79]) != 1 {
		t.Fatal("the absence witness does not verify from leaf 1")
	}
	if VerifyCoinMarkerAbsence(root, m0, aw) || VerifyCoinMarkerAbsence(root, m1, aw) {
		t.Error("a spent marker verifies as absent")
	}
	if i := flipEachByte(aw, func(b []byte) bool { return VerifyCoinMarkerAbsence(root, absent, b) }); i >= 0 {
		t.Errorf("the absence witness verifies with byte %d changed", i)
	}
	if _, err := CoinMarkerAbsenceWitness(st, m1); !errors.Is(err, ErrMarkerSpent) {
		t.Errorf("absence witness of a spent marker: %v", err)
	}
	if err := MarkSpent(st, Coin, 1, common.Hash{}, NoGlobalPosition); !errors.Is(err, ErrZeroMarker) {
		t.Errorf("zero coin marker: %v", err)
	}
	if err := MarkSpent(st, Coin, 1, testMarker(9), NoGlobalPosition+1); !errors.Is(err, ErrGlobalPosition) {
		t.Errorf("an appended position beyond 40 bits: %v", err)
	}
	if coinRoot() != root {
		t.Error("a refused marker changed the set")
	}
}

// TestLookupKeepsTheDataMarkerSet checks that the data marker set, now one
// of the indexed trees, still gives the vectors of spec 05: the roots after
// one and two markers, its leaves and the absence witness.
func TestLookupKeepsTheDataMarkerSet(t *testing.T) {
	st := newState(t)
	if markerRoot(t, st) != EmptyMarkerSetRoot || newRefSet().root() != EmptyMarkerSetRoot {
		t.Fatal("the empty data marker set root changed")
	}
	markData(t, st, vectorMarker1)
	if got := markerRoot(t, st); got != vectorRoot1 {
		t.Errorf("root after one marker %x, want %x", got, vectorRoot1)
	}
	markData(t, st, vectorMarker2)
	if got := markerRoot(t, st); got != vectorRoot2 {
		t.Errorf("root after two markers %x, want %x", got, vectorRoot2)
	}
	checkLeaf(t, st, 0, refLeaf{common.Hash{}, vectorMarker2, 2})
	checkLeaf(t, st, 1, refLeaf{vectorMarker1, common.Hash{}, 0})
	checkLeaf(t, st, 2, refLeaf{vectorMarker2, vectorMarker1, 1})
	marker := common.HexToHash("8888888888888888888888888888888888888888888888888888888888888888")
	w, err := MarkerAbsenceWitness(st, marker)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := crypto.Keccak256Hash(w), common.HexToHash("e0019752573b22d754bbbfae50852f927e5b42cfd92711bcdab824f6c9612b44"); got != want {
		t.Errorf("witness hash %x, want %x", got, want)
	}
	if !VerifyMarkerAbsence(vectorRoot2, marker, w) || VerifyMarkerAbsence(vectorRoot2, vectorMarker1, w) {
		t.Error("the absence witness verifies wrongly")
	}
	// A random run against the reference model of spec 05.
	ref, fresh := newRefSet(), newState(t)
	for _, m := range referenceMarkers(300) {
		ref.insert(m)
		markData(t, fresh, m)
	}
	if got, want := markerRoot(t, fresh), ref.root(); got != want {
		t.Errorf("300 markers: root %x, reference %x", got, want)
	}
	if st.Exist(ghost.CoinMarkerAccount) || st.Exist(ghost.CoinTreeAccount) {
		t.Error("data markers wrote to a coin account")
	}
}

func TestLookupDigestGolden(t *testing.T) {
	v := vectors0004(t)
	empty := new(BlockLookup)
	if got, want := empty.Encode(), vecHex(t, v, "block-lookup-digest-empty", "encoding"); !bytes.Equal(got, want) {
		t.Errorf("empty encoding %x, want %x", got, want)
	}
	if got, want := empty.Digest(), vecHash(t, v, "block-lookup-digest-empty", "digest"); got != want || EmptyLookupDigest != want {
		t.Errorf("empty digest %x, want %x", got, want)
	}
	tag0, tag1 := vecTag(t, v, "lookup-tag", "tag0"), vecTag(t, v, "lookup-tag", "tag1")
	dtag0 := vecTag(t, v, "data-lookup-tag", "tag0")
	m0 := vecHash(t, v, "coin-marker-set-markers", "m0")
	example := &BlockLookup{CoinStart: 1, CoinTags: []LookupTag{tag1}, DataTags: []LookupTag{dtag0}, CoinMarkers: []common.Hash{m0}}
	wantEnc := vecHex(t, v, "block-lookup-digest-example", "encoding")
	wantDigest := vecHash(t, v, "block-lookup-digest-example", "digest")
	if got := example.Encode(); !bytes.Equal(got, wantEnc) {
		t.Errorf("example encoding %x, want %x", got, wantEnc)
	}
	if got := example.Digest(); got != wantDigest {
		t.Errorf("example digest %x, want %x", got, wantDigest)
	}

	// The same lists, as the state of a chain records them: block 4 appends
	// tag(0) at 0, block 5 appends tag(1) at 1 and data tag(0) at 0 and
	// spends m0.
	st := newState(t)
	got, err := LookupDigest(st, 1)
	if err != nil || got != EmptyLookupDigest {
		t.Errorf("a block of the empty chain: %x (%v)", got, err)
	}
	appendTagged(t, st, Coin, 4, testLeaf(0), tag0)
	appendTagged(t, st, Coin, 5, testLeaf(1), tag1)
	appendTagged(t, st, Data, 5, testLeaf(2), dtag0)
	if err := MarkSpent(st, Coin, 5, m0, 1); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBlockLookup(st, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Encode(), wantEnc) || b.Digest() != wantDigest {
		t.Errorf("block 5 encodes as %x, want %x", b.Encode(), wantEnc)
	}
	// A later block that changes nothing starts each list at the next
	// position.
	next, err := ReadBlockLookup(st, 6)
	if err != nil {
		t.Fatal(err)
	}
	if next.CoinStart != 2 || next.DataStart != 1 || len(next.CoinTags)+len(next.DataTags)+len(next.CoinMarkers)+len(next.DataMarkers) != 0 {
		t.Errorf("block 6 lists %+v", next)
	}
	// A leaf without a tag is listed with the zero tag, and a data marker
	// in its own list.
	appendTagged(t, st, Coin, 6, testLeaf(3), LookupTag{})
	appendTagged(t, st, Coin, 6, testLeaf(4), tag0)
	if err := MarkSpent(st, Data, 6, m0, NoGlobalPosition); err != nil {
		t.Fatal(err)
	}
	b6, err := ReadBlockLookup(st, 6)
	if err != nil {
		t.Fatal(err)
	}
	if b6.CoinStart != 2 || len(b6.CoinTags) != 2 || !b6.CoinTags[0].IsZero() || b6.CoinTags[1] != tag0 || len(b6.DataTags) != 0 || b6.DataStart != 1 {
		t.Errorf("block 6 coin lists %+v", b6)
	}
	if len(b6.CoinMarkers) != 0 || len(b6.DataMarkers) != 1 || b6.DataMarkers[0] != m0 {
		t.Errorf("block 6 marker lists %+v", b6)
	}
	// Every list changes the digest.
	base := b6.Digest()
	for name, edit := range map[string]func(*BlockLookup){
		"coin start":   func(b *BlockLookup) { b.CoinStart++ },
		"coin tag":     func(b *BlockLookup) { b.CoinTags[1][0] ^= 1 },
		"data start":   func(b *BlockLookup) { b.DataStart++ },
		"data tag":     func(b *BlockLookup) { b.DataTags = append(b.DataTags, tag1) },
		"coin marker":  func(b *BlockLookup) { b.CoinMarkers = append(b.CoinMarkers, m0) },
		"data marker":  func(b *BlockLookup) { b.DataMarkers[0][31] ^= 1 },
		"marker order": func(b *BlockLookup) { b.CoinMarkers, b.DataMarkers = b.DataMarkers, b.CoinMarkers },
	} {
		c, err := ReadBlockLookup(st, 6)
		if err != nil {
			t.Fatal(err)
		}
		edit(c)
		if c.Digest() == base {
			t.Errorf("changing the %s keeps the digest", name)
		}
	}
}
