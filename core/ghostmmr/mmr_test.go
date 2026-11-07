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

package ghostmmr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"math/bits"
	"math/rand"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"
)

// Values of decision 0005, copied from the record.
const (
	recordEmptyRoot     = "b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac"
	recordGenesisHash   = "31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65" // header-genesis-with-mmr
	recordGenesisLeaf   = "cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a" // header-mmr-leaf-genesis
	recordOneLeafRoot   = "f350a609073159867968bed20feef366627cadfa06e7e16149b9116b3b40d8ac" // header-mmr-one-leaf
	recordBlockOneHash  = "c2a2926fc0d94c1b381f8c106eb0faf571d9c72b6b3e15b1a98bbd9e958375cb" // header-block-one-with-mmr
	recordSevenRoot     = "fb94d9e93c3815fe907f4420cc32aa620c904da8e4fee556790a0a5dc55306a0" // header-mmr-seven-leaves
	recordSevenWork     = 118751232
	recordFiveYearRoot  = "a262148a8926dd27bda83c8ae07bac1da59c1471f966301d4addc6f9d89dcb01" // header-mmr-five-years
	recordFiveYearWork  = 88181114404864
	recordFiveYearDepth = 5_256_000 // five years of 30-second blocks
)

// The first and the last entries of the record's header-mmr-path-five-years-
// genesis: the sibling of the genesis leaf, block one's leaf, and the bag of
// the six peaks after the first.
var recordGenesisPathEntries = map[int]string{
	0:  "ea98f3073eabe1f43d9d6e6b13798a1db0c64146a596bbbec0c5dd5e17920af700000000000000000000000001000000",
	1:  "e1e2e752142155b2705894920e7db2e0d245ca3955983d2a04cf3a28d1e0df7d00000000000000000000000002000000",
	2:  "1f5eb73b832f8f8516e43a0d6e089c942a643357dacb3a93f553101f7080e7ec00000000000000000000000004000000",
	3:  "62ceb086561a4c565f04ac9bf9dfca830841412c7ec55c8be41a86b793f1c51a00000000000000000000000008000000",
	22: "bf0b51b7e31f6453fcf73ede17c7b40997a6fa8ee336086e357638ce8918e9e100000000000000000000103344000000",
}

func mustHash(t testing.TB, s string) (h [HashSize]byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != HashSize {
		t.Fatalf("bad hash literal %q", s)
	}
	copy(h[:], b)
	return h
}

func repeated(b byte) (h [HashSize]byte) {
	for i := range h {
		h[i] = b
	}
	return h
}

var d24 = WorkFromUint64(1 << 24)

// --- The independent verifier -------------------------------------------
//
// refFold is written from the decision record alone, with big integers and
// its own hashing, and shares no code with the package: it folds a path for
// leaf i of n back to a root and returns the work before the leaf.

var two128 = new(big.Int).Lsh(big.NewInt(1), 128)

func refK(tag string, parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte{byte(len(tag))})
	h.Write([]byte(tag))
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func refWork(w *big.Int) []byte {
	out := make([]byte, 16)
	w.FillBytes(out)
	return out
}

type refEntry struct {
	hash []byte
	work *big.Int
}

func refCombine(tag string, a, b refEntry) (refEntry, bool) {
	work := new(big.Int).Add(a.work, b.work)
	if work.Cmp(two128) >= 0 {
		return refEntry{}, false
	}
	return refEntry{refK(tag, a.hash, refWork(a.work), b.hash, refWork(b.work)), work}, true
}

func refFold(n, i uint64, headerHash [32]byte, difficulty *big.Int, path []byte) (root []byte, before *big.Int, ok bool) {
	if i >= n || len(path)%48 != 0 {
		return nil, nil, false
	}
	// The peak heights, highest first, and the peak of i.
	var heights []int
	for h := 63; h >= 0; h-- {
		if n&(1<<uint(h)) != 0 {
			heights = append(heights, h)
		}
	}
	j, start := 0, uint64(0)
	for start+(1<<uint(heights[j])) <= i {
		start += 1 << uint(heights[j])
		j++
	}
	h := heights[j]
	last := j == len(heights)-1
	want := h + j
	if !last {
		want++
	}
	if len(path) != 48*want {
		return nil, nil, false
	}
	entries := make([]refEntry, want)
	for k := range entries {
		entries[k] = refEntry{path[48*k : 48*k+32], new(big.Int).SetBytes(path[48*k+32 : 48*k+48])}
	}
	cur := refEntry{refK(LeafTag, headerHash[:], refWork(difficulty)), difficulty}
	before = new(big.Int)
	pos := i - start
	for level := 0; level < h; level++ {
		if (pos>>uint(level))&1 == 1 {
			cur, ok = refCombine(NodeTag, entries[level], cur)
			before.Add(before, entries[level].work)
		} else {
			cur, ok = refCombine(NodeTag, cur, entries[level])
		}
		if !ok {
			return nil, nil, false
		}
	}
	k := h
	if !last {
		if cur, ok = refCombine(BagTag, cur, entries[k]); !ok {
			return nil, nil, false
		}
		k++
	}
	for t := 0; t < j; t++ {
		if cur, ok = refCombine(BagTag, entries[k+t], cur); !ok {
			return nil, nil, false
		}
		before.Add(before, entries[k+t].work)
	}
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], n)
	return refK(RootTag, count[:], cur.hash, refWork(cur.work)), before, before.Cmp(two128) < 0
}

// --- Test MMRs ------------------------------------------------------------

// memMMR is an MMR with its inner nodes in a map, keyed by hash as the node
// keys them.
type memMMR struct {
	State
	nodes map[[HashSize]byte][2]Entry
}

func newMemMMR() *memMMR { return &memMMR{nodes: make(map[[HashSize]byte][2]Entry)} }

func (m *memMMR) push(t testing.TB, leaf Entry) {
	if err := m.Push(leaf, func(in Inner) { m.nodes[in.Node.Hash] = [2]Entry{in.Left, in.Right} }); err != nil {
		t.Fatalf("push leaf %d: %v", m.N, err)
	}
}

func (m *memMMR) children(hash [HashSize]byte) (Entry, Entry, bool, error) {
	c, ok := m.nodes[hash]
	return c[0], c[1], ok, nil
}

func (m *memMMR) path(t testing.TB, s State, i uint64) []byte {
	t.Helper()
	p, err := Path(s, i, m.children)
	if err != nil {
		t.Fatalf("path of leaf %d of %d: %v", i, s.N, err)
	}
	return p
}

// fiveYearLeaf is the leaf input of the record's header-mmr-five-years.
func fiveYearLeaf(t testing.TB, i uint64) ([HashSize]byte, Work) {
	switch i {
	case 0:
		return mustHash(t, recordGenesisHash), d24
	case 1:
		return mustHash(t, recordBlockOneHash), d24
	case 4_200_000:
		return repeated(0x5a), WorkFromUint64(1 << 25)
	case recordFiveYearDepth - 1:
		return repeated(0x5b), WorkFromUint64(1 << 26)
	}
	return repeated(0xee), d24
}

// The checkpoints of the five-year build: depths at which the state is kept
// and paths are checked.
var fiveYearCheckpoints = []uint64{1, 2, 3, 4, 5, 7, 8, 1000, 2880, 1 << 20, 1_051_200, 1 << 22, 1<<22 + 1, 4_200_001, recordFiveYearDepth}

type fiveYearBuild struct {
	mmr    *memMMR
	states map[uint64]State
}

var (
	fiveYearOnce sync.Once
	fiveYear     *fiveYearBuild
)

// buildFiveYears appends the record's five-year leaves once per test binary.
func buildFiveYears(t testing.TB) *fiveYearBuild {
	t.Helper()
	fiveYearOnce.Do(func() {
		b := &fiveYearBuild{mmr: newMemMMR(), states: make(map[uint64]State)}
		next := 0
		for i := uint64(0); i < recordFiveYearDepth; i++ {
			hash, work := fiveYearLeaf(t, i)
			b.mmr.push(t, Leaf(hash, work))
			if b.mmr.N == fiveYearCheckpoints[next] {
				b.states[b.mmr.N] = b.mmr.State.Copy()
				next++
			}
		}
		fiveYear = b
	})
	if fiveYear == nil {
		t.Fatal("the five-year build failed")
	}
	return fiveYear
}

// --- Tests ----------------------------------------------------------------

func TestHeaderMMRTags(t *testing.T) {
	if len(leafPrefix) != 25 || leafPrefix[0] != 0x18 {
		t.Errorf("leaf tag bytes %x, want the length byte 0x18", leafPrefix)
	}
	// Input byte counts of the record's tag table.
	for _, c := range []struct {
		tag   string
		after int
		want  int
	}{
		{LeafTag, 32 + 16, 73},
		{NodeTag, 4*16 + 2*16, 121},
		{BagTag, 2*32 + 2*16, 120},
		{RootTag, 8 + 32 + 16, 81},
	} {
		if got := 1 + len(c.tag) + c.after; got != c.want {
			t.Errorf("%s: %d input bytes, want %d", c.tag, got, c.want)
		}
	}
}

func TestHeaderMMRVectors(t *testing.T) {
	if EmptyRoot != mustHash(t, recordEmptyRoot) {
		t.Errorf("empty root %x, want %s", EmptyRoot, recordEmptyRoot)
	}
	if root, err := (State{}).Root(); err != nil || root != EmptyRoot {
		t.Errorf("root of the zero state %x (%v)", root, err)
	}
	genesis := Leaf(mustHash(t, recordGenesisHash), d24)
	if genesis.Hash != mustHash(t, recordGenesisLeaf) || genesis.Work != d24 {
		t.Errorf("genesis leaf %x work %v, want %s", genesis.Hash, genesis.Work, recordGenesisLeaf)
	}
	if w := genesis.Work.Bytes(); hex.EncodeToString(w[:]) != "00000000000000000000000001000000" {
		t.Errorf("genesis leaf work bytes %x", w)
	}
	one, _, err := State{}.Append(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if root, _ := one.Root(); root != mustHash(t, recordOneLeafRoot) {
		t.Errorf("one-leaf root %x, want %s", root, recordOneLeafRoot)
	}
	if total, _ := one.TotalWork(); total != d24 {
		t.Errorf("one-leaf total work %v", total)
	}

	// Seven leaves.
	seven := newMemMMR()
	sevenLeaf := func(i uint64) ([HashSize]byte, Work) {
		switch i {
		case 0:
			return mustHash(t, recordGenesisHash), d24
		case 1:
			return mustHash(t, recordBlockOneHash), d24
		}
		return repeated(byte(0x11 * i)), WorkFromUint64(1<<24 + 65_536*i)
	}
	for i := uint64(0); i < 7; i++ {
		hash, work := sevenLeaf(i)
		seven.push(t, Leaf(hash, work))
	}
	sevenRoot, _ := seven.Root()
	if sevenRoot != mustHash(t, recordSevenRoot) {
		t.Errorf("seven-leaf root %x, want %s", sevenRoot, recordSevenRoot)
	}
	if total, _ := seven.TotalWork(); total != WorkFromUint64(recordSevenWork) {
		t.Errorf("seven-leaf total work %v, want %d", total, recordSevenWork)
	}
	for _, v := range []struct {
		index, entries, before, reject uint64
	}{
		{0, 3, 0, 1},
		{4, 3, 67_436_544, 5},
		{6, 2, 101_580_800, 5},
	} {
		checkVectorPath(t, "seven", seven, seven.State, sevenRoot, v.index, v.entries, v.before, v.reject, sevenLeaf)
	}

	// Five years.
	build := buildFiveYears(t)
	full := build.states[recordFiveYearDepth]
	root, _ := full.Root()
	if root != mustHash(t, recordFiveYearRoot) {
		t.Errorf("five-year root %x, want %s", root, recordFiveYearRoot)
	}
	if total, _ := full.TotalWork(); total != WorkFromUint64(recordFiveYearWork) {
		t.Errorf("five-year total work %v, want %d", total, recordFiveYearWork)
	}
	leaf := func(i uint64) ([HashSize]byte, Work) { return fiveYearLeaf(t, i) }
	for _, v := range []struct {
		index, entries, before, reject uint64
	}{
		{0, 23, 0, 1},
		{4_200_000, 22, 70_464_307_200_000, 4_200_001},
		{recordFiveYearDepth - 1, 12, 88_181_047_296_000, recordFiveYearDepth - 2},
	} {
		checkVectorPath(t, "five years", build.mmr, full, root, v.index, v.entries, v.before, v.reject, leaf)
	}
	// The genesis path: 23 entries, 1,104 bytes, with the entries of the record.
	path := build.mmr.path(t, full, 0)
	if len(path) != 1104 {
		t.Fatalf("five-year genesis path of %d bytes, want 1104", len(path))
	}
	for k, want := range recordGenesisPathEntries {
		if got := hex.EncodeToString(path[48*k : 48*k+48]); got != want {
			t.Errorf("five-year genesis path entry %d:\n%s\nwant\n%s", k, got, want)
		}
	}
	if got := hex.EncodeToString(path); got != fiveYearGenesisPath {
		t.Errorf("five-year genesis path\n%s\nwant\n%s", got, fiveYearGenesisPath)
	}
}

// fiveYearGenesisPath is the record's header-mmr-path-five-years-genesis, 23
// entries of 48 bytes: the 22 siblings from the bottom, each the subtree of
// 2^k leaves after the genesis leaf, then the bag of the six later peaks.
const fiveYearGenesisPath = "" +
	"ea98f3073eabe1f43d9d6e6b13798a1db0c64146a596bbbec0c5dd5e17920af700000000000000000000000001000000" +
	"e1e2e752142155b2705894920e7db2e0d245ca3955983d2a04cf3a28d1e0df7d00000000000000000000000002000000" +
	"1f5eb73b832f8f8516e43a0d6e089c942a643357dacb3a93f553101f7080e7ec00000000000000000000000004000000" +
	"62ceb086561a4c565f04ac9bf9dfca830841412c7ec55c8be41a86b793f1c51a00000000000000000000000008000000" +
	"90cf377b55720533ce0b1ffda4eef441901aa51cb94695c1a18bb684b9d037ba00000000000000000000000010000000" +
	"e24f53f10b02602e6d8b7b5ce7d221a751e8093bb66f0c888085fdb844de19bd00000000000000000000000020000000" +
	"376eaf927ced55e1d6b9611e4978cf42728895028251410e635daaf89e40ff0c00000000000000000000000040000000" +
	"6e704259d84151237283e340d917422e0f8be813fb157a51a7af566e86aab6c100000000000000000000000080000000" +
	"d0ddccfbb6f202df2586f50ddb1454f2381f31bbb108541189d5779505f2f73300000000000000000000000100000000" +
	"04a7ad2c1e2b4cf48eb033ec6984fa9391586b0995fb9bbbf1f11acc1291a04700000000000000000000000200000000" +
	"a1bb0ee1bb469ba5fabb5dcd8e7715b8b71ef458bd229db20ba0e814a909c96300000000000000000000000400000000" +
	"46c6265cd85fcc75c01ecb3880339a08c31f8aa7bbfe58006d1498d6aab5b62a00000000000000000000000800000000" +
	"8f1be1db34cd942e378f9ef472c58003a50e13a5c72496f35513f1a3d2a80e0000000000000000000000001000000000" +
	"5ee783e7d624888f4db7dde9e27a0e6cb17d1e7be4e6093bb43bf5c3747e25af00000000000000000000002000000000" +
	"a93f028054e1ddf8e6fea6f9e1a8b61431b4e2d875240fcd0f922f8ac4aa2b8b00000000000000000000004000000000" +
	"7c6dfd35601a884f28aa3bac6b28fa73e7fe2c370f7a47507bc4fa00636c279a00000000000000000000008000000000" +
	"ee817eeb5d9b8394e346a9ef2d89231012a9c1d407d9c1f05b9b3c0124581ea300000000000000000000010000000000" +
	"8df51715f0b719776e6f76855927237d9c22c6ae4c180c147ecbce6833f5054b00000000000000000000020000000000" +
	"8893aa8f53d9f31c6e24c361a2e4b230c597831ada51a3ff5a125d5eff6d3e2800000000000000000000040000000000" +
	"56729dc9d4e0e8cc144125a757472bbcba52409284fd454e223ba20b43d8ca9f00000000000000000000080000000000" +
	"4d5ea36f534ed3c901c531ec272cfebb0087b813176dbe37c6708c705d640ad800000000000000000000100000000000" +
	"57f8398677e5c7c518cef4191b922656177f60a7ae968b27f9d1d0d89b77370d00000000000000000000200000000000" +
	"bf0b51b7e31f6453fcf73ede17c7b40997a6fa8ee336086e357638ce8918e9e100000000000000000000103344000000"

func checkVectorPath(t *testing.T, name string, m *memMMR, s State, root [HashSize]byte, index, entries, before, reject uint64, leaf func(uint64) ([HashSize]byte, Work)) {
	t.Helper()
	path := m.path(t, s, index)
	if uint64(len(path)) != 48*entries {
		t.Errorf("%s, leaf %d: path of %d bytes, want %d entries", name, index, len(path), entries)
	}
	if l, _ := PathLen(s.N, index); uint64(l) != entries {
		t.Errorf("%s, leaf %d: PathLen %d, want %d", name, index, l, entries)
	}
	hash, work := leaf(index)
	got, total, err := VerifyPath(root, s.N, index, hash, work, path)
	if err != nil {
		t.Fatalf("%s, leaf %d: %v", name, index, err)
	}
	if got != WorkFromUint64(before) {
		t.Errorf("%s, leaf %d: work before %v, want %d", name, index, got, before)
	}
	if want, _ := s.TotalWork(); total != want {
		t.Errorf("%s, leaf %d: total work %v, want %v", name, index, total, want)
	}
	if _, _, err := VerifyPath(root, s.N, reject, hash, work, path); err == nil {
		t.Errorf("%s, leaf %d: the path verifies at index %d", name, index, reject)
	}
	refRoot, refBefore, ok := refFold(s.N, index, hash, work.Big(), path)
	if !ok || !bytes.Equal(refRoot, root[:]) || refBefore.Cmp(new(big.Int).SetUint64(before)) != 0 {
		t.Errorf("%s, leaf %d: the independent fold gives %x before %v (%v)", name, index, refRoot, refBefore, ok)
	}
}

// TestHeaderMMRFiveYearPaths builds the MMR over five years of synthetic
// leaves and checks paths at depths up to the full five years: the first and
// the last leaf, the first and last leaf of every peak, the record's special
// leaves and a seeded random sample, each against the independent fold.
func TestHeaderMMRFiveYearPaths(t *testing.T) {
	build := buildFiveYears(t)
	rng := rand.New(rand.NewSource(5_256_000))
	for _, n := range fiveYearCheckpoints {
		s, ok := build.states[n]
		if !ok || s.N != n {
			t.Fatalf("no state kept at depth %d", n)
		}
		root, err := s.Root()
		if err != nil {
			t.Fatal(err)
		}
		indexes := map[uint64]bool{0: true, n - 1: true}
		var start uint64
		for h := 63; h >= 0; h-- {
			if n&(1<<uint(h)) != 0 {
				indexes[start] = true
				indexes[start+1<<uint(h)-1] = true
				start += 1 << uint(h)
			}
		}
		for _, special := range []uint64{1, 4_200_000, recordFiveYearDepth - 1} {
			if special < n {
				indexes[special] = true
			}
		}
		for k := 0; k < 24; k++ {
			indexes[uint64(rng.Int63n(int64(n)))] = true
		}
		maxLen := bits.Len64(n) // floor(log2 n) + 1
		for i := range indexes {
			path := build.mmr.path(t, s, i)
			if len(path)%48 != 0 || len(path)/48 > maxLen {
				t.Errorf("depth %d, leaf %d: path of %d bytes, more than %d entries", n, i, len(path), maxLen)
			}
			hash, work := fiveYearLeaf(t, i)
			refRoot, refBefore, ok := refFold(n, i, hash, work.Big(), path)
			if !ok || !bytes.Equal(refRoot, root[:]) {
				t.Fatalf("depth %d, leaf %d: the independent fold gives %x, the root is %x", n, i, refRoot, root)
			}
			before, _, err := VerifyPath(root, n, i, hash, work, path)
			if err != nil || before.Big().Cmp(refBefore) != 0 {
				t.Fatalf("depth %d, leaf %d: VerifyPath %v, work before %v, the fold's %v", n, i, err, before, refBefore)
			}
			// Another header at the same place does not verify.
			if _, _, err := VerifyPath(root, n, i, repeated(0x01), work, path); !errors.Is(err, ErrRootMismatch) {
				t.Fatalf("depth %d, leaf %d: another header: %v", n, i, err)
			}
		}
	}
	// The longest path at one year is 21 entries, 1,008 bytes; at five years
	// 23, 1,104 bytes.
	for _, c := range []struct {
		n    uint64
		want int
	}{{1_051_200, 21}, {recordFiveYearDepth, 23}} {
		if l, _ := PathLen(c.n, 0); l != c.want {
			t.Errorf("longest path at depth %d: %d entries, want %d", c.n, l, c.want)
		}
	}
}

// TestHeaderMMRSmallExhaustive checks every leaf of every MMR of up to 130
// distinct leaves against the independent fold, and that a path refuses a
// changed byte, another index, another leaf count and another length.
func TestHeaderMMRSmallExhaustive(t *testing.T) {
	m := newMemMMR()
	leafOf := func(i uint64) ([HashSize]byte, Work) {
		var h [HashSize]byte
		binary.BigEndian.PutUint64(h[:], i*0x9e3779b97f4a7c15)
		h[31] = byte(i)
		return h, WorkFromUint64(1000 + 7*i)
	}
	for n := uint64(1); n <= 130; n++ {
		hash, work := leafOf(n - 1)
		m.push(t, Leaf(hash, work))
		root, _ := m.Root()
		for i := uint64(0); i < n; i++ {
			path := m.path(t, m.State, i)
			hash, work := leafOf(i)
			refRoot, refBefore, ok := refFold(n, i, hash, work.Big(), path)
			if !ok || !bytes.Equal(refRoot, root[:]) {
				t.Fatalf("n %d, leaf %d: independent fold %x, root %x", n, i, refRoot, root)
			}
			before, _, err := VerifyPath(root, n, i, hash, work, path)
			if err != nil || before.Big().Cmp(refBefore) != 0 {
				t.Fatalf("n %d, leaf %d: %v, before %v want %v", n, i, err, before, refBefore)
			}
			if want := 1000*i + 7*i*(i-1)/2; before != WorkFromUint64(want) && i > 0 {
				t.Fatalf("n %d, leaf %d: work before %v, want %d", n, i, before, want)
			}
			if len(path) > 0 {
				bad := append([]byte{}, path...)
				bad[int(i)%len(bad)] ^= 0x40
				if _, _, err := VerifyPath(root, n, i, hash, work, bad); err == nil {
					t.Fatalf("n %d, leaf %d: a changed byte verifies", n, i)
				}
				if _, _, err := VerifyPath(root, n, i, hash, work, path[:len(path)-48]); !errors.Is(err, ErrPathLength) {
					t.Fatalf("n %d, leaf %d: a short path: %v", n, i, err)
				}
			}
			if _, _, err := VerifyPath(root, n, i, hash, work, append(append([]byte{}, path...), make([]byte, 48)...)); !errors.Is(err, ErrPathLength) {
				t.Fatalf("n %d, leaf %d: a long path: %v", n, i, err)
			}
			if _, _, err := VerifyPath(root, n+1, i, hash, work, path); err == nil {
				t.Fatalf("n %d, leaf %d: verifies with leaf count %d", n, i, n+1)
			}
			if _, _, err := VerifyPath(root, n, i, hash, WorkFromUint64(1), path); err == nil {
				t.Fatalf("n %d, leaf %d: verifies with another difficulty", n, i)
			}
			if n > 1 {
				other := (i + 1) % n
				if _, _, err := VerifyPath(root, n, other, hash, work, path); err == nil {
					t.Fatalf("n %d, leaf %d: verifies at index %d", n, i, other)
				}
			}
		}
		if _, _, err := VerifyPath(root, n, n, repeated(1), WorkFromUint64(1), nil); !errors.Is(err, ErrIndex) {
			t.Fatalf("n %d: index n: %v", n, err)
		}
	}
	if _, err := Path(m.State, 0, func([HashSize]byte) (Entry, Entry, bool, error) { return Entry{}, Entry{}, false, nil }); !errors.Is(err, ErrMissingNode) {
		t.Errorf("path without stored nodes: %v", err)
	}
	lying := func(h [HashSize]byte) (Entry, Entry, bool, error) {
		l, r, ok, _ := m.children(h)
		l.Work, _ = l.Work.Add(WorkFromUint64(1))
		return l, r, ok, nil
	}
	if _, err := Path(m.State, 0, lying); !errors.Is(err, ErrCorrupt) {
		t.Errorf("path over a wrong stored node: %v", err)
	}
}

func TestHeaderMMRWorkOverflow(t *testing.T) {
	max := Work{Hi: ^uint64(0), Lo: ^uint64(0)}
	if _, ok := max.Add(WorkFromUint64(1)); ok {
		t.Fatal("2^128 - 1 + 1 fits")
	}
	if _, err := WorkFromBig(two128); !errors.Is(err, ErrWorkOverflow) {
		t.Errorf("2^128 as work: %v", err)
	}
	if w, err := WorkFromBig(new(big.Int).Sub(two128, big.NewInt(1))); err != nil || w != max {
		t.Errorf("2^128 - 1 as work: %v %v", w, err)
	}
	half := Work{Hi: 1 << 63}
	s := State{}
	if err := s.Push(Leaf(repeated(1), half), nil); err != nil {
		t.Fatal(err)
	}
	before := s.Copy()
	// A second leaf of 2^127 brings the total to 2^128.
	if err := s.Push(Leaf(repeated(2), half), nil); !errors.Is(err, ErrWorkOverflow) {
		t.Fatalf("total work of 2^128: %v", err)
	}
	if s.N != before.N || len(s.Peaks) != len(before.Peaks) || s.Peaks[0] != before.Peaks[0] {
		t.Fatal("a refused push changed the state")
	}
	// Just below is fine, and a path whose sibling claims more work is refused.
	if err := s.Push(Leaf(repeated(2), Work{Hi: 1<<63 - 1, Lo: ^uint64(0)}), nil); err != nil {
		t.Fatal(err)
	}
	root, _ := s.Root()
	sibling := Entry{Hash: repeated(9), Work: half}
	b := sibling.Bytes()
	if _, _, err := VerifyPath(root, 2, 0, repeated(1), half, b[:]); !errors.Is(err, ErrWorkOverflow) {
		t.Errorf("a fold to 2^128: %v", err)
	}
	enc := State{N: 3, Peaks: []Entry{{Work: half}, {Work: half}}}.Encode()
	if _, err := DecodeState(enc); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a stored state of 2^128 work: %v", err)
	}
}

func TestHeaderMMRStateEncoding(t *testing.T) {
	m := newMemMMR()
	for i := 0; i < 11; i++ {
		m.push(t, Leaf(repeated(byte(i)), WorkFromUint64(uint64(i+1))))
		enc := m.Encode()
		if len(enc) != 8+48*bits.OnesCount64(m.N) {
			t.Fatalf("state of %d leaves encodes to %d bytes", m.N, len(enc))
		}
		back, err := DecodeState(enc)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := back.Root()
		b, _ := m.Root()
		if a != b || back.N != m.N {
			t.Fatalf("state of %d leaves does not round trip", m.N)
		}
		if _, err := DecodeState(enc[:len(enc)-1]); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("a truncated state decodes: %v", err)
		}
	}
	// Append leaves its receiver alone.
	before, _ := m.Root()
	next, inners, err := m.State.Append(Leaf(repeated(0xaa), WorkFromUint64(5)))
	if err != nil {
		t.Fatal(err)
	}
	if after, _ := m.Root(); after != before || next.N != m.N+1 {
		t.Fatal("Append changed its receiver")
	}
	// 11 leaves (1011) plus one merges the two lowest peaks: two inner nodes.
	if len(inners) != 2 || inners[1].Node != next.Peaks[len(next.Peaks)-1] {
		t.Fatalf("appending to 11 leaves made %d inner nodes", len(inners))
	}
	left, right, err := DecodeChildren(EncodeChildren(inners[0].Left, inners[0].Right))
	if err != nil || left != inners[0].Left || right != inners[0].Right {
		t.Fatal("children do not round trip")
	}
}
