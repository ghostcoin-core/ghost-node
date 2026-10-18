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
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

func newState(t *testing.T) *state.StateDB {
	t.Helper()
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// testLeaf is a distinct non-zero leaf for each i.
func testLeaf(i int) common.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return K("ghost/test-leaf", b[:])
}

// naiveLevels builds the tree over leaves level by level, padding with the
// empty subtree of each level; levels[l] holds the nodes of height l in use.
func naiveLevels(kind Kind, depth int, leaves []common.Hash) [][]common.Hash {
	z := zeros(kind, depth)
	levels := [][]common.Hash{leaves}
	for l := 0; l < depth; l++ {
		below := levels[l]
		var next []common.Hash
		for i := 0; i < len(below); i += 2 {
			right := z[l]
			if i+1 < len(below) {
				right = below[i+1]
			}
			next = append(next, node(kind, l, below[i], right))
		}
		levels = append(levels, next)
	}
	return levels
}

func naiveRoot(kind Kind, depth int, leaves []common.Hash) common.Hash {
	levels := naiveLevels(kind, depth, leaves)
	if top := levels[depth]; len(top) == 1 {
		return top[0]
	}
	return zeros(kind, depth)[depth]
}

// naivePath returns the siblings of the leaf at position.
func naivePath(kind Kind, leaves []common.Hash, position int) [32]common.Hash {
	levels := naiveLevels(kind, 32, leaves)
	z := zeros(kind, 32)
	var siblings [32]common.Hash
	for l := 0; l < 32; l++ {
		i := (position >> l) ^ 1
		if i < len(levels[l]) {
			siblings[l] = levels[l][i]
		} else {
			siblings[l] = z[l]
		}
	}
	return siblings
}

func mustRoot(t *testing.T, p Params, st StateDB, kind Kind) common.Hash {
	t.Helper()
	r, err := root(p, st, kind)
	if err != nil {
		t.Fatalf("%v root: %v", kind, err)
	}
	return r
}

func setUint(st *state.StateDB, kind Kind, slot int, v uint64) {
	st.SetState(TreeAccount(kind), Slot(uint64(slot)), word(v))
}

func getUint(t *testing.T, st StateDB, kind Kind, slot int) uint64 {
	t.Helper()
	v, ok := readUint(st.GetState(TreeAccount(kind), Slot(uint64(slot))))
	if !ok {
		t.Fatalf("%v slot %d out of range", kind, slot)
	}
	return v
}

// prefill writes a tree state directly into storage, with arbitrary non-zero
// frontier values, as spec TH-3 does.
func prefill(st *state.StateDB, p Params, kind Kind, index, count, lastFilled uint64) {
	addr := TreeAccount(kind)
	ensureAccount(st, addr)
	setUint(st, kind, SlotTreeIndex, index)
	setUint(st, kind, SlotLeafCount, count)
	setUint(st, kind, SlotLastFilled, lastFilled)
	for l := 0; l < p.Depth; l++ {
		st.SetState(addr, Slot(uint64(SlotFrontier+l)), K("ghost/test-frontier", []byte{byte(kind), byte(l)}))
	}
	if count == p.capacity() {
		st.SetState(addr, Slot(SlotFinalRoot), K("ghost/test-final-root", []byte{byte(kind)}))
	}
}

func TestEmptyTreeRoots(t *testing.T) {
	want := map[Kind]common.Hash{
		Coin: common.HexToHash("8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8"),
		Data: common.HexToHash("3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03"),
	}
	st := newState(t)
	for kind, w := range want {
		if got := EmptyRoot(kind); got != w {
			t.Errorf("%v: empty root %x, want %x", kind, got, w)
		}
		if got := naiveRoot(kind, 32, nil); got != w {
			t.Errorf("%v: naive empty root %x, want %x", kind, got, w)
		}
		got, err := Root(st, kind)
		if err != nil || got != w {
			t.Errorf("%v: root of an absent account %x (%v), want %x", kind, got, err, w)
		}
	}
	if st.Exist(ghost.CoinTreeAccount) || st.Exist(ghost.DataTreeAccount) {
		t.Error("reading a root created an account")
	}
}

func TestTreeRootVectors(t *testing.T) {
	for _, v := range []struct {
		name   string
		kind   Kind
		leaves []string
		root   string
	}{
		{"coin-tree-two-leaves", Coin, []string{
			"562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458",
			"93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15",
		}, "142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5"},
		{"data-tree-one-leaf", Data, []string{
			"39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06",
		}, "dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a"},
	} {
		st := newState(t)
		var leaves []common.Hash
		for i, s := range v.leaves {
			leaf := common.HexToHash(s)
			leaves = append(leaves, leaf)
			res, err := Append(st, v.kind, 1, leaf)
			if err != nil {
				t.Fatalf("%s: append %d: %v", v.name, i, err)
			}
			if res != (AppendResult{Kind: v.kind, TreeIndex: 0, Position: uint32(i), Leaf: leaf}) {
				t.Errorf("%s: append %d: %+v", v.name, i, res)
			}
		}
		want := common.HexToHash(v.root)
		if got, err := Root(st, v.kind); err != nil || got != want {
			t.Errorf("%s: root %x (%v), want %x", v.name, got, err, want)
		}
		if got := naiveRoot(v.kind, 32, leaves); got != want {
			t.Errorf("%s: naive root %x, want %x", v.name, got, want)
		}
		other := Data
		if v.kind == Data {
			other = Coin
		}
		if got, _ := Root(st, other); got != EmptyRoot(other) {
			t.Errorf("%s: the %v tree changed", v.name, other)
		}
	}
}

// TestAppendMatchesNaiveRoot appends to small trees up to full, and to the
// release tree for a while, comparing every root with a full recomputation.
func TestAppendMatchesNaiveRoot(t *testing.T) {
	for _, depth := range []int{1, 2, 3, 5} {
		p := Params{Depth: depth}
		for _, kind := range []Kind{Coin, Data} {
			st := newState(t)
			var leaves []common.Hash
			for n := 0; ; n++ {
				if got, want := mustRoot(t, p, st, kind), naiveRoot(kind, depth, leaves); got != want {
					t.Fatalf("depth %d, %v, %d leaves: root %x, want %x", depth, kind, n, got, want)
				}
				if uint64(n) == p.capacity() {
					break
				}
				leaf := testLeaf(n)
				res, err := appendLeaf(p, st, kind, 7, leaf)
				if err != nil {
					t.Fatalf("depth %d, append %d: %v", depth, n, err)
				}
				if res.Position != uint32(n) || res.TreeIndex != 0 {
					t.Fatalf("depth %d, append %d: %+v", depth, n, res)
				}
				leaves = append(leaves, leaf)
			}
			if got := getUint(t, st, kind, SlotLastFilled); got != 7 {
				t.Errorf("depth %d: last filled height %d, want 7", depth, got)
			}
			if got := st.GetState(TreeAccount(kind), Slot(SlotFinalRoot)); got != naiveRoot(kind, depth, leaves) {
				t.Errorf("depth %d: final root %x", depth, got)
			}
		}
	}
	st := newState(t)
	var leaves []common.Hash
	for n := 0; n < 70; n++ {
		leaf := testLeaf(n)
		if _, err := Append(st, Coin, 1, leaf); err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, leaf)
		if got, want := mustRoot(t, Release, st, Coin), naiveRoot(Coin, 32, leaves); got != want {
			t.Fatalf("release depth, %d leaves: root %x, want %x", n+1, got, want)
		}
	}
}

// appendCase is one rollover vector of spec 05, section 11.
type appendCase struct {
	name                       string
	indexBefore, countBefore   uint64
	filledThisBlock            bool
	includable                 bool
	indexAfter, countAfter     uint64
	position                   uint32
	lastFilledAfterIsThisBlock bool
}

// runAppendCase prefills the coin tree, appends one leaf in the block at
// height 100 and checks the outcome against c and the data tree unchanged.
func runAppendCase(t *testing.T, p Params, c appendCase) error {
	t.Helper()
	const height = 100
	st := newState(t)
	lastFilled := uint64(40)
	if c.filledThisBlock {
		lastFilled = height
	}
	prefill(st, p, Coin, c.indexBefore, c.countBefore, lastFilled)
	dataLeaf := testLeaf(1000)
	if _, err := appendLeaf(p, st, Data, height, dataLeaf); err != nil {
		t.Fatalf("%s: data append: %v", c.name, err)
	}
	dataRoot := mustRoot(t, p, st, Data)
	before := st.Copy()

	leaf := testLeaf(1)
	res, err := appendLeaf(p, st, Coin, height, leaf)
	if c.includable != (err == nil) {
		t.Fatalf("%s: includable %v, error %v", c.name, c.includable, err)
	}
	if got := getUint(t, st, Coin, SlotTreeIndex); got != c.indexAfter {
		t.Errorf("%s: index after %d, want %d", c.name, got, c.indexAfter)
	}
	if got := getUint(t, st, Coin, SlotLeafCount); got != c.countAfter {
		t.Errorf("%s: count after %d, want %d", c.name, got, c.countAfter)
	}
	if err != nil {
		for i := uint64(0); i < SlotFrontier+MaxDepth; i++ {
			if a, b := st.GetState(TreeAccount(Coin), Slot(i)), before.GetState(TreeAccount(Coin), Slot(i)); a != b {
				t.Errorf("%s: a rejected append changed slot %d", c.name, i)
			}
		}
	} else {
		if res != (AppendResult{Kind: Coin, TreeIndex: c.indexAfter, Position: c.position, Leaf: leaf}) {
			t.Errorf("%s: result %+v", c.name, res)
		}
		wantFilled := lastFilled
		if c.lastFilledAfterIsThisBlock {
			wantFilled = height
		}
		if got := getUint(t, st, Coin, SlotLastFilled); got != wantFilled {
			t.Errorf("%s: last filled height %d, want %d", c.name, got, wantFilled)
		}
	}
	if got := mustRoot(t, p, st, Data); got != dataRoot {
		t.Errorf("%s: the data tree changed", c.name)
	}
	if _, err := appendLeaf(p, st, Data, height, testLeaf(1001)); err != nil {
		t.Errorf("%s: a data append after it: %v", c.name, err)
	}
	return err
}

func TestRolloverStartsNextTree(t *testing.T) {
	for _, p := range []Params{{Depth: 3}, Release} {
		full := p.capacity()
		for _, c := range []appendCase{
			{name: "append-ordinary", indexBefore: 0, countBefore: 2, includable: true, indexAfter: 0, countAfter: 3, position: 2},
			{name: "append-fills-tree", indexBefore: 0, countBefore: full - 1, includable: true, indexAfter: 0, countAfter: full, position: uint32(full - 1), lastFilledAfterIsThisBlock: true},
			{name: "rollover", indexBefore: 0, countBefore: full, includable: true, indexAfter: 1, countAfter: 1, position: 0},
		} {
			runAppendCase(t, p, c)
		}
	}

	// The rollover in detail: the next tree holds just the leaf, its frontier
	// and final root are cleared, and the full tree's root came out of the
	// filling append.
	p := Params{Depth: 3}
	st := newState(t)
	var leaves []common.Hash
	for i := 0; i < 8; i++ {
		leaves = append(leaves, testLeaf(i))
		if _, err := appendLeaf(p, st, Coin, 5, leaves[i]); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustRoot(t, p, st, Coin); got != naiveRoot(Coin, 3, leaves) {
		t.Fatalf("full tree root %x", got)
	}
	leaf := testLeaf(100)
	res, err := appendLeaf(p, st, Coin, 6, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if res.TreeIndex != 1 || res.Position != 0 {
		t.Errorf("rollover went to %+v", res)
	}
	if got, want := mustRoot(t, p, st, Coin), naiveRoot(Coin, 3, []common.Hash{leaf}); got != want {
		t.Errorf("root of the next tree %x, want %x", got, want)
	}
	if got := st.GetState(TreeAccount(Coin), Slot(SlotFinalRoot)); got != (common.Hash{}) {
		t.Errorf("final root not cleared: %x", got)
	}
	for l := 1; l < 3; l++ {
		if got := st.GetState(TreeAccount(Coin), Slot(uint64(SlotFrontier+l))); got != (common.Hash{}) {
			t.Errorf("frontier slot %d not cleared", l)
		}
	}
	if got := getUint(t, st, Coin, SlotLastFilled); got != 5 {
		t.Errorf("last filled height %d, want 5", got)
	}

	// At release depth from a prefilled full tree (TH-3): tree 1 with one leaf.
	st = newState(t)
	prefill(st, Release, Coin, 0, Release.capacity(), 9)
	if _, err := Append(st, Coin, 10, leaf); err != nil {
		t.Fatal(err)
	}
	if got, want := mustRoot(t, Release, st, Coin), naiveRoot(Coin, 32, []common.Hash{leaf}); got != want {
		t.Errorf("release rollover root %x, want %x", got, want)
	}
}

func TestFillingBlockBlocksSecondIndex(t *testing.T) {
	for _, p := range []Params{{Depth: 3}, Release} {
		err := runAppendCase(t, p, appendCase{name: "rollover-in-filling-block", indexBefore: 0, countBefore: p.capacity(), filledThisBlock: true, includable: false, indexAfter: 0, countAfter: p.capacity()})
		if !errors.Is(err, ErrFillingBlock) {
			t.Errorf("depth %d: error %v, want %v", p.Depth, err, ErrFillingBlock)
		}
	}

	// TH-4: fill in block 5, the next append in block 5 is refused and is
	// accepted in block 6; a data append in block 5 is accepted.
	p := Params{Depth: 2}
	st := newState(t)
	for i := 0; i < 4; i++ {
		if _, err := appendLeaf(p, st, Coin, 5, testLeaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := appendLeaf(p, st, Coin, 5, testLeaf(4)); !errors.Is(err, ErrFillingBlock) {
		t.Fatalf("second index in the filling block: %v, want %v", err, ErrFillingBlock)
	}
	if _, err := appendLeaf(p, st, Data, 5, testLeaf(5)); err != nil {
		t.Fatalf("data append in the filling block: %v", err)
	}
	res, err := appendLeaf(p, st, Coin, 6, testLeaf(4))
	if err != nil || res.TreeIndex != 1 || res.Position != 0 {
		t.Fatalf("the same append in the next block: %+v, %v", res, err)
	}
}

func TestIndexExhaustedRejects(t *testing.T) {
	for _, p := range []Params{{Depth: 3}, Release} {
		err := runAppendCase(t, p, appendCase{name: "rollover-index-exhausted", indexBefore: math.MaxUint64, countBefore: p.capacity(), includable: false, indexAfter: math.MaxUint64, countAfter: p.capacity()})
		if !errors.Is(err, ErrIndexExhausted) {
			t.Errorf("depth %d: error %v, want %v", p.Depth, err, ErrIndexExhausted)
		}
		// One index below the last still rolls over.
		runAppendCase(t, p, appendCase{name: "rollover to the last index", indexBefore: math.MaxUint64 - 1, countBefore: p.capacity(), includable: true, indexAfter: math.MaxUint64, countAfter: 1, position: 0})
	}
}

func TestReleaseDepthIsThirtyTwo(t *testing.T) {
	if Release.Depth != 32 {
		t.Fatalf("release depth %d", Release.Depth)
	}
	if err := Release.Check(); err != nil {
		t.Fatalf("release parameters refused: %v", err)
	}
	if Release.capacity() != 1<<32 {
		t.Errorf("release capacity %d", Release.capacity())
	}
	for _, d := range []int{0, 1, 3, 16, 31, 33, 64} {
		if err := (Params{Depth: d}).Check(); !errors.Is(err, ErrDepth) {
			t.Errorf("depth %d: Check %v, want %v", d, err, ErrDepth)
		}
	}
	for _, d := range []int{0, 33} {
		if _, err := root(Params{Depth: d}, newState(t), Coin); !errors.Is(err, ErrDepth) {
			t.Errorf("depth %d: root %v, want %v", d, err, ErrDepth)
		}
	}
	// The frontier of the release tree fills slots 4 to 35 and no more.
	st := newState(t)
	prefill(st, Release, Coin, 0, Release.capacity()-1, 0)
	if _, err := Append(st, Coin, 1, testLeaf(0)); err != nil {
		t.Fatal(err)
	}
	if got := st.GetState(TreeAccount(Coin), Slot(SlotFrontier+32)); got != (common.Hash{}) {
		t.Error("a 33rd frontier slot was written")
	}
	if SlotFrontier+MaxDepth-1 != 35 {
		t.Errorf("the last frontier slot is %d, want 35", SlotFrontier+MaxDepth-1)
	}
}

func TestCorruptTreeStateRejects(t *testing.T) {
	twoTo64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for _, c := range []struct {
		name  string
		setup func(st *state.StateDB)
	}{
		{"count above 2^32", func(st *state.StateDB) {
			setUint(st, Coin, SlotLeafCount, 1<<32+1)
		}},
		{"count above 2^64", func(st *state.StateDB) {
			st.SetState(TreeAccount(Coin), Slot(SlotLeafCount), common.BigToHash(twoTo64))
		}},
		{"tree index above 2^64", func(st *state.StateDB) {
			st.SetState(TreeAccount(Coin), Slot(SlotTreeIndex), common.BigToHash(twoTo64))
		}},
		{"set bit with a zero frontier slot", func(st *state.StateDB) {
			setUint(st, Coin, SlotLeafCount, 3)
			st.SetState(TreeAccount(Coin), Slot(SlotFrontier), testLeaf(0))
		}},
		{"full tree without a final root", func(st *state.StateDB) {
			prefill(st, Release, Coin, 0, Release.capacity(), 1)
			st.SetState(TreeAccount(Coin), Slot(SlotFinalRoot), common.Hash{})
		}},
		{"final root on a tree not full", func(st *state.StateDB) {
			prefill(st, Release, Coin, 0, 4, 0)
			st.SetState(TreeAccount(Coin), Slot(SlotFinalRoot), testLeaf(9))
		}},
	} {
		st := newState(t)
		c.setup(st)
		if r, err := Root(st, Coin); !errors.Is(err, ErrCorruptTreeState) {
			t.Errorf("%s: root %x, error %v; want %v", c.name, r, err, ErrCorruptTreeState)
		}
		before := st.Copy()
		if _, err := Append(st, Coin, 1, testLeaf(1)); !errors.Is(err, ErrCorruptTreeState) {
			t.Errorf("%s: append error %v, want %v", c.name, err, ErrCorruptTreeState)
		}
		for i := uint64(0); i < SlotFrontier+MaxDepth; i++ {
			if st.GetState(TreeAccount(Coin), Slot(i)) != before.GetState(TreeAccount(Coin), Slot(i)) {
				t.Errorf("%s: a refused append wrote slot %d", c.name, i)
			}
		}
		if _, err := Root(st, Data); err != nil {
			t.Errorf("%s: the data tree is unreadable: %v", c.name, err)
		}
	}
	// A zero leaf is refused, and an unknown kind.
	st := newState(t)
	if _, err := Append(st, Coin, 1, common.Hash{}); !errors.Is(err, ErrZeroLeaf) {
		t.Errorf("zero leaf: %v", err)
	}
	if _, err := Append(st, Kind(2), 1, testLeaf(0)); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: %v", err)
	}
	if _, err := Root(st, Kind(2)); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind root: %v", err)
	}
}

func TestMembershipPathVerifiesAgainstHeaderAlone(t *testing.T) {
	st := newState(t)
	var coinLeaves, dataLeaves []common.Hash
	for i := 0; i < 5; i++ {
		coinLeaves = append(coinLeaves, testLeaf(i))
		dataLeaves = append(dataLeaves, testLeaf(100+i))
		if _, err := Append(st, Coin, 1, coinLeaves[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := Append(st, Data, 1, dataLeaves[i]); err != nil {
			t.Fatal(err)
		}
	}
	coinRoot, dataRoot := mustRoot(t, Release, st, Coin), mustRoot(t, Release, st, Data)
	// Only the header travels to the verifier.
	header := &types.Header{Number: big.NewInt(1), CoinTreeRoot: &coinRoot, DataTreeRoot: &dataRoot}

	for i, leaf := range coinLeaves {
		path := naivePath(Coin, coinLeaves, i)
		if !VerifyMembership(header, Coin, uint32(i), leaf, path) {
			t.Errorf("coin leaf %d does not verify", i)
		}
		if VerifyMembership(header, Data, uint32(i), leaf, path) {
			t.Errorf("coin leaf %d verifies as data", i)
		}
		if VerifyMembership(header, Coin, uint32(i)^1, leaf, path) {
			t.Errorf("coin leaf %d verifies at position %d", i, i^1)
		}
		if VerifyMembership(header, Coin, uint32(i)|1<<31, leaf, path) {
			t.Errorf("coin leaf %d verifies at a far position", i)
		}
		for l := 0; l < 32; l += 7 {
			bad := path
			bad[l][31] ^= 1
			if VerifyMembership(header, Coin, uint32(i), leaf, bad) {
				t.Errorf("coin leaf %d verifies with sibling %d changed", i, l)
			}
		}
		if VerifyMembership(header, Coin, uint32(i), dataLeaves[i], path) {
			t.Errorf("a data leaf verifies at coin position %d", i)
		}
	}
	for i, leaf := range dataLeaves {
		if !VerifyMembership(header, Data, uint32(i), leaf, naivePath(Data, dataLeaves, i)) {
			t.Errorf("data leaf %d does not verify", i)
		}
	}
	// The same path against a header that lacks the root, or another header.
	path := naivePath(Coin, coinLeaves, 2)
	if VerifyMembership(&types.Header{Number: big.NewInt(1), DataTreeRoot: &dataRoot}, Coin, 2, coinLeaves[2], path) {
		t.Error("verifies against a nil coin root")
	}
	if VerifyMembership(nil, Coin, 2, coinLeaves[2], path) {
		t.Error("verifies against no header")
	}
	if VerifyMembership(header, Kind(2), 2, coinLeaves[2], path) {
		t.Error("verifies for an unknown kind")
	}
	other := EmptyRoot(Coin)
	if VerifyMembership(&types.Header{CoinTreeRoot: &other, DataTreeRoot: &dataRoot}, Coin, 2, coinLeaves[2], path) {
		t.Error("verifies against the empty tree's header")
	}
}
