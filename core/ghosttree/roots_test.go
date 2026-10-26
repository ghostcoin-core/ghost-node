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
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// stubChain is a header store with canonical pointers and the root index in
// a memory database, moved the way the blockchain moves them.
type stubChain struct {
	DBRootIndex
	db      ethdb.Database
	headers map[common.Hash]*types.Header
	canon   map[uint64]common.Hash
}

func newStubChain() *stubChain {
	db := rawdb.NewMemoryDatabase()
	return &stubChain{
		DBRootIndex: DBRootIndex{DB: db},
		db:          db,
		headers:     make(map[common.Hash]*types.Header),
		canon:       make(map[uint64]common.Hash),
	}
}

func (c *stubChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if h := c.headers[hash]; h != nil && h.Number.Uint64() == number {
		return h
	}
	return nil
}

func (c *stubChain) GetCanonicalHash(number uint64) common.Hash { return c.canon[number] }

// headersOnly is a chain without a root index.
type headersOnly struct{ chain *stubChain }

func (c headersOnly) GetHeader(hash common.Hash, number uint64) *types.Header {
	return c.chain.GetHeader(hash, number)
}

func (c headersOnly) GetCanonicalHash(number uint64) common.Hash {
	return c.chain.GetCanonicalHash(number)
}

// failingIndex is a chain whose index lookups fail.
type failingIndex struct{ *stubChain }

func (c failingIndex) RootFirstHeight(Kind, common.Hash) (uint64, bool, error) {
	return 0, false, errors.New("synthetic read failure")
}

func testRoot(kind Kind, i int) common.Hash {
	return K("ghost/test-root", []byte{byte(kind), byte(i >> 8), byte(i)})
}

// add stores a header on parent, nil for the genesis, with the given roots.
func (c *stubChain) add(parent *types.Header, coin, data common.Hash) *types.Header {
	marker := EmptyMarkerSetRoot
	h := &types.Header{
		Number:         big.NewInt(0),
		Difficulty:     big.NewInt(1),
		BaseFee:        big.NewInt(1),
		CoinTreeRoot:   &coin,
		DataTreeRoot:   &data,
		DataMarkerRoot: &marker,
		Extra:          []byte(fmt.Sprintf("stub %d", len(c.headers))),
	}
	if parent != nil {
		h.ParentHash = parent.Hash()
		h.Number = new(big.Int).Add(parent.Number, common.Big1)
	}
	c.headers[h.Hash()] = h
	return h
}

// extend adds n headers on parent, header i with the roots testRoot(kind,
// first+i), and returns them.
func (c *stubChain) extend(parent *types.Header, first, n int) []*types.Header {
	var out []*types.Header
	for i := 0; i < n; i++ {
		parent = c.add(parent, testRoot(Coin, first+i), testRoot(Data, first+i))
		out = append(out, parent)
	}
	return out
}

// setHead makes head the canonical head and moves the index with it.
func (c *stubChain) setHead(t *testing.T, head *types.Header) {
	t.Helper()
	for h := head; c.canon[h.Number.Uint64()] != h.Hash(); h = c.headers[h.ParentHash] {
		c.canon[h.Number.Uint64()] = h.Hash()
		if h.Number.Sign() == 0 {
			break
		}
	}
	for n := head.Number.Uint64() + 1; c.canon[n] != (common.Hash{}); n++ {
		delete(c.canon, n)
	}
	batch := c.db.NewBatch()
	if err := MoveRootIndex(c.db, c, batch, head); err != nil {
		t.Fatal(err)
	}
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
}

func dumpIndex(t *testing.T, db ethdb.Database) map[string]uint64 {
	t.Helper()
	out := make(map[string]uint64)
	err := rawdb.IterateGhostRootHeights(db, func(kind uint8, root common.Hash, number uint64) error {
		out[fmt.Sprintf("%v %x", Kind(kind), root)] = number
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wantEligible(t *testing.T, chain HeaderLookup, parent *types.Header, kind Kind, root common.Hash, want bool, what string) {
	t.Helper()
	got, err := EligibleRoot(chain, parent, kind, root)
	if err != nil {
		t.Errorf("%s: %v", what, err)
	} else if got != want {
		t.Errorf("%s: eligible %v, want %v", what, got, want)
	}
}

func wantNotReady(t *testing.T, chain HeaderLookup, parent *types.Header, kind Kind, root common.Hash, target error, what string) {
	t.Helper()
	got, err := EligibleRoot(chain, parent, kind, root)
	if got {
		t.Errorf("%s: eligible", what)
	}
	if !errors.Is(err, target) {
		t.Errorf("%s: error %v, want %v", what, err, target)
	}
}

// TestOldRootStaysEligible checks that roots of blocks far more than 300
// blocks below the including block stay eligible, from the canonical chain
// and from a side branch.
func TestOldRootStaysEligible(t *testing.T) {
	c := newStubChain()
	genesis := c.add(nil, EmptyRoot(Coin), EmptyRoot(Data))
	blocks := append([]*types.Header{genesis}, c.extend(genesis, 1, 400)...)
	head := blocks[400]
	c.setHead(t, head)

	for _, kind := range []Kind{Coin, Data} {
		wantEligible(t, c, head, kind, EmptyRoot(kind), true, fmt.Sprintf("%v genesis root, 401 blocks down", kind))
		wantEligible(t, c, head, kind, testRoot(kind, 5), true, fmt.Sprintf("%v root of block 5, 396 blocks down", kind))
		wantEligible(t, c, head, kind, testRoot(kind, 99), true, fmt.Sprintf("%v root of block 99, 302 blocks down", kind))
		wantEligible(t, c, head, kind, testRoot(kind, 1000), false, fmt.Sprintf("%v root of no block", kind))
	}
	// From a branch that leaves the canonical chain at block 390.
	side := c.extend(blocks[390], 2000, 5)
	wantEligible(t, c, side[4], Coin, testRoot(Coin, 5), true, "root of block 5 from a side branch")
	wantEligible(t, c, side[4], Coin, testRoot(Coin, 2001), true, "root of the side branch's own earlier block")
	wantEligible(t, c, side[4], Coin, testRoot(Coin, 395), false, "root of a canonical block above the fork")
}

// TestOwnAndLaterRootsAreNotEligible checks that the parent's root is eligible
// only for a block above the parent, and that the including block's own
// root, a later block's root and a root of the other kind are not.
func TestOwnAndLaterRootsAreNotEligible(t *testing.T) {
	c := newStubChain()
	genesis := c.add(nil, EmptyRoot(Coin), EmptyRoot(Data))
	blocks := append([]*types.Header{genesis}, c.extend(genesis, 1, 10)...)
	c.setHead(t, blocks[10])

	for _, kind := range []Kind{Coin, Data} {
		other := Data
		if kind == Data {
			other = Coin
		}
		// Including block 6, parent 5.
		wantEligible(t, c, blocks[5], kind, testRoot(kind, 5), true, fmt.Sprintf("%v root of the parent", kind))
		wantEligible(t, c, blocks[5], kind, testRoot(kind, 1), true, fmt.Sprintf("%v root of an earlier block", kind))
		wantEligible(t, c, blocks[5], kind, testRoot(kind, 6), false, fmt.Sprintf("%v root of the including block", kind))
		wantEligible(t, c, blocks[5], kind, testRoot(kind, 8), false, fmt.Sprintf("%v root of a later block", kind))
		wantEligible(t, c, blocks[5], other, testRoot(kind, 5), false, fmt.Sprintf("%v root of the parent as a %v root", kind, other))
		// Including block 5, parent 4: block 5's root is its own.
		wantEligible(t, c, blocks[4], kind, testRoot(kind, 5), false, fmt.Sprintf("%v root of block 5 for block 5", kind))
		// Including block 11 above the head, and the head itself.
		wantEligible(t, c, blocks[10], kind, testRoot(kind, 10), true, fmt.Sprintf("%v root of the head for the next block", kind))
		wantEligible(t, c, blocks[9], kind, testRoot(kind, 10), false, fmt.Sprintf("%v root of the head for the head", kind))
	}

	// A block that repeats an ancestor's root: eligible through the ancestor.
	repeat := c.add(blocks[10], testRoot(Coin, 3), testRoot(Data, 11))
	c.setHead(t, repeat)
	wantEligible(t, c, blocks[10], Coin, testRoot(Coin, 3), true, "own root also carried by block 3")
	wantEligible(t, c, blocks[10], Data, testRoot(Data, 11), false, "own data root carried by no ancestor")

	// On a side branch from block 5, a canonical block's later root is
	// outside the ancestry, and the branch's own block is not its own
	// ancestor.
	side := c.extend(blocks[5], 100, 3)
	wantEligible(t, c, side[1], Coin, testRoot(Coin, 100), true, "side branch: root of its earlier block")
	wantEligible(t, c, side[1], Coin, testRoot(Coin, 101), true, "side branch: root of the parent")
	wantEligible(t, c, side[1], Coin, testRoot(Coin, 102), false, "side branch: own root")
	wantEligible(t, c, side[1], Coin, testRoot(Coin, 7), false, "side branch: canonical root above the fork")
	wantEligible(t, c, side[1], Coin, testRoot(Coin, 5), true, "side branch: root of the fork block")
	wantEligible(t, c, side[1], Data, testRoot(Coin, 100), false, "side branch: coin root as a data root")
}

// TestIndexNotReadyRejects checks that a missing, lagging, stale or failing
// index, and a missing header, give an error and never true.
func TestIndexNotReadyRejects(t *testing.T) {
	c := newStubChain()
	genesis := c.add(nil, EmptyRoot(Coin), EmptyRoot(Data))
	blocks := append([]*types.Header{genesis}, c.extend(genesis, 1, 10)...)
	root := testRoot(Coin, 3)

	// Headers and canonical pointers without an index, as a database
	// written before the index existed.
	for _, b := range blocks {
		c.canon[b.Number.Uint64()] = b.Hash()
	}
	wantNotReady(t, c, blocks[10], Coin, root, ErrIndexNotReady, "no index yet")
	if n := len(dumpIndex(t, c.db)); n != 0 {
		t.Fatalf("%d entries before the index was built", n)
	}

	// Built from the stored headers, it answers.
	c.setHead(t, blocks[10])
	wantEligible(t, c, blocks[10], Coin, root, true, "index built")

	// Marked not ready.
	if err := rawdb.DeleteGhostRootIndexHead(c.db); err != nil {
		t.Fatal(err)
	}
	wantNotReady(t, c, blocks[10], Coin, root, ErrIndexNotReady, "index head removed")
	wantNotReady(t, c, blocks[10], Coin, testRoot(Coin, 1000), ErrIndexNotReady, "unknown root, index head removed")
	c.setHead(t, blocks[10])

	// The canonical chain went on without the index, as in a header sync.
	more := c.extend(blocks[10], 11, 3)
	for _, b := range more {
		c.canon[b.Number.Uint64()] = b.Hash()
	}
	wantNotReady(t, c, more[2], Coin, root, ErrIndexNotReady, "index behind the canonical head")
	side := c.extend(more[0], 50, 2)
	wantNotReady(t, c, side[1], Coin, root, ErrIndexNotReady, "side branch forking above the index head")
	wantNotReady(t, c, side[1], Coin, testRoot(Coin, 50), ErrIndexNotReady, "root on a side branch forking above the index head")
	wantEligible(t, c, blocks[8], Coin, root, true, "parent below the index head")

	// The canonical pointers moved to another branch below the index head.
	saved := c.canon[10]
	c.canon[10] = common.Hash{0x01}
	wantNotReady(t, c, blocks[8], Coin, root, ErrIndexNotReady, "index head no longer canonical")
	c.canon[10] = saved
	c.setHead(t, more[2])

	// No index at all, and failing index reads.
	wantNotReady(t, headersOnly{c}, more[2], Coin, root, ErrIndexNotReady, "chain without an index")
	wantNotReady(t, failingIndex{c}, more[2], Coin, root, ErrRootLookup, "index read fails")

	// A missing header on the including block's branch.
	orphanParent := c.add(blocks[5], testRoot(Coin, 60), testRoot(Data, 60))
	orphan := c.add(orphanParent, testRoot(Coin, 61), testRoot(Data, 61))
	delete(c.headers, orphanParent.Hash())
	wantNotReady(t, c, orphan, Coin, root, ErrRootLookup, "missing header on the branch")
	wantNotReady(t, c, nil, Coin, root, ErrRootLookup, "no parent")

	// An entry that no canonical header backs.
	if err := rawdb.WriteGhostRootHeight(c.db, uint8(Coin), testRoot(Coin, 70), 4); err != nil {
		t.Fatal(err)
	}
	wantNotReady(t, c, more[2], Coin, testRoot(Coin, 70), ErrRootLookup, "entry without its header")

	// An unknown kind.
	if ok, err := EligibleRoot(c, more[2], Kind(2), root); ok || !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: %v, %v", ok, err)
	}
}

// TestRootIndexAfterReorgEqualsFreshIndex moves the index across branches
// and back and compares it with an index built from scratch each time.
func TestRootIndexAfterReorgEqualsFreshIndex(t *testing.T) {
	c := newStubChain()
	genesis := c.add(nil, EmptyRoot(Coin), EmptyRoot(Data))
	trunk := c.extend(genesis, 1, 5)
	c.setHead(t, trunk[4])
	a := c.extend(trunk[4], 10, 4)
	// Branch B repeats a trunk root and a root of branch A.
	b1 := c.add(trunk[4], testRoot(Coin, 2), testRoot(Data, 20))
	b2 := c.add(b1, testRoot(Coin, 11), testRoot(Data, 21))
	b3 := c.add(b2, testRoot(Coin, 22), testRoot(Data, 22))
	for _, step := range []struct {
		name string
		head *types.Header
	}{
		{"branch A", a[3]},
		{"branch B", b3},
		{"back to A, partly", a[1]},
		{"rewind to the trunk", trunk[2]},
		{"branch B again", b2},
	} {
		c.setHead(t, step.head)
		fresh := newStubChain()
		fresh.headers = c.headers
		fresh.setHead(t, step.head)
		got, want := dumpIndex(t, c.db), dumpIndex(t, fresh.db)
		if len(got) != len(want) {
			t.Errorf("%s: %d entries, fresh index %d", step.name, len(got), len(want))
		}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("%s: %s at %d, fresh index %d", step.name, k, got[k], n)
			}
		}
	}
}

// TestEmptyMarkerSetRoot checks the root of the empty data marker set
// against spec 05 vector marker-set-empty, and that DataMarkerRoot gives it
// for every state until the node keeps the marker-set tree.
func TestEmptyMarkerSetRoot(t *testing.T) {
	want := common.HexToHash("0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3")
	if EmptyMarkerSetRoot != want {
		t.Fatalf("EmptyMarkerSetRoot %x, want %x", EmptyMarkerSetRoot, want)
	}
	st := newState(t)
	if got, err := DataMarkerRoot(st); err != nil || got != want {
		t.Errorf("empty state: %x, %v; want %x", got, err, want)
	}
	if _, err := Append(st, Coin, 1, testLeaf(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(st, Data, 1, testLeaf(2)); err != nil {
		t.Fatal(err)
	}
	if got, err := DataMarkerRoot(st); err != nil || got != want {
		t.Errorf("one coin and one data leaf: %x, %v; want %x", got, err, want)
	}
}
