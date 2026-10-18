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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

func testMarker(i byte) common.Hash { return K("ghost/test-marker", []byte{i}) }

// commitAndReopen commits st with empty-object deletion on, as every block
// after EIP-161 does, and opens the committed state afresh.
func commitAndReopen(t *testing.T, sdb state.Database, st *state.StateDB, block uint64) *state.StateDB {
	t.Helper()
	st.Finalise(true)
	root, err := st.Commit(block, true)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := state.New(root, sdb, nil)
	if err != nil {
		t.Fatal(err)
	}
	return reopened
}

func TestRepeatedMarkerIsRejected(t *testing.T) {
	sdb := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(types.EmptyRootHash, sdb, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := testMarker(1)
	if IsSpent(st, Coin, m) {
		t.Fatal("a fresh marker is spent")
	}
	if err := MarkSpent(st, Coin, m); err != nil {
		t.Fatal(err)
	}
	if !IsSpent(st, Coin, m) {
		t.Fatal("a marked marker is not spent")
	}
	// Again in the same block: the state already holds it.
	if err := MarkSpent(st, Coin, m); !errors.Is(err, ErrMarkerSpent) {
		t.Errorf("repeat in the same block: %v, want %v", err, ErrMarkerSpent)
	}
	// And in a later block.
	st = commitAndReopen(t, sdb, st, 1)
	if err := MarkSpent(st, Coin, m); !errors.Is(err, ErrMarkerSpent) {
		t.Errorf("repeat in a later block: %v, want %v", err, ErrMarkerSpent)
	}
	if err := MarkSpent(st, Coin, testMarker(2)); err != nil {
		t.Errorf("another marker: %v", err)
	}
	if err := MarkSpent(st, Kind(7), testMarker(3)); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: %v", err)
	}
	if !IsSpent(st, Kind(7), testMarker(3)) {
		t.Error("a marker of an unknown kind does not count as spent")
	}
}

func TestMarkerSetsAreSeparate(t *testing.T) {
	st := newState(t)
	m := testMarker(1)
	// A data marker value written into the coin set (TH-13).
	if err := MarkSpent(st, Coin, m); err != nil {
		t.Fatal(err)
	}
	if IsSpent(st, Data, m) {
		t.Fatal("a coin marker counts as a spent data marker")
	}
	if err := MarkSpent(st, Data, m); err != nil {
		t.Fatalf("the data set refuses a value spent in the coin set: %v", err)
	}
	n := testMarker(2)
	if err := MarkSpent(st, Data, n); err != nil {
		t.Fatal(err)
	}
	if IsSpent(st, Coin, n) {
		t.Error("a data marker counts as a spent coin marker")
	}
	if got := st.GetState(ghost.CoinMarkerAccount, n); got != (common.Hash{}) {
		t.Error("a data marker was written to the coin account")
	}
	for _, addr := range []common.Address{ghost.CoinTreeAccount, ghost.DataTreeAccount} {
		if st.Exist(addr) {
			t.Errorf("marking created the tree account %x", addr)
		}
	}
}

func TestMarkerSlotLayout(t *testing.T) {
	sdb := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(types.EmptyRootHash, sdb, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := testMarker(1)
	if got := st.GetState(ghost.CoinMarkerAccount, m); got != (common.Hash{}) {
		t.Fatalf("marker slot before: %x", got)
	}
	if err := MarkSpent(st, Coin, m); err != nil {
		t.Fatal(err)
	}
	st = commitAndReopen(t, sdb, st, 1)
	one := common.Hash{31: 1}
	if got := st.GetState(ghost.CoinMarkerAccount, m); got != one {
		t.Errorf("coin marker slot after: %x, want %x", got, one)
	}
	if got := st.GetState(ghost.DataMarkerAccount, m); got != (common.Hash{}) {
		t.Errorf("data marker slot: %x", got)
	}
	if got := st.GetNonce(ghost.CoinMarkerAccount); got != 1 {
		t.Errorf("marker account nonce %d, want 1", got)
	}
	if !st.GetBalance(ghost.CoinMarkerAccount).IsZero() || st.GetCodeSize(ghost.CoinMarkerAccount) != 0 {
		t.Error("the marker account holds a balance or code")
	}
}

func TestAnyNonZeroMarkerCountsAsSpent(t *testing.T) {
	for _, v := range []common.Hash{{31: 2}, {0: 0x80}, {15: 1}, common.HexToHash("ff")} {
		st := newState(t)
		m := testMarker(9)
		st.SetState(ghost.DataMarkerAccount, m, v)
		if !IsSpent(st, Data, m) {
			t.Errorf("value %x does not count as spent", v)
		}
		if err := MarkSpent(st, Data, m); !errors.Is(err, ErrMarkerSpent) {
			t.Errorf("value %x: MarkSpent %v, want %v", v, err, ErrMarkerSpent)
		}
		if got := st.GetState(ghost.DataMarkerAccount, m); got != v {
			t.Errorf("value %x overwritten with %x", v, got)
		}
	}
}

func TestAccountsSurviveEmptyAccountCleanup(t *testing.T) {
	sdb := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(types.EmptyRootHash, sdb, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Append(st, Coin, 1, testLeaf(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(st, Data, 1, testLeaf(1)); err != nil {
		t.Fatal(err)
	}
	if err := MarkSpent(st, Coin, testMarker(0)); err != nil {
		t.Fatal(err)
	}
	if err := MarkSpent(st, Data, testMarker(1)); err != nil {
		t.Fatal(err)
	}
	coinRoot, dataRoot := mustRoot(t, Release, st, Coin), mustRoot(t, Release, st, Data)

	st = commitAndReopen(t, sdb, st, 1)
	for _, addr := range []common.Address{ghost.CoinTreeAccount, ghost.DataTreeAccount, ghost.CoinMarkerAccount, ghost.DataMarkerAccount} {
		if !st.Exist(addr) {
			t.Errorf("account %x deleted by the cleanup", addr)
			continue
		}
		if st.GetNonce(addr) != 1 || !st.GetBalance(addr).IsZero() || st.GetCodeSize(addr) != 0 {
			t.Errorf("account %x: nonce %d, balance %v, code %d bytes", addr, st.GetNonce(addr), st.GetBalance(addr), st.GetCodeSize(addr))
		}
	}
	if got := mustRoot(t, Release, st, Coin); got != coinRoot {
		t.Errorf("coin root after reopening %x, want %x", got, coinRoot)
	}
	if got := mustRoot(t, Release, st, Data); got != dataRoot {
		t.Errorf("data root after reopening %x, want %x", got, dataRoot)
	}
	if got := getUint(t, st, Coin, SlotLeafCount); got != 1 {
		t.Errorf("coin leaf count %d", got)
	}
	if !IsSpent(st, Coin, testMarker(0)) || !IsSpent(st, Data, testMarker(1)) {
		t.Error("a marker was lost in the cleanup")
	}
}
