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

package randomx

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// TestSealHashCoversEveryField changes each field of types.Header in turn,
// found by reflection: every change except to MixDigest and Nonce must change
// the seal hash, and those two must not. A change that leaves the header in
// neither encoding layout (one tree root on a base header, a forbidden field
// on a Ghost header) must make it impossible to encode, so it can never be
// sealed.
func TestSealHashCoversEveryField(t *testing.T) {
	engine := newTestEngine(t, testParams())
	legacy := fullHeader()
	legacy.BaseFee, legacy.WithdrawalsHash, legacy.BlobGasUsed, legacy.ExcessBlobGas, legacy.ParentBeaconRoot = nil, nil, nil, nil, nil
	baseOnly := map[string]bool{"CoinTreeRoot": true, "DataTreeRoot": true, "DataMarkerRoot": true}
	ghostForbids := map[string]bool{"WithdrawalsHash": true, "BlobGasUsed": true, "ExcessBlobGas": true, "ParentBeaconRoot": true}

	for name, c := range map[string]struct {
		base        *types.Header
		unencodable map[string]bool
	}{
		"all fields set":        {fullHeader(), baseOnly},
		"optional fields unset": {legacy, baseOnly},
		"ghost layout":          {ghostHeader(), ghostForbids},
	} {
		base := c.base
		if _, err := rlp.EncodeToBytes(base); err != nil {
			t.Fatalf("%s: base header does not encode: %v", name, err)
		}
		want := engine.SealHash(base)
		for _, field := range headerFields() {
			h := types.CopyHeader(base)
			mutateField(t, h, field, 0)
			if _, err := rlp.EncodeToBytes(h); (err != nil) != c.unencodable[field] {
				t.Errorf("%s: changing %s: encoding error %v", name, field, err)
			}
			if c.unencodable[field] {
				continue
			}
			changed := engine.SealHash(h) != want
			switch sealField := field == "MixDigest" || field == "Nonce"; {
			case sealField && changed:
				t.Errorf("%s: changing %s changes the seal hash", name, field)
			case !sealField && !changed:
				t.Errorf("%s: changing %s leaves the seal hash unchanged", name, field)
			}
		}
	}
}

// TestRewardPaidToCoinbase checks that Finalize credits exactly the block
// reward to the coinbase and nothing to anyone else, with the 30-second
// preset, and that a block with an uncle is invalid.
func TestRewardPaidToCoinbase(t *testing.T) {
	params := ghostrules.Launch30s()
	engine := newTestEngine(t, params)
	miner, uncleMiner := common.Address{0x01}, common.Address{0x02}

	for _, c := range []struct {
		height uint64
		want   *uint256.Int
	}{
		{1, uint256.NewInt(6_923_560_000_000_000_000)},
		{2, params.BlockReward(2)},
		// One emission half-life after block 1: half the first reward.
		{2_102_401, uint256.NewInt(3_461_780_000_000_000_000)},
	} {
		if got := params.BlockReward(c.height); !got.Eq(c.want) {
			t.Fatalf("height %d: BlockReward %v, want %v", c.height, got, c.want)
		}
		statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatal(err)
		}
		header := &types.Header{Number: new(big.Int).SetUint64(c.height), Coinbase: miner}
		uncle := &types.Header{Number: new(big.Int).SetUint64(c.height - 1), Coinbase: uncleMiner}
		engine.Finalize(nil, header, statedb, nil, []*types.Header{uncle}, nil)
		if got := statedb.GetBalance(miner); !got.Eq(c.want) {
			t.Errorf("height %d: coinbase credited %v, want %v", c.height, got, c.want)
		}
		if got := statedb.GetBalance(uncleMiner); !got.IsZero() {
			t.Errorf("height %d: uncle coinbase credited %v", c.height, got)
		}
	}
	if r1, r2 := params.BlockReward(1), params.BlockReward(2); !r2.Lt(r1) {
		t.Errorf("reward does not decay: %v then %v", r1, r2)
	}

	// A block with an uncle is invalid, and cannot be assembled.
	f := sealedChain(t)
	uncle := f.blocks[0].Header()
	withUncle := types.NewBlock(f.blocks[1].Header(), nil, []*types.Header{uncle}, nil, trie.NewStackTrie(nil))
	if err := engine.VerifyUncles(nil, withUncle); !errors.Is(err, errUnclesNotAllowed) {
		t.Errorf("VerifyUncles: error %v, want %v", err, errUnclesNotAllowed)
	}
	if _, err := engine.FinalizeAndAssemble(nil, f.blocks[1].Header(), nil, nil, []*types.Header{uncle}, nil, nil); !errors.Is(err, errUnclesNotAllowed) {
		t.Errorf("FinalizeAndAssemble: error %v, want %v", err, errUnclesNotAllowed)
	}
	chain, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if _, err := chain.InsertChain(types.Blocks{f.blocks[0]}); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(types.Blocks{withUncle}); !errors.Is(err, errInvalidUncleHash) {
		t.Errorf("inserting a block with an uncle: error %v, want %v", err, errInvalidUncleHash)
	}
	if chain.CurrentBlock().Number.Uint64() != 1 {
		t.Error("a block with an uncle moved the head")
	}
}

// TestCalcDifficultyMatchesRules checks that CalcDifficulty and Prepare give
// the ghostrules ASERT difficulty anchored at the genesis header's time, and
// that a header with any other difficulty is rejected.
func TestCalcDifficultyMatchesRules(t *testing.T) {
	params := ghostrules.Launch30s()
	engine := newTestEngine(t, params)
	const g = 1_800_000_000
	genesis := &types.Header{Number: big.NewInt(0), Time: g, Difficulty: params.StartDifficulty}

	// On schedule, well ahead of it (harder), behind it (easier) and far
	// behind it (the minimum).
	anchored, moved := false, false
	for _, c := range []struct{ parent, parentTime, time uint64 }{
		{0, g, g + 30},
		{0, g, g + 1},
		{9, g + 270, g + 300},
		{9, g + 100, g + 101},
		{99, g + 5_000, g + 5_100},
		{1_000, g + 20_000, g + 20_005},
		{50, g + 900_000, g + 900_030},
	} {
		parent := &types.Header{Number: new(big.Int).SetUint64(c.parent), Time: c.parentTime, Difficulty: big.NewInt(1)}
		if c.parent == 0 {
			parent = genesis
		}
		reader := newTestReader(testConfig(), genesis, parent)
		want := params.RequiredDifficulty(g, c.parent+1, c.time)
		if got := engine.CalcDifficulty(reader, c.time, parent); got == nil || got.Cmp(want) != 0 {
			t.Errorf("parent %d at %d, time %d: difficulty %v, want %v", c.parent, c.parentTime, c.time, got, want)
		}
		if want.Cmp(params.RequiredDifficulty(c.parentTime, c.parent+1, c.time)) != 0 {
			anchored = true
		}
		if want.Cmp(params.StartDifficulty) != 0 {
			moved = true
		}

		header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).SetUint64(c.parent + 1), Time: c.time, MixDigest: common.Hash{1}, Nonce: types.EncodeNonce(1)}
		if err := engine.Prepare(reader, header); err != nil {
			t.Fatal(err)
		}
		if header.Difficulty.Cmp(want) != 0 || header.MixDigest != (common.Hash{}) || header.Nonce != (types.BlockNonce{}) {
			t.Errorf("parent %d: Prepare set difficulty %v, mix %x, nonce %x; want %v and zero seal fields", c.parent, header.Difficulty, header.MixDigest, header.Nonce, want)
		}
		header.Difficulty = new(big.Int).Add(want, common.Big1)
		if err := engine.verifyHeader(reader, header, parent, false, common.Hash{}, c.time); !errors.Is(err, errInvalidDifficulty) {
			t.Errorf("parent %d: difficulty off by one: error %v, want %v", c.parent, err, errInvalidDifficulty)
		}
	}
	if !anchored || !moved {
		t.Fatal("the cases do not tell the genesis anchor from the parent's, or never move the difficulty")
	}

	// Without its genesis header a chain has no difficulty.
	orphanParent := &types.Header{Number: big.NewInt(5), Time: g + 150}
	if got := engine.CalcDifficulty(newTestReader(testConfig(), nil), g+180, orphanParent); got != nil {
		t.Errorf("difficulty without genesis: %v, want nil", got)
	}
}

// TestTimestampErrors checks that only a timestamp too far ahead of the
// local clock is a future block; other failures make the header invalid.
func TestTimestampErrors(t *testing.T) {
	params := testParams()
	engine := newTestEngine(t, params)
	genesis := &types.Header{Number: big.NewInt(0), Time: testGenesisAt, Difficulty: big.NewInt(16)}
	reader := newTestReader(testConfig(), genesis)
	now := uint64(testGenesisAt + 100)

	for _, c := range []struct {
		name   string
		time   uint64
		future bool
	}{
		{"same as parent", testGenesisAt, false},
		{"before parent", testGenesisAt - 1, false},
		{"beyond the drift", now + params.FutureDrift + 1, true},
		{"at 2^63", 1 << 63, false},
	} {
		header := &types.Header{ParentHash: genesis.Hash(), Number: big.NewInt(1), Time: c.time, Difficulty: big.NewInt(16)}
		err := engine.verifyHeader(reader, header, genesis, false, common.Hash{}, now)
		if isFuture := errors.Is(err, consensus.ErrFutureBlock); isFuture != c.future || err == nil {
			t.Errorf("%s: error %v, future block %v, want %v", c.name, err, isFuture, c.future)
		}
		if !c.future && !errors.Is(err, errInvalidTimestamp) {
			t.Errorf("%s: error %v, want %v", c.name, err, errInvalidTimestamp)
		}
	}
	// At the edge of the drift the timestamp passes and checking goes on.
	header := &types.Header{ParentHash: genesis.Hash(), Number: big.NewInt(1), Time: now + params.FutureDrift, Difficulty: big.NewInt(1)}
	if err := engine.verifyHeader(reader, header, genesis, false, common.Hash{}, now); !errors.Is(err, errInvalidDifficulty) {
		t.Errorf("timestamp at the drift edge: error %v, want the next check's %v", err, errInvalidDifficulty)
	}
}
