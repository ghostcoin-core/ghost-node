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

package ghost

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestInternalNetGenesisPassesProfile checks the internal network's first
// block: its identity, its empty allocation, its header values, and that its
// chain configuration is the Ghost EVM profile from block 0, which passes
// CheckProfile and survives a round trip through the genesis file format.
func TestInternalNetGenesisPassesProfile(t *testing.T) {
	g := InternalNetGenesis()
	c := g.Config
	if err := CheckProfile(c); err != nil {
		t.Fatalf("CheckProfile: %v", err)
	}
	if id := c.GetChainID(); id == nil || id.Uint64() != 6_777_971 {
		t.Errorf("chain ID %v, want 6777971", id)
	}
	if id := c.GetNetworkID(); id == nil || *id != 6_777_971 {
		t.Errorf("network ID %v, want 6777971", id)
	}
	if c.GetConsensusEngineType() != ctypes.ConsensusEngineT_Ethash {
		t.Errorf("consensus type %v, want the proof-of-work marker", c.GetConsensusEngineType())
	}
	if len(g.Alloc) != 0 {
		t.Errorf("genesis allocates %d accounts, want none", len(g.Alloc))
	}
	if g.Timestamp != InternalNetTimestamp || g.Timestamp == 0 {
		t.Errorf("timestamp %d, want the fixed %d", g.Timestamp, InternalNetTimestamp)
	}
	if g.Difficulty == nil || g.Difficulty.Cmp(InternalNetParams().StartDifficulty) != 0 {
		t.Errorf("difficulty %v, want the starting difficulty %v", g.Difficulty, InternalNetParams().StartDifficulty)
	}
	if g.GasLimit != 30_000_000 {
		t.Errorf("gas limit %d, want 30000000", g.GasLimit)
	}
	if g.BaseFee == nil || g.BaseFee.Cmp(big.NewInt(vars.InitialBaseFee)) != 0 {
		t.Errorf("base fee %v, want %d", g.BaseFee, vars.InitialBaseFee)
	}

	on := map[string]func() *uint64{
		"EIP-2": c.GetEIP2Transition, "EIP-7": c.GetEIP7Transition,
		"EIP-150": c.GetEIP150Transition, "EIP-155": c.GetEIP155Transition,
		"EIP-160": c.GetEIP160Transition, "EIP-161abc": c.GetEIP161abcTransition,
		"EIP-161d": c.GetEIP161dTransition, "EIP-170": c.GetEIP170Transition,
		"EIP-140": c.GetEIP140Transition, "EIP-198": c.GetEIP198Transition,
		"EIP-211": c.GetEIP211Transition, "EIP-212": c.GetEIP212Transition,
		"EIP-213": c.GetEIP213Transition, "EIP-214": c.GetEIP214Transition,
		"EIP-658": c.GetEIP658Transition, "EIP-145": c.GetEIP145Transition,
		"EIP-1014": c.GetEIP1014Transition, "EIP-1052": c.GetEIP1052Transition,
		"EIP-152": c.GetEIP152Transition, "EIP-1108": c.GetEIP1108Transition,
		"EIP-1344": c.GetEIP1344Transition, "EIP-1884": c.GetEIP1884Transition,
		"EIP-2028": c.GetEIP2028Transition, "EIP-2200": c.GetEIP2200Transition,
		"EIP-2565": c.GetEIP2565Transition, "EIP-2718": c.GetEIP2718Transition,
		"EIP-2929": c.GetEIP2929Transition, "EIP-2930": c.GetEIP2930Transition,
		"EIP-1559": c.GetEIP1559Transition, "EIP-3198": c.GetEIP3198Transition,
		"EIP-3529": c.GetEIP3529Transition, "EIP-3541": c.GetEIP3541Transition,
		"EIP-3651": c.GetEIP3651Transition, "EIP-3855": c.GetEIP3855Transition,
		"EIP-3860": c.GetEIP3860Transition, "EIP-6049": c.GetEIP6049Transition,
		"EIP-1153": c.GetEIP1153Transition, "EIP-5656": c.GetEIP5656Transition,
		"EIP-6780": c.GetEIP6780Transition,
	}
	for name, get := range on {
		if n := get(); n == nil || *n != 0 {
			t.Errorf("%s is not on from block 0: %v", name, n)
		}
	}
	off := map[string]func() *uint64{
		"EIP-4895": c.GetEIP4895Transition, "EIP-4895 (time)": c.GetEIP4895TransitionTime,
		"EIP-4844": c.GetEIP4844Transition, "EIP-4844 (time)": c.GetEIP4844TransitionTime,
		"EIP-4788": c.GetEIP4788Transition, "EIP-4788 (time)": c.GetEIP4788TransitionTime,
		"EIP-7516": c.GetEIP7516Transition, "EIP-4399": c.GetEIP4399Transition,
		"EIP-2537": c.GetEIP2537Transition, "EIP-2315": c.GetEIP2315Transition,
	}
	for name, get := range off {
		if n := get(); n != nil {
			t.Errorf("%s is switched on at %d", name, *n)
		}
	}

	// The genesis file format keeps every value.
	blob, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var back genesisT.Genesis
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("genesis file does not read back: %v", err)
	}
	if err := CheckProfile(back.Config); err != nil {
		t.Errorf("genesis read back fails CheckProfile: %v", err)
	}
	again, err := json.Marshal(&back)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(blob) {
		t.Errorf("genesis changes in a round trip:\n%s\n%s", blob, again)
	}
}

// TestInternalNetParams checks the internal network's consensus constants.
func TestInternalNetParams(t *testing.T) {
	p := InternalNetParams()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	launch := ghostrules.Launch30s()
	switch {
	case p.BlockTime != 1:
		t.Errorf("block time %d, want 1", p.BlockTime)
	case p.HalfLife != 3_600:
		t.Errorf("half-life %d, want 3600", p.HalfLife)
	case p.StartDifficulty.Cmp(big.NewInt(1)) != 0 || p.MinDifficulty.Cmp(big.NewInt(1)) != 0:
		t.Errorf("difficulties %v and %v, want 1", p.StartDifficulty, p.MinDifficulty)
	case p.FutureDrift != 3_600:
		t.Errorf("future drift %d, want 3600", p.FutureDrift)
	case !p.FirstReward.Eq(launch.FirstReward) || !p.TailReward.Eq(launch.TailReward):
		t.Errorf("rewards %v and %v, want the 30-second preset's", p.FirstReward, p.TailReward)
	}
	// The values are internal-test values, never a launch preset's.
	for _, preset := range []ghostrules.Params{ghostrules.Launch30s(), ghostrules.Launch60s()} {
		if p.BlockTime == preset.BlockTime || p.FutureDrift == preset.FutureDrift || p.MinDifficulty.Cmp(preset.MinDifficulty) == 0 {
			t.Errorf("internal values coincide with a launch preset: %+v", preset)
		}
	}
	// Each call returns its own values.
	p.StartDifficulty.SetInt64(5)
	p.FirstReward.SetUint64(5)
	if q := InternalNetParams(); q.StartDifficulty.Int64() != 1 || q.FirstReward.Eq(p.FirstReward) {
		t.Error("InternalNetParams shares its values between calls")
	}
}
