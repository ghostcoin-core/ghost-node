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

package ghost_test

import (
	"encoding/json"
	"math/big"
	"reflect"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestPublicTestNetGenesisHashStable pins the public test network's first
// block: a change to its genesis is a new network, so it has to be made on
// purpose, here and in TestNetGenesisHash together.
func TestPublicTestNetGenesisHashStable(t *testing.T) {
	want := common.HexToHash("0xeecbc41f98be17f5a47dec0c9fab9ad566107669b70323d0588a171390f6ab58")
	block := core.GenesisToBlock(ghost.TestNetGenesis(), nil)
	if block.Hash() != want {
		t.Errorf("test network genesis hash %x, want %x", block.Hash(), want)
	}
	if ghost.TestNetGenesisHash != want {
		t.Errorf("TestNetGenesisHash is %x, want %x", ghost.TestNetGenesisHash, want)
	}
	// The header carries the Ghost tree roots, as every Ghost chain does.
	h := block.Header()
	if h.CoinTreeRoot == nil || h.DataTreeRoot == nil || h.DataMarkerRoot == nil {
		t.Error("test network genesis header has no Ghost tree roots")
	}
	if block.Hash() == core.GenesisToBlock(ghost.InternalNetGenesis(), nil).Hash() {
		t.Error("test network genesis is the internal network's")
	}
	// Each call returns its own genesis with the same block.
	g := ghost.TestNetGenesis()
	g.Timestamp++
	g.ExtraData[0] ^= 0xff
	if core.GenesisToBlock(ghost.TestNetGenesis(), nil).Hash() != want {
		t.Error("TestNetGenesis shares its values between calls")
	}
}

// TestPublicTestNetGenesis checks the test network's first block: its own
// chain and network ID, its fixed time, no allocation, and the Ghost EVM
// profile of the internal network.
func TestPublicTestNetGenesis(t *testing.T) {
	g := ghost.TestNetGenesis()
	c := g.Config
	if err := ghost.CheckProfile(c); err != nil {
		t.Fatalf("CheckProfile: %v", err)
	}
	if id := c.GetChainID(); id == nil || id.Uint64() != 6_777_972 || ghost.TestNetChainID != 6_777_972 {
		t.Errorf("chain ID %v (constant %d), want 6777972", id, ghost.TestNetChainID)
	}
	if id := c.GetNetworkID(); id == nil || *id != 6_777_972 {
		t.Errorf("network ID %v, want 6777972", id)
	}
	if c.GetConsensusEngineType() != ctypes.ConsensusEngineT_Ethash {
		t.Errorf("consensus type %v, want the proof-of-work marker", c.GetConsensusEngineType())
	}
	if len(g.Alloc) != 0 {
		t.Errorf("genesis allocates %d accounts, want none", len(g.Alloc))
	}
	if g.Timestamp != 1_790_812_800 || ghost.TestNetTimestamp != 1_790_812_800 {
		t.Errorf("timestamp %d, want 1790812800 (2026-10-01 00:00:00 UTC)", g.Timestamp)
	}
	// The time is the internal network's, so the extra data keeps the two
	// first blocks apart.
	if string(g.ExtraData) != "ghost public test network" || ghost.TestNetExtraData != "ghost public test network" {
		t.Errorf("extra data %q, want %q", g.ExtraData, "ghost public test network")
	}
	if len(g.ExtraData) > int(vars.MaximumExtraDataSize) {
		t.Errorf("extra data is %d bytes, longer than %d", len(g.ExtraData), vars.MaximumExtraDataSize)
	}
	if g.GasLimit != 30_000_000 {
		t.Errorf("gas limit %d, want 30000000", g.GasLimit)
	}
	if g.BaseFee == nil || g.BaseFee.Cmp(big.NewInt(vars.InitialBaseFee)) != 0 {
		t.Errorf("base fee %v, want %d", g.BaseFee, vars.InitialBaseFee)
	}
	if g.Difficulty == nil || g.Difficulty.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("difficulty %v, want 1", g.Difficulty)
	}

	// Apart from the chain and network ID the configuration is the internal
	// network's.
	internal := ghost.InternalNetGenesis().Config
	id := uint64(ghost.TestNetChainID)
	if err := internal.SetChainID(new(big.Int).SetUint64(id)); err != nil {
		t.Fatal(err)
	}
	if err := internal.SetNetworkID(&id); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(c)
	b, _ := json.Marshal(internal)
	if string(a) != string(b) {
		t.Errorf("test network configuration differs from the internal network's:\n%s\n%s", a, b)
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
	if core.GenesisToBlock(&back, nil).Hash() != core.GenesisToBlock(g, nil).Hash() {
		t.Error("genesis changes in a round trip through the file format")
	}
}

// TestPublicTestNetChainIDNotReserved checks that the test network's chain ID
// is neither the internal network's nor developer mode's.
func TestPublicTestNetChainIDNotReserved(t *testing.T) {
	id := ghost.TestNetGenesis().Config.GetChainID().Uint64()
	for _, other := range []uint64{6_777_971, 1337, ghost.InternalNetChainID, ghost.DeveloperChainID} {
		if id == other {
			t.Errorf("test network chain ID %d is reserved", id)
		}
	}
}

// TestPublicTestNetParams checks that the test network has the internal
// network's consensus constants.
func TestPublicTestNetParams(t *testing.T) {
	p := ghost.TestNetParams()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, ghost.InternalNetParams()) {
		t.Errorf("test network constants %+v differ from the internal network's", p)
	}
	p.StartDifficulty.SetInt64(5)
	if ghost.TestNetParams().StartDifficulty.Int64() != 1 {
		t.Error("TestNetParams shares its values between calls")
	}
}

// TestPublicTestNetSeeds checks that the built-in seed list is exactly the
// three seed nodes, in order, and that each parses as a node with an endpoint.
func TestPublicTestNetSeeds(t *testing.T) {
	want := []string{
		"enode://3fdaf0ab54eca22eddd4f0aae6479d56318ddbdc0d08ad44b3c1ecee8d7093cb@65.21.102.174:30303",
		"enode://2ef843c2bd12dd54c344966752e97d72b4e380597d438025f2cd2b2434a5405f@65.21.102.174:30304",
		"enode://d438702bc0ce195458046d316ec67a9da0d9cac60c28179b9685d0c6136c0d80@65.21.102.174:30305",
	}
	if !slices.Equal(ghost.TestNetBootnodes, want) {
		t.Fatalf("seed list\n%q\nwant\n%q", ghost.TestNetBootnodes, want)
	}
	for _, url := range ghost.TestNetBootnodes {
		n, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			t.Errorf("seed %s does not parse: %v", url, err)
			continue
		}
		if !n.IPAddr().IsValid() || n.TCP() == 0 {
			t.Errorf("seed %s has no endpoint", url)
		}
	}
}
