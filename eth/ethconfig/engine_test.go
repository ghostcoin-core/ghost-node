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

package ethconfig

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
)

// TestUnknownChainIDHasNoEngine checks that a proof-of-work chain gets the
// RandomX engine only for a chain ID with consensus parameters, and that any
// other chain ID is refused with a one-line message naming it.
func TestUnknownChainIDHasNoEngine(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	for _, id := range []*big.Int{big.NewInt(1), big.NewInt(61), big.NewInt(7), big.NewInt(6_777_973), new(big.Int).Lsh(big.NewInt(1), 70), nil} {
		engine, err := CreateConsensusEngine(nil, &ethash.Config{}, nil, id, nil, false, db)
		if err == nil {
			t.Errorf("chain ID %v: engine %T created, want a refusal", id, engine)
			continue
		}
		if engine != nil {
			t.Errorf("chain ID %v: refused but returned engine %T", id, engine)
		}
		msg := err.Error()
		if strings.Contains(msg, "\n") || !strings.Contains(msg, "chain ID "+id.String()) {
			t.Errorf("chain ID %v: message is not one line naming the chain ID: %q", id, msg)
		}
	}
	for _, id := range []int64{ghost.TestNetChainID, ghost.InternalNetChainID, 1337} {
		engine, err := CreateConsensusEngine(nil, &ethash.Config{}, nil, big.NewInt(id), nil, false, db)
		if err != nil {
			t.Fatalf("chain ID %d refused: %v", id, err)
		}
		rx, ok := engine.(*randomx.RandomX)
		if !ok {
			t.Fatalf("chain ID %d: engine %T, want RandomX", id, engine)
		}
		if rx.Threads() >= 0 {
			t.Errorf("chain ID %d: engine mines on %d threads before mining starts", id, rx.Threads())
		}
		rx.Close()
	}
}

// TestEngineParamsByChainID checks that the public test network uses its own
// 30-second consensus parameters, and that the internal network and developer
// mode use the internal network's.
func TestEngineParamsByChainID(t *testing.T) {
	for _, c := range []struct {
		id   int64
		want ghostrules.Params
	}{
		{ghost.TestNetChainID, ghost.TestNetParams()},
		{ghost.InternalNetChainID, ghost.InternalNetParams()},
		{ghost.DeveloperChainID, ghost.InternalNetParams()},
	} {
		params, err := consensusParams(big.NewInt(c.id))
		if err != nil {
			t.Fatalf("chain ID %d: %v", c.id, err)
		}
		want := c.want
		if params.BlockTime != want.BlockTime || params.FutureDrift != want.FutureDrift ||
			params.StartDifficulty.Cmp(want.StartDifficulty) != 0 ||
			params.MinDifficulty.Cmp(want.MinDifficulty) != 0 || !params.FirstReward.Eq(want.FirstReward) {
			t.Errorf("chain ID %d: parameters %+v, want %+v", c.id, params, want)
		}
	}
}

// TestTestModesKeepEthash checks that the ethash test mode keeps its ethash
// engine whatever the chain ID, outside release builds.
func TestTestModesKeepEthash(t *testing.T) {
	if !ethash.FakeSealsAllowed {
		t.Skip("release builds have no test modes")
	}
	engine, err := CreateConsensusEngine(nil, &ethash.Config{PowMode: ethash.ModeTest}, nil, big.NewInt(1), nil, false, rawdb.NewMemoryDatabase())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, ok := engine.(*ethash.Ethash); !ok {
		t.Fatalf("test mode engine %T, want ethash", engine)
	}
}

// TestConsensusChainID checks which chain ID picks the parameters: the
// configuration's, or for a configuration without one its network ID.
func TestConsensusChainID(t *testing.T) {
	for _, c := range []struct {
		name      string
		chainID   *big.Int
		networkID uint64
		flag      uint64
		want      uint64
	}{
		{"chain ID", big.NewInt(6_777_971), 0, 0, 6_777_971},
		{"chain ID wins over the flag", big.NewInt(6_777_971), 0, 1337, 6_777_971},
		{"no chain ID, flag", nil, 0, 1337, 1337},
		{"no chain ID, configured network ID", nil, 1337, 0, 1337},
		{"no chain ID, flag wins", nil, 5, 1337, 1337},
	} {
		config := &coregeth.CoreGethChainConfig{ChainID: c.chainID, NetworkID: c.networkID}
		if got := ConsensusChainID(config, c.flag); got == nil || got.Uint64() != c.want {
			t.Errorf("%s: chain ID %v, want %d", c.name, got, c.want)
		}
	}
	// A go-ethereum configuration without either falls back to the default
	// network ID, which has no parameters.
	id := ConsensusChainID(&goethereum.ChainConfig{}, 0)
	if _, err := consensusParams(id); err == nil {
		t.Errorf("empty configuration resolves to chain ID %v, which has parameters", id)
	}
}
