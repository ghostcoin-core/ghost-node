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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// The public test network is the network built into the node: a node given
// no genesis and holding none joins it. Its coins have no value. It is a test
// network, not the launch network, and its values are not launch values.
const (
	// TestNetChainID is the chain ID and network ID of the public test
	// network, the internal network's plus one. It is not a launch value.
	TestNetChainID = InternalNetChainID + 1

	// TestNetTimestamp is the fixed genesis time of the public test network,
	// 2026-10-27 18:00:00 UTC. It must lie in the past: block 1 must be
	// later than its parent and no more than FutureDrift ahead of the clock,
	// so a future genesis time leaves every miner waiting until that time.
	// It must also lie close to the network's start: ASERT measures each
	// block's lag from this time, and every half-life (an hour) of lag at
	// the first blocks halves the difficulty, down to the minimum.
	TestNetTimestamp = 1_793_124_000

	// TestNetExtraData is the extra data of the public test network's first
	// block. A header carries no chain ID, so this is what keeps its first
	// block apart from the internal network's whatever the two genesis
	// times: a database holding the internal chain is never taken for this
	// one.
	TestNetExtraData = "ghost public test network"

	// TestNetStartDifficulty is the difficulty of the public test network's
	// genesis, 2^14: about 30 seconds of work for a CPU miner hashing about
	// 550 times a second in light mode (16 threads at about 35 to 50 hashes
	// a second each, measured on 2026-10-27).
	TestNetStartDifficulty = 1 << 14

	// TestNetMinDifficulty is the lowest difficulty the public test network
	// ever requires, 2^12, a quarter of the start. Even with ASERT at its
	// floor a block still takes that miner about 7.5 seconds of real work.
	TestNetMinDifficulty = 1 << 12
)

// TestNetGenesisHash is the hash of the public test network's first block.
var TestNetGenesisHash = common.HexToHash("0xdfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436")

// TestNetBootnodes are the seed nodes of the public test network, the
// bootstrap nodes a node uses when neither --bootnodes nor the config file
// names any.
var TestNetBootnodes = []string{
	"enode://3fdaf0ab54eca22eddd4f0aae6479d56318ddbdc0d08ad44b3c1ecee8d7093cb@65.21.102.174:30303",
	"enode://2ef843c2bd12dd54c344966752e97d72b4e380597d438025f2cd2b2434a5405f@65.21.102.174:30304",
	"enode://d438702bc0ce195458046d316ec67a9da0d9cac60c28179b9685d0c6136c0d80@65.21.102.174:30305",
}

// TestNetParams returns the consensus constants of the public test network:
// those of the 30-second launch preset (block time, ASERT half-life, future
// drift and rewards) with a start and minimum difficulty a CPU miner in
// light mode meets in about 30 seconds. They are not launch values.
func TestNetParams() ghostrules.Params {
	launch := ghostrules.Launch30s()
	return ghostrules.Params{
		BlockTime:       launch.BlockTime,
		HalfLife:        launch.HalfLife,
		StartDifficulty: big.NewInt(TestNetStartDifficulty),
		MinDifficulty:   big.NewInt(TestNetMinDifficulty),
		FutureDrift:     launch.FutureDrift,
		FirstReward:     launch.FirstReward,
		TailReward:      launch.TailReward,
	}
}

// TestNetGenesis returns the first block of the public test network: the
// Ghost EVM profile from block 0, like InternalNetGenesis, with its own chain
// ID, time, extra data and start difficulty. Nothing is allocated: test coins come only from mined rewards.
//
// This is a test-network genesis, not the launch genesis.
func TestNetGenesis() *genesisT.Genesis {
	return &genesisT.Genesis{
		Config:     profileChainConfig(TestNetChainID),
		Timestamp:  TestNetTimestamp,
		ExtraData:  []byte(TestNetExtraData),
		GasLimit:   InternalNetGasLimit,
		Difficulty: TestNetParams().StartDifficulty,
		BaseFee:    big.NewInt(vars.InitialBaseFee),
		Alloc:      genesisT.GenesisAlloc{},
	}
}
