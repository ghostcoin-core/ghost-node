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
	// 2026-11-01 00:00:00 UTC.
	TestNetTimestamp = 1_793_491_200
)

// TestNetGenesisHash is the hash of the public test network's first block.
var TestNetGenesisHash = common.HexToHash("0xca344c2a5aad1a81fecd0a32e5d84a83567fdc2a9314e44d6ba79ba0a15a69e9")

// TestNetBootnodes are the seed nodes of the public test network, the
// bootstrap nodes a node uses when neither --bootnodes nor the config file
// names any.
var TestNetBootnodes = []string{
	"enode://3fdaf0ab54eca22eddd4f0aae6479d56318ddbdc0d08ad44b3c1ecee8d7093cb@65.21.102.174:30303",
	"enode://2ef843c2bd12dd54c344966752e97d72b4e380597d438025f2cd2b2434a5405f@65.21.102.174:30304",
	"enode://d438702bc0ce195458046d316ec67a9da0d9cac60c28179b9685d0c6136c0d80@65.21.102.174:30305",
}

// TestNetParams returns the consensus constants of the public test network,
// those of the internal network.
func TestNetParams() ghostrules.Params {
	return InternalNetParams()
}

// TestNetGenesis returns the first block of the public test network: the
// Ghost EVM profile from block 0, like InternalNetGenesis, with its own chain
// ID and time. Nothing is allocated: test coins come only from mined rewards.
//
// This is a test-network genesis, not the launch genesis.
func TestNetGenesis() *genesisT.Genesis {
	return &genesisT.Genesis{
		Config:     profileChainConfig(TestNetChainID),
		Timestamp:  TestNetTimestamp,
		GasLimit:   InternalNetGasLimit,
		Difficulty: TestNetParams().StartDifficulty,
		BaseFee:    big.NewInt(vars.InitialBaseFee),
		Alloc:      genesisT.GenesisAlloc{},
	}
}
