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

	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

const (
	// InternalNetChainID is the chain ID of the internal test network,
	// ASCII "ghs". It is not a launch value.
	InternalNetChainID = 6_777_971

	// DeveloperChainID is the chain ID of developer mode (--dev).
	DeveloperChainID = 1337

	// InternalNetTimestamp is the fixed genesis time of the internal test
	// network, 2026-10-01 00:00:00 UTC.
	InternalNetTimestamp = 1_790_812_800

	// InternalNetGasLimit is the genesis gas limit of the internal test
	// network.
	InternalNetGasLimit = 30_000_000
)

// InternalNetParams returns the consensus constants of the internal test
// network and of developer mode.
//
// These are internal-test values, never a launch preset: one-second blocks,
// difficulty 1 and an hour of future drift exist only so that a thousand
// blocks mine in seconds on one machine with light-mode RandomX. The reward
// constants are those of the 30-second launch preset. The launch genesis and
// its constants come with the built-in network.
func InternalNetParams() ghostrules.Params {
	launch := ghostrules.Launch30s()
	return ghostrules.Params{
		BlockTime:       1,
		HalfLife:        3_600,
		StartDifficulty: big.NewInt(1),
		MinDifficulty:   big.NewInt(1),
		FutureDrift:     3_600,
		FirstReward:     launch.FirstReward,
		TailReward:      launch.TailReward,
	}
}

// InternalNetGenesis returns the first block of the internal test network.
// Nothing is allocated: test funds come only from mined rewards.
//
// The chain runs the Ghost EVM profile from block 0: Frontier through
// Shanghai without withdrawals (EIP-4895), London, and Cancun's EIP-1153,
// EIP-5656 and EIP-6780. The consensus type is "ethash", the proof-of-work
// marker, for which the node runs RandomX.
//
// This is an internal-test genesis, not the launch genesis.
func InternalNetGenesis() *genesisT.Genesis {
	return &genesisT.Genesis{
		Config:     profileChainConfig(InternalNetChainID),
		Timestamp:  InternalNetTimestamp,
		GasLimit:   InternalNetGasLimit,
		Difficulty: InternalNetParams().StartDifficulty,
		BaseFee:    big.NewInt(vars.InitialBaseFee),
		Alloc:      genesisT.GenesisAlloc{},
	}
}

// profileChainConfig returns the chain configuration of the Ghost EVM
// profile from block 0, with the given chain ID as chain and network ID.
func profileChainConfig(chainID uint64) *coregeth.CoreGethChainConfig {
	zero := func() *big.Int { return big.NewInt(0) }
	return &coregeth.CoreGethChainConfig{
		NetworkID: chainID,
		ChainID:   new(big.Int).SetUint64(chainID),
		Ethash:    new(ctypes.EthashConfig),

		// Frontier to Petersburg.
		EIP2FBlock:      zero(),
		EIP7FBlock:      zero(),
		EIP150Block:     zero(),
		EIP155Block:     zero(),
		EIP160FBlock:    zero(),
		EIP161FBlock:    zero(),
		EIP170FBlock:    zero(),
		EIP100FBlock:    zero(),
		EIP140FBlock:    zero(),
		EIP198FBlock:    zero(),
		EIP211FBlock:    zero(),
		EIP212FBlock:    zero(),
		EIP213FBlock:    zero(),
		EIP214FBlock:    zero(),
		EIP658FBlock:    zero(),
		EIP145FBlock:    zero(),
		EIP1014FBlock:   zero(),
		EIP1052FBlock:   zero(),
		EIP1283FBlock:   zero(),
		PetersburgBlock: zero(),

		// Istanbul.
		EIP152FBlock:  zero(),
		EIP1108FBlock: zero(),
		EIP1344FBlock: zero(),
		EIP1884FBlock: zero(),
		EIP2028FBlock: zero(),
		EIP2200FBlock: zero(),

		// Berlin.
		EIP2565FBlock: zero(),
		EIP2718FBlock: zero(),
		EIP2929FBlock: zero(),
		EIP2930FBlock: zero(),

		// London.
		EIP1559FBlock: zero(),
		EIP3198FBlock: zero(),
		EIP3529FBlock: zero(),
		EIP3541FBlock: zero(),

		// Shanghai without withdrawals.
		EIP3651FBlock: zero(),
		EIP3855FBlock: zero(),
		EIP3860FBlock: zero(),
		EIP6049FBlock: zero(),

		// Cancun's transient storage, MCOPY and SELFDESTRUCT change.
		EIP1153FBlock: zero(),
		EIP5656FBlock: zero(),
		EIP6780FBlock: zero(),

		DisposalBlock: zero(),
	}
}
