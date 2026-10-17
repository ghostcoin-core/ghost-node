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
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
)

func u64(n uint64) *uint64 { return &n }

func TestCheckProfileAccepts(t *testing.T) {
	for name, c := range map[string]ctypes.ChainConfigurator{
		"developer mode": params.DeveloperGenesisBlock(11_500_000, nil).Config,
		"plain ethash":   &goethereum.ChainConfig{ChainID: big.NewInt(7), HomesteadBlock: big.NewInt(0), Ethash: new(ctypes.EthashConfig)},
	} {
		if err := CheckProfile(c); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestCheckProfileRefuses(t *testing.T) {
	ethash := func() *coregeth.CoreGethChainConfig {
		return &coregeth.CoreGethChainConfig{ChainID: big.NewInt(7), Ethash: new(ctypes.EthashConfig)}
	}
	cases := map[string]func() ctypes.ChainConfigurator{
		"terminalTotalDifficulty": func() ctypes.ChainConfigurator {
			return &goethereum.ChainConfig{Ethash: new(ctypes.EthashConfig), TerminalTotalDifficulty: big.NewInt(0)}
		},
		"ECBP-1100": func() ctypes.ChainConfigurator { c := ethash(); c.ECBP1100FBlock = big.NewInt(10); return c },
		"ECIP-1017": func() ctypes.ChainConfigurator {
			c := ethash()
			c.ECIP1017FBlock, c.ECIP1017EraRounds = big.NewInt(10), big.NewInt(100)
			return c
		},
		"ECIP-1010": func() ctypes.ChainConfigurator {
			c := ethash()
			c.ECIP1010PauseBlock, c.ECIP1010Length = big.NewInt(10), big.NewInt(10)
			return c
		},
		"ECIP-1099": func() ctypes.ChainConfigurator { c := ethash(); c.ECIP1099FBlock = big.NewInt(10); return c },
		"EIP-4895": func() ctypes.ChainConfigurator {
			c := ethash()
			c.SetEIP4895TransitionTime(u64(1))
			return c
		},
		"EIP-4844": func() ctypes.ChainConfigurator {
			c := ethash()
			c.SetEIP4844TransitionTime(u64(1))
			return c
		},
		"EIP-7516": func() ctypes.ChainConfigurator {
			c := ethash()
			c.SetEIP7516TransitionTime(u64(1))
			return c
		},
		"EIP-4788": func() ctypes.ChainConfigurator {
			c := ethash()
			c.SetEIP4788TransitionTime(u64(1))
			return c
		},
		"EIP-4399": func() ctypes.ChainConfigurator {
			c := ethash()
			c.SetEIP4399Transition(u64(1))
			return c
		},
	}
	for want, build := range cases {
		err := CheckProfile(build())
		if !errors.Is(err, ErrNotGhostProfile) {
			t.Errorf("%s: have %v, want %v", want, err, ErrNotGhostProfile)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error does not name it: %v", want, err)
		}
	}
}

func TestCheckProfileRefusesEthereumMainnet(t *testing.T) {
	err := CheckProfile(params.MainnetChainConfig)
	if !errors.Is(err, ErrNotGhostProfile) {
		t.Fatalf("Ethereum mainnet accepted: %v", err)
	}
	for _, want := range []string{"terminalTotalDifficulty", "EIP-4895", "EIP-4844", "EIP-4788"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
}
