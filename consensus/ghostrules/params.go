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

// Package ghostrules holds Ghost's proof-of-work consensus rules as pure
// functions: the ASERT difficulty, the timestamp rule, the block reward and
// the seal check. Nothing here reads the clock, keeps state or knows about
// headers; the caller passes every input, so the rules can be tested alone.
//
// All arithmetic is integer: math/big for ASERT, whose intermediates exceed
// 256 bits, and uint256 for the reward.
package ghostrules

import (
	"errors"
	"math/big"

	"github.com/holiman/uint256"
)

// EmissionHalfLife is the time in seconds over which the decaying part of the
// block reward halves (two years of 365 days). The half-life in blocks is
// EmissionHalfLife / BlockTime.
const EmissionHalfLife = 63_072_000

// Params are the constants of one Ghost chain.
type Params struct {
	BlockTime       uint64       // target seconds between blocks (B)
	HalfLife        uint64       // ASERT half-life in seconds (TAU)
	StartDifficulty *big.Int     // difficulty of the genesis anchor (D_START)
	MinDifficulty   *big.Int     // lowest difficulty ever required (D_MIN)
	FutureDrift     uint64       // seconds a timestamp may run ahead of the local clock
	FirstReward     *uint256.Int // reward of block 1 in wei (R0)
	TailReward      *uint256.Int // reward floor in wei once the decay reaches it (TAIL)
}

// Launch30s returns the constants of the 30-second chain.
func Launch30s() Params {
	return Params{
		BlockTime:       30,
		HalfLife:        3_600,
		StartDifficulty: big.NewInt(1 << 24),
		MinDifficulty:   big.NewInt(1 << 17),
		FutureDrift:     30,
		FirstReward:     uint256.NewInt(6_923_560_000_000_000_000),
		TailReward:      uint256.NewInt(200_000_000_000_000_000),
	}
}

// Launch60s returns the constants of the 60-second chain.
func Launch60s() Params {
	return Params{
		BlockTime:       60,
		HalfLife:        3_600,
		StartDifficulty: big.NewInt(1 << 25),
		MinDifficulty:   big.NewInt(1 << 17),
		FutureDrift:     30,
		FirstReward:     uint256.NewInt(13_847_120_000_000_000_000),
		TailReward:      uint256.NewInt(400_000_000_000_000_000),
	}
}

var (
	errZeroBlockTime      = errors.New("ghostrules: block time is zero")
	errLongBlockTime      = errors.New("ghostrules: block time exceeds the emission half-life")
	errZeroHalfLife       = errors.New("ghostrules: half-life is zero")
	errBadMinDifficulty   = errors.New("ghostrules: minimum difficulty is missing or not positive")
	errBadStartDifficulty = errors.New("ghostrules: starting difficulty is missing or below the minimum")
	errMissingReward      = errors.New("ghostrules: first or tail reward is missing")
)

// Validate reports whether the parameters can drive the rules.
func (p Params) Validate() error {
	switch {
	case p.BlockTime == 0:
		return errZeroBlockTime
	case p.BlockTime > EmissionHalfLife:
		return errLongBlockTime
	case p.HalfLife == 0:
		return errZeroHalfLife
	case p.MinDifficulty == nil || p.MinDifficulty.Sign() <= 0:
		return errBadMinDifficulty
	case p.StartDifficulty == nil || p.StartDifficulty.Cmp(p.MinDifficulty) < 0:
		return errBadStartDifficulty
	case p.FirstReward == nil || p.TailReward == nil:
		return errMissingReward
	}
	return nil
}
