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

package ghostrules

import (
	"math/big"
)

// radixBits is log2 of the ASERT fixed-point radix (RADIX = 65536).
const radixBits = 16

var (
	// maxUint256 is M = 2^256 - 1, the largest 32-byte hash.
	maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	// Coefficients of the BCH cubic approximation of 2^x on [0, 1), scaled
	// by 2^48, and the rounding term added before the final shift.
	polyC1    = big.NewInt(195_766_423_245_049)
	polyC2    = big.NewInt(971_821_376)
	polyC3    = big.NewInt(5_127)
	polyRound = new(big.Int).Lsh(big.NewInt(1), 47)
	radix     = big.NewInt(1 << radixBits)
)

// asertSteps are the intermediate values of one ASERT evaluation, kept so the
// tests can check each column of the spec's vector table.
type asertSteps struct {
	exponent   *big.Int
	shifts     *big.Int
	frac       *big.Int
	factor     *big.Int
	difficulty *big.Int
}

// RequiredDifficulty returns the difficulty a block at the given height with
// the given timestamp must carry, from ASERT anchored at genesis. Height 0
// returns the starting difficulty. The parameters must pass Validate.
func (p Params) RequiredDifficulty(genesisTime, height, timestamp uint64) *big.Int {
	if height == 0 {
		return new(big.Int).Set(p.StartDifficulty)
	}
	return p.asert(genesisTime, height, timestamp).difficulty
}

func (p Params) asert(genesisTime, height, timestamp uint64) asertSteps {
	var s asertSteps

	// lag = ts - G - B*n, which may be negative.
	lag := new(big.Int).SetUint64(timestamp)
	lag.Sub(lag, new(big.Int).SetUint64(genesisTime))
	lag.Sub(lag, new(big.Int).Mul(new(big.Int).SetUint64(p.BlockTime), new(big.Int).SetUint64(height)))

	// exponent = (lag * RADIX) // TAU. big.Int.Div is Euclidean division,
	// which equals floor division for the positive divisor TAU; Go's / and
	// Quo would truncate toward zero instead.
	s.exponent = new(big.Int).Mul(lag, radix)
	s.exponent.Div(s.exponent, new(big.Int).SetUint64(p.HalfLife))

	// shifts = exponent >> 16 (arithmetic, so a floor for negatives) and
	// frac = exponent - (shifts << 16), always in [0, 65536).
	s.shifts = new(big.Int).Rsh(s.exponent, radixBits)
	s.frac = new(big.Int).Sub(s.exponent, new(big.Int).Lsh(s.shifts, radixBits))

	// factor = 65536 + ((c1*f + c2*f^2 + c3*f^3 + 2^47) >> 48).
	f := s.frac
	f2 := new(big.Int).Mul(f, f)
	f3 := new(big.Int).Mul(f2, f)
	poly := new(big.Int).Mul(polyC1, f)
	poly.Add(poly, new(big.Int).Mul(polyC2, f2))
	poly.Add(poly, new(big.Int).Mul(polyC3, f3))
	poly.Add(poly, polyRound)
	poly.Rsh(poly, 48)
	s.factor = poly.Add(poly, radix)

	maxTarget := new(big.Int).Div(maxUint256, p.MinDifficulty)
	var target *big.Int
	if s.shifts.Cmp(big.NewInt(256)) >= 0 {
		target = maxTarget
	} else {
		startTarget := new(big.Int).Div(maxUint256, p.StartDifficulty)
		target = new(big.Int).Mul(startTarget, s.factor)
		shift := new(big.Int).Sub(s.shifts, big.NewInt(radixBits))
		switch {
		case shift.Sign() >= 0:
			// shift is below 240 here.
			target.Lsh(target, uint(shift.Uint64()))
		case shift.Cmp(big.NewInt(-1024)) < 0:
			// The product has well under 1024 bits, so it shifts to zero.
			target.SetUint64(0)
		default:
			target.Rsh(target, uint(-shift.Int64()))
		}
		if target.Sign() < 1 {
			target.SetUint64(1)
		}
		if target.Cmp(maxTarget) > 0 {
			target = maxTarget
		}
	}
	s.difficulty = new(big.Int).Div(maxUint256, target)
	if s.difficulty.Cmp(p.MinDifficulty) < 0 {
		s.difficulty.Set(p.MinDifficulty)
	}
	return s
}

// SealTarget returns M // difficulty, the largest hash that seals a block of
// the given difficulty. It returns nil for a difficulty that is not positive.
func SealTarget(difficulty *big.Int) *big.Int {
	if difficulty == nil || difficulty.Sign() <= 0 {
		return nil
	}
	return new(big.Int).Div(maxUint256, difficulty)
}

// SealValid reports whether a proof-of-work hash, read as a big-endian
// number, is at most M // difficulty. A difficulty that is not positive
// never validates.
func SealValid(hash [32]byte, difficulty *big.Int) bool {
	target := SealTarget(difficulty)
	if target == nil {
		return false
	}
	return new(big.Int).SetBytes(hash[:]).Cmp(target) <= 0
}
