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

import "github.com/holiman/uint256"

const (
	// fixedBits is the scale of the reward's fixed point: 1.0 is 2^128.
	fixedBits = 128

	// hornerTerms is the number of terms of the Taylor series of e^(-u).
	hornerTerms = 24

	// maxHalvings caps the completed emission half-lives; past it the
	// decayed value is zero and the tail applies.
	maxHalvings = 255
)

// ln2Fixed is floor(ln 2 * 2^128).
var ln2Fixed = uint256.MustFromHex("0xb17217f7d1cf79abc9e3b39803f2f6af")

// BlockReward returns the reward in wei of the block at the given height:
// floor(R0 * 2^(-(h-1)/H)) with H = EmissionHalfLife / BlockTime, or the tail
// reward once that is not above the tail. Height 0 pays nothing. The
// parameters must pass Validate.
func (p Params) BlockReward(height uint64) *uint256.Int {
	if height == 0 {
		return new(uint256.Int)
	}
	halfLife := EmissionHalfLife / p.BlockTime
	e := height - 1
	q := min(e/halfLife, maxHalvings)
	r := e % halfLife

	// u = r/H * ln 2 in fixed point; r < H, so u < ln 2.
	u := new(uint256.Int).Mul(uint256.NewInt(r), ln2Fixed)
	u.Div(u, uint256.NewInt(halfLife))

	// Horner form of e^(-u): s = 1 - u*s/k for k = 24 down to 1. Each
	// step keeps s in [0, 2^128], so u*s stays below 2^256.
	one := new(uint256.Int).Lsh(uint256.NewInt(1), fixedBits)
	s := new(uint256.Int).Set(one)
	t := new(uint256.Int)
	for k := uint64(hornerTerms); k > 0; k-- {
		t.Mul(u, s)
		t.Rsh(t, fixedBits)
		t.Div(t, uint256.NewInt(k))
		s.Sub(one, t)
	}

	// The single floor: R0 * s < 2^192, shifted down by 128 + q.
	decayed := new(uint256.Int).Mul(p.FirstReward, s)
	decayed.Rsh(decayed, uint(fixedBits+q))
	if decayed.Gt(p.TailReward) {
		return decayed
	}
	return new(uint256.Int).Set(p.TailReward)
}
