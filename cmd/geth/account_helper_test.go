// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// testAccount returns the ML-DSA-44 key made from a seed of the given byte,
// its public key and the address of its account.
func testAccount(seed byte) (*mldsa44.PrivateKey, []byte, common.Address) {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa44.NewKeyFromSeed(&s)
	pub := pk.Bytes()
	return sk, pub, types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub)
}
