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

//go:build cgo && ghostproofs && (linux || darwin)

package ghostpool

import "github.com/ethereum/go-ethereum/crypto"

// testKey and testAddr are the account of the real-proof tests' genesis and
// block 1 commit. The recorded fixture is made for the chain they give, so
// they stay the secp256k1 account until that fixture is regenerated.
var (
	testKey, _ = crypto.ToECDSA(crypto.Keccak256([]byte("ghost synthetic test account pool")))
	testAddr   = crypto.PubkeyToAddress(testKey.PublicKey)
)
