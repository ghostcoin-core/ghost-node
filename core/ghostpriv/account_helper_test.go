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

package ghostpriv_test

import (
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// testAccount is the ML-DSA-44 test account of a fixed seed: the key, the
// public key and the account address.
func testAccount(seed byte) (*mldsa44.PrivateKey, []byte, common.Address) {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa44.NewKeyFromSeed(&s)
	pub := pk.Bytes()
	return sk, pub, types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub)
}

// accountExtraGas is the intrinsic gas an ML-DSA-44 account transaction
// takes on top of that of a type 0x02 transaction: its scheme, public key and
// signature as calldata and the signature verification.
var accountExtraGas uint64 = 16*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

var (
	keyA, _, addrA = testAccount(0xa1)
	keyB, _, addrB = testAccount(0xb2)
	keyC, _, addrC = testAccount(0xc3)
)

// callTx is a call of to from key, an account transaction; gas is the gas
// the call takes beyond the account transaction's extra intrinsic gas.
func (f *fixture) callTx(key *mldsa44.PrivateKey, nonce uint64, to common.Address, value *big.Int, data []byte, gas uint64) *types.Transaction {
	f.t.Helper()
	return f.signAccountTx(key, &types.GhostAccountTx{
		ChainID:   new(big.Int).SetUint64(f.chainID),
		Nonce:     nonce,
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       gas + accountExtraGas,
		To:        &to,
		Value:     value,
		Data:      data,
	})
}

// signAccountTx signs txdata with key for the fixture's chain. An ML-DSA
// signature is hedged, so two signatures of one transaction differ: the
// fixture signs each transaction once and hands the same one back, so that a
// chain generated twice is generated identically.
func (f *fixture) signAccountTx(key *mldsa44.PrivateKey, txdata *types.GhostAccountTx) *types.Transaction {
	f.t.Helper()
	unsigned := *txdata
	unsigned.Scheme = types.GhostScheme(types.GhostSchemeMLDSA44)
	unsigned.PublicKey = key.Public().(*mldsa44.PublicKey).Bytes()
	unsigned.Signature = nil
	id := f.signer.Hash(types.NewTx(&unsigned))
	if tx, ok := f.signed[id]; ok {
		return tx
	}
	tx, err := types.SignGhostAccountTx(f.signer, key, txdata)
	if err != nil {
		f.t.Fatal(err)
	}
	f.signed[id] = tx
	return tx
}
