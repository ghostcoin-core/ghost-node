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

package ghostpool

import (
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// accountTxExtraGas is the intrinsic gas an ML-DSA-44 account transaction
// takes on top of the intrinsic gas of the same transfer of type 0x02.
var accountTxExtraGas uint64 = 16*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// testAccount is the ML-DSA-44 test account of the 32-byte seed filled with
// seed: its key, public key and address.
func testAccount(seed byte) (*mldsa44.PrivateKey, []byte, common.Address) {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pub, key := mldsa44.NewKeyFromSeed(&s)
	pk := pub.Bytes()
	return key, pk, types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pk)
}

// signAccountTransfer signs a transfer of value with data to to as an account
// transaction of key, for the chain ID of signer, which must come from
// types.NewGhostAccountSigner. It panics if the transaction cannot be signed.
func signAccountTransfer(signer types.Signer, key *mldsa44.PrivateKey, nonce uint64, to *common.Address, value, tipCap, feeCap *big.Int, gas uint64, data []byte) *types.Transaction {
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   signer.ChainID(),
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       gas,
		To:        to,
		Value:     value,
		Data:      data,
	})
	if err != nil {
		panic(err)
	}
	return tx
}
