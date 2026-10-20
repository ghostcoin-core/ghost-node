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

package fetcher

import (
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
)

// testTransferGas is the gas of an ML-DSA-44 account transfer: the transfer
// gas, the gas of the scheme ID, public key and signature bytes, and the
// verification gas of the scheme.
var testTransferGas = vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

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

// signTestTransfer signs an account transfer of value to the recipient with
// testKey, for the test chain, paying the block's base fee.
func signTestTransfer(block *core.BlockGen, to common.Address, value *big.Int) *types.Transaction {
	signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), genesis.Hash())
	tx, err := types.SignGhostAccountTx(signer, testKey, &types.GhostAccountTx{
		ChainID:   gspec.Config.GetChainID(),
		Nonce:     block.TxNonce(testAddress),
		GasTipCap: new(big.Int),
		GasFeeCap: block.BaseFee(),
		Gas:       testTransferGas,
		To:        &to,
		Value:     value,
	})
	if err != nil {
		panic(err)
	}
	return tx
}
