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

package linkage

import (
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
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

// accountCallTx is a call of to from key on bc, an account transaction
// signed for the chain's genesis; gas is the gas the call takes beyond the
// account transaction's extra intrinsic gas.
func accountCallTx(t *testing.T, bc *core.BlockChain, key *mldsa44.PrivateKey, nonce uint64, to common.Address, value *big.Int, data []byte, gas uint64) *types.Transaction {
	t.Helper()
	config := bc.Config()
	signer := types.NewGhostAccountSigner(types.LatestSigner(config), bc.Genesis().Hash())
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   config.GetChainID(),
		Nonce:     nonce,
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       gas + accountExtraGas,
		To:        &to,
		Value:     value,
		Data:      data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}
