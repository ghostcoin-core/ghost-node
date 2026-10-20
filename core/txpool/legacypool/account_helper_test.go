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

package legacypool

import (
	crand "crypto/rand"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	// testGenesis is the genesis block of the test chains: the pool takes
	// account transactions only from a chain that gives its genesis block.
	testGenesis = types.NewBlock(&types.Header{Number: new(big.Int), GasLimit: 10_000_000, Extra: []byte("legacypool test genesis")}, nil, nil, nil, trie.NewStackTrie(nil))

	// testSigner signs account transactions for the chain of testGenesis.
	testSigner = types.NewGhostAccountSigner(types.LatestSignerForChainID(params.TestChainConfig.GetChainID()), testGenesis.Hash())
)

// txGas is the intrinsic gas of a plain transfer by account transaction: the
// type 0x02 intrinsic gas, the gas per byte (16) of the scheme, key and
// signature, and the verification gas: 83744 gas.
var txGas = vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// testAccount returns the ML-DSA-44 key of a test account made from a fixed
// seed, its public key and its account address. A test that needs two
// accounts passes two seeds.
func testAccount(seed byte) (*mldsa44.PrivateKey, []byte, common.Address) {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	_, key := mldsa44.NewKeyFromSeed(&s)
	pub := key.Public().(*mldsa44.PublicKey).Bytes()
	return key, pub, types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub)
}

// accountTx signs a transfer to the zero address as an account transaction
// for the chain of testGenesis. It panics on error.
func accountTx(nonce uint64, gaslimit uint64, gasFeeCap, gasTipCap, value *big.Int, data []byte, key *mldsa44.PrivateKey) *types.Transaction {
	tx, err := types.SignGhostAccountTx(testSigner, key, &types.GhostAccountTx{
		ChainID:   params.TestChainConfig.GetChainID(),
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gaslimit,
		To:        &common.Address{},
		Value:     value,
		Data:      data,
	})
	if err != nil {
		panic(err)
	}
	return tx
}

func transaction(nonce uint64, gaslimit uint64, key *mldsa44.PrivateKey) *types.Transaction {
	return pricedTransaction(nonce, gaslimit, big.NewInt(1), key)
}

// pricedTransaction is the account transaction of a legacy transaction of a
// gas price: its fee cap and its tip are the gas price.
func pricedTransaction(nonce uint64, gaslimit uint64, gasprice *big.Int, key *mldsa44.PrivateKey) *types.Transaction {
	return accountTx(nonce, gaslimit, gasprice, gasprice, big.NewInt(100), nil, key)
}

func pricedValuedTransaction(nonce uint64, value int64, gaslimit uint64, gasprice *big.Int, key *mldsa44.PrivateKey) *types.Transaction {
	return accountTx(nonce, gaslimit, gasprice, gasprice, big.NewInt(value), nil, key)
}

func pricedDataTransaction(nonce uint64, gaslimit uint64, gasprice *big.Int, key *mldsa44.PrivateKey, bytes uint64) *types.Transaction {
	data := make([]byte, bytes)
	crand.Read(data)
	return accountTx(nonce, gaslimit, gasprice, gasprice, big.NewInt(0), data, key)
}

func dynamicFeeTx(nonce uint64, gaslimit uint64, gasFee *big.Int, tip *big.Int, key *mldsa44.PrivateKey) *types.Transaction {
	return accountTx(nonce, gaslimit, gasFee, tip, big.NewInt(100), nil, key)
}
