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

package core

import (
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
)

// accountTransferGas is the intrinsic gas of a plain transfer by account
// transaction.
var accountTransferGas = vars.TxGas + ghostExtraGas

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

// accountSigner returns the signer of account transactions of config for the
// chain of genesis.
func accountSigner(config ctypes.ChainConfigurator, genesis common.Hash) types.Signer {
	return types.NewGhostAccountSigner(types.LatestSigner(config), genesis)
}

// signAccountTx signs txdata as an account transaction for the chain of
// genesis. The chain ID is set from config when txdata has none, and nil
// amounts are zero. It panics on error, so it can be used in block
// generators.
func signAccountTx(config ctypes.ChainConfigurator, genesis common.Hash, key *mldsa44.PrivateKey, txdata *types.GhostAccountTx) *types.Transaction {
	if txdata.ChainID == nil {
		txdata.ChainID = config.GetChainID()
	}
	for _, v := range []**big.Int{&txdata.GasTipCap, &txdata.GasFeeCap, &txdata.Value} {
		if *v == nil {
			*v = new(big.Int)
		}
	}
	tx, err := types.SignGhostAccountTx(accountSigner(config, genesis), key, txdata)
	if err != nil {
		panic(err)
	}
	return tx
}

// signTransfer signs a transfer of value to to, with the gas and the fee cap
// given and a tip of the fee cap, for the chain of genesis.
func signTransfer(config ctypes.ChainConfigurator, genesis common.Hash, key *mldsa44.PrivateKey, nonce uint64, to common.Address, value *big.Int, gas uint64, feeCap *big.Int, data []byte) *types.Transaction {
	return signAccountTx(config, genesis, key, &types.GhostAccountTx{
		Nonce:     nonce,
		GasTipCap: feeCap,
		GasFeeCap: feeCap,
		Gas:       gas,
		To:        &to,
		Value:     value,
		Data:      data,
	})
}

// genesisOf returns the genesis hash of the chain a block is generated on,
// zero when the generation does not start at the genesis block.
func genesisOf(b *BlockGen) common.Hash {
	if g := b.cm.GetHeaderByNumber(0); g != nil {
		return g.Hash()
	}
	return common.Hash{}
}

// blockTransfer signs a transfer for the block being generated: the sender's
// next nonce, the block's base fee as fee cap and tip, and the chain of the
// block's genesis.
func blockTransfer(b *BlockGen, key *mldsa44.PrivateKey, from, to common.Address, value *big.Int, gas uint64, data []byte) *types.Transaction {
	return signTransfer(b.cm.config, genesisOf(b), key, b.TxNonce(from), to, value, gas, b.BaseFee(), data)
}
