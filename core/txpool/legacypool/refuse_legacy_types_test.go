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
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// secp256k1PoolTxs returns a transaction of each secp256k1 type the node can
// decode, legacy (0x00), EIP-2930 (0x01), EIP-1559 (0x02) and EIP-4844 (0x03),
// each with a valid secp256k1 signature of key for chainID: types.SignTx signs
// and recovers nothing. Each pays well above its intrinsic gas and fee.
func secp256k1PoolTxs(t *testing.T, chainID *big.Int, nonce uint64, key *ecdsa.PrivateKey) []*types.Transaction {
	t.Helper()
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	price := big.NewInt(1_000_000_000)
	txdata := []types.TxData{
		&types.LegacyTx{Nonce: nonce, GasPrice: price, Gas: 100_000, To: &to, Value: big.NewInt(1)},
		&types.AccessListTx{ChainID: chainID, Nonce: nonce, GasPrice: price, Gas: 100_000, To: &to, Value: big.NewInt(1)},
		&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: price, GasFeeCap: price, Gas: 100_000, To: &to, Value: big.NewInt(1)},
		&types.BlobTx{
			ChainID:    uint256.MustFromBig(chainID),
			Nonce:      nonce,
			GasTipCap:  uint256.MustFromBig(price),
			GasFeeCap:  uint256.MustFromBig(price),
			Gas:        100_000,
			To:         to,
			Value:      uint256.NewInt(1),
			BlobFeeCap: uint256.NewInt(1_000_000_000),
			BlobHashes: []common.Hash{{0x01}},
		},
	}
	signer := types.LatestSignerForChainID(chainID)
	txs := make([]*types.Transaction, 0, len(txdata))
	for _, data := range txdata {
		tx, err := types.SignTx(types.NewTx(data), signer, key)
		if err != nil {
			t.Fatalf("sign type %#x: %v", types.NewTx(data).Type(), err)
		}
		if v, r, s := tx.RawSignatureValues(); r.Sign() == 0 || s.Sign() == 0 || v == nil {
			t.Fatalf("type %#x not signed", tx.Type())
		}
		txs = append(txs, tx)
	}
	return txs
}

// setCodeTxEnvelope returns an EIP-7702 envelope (type 0x04) of key for
// chainID, with a valid secp256k1 signature over its signature hash.
func setCodeTxEnvelope(t *testing.T, chainID *big.Int, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	fields := []interface{}{chainID, uint64(0), big.NewInt(1), big.NewInt(1), uint64(100_000), to, big.NewInt(1), []byte{}, types.AccessList{}, []interface{}{}}
	payload, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	sighash := crypto.Keccak256(append([]byte{0x04}, payload...))
	sig, err := crypto.Sign(sighash, key)
	if err != nil {
		t.Fatal(err)
	}
	signed := append(fields, uint64(sig[64]), new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]))
	if payload, err = rlp.EncodeToBytes(signed); err != nil {
		t.Fatal(err)
	}
	return append([]byte{0x04}, payload...)
}

// TestSecp256k1TxTypesRefusedByPool checks QS-1 in the pool: a transaction of
// each secp256k1 type with a valid signature, from a funded address, is
// refused by its type byte, as a remote and as a local transaction, on a
// chain with every fork and on a Frontier chain, where Ethereum would take a
// legacy transaction. A type 0x04 envelope is not decoded at all, so it never
// reaches the pool.
func TestSecp256k1TxTypesRefusedByPool(t *testing.T) {
	frontier := &goethereum.ChainConfig{ChainID: big.NewInt(1337), Ethash: new(ctypes.EthashConfig)}
	for _, tc := range []struct {
		name      string
		config    ctypes.ChainConfigurator
		accountTx bool // the chain takes account transactions (Berlin)
	}{
		{"every fork", params.TestChainConfig, true},
		{"frontier", frontier, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, _, _ := setupPoolWithConfig(tc.config)
			defer pool.Close()

			key, _ := crypto.GenerateKey()
			testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1_000_000_000_000_000_000))
			chainID := tc.config.GetChainID()

			for _, tx := range secp256k1PoolTxs(t, chainID, 0, key) {
				if pool.Filter(tx) {
					t.Errorf("type %#x: the pool takes it", tx.Type())
				}
				if err := pool.addRemoteSync(tx); !errors.Is(err, types.ErrSecp256k1TxType) || !errors.Is(err, core.ErrTxTypeNotSupported) {
					t.Errorf("type %#x remote: error %v, want %v", tx.Type(), err, types.ErrSecp256k1TxType)
				}
				if err := pool.addLocal(tx); !errors.Is(err, types.ErrSecp256k1TxType) {
					t.Errorf("type %#x local: error %v, want %v", tx.Type(), err, types.ErrSecp256k1TxType)
				}
				if pool.Get(tx.Hash()) != nil {
					t.Errorf("type %#x: in the pool", tx.Type())
				}
			}
			// The refusal is by the type byte, before any other check: a
			// transaction of each type with a zero signature and no gas is
			// refused the same way.
			for _, tx := range secp256k1PoolTxs(t, chainID, 0, key) {
				var unsigned types.TxData
				switch tx.Type() {
				case types.LegacyTxType:
					unsigned = &types.LegacyTx{GasPrice: tx.GasPrice(), To: tx.To(), Value: tx.Value()}
				case types.AccessListTxType:
					unsigned = &types.AccessListTx{ChainID: chainID, GasPrice: tx.GasPrice(), To: tx.To(), Value: tx.Value()}
				case types.DynamicFeeTxType:
					unsigned = &types.DynamicFeeTx{ChainID: chainID, GasTipCap: tx.GasTipCap(), GasFeeCap: tx.GasFeeCap(), To: tx.To(), Value: tx.Value()}
				case types.BlobTxType:
					unsigned = &types.BlobTx{ChainID: uint256.MustFromBig(chainID), To: *tx.To()}
				}
				bad := types.NewTx(unsigned)
				if err := pool.addRemoteSync(bad); !errors.Is(err, types.ErrSecp256k1TxType) {
					t.Errorf("unsigned type %#x without gas: error %v, want %v", bad.Type(), err, types.ErrSecp256k1TxType)
				}
			}
			if pending, queued := pool.Stats(); pending != 0 || queued != 0 {
				t.Fatalf("pending %d, queued %d, want none", pending, queued)
			}

			// Type 0x04: the envelope is refused when it is decoded.
			var setCode types.Transaction
			if err := setCode.UnmarshalBinary(setCodeTxEnvelope(t, chainID, key)); !errors.Is(err, types.ErrTxTypeNotSupported) {
				t.Errorf("type 0x04 envelope: decode error %v, want %v", err, types.ErrTxTypeNotSupported)
			}

			if !tc.accountTx {
				return
			}
			// An account transaction of a funded account is still taken.
			accKey, _, accAddr := testAccount(1)
			testAddBalance(pool, accAddr, big.NewInt(1_000_000_000_000_000_000))
			acc := makeGhostPoolTx(t, testGenesis.Hash(), accKey, ghostPoolTx{nonce: 0, gas: txGas})
			if !pool.Filter(acc) {
				t.Fatal("the pool does not take account transactions")
			}
			if err := pool.addRemoteSync(acc); err != nil {
				t.Fatalf("account transaction refused: %v", err)
			}
			if err := validatePoolInternals(pool); err != nil {
				t.Fatal(err)
			}
		})
	}
}
