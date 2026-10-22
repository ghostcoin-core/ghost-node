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
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// TestBlockWithSecp256k1TxTypeIsInvalid checks QS-1 in block processing: a
// block holding one transaction of a secp256k1 type, legacy (0x00), EIP-2930
// (0x01), EIP-1559 (0x02) or EIP-4844 (0x03), with a valid secp256k1
// signature of a funded address, is invalid, on a chain where every fork is
// active. The refusal is by the type byte: the transaction is not applied.
// A block holding a type 0x04 transaction cannot be decoded.
func TestBlockWithSecp256k1TxTypeIsInvalid(t *testing.T) {
	var (
		config = ghostAccountTestConfig()
		key, _ = crypto.GenerateKey()
		from   = crypto.PubkeyToAddress(key.PublicKey)
		to     = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		gspec  = &genesisT.Genesis{
			Config:  config,
			Alloc:   genesisT.GenesisAlloc{from: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			BaseFee: big.NewInt(vars.InitialBaseFee),
		}
		engine  = beacon.New(ethash.NewFaker())
		price   = big.NewInt(100 * vars.InitialBaseFee)
		chainID = config.ChainID
		signer  = types.LatestSigner(config)
	)
	txdata := []types.TxData{
		&types.LegacyTx{GasPrice: price, Gas: vars.TxGas, To: &to, Value: big.NewInt(1)},
		&types.AccessListTx{ChainID: chainID, GasPrice: price, Gas: vars.TxGas, To: &to, Value: big.NewInt(1)},
		&types.DynamicFeeTx{ChainID: chainID, GasTipCap: price, GasFeeCap: price, Gas: vars.TxGas, To: &to, Value: big.NewInt(1)},
		&types.BlobTx{
			ChainID:    uint256.MustFromBig(chainID),
			GasTipCap:  uint256.MustFromBig(price),
			GasFeeCap:  uint256.MustFromBig(price),
			Gas:        vars.TxGas,
			To:         to,
			Value:      uint256.NewInt(1),
			BlobFeeCap: uint256.MustFromBig(price),
			BlobHashes: []common.Hash{{0x01}},
		},
	}
	for _, data := range txdata {
		tx, err := types.SignTx(types.NewTx(data), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, r, s := tx.RawSignatureValues(); r.Sign() == 0 || s.Sign() == 0 {
			t.Fatalf("type %#x not signed", tx.Type())
		}

		chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// The block is invalid: the chain does not import it.
		bad := GenerateBadBlock(chain.Genesis(), engine, types.Transactions{tx}, config)
		if _, err := chain.InsertChain(types.Blocks{bad}); err == nil {
			t.Errorf("type %#x: block imported", tx.Type())
		}
		if chain.CurrentBlock().Number.Sign() != 0 {
			t.Errorf("type %#x: head moved to block %d", tx.Type(), chain.CurrentBlock().Number)
		}
		// It is invalid for the type of its transaction: processing refuses
		// it before the transaction is applied.
		statedb, err := state.New(chain.Genesis().Root(), chain.StateCache(), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, err = chain.Processor().Process(bad, statedb, vm.Config{})
		if !errors.Is(err, types.ErrSecp256k1TxType) {
			t.Errorf("type %#x: process error %v, want %v", tx.Type(), err, types.ErrSecp256k1TxType)
		}
		if got := statedb.GetNonce(from); got != 0 {
			t.Errorf("type %#x: sender nonce %d, want 0", tx.Type(), got)
		}
		if got := statedb.GetBalance(to); !got.IsZero() {
			t.Errorf("type %#x: recipient balance %v, want 0", tx.Type(), got)
		}
		// Applied alone, it is refused the same way.
		gp := new(GasPool).AddGas(bad.GasLimit())
		if _, err := ApplyTransaction(config, chain, nil, gp, statedb, bad.Header(), tx, new(uint64), vm.Config{}); !errors.Is(err, types.ErrSecp256k1TxType) {
			t.Errorf("type %#x: apply error %v, want %v", tx.Type(), err, types.ErrSecp256k1TxType)
		}
		chain.Stop()
	}

	// A block holding a type 0x04 transaction, signed with secp256k1, is not
	// decoded: the type is unknown to the node.
	fields := []interface{}{chainID, uint64(0), price, price, vars.TxGas, to, big.NewInt(1), []byte{}, types.AccessList{}, []interface{}{}}
	payload, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(crypto.Keccak256(append([]byte{0x04}, payload...)), key)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err = rlp.EncodeToBytes(append(fields, uint64(sig[64]), new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]))); err != nil {
		t.Fatal(err)
	}
	envelope, err := rlp.EncodeToBytes(append([]byte{0x04}, payload...))
	if err != nil {
		t.Fatal(err)
	}
	header := types.NewBlock(&types.Header{Number: big.NewInt(1), GasLimit: 30_000_000}, nil, nil, nil, trie.NewStackTrie(nil)).Header()
	enc, err := rlp.EncodeToBytes([]interface{}{header, []rlp.RawValue{envelope}, []*types.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rlp.DecodeBytes(enc, new(types.Block)); !errors.Is(err, types.ErrTxTypeNotSupported) {
		t.Errorf("block with a type 0x04 transaction: decode error %v, want %v", err, types.ErrTxTypeNotSupported)
	}
}
