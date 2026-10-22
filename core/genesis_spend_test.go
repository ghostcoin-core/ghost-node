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
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rlp"
)

// TestBlockSpendingCreditedFundsWithSecp256k1TypesInvalid checks QS-1 on the
// internal network's chain configuration. Funds reach the address of a
// secp256k1 key the three ways an address is credited without sending: a
// block reward, a transaction tip and a SELFDESTRUCT beneficiary, all paid by
// an account transaction from an account funded by a block reward. A block
// spending those funds with a legacy, EIP-2930 or EIP-1559 transaction signed
// with that key is invalid, alone or after a valid account transaction, and
// leaves the funds where they are. A block holding an EIP-7702 transaction
// does not decode.
func TestBlockSpendingCreditedFundsWithSecp256k1TypesInvalid(t *testing.T) {
	var (
		gspec                  = ghost.InternalNetGenesis()
		config                 = gspec.Config
		chainID                = config.GetChainID()
		engine                 = ethash.NewFullFaker()
		accountKey, _, account = testAccount(0xa1)
		secpKey, _             = crypto.ToECDSA(common.LeftPadBytes([]byte{0x5e, 0xc9}, 32))
		secpAddr               = crypto.PubkeyToAddress(secpKey.PublicKey)
		recipient              = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		tip                    = big.NewInt(2_000_000_000)
		value                  = new(big.Int).Exp(big.NewInt(10), big.NewInt(17), nil)
		destructGas            = 100_000 + ghostExtraGas
	)
	if len(gspec.Alloc) != 0 {
		t.Fatalf("the internal network allocates %d accounts at genesis", len(gspec.Alloc))
	}
	// Init code that sends the new contract's balance to the secp256k1
	// address: PUSH20 address, SELFDESTRUCT.
	initCode := append(append([]byte{0x73}, secpAddr.Bytes()...), 0xff)
	contract := crypto.CreateAddress(account, 0)

	// Block 1 pays its reward to the account. Block 2 pays its reward to the
	// secp256k1 address, and holds the account's contract creation, whose
	// tip goes to the block's coinbase and whose value the contract's
	// SELFDESTRUCT sends to the same address.
	var genesisHash common.Hash
	_, blocks, receipts := GenerateChainWithGenesis(gspec, engine, 2, func(i int, b *BlockGen) {
		if i == 0 {
			genesisHash = b.PrevBlock(-1).Hash()
			b.SetCoinbase(account)
			return
		}
		b.SetCoinbase(secpAddr)
		b.AddTx(signAccountTx(config, genesisHash, accountKey, &types.GhostAccountTx{
			Nonce:     b.TxNonce(account),
			GasTipCap: tip,
			GasFeeCap: new(big.Int).Add(b.BaseFee(), tip),
			Gas:       destructGas,
			Value:     value,
			Data:      initCode,
		}))
	})
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if chain.Genesis().Hash() != genesisHash {
		t.Fatal("the chain's genesis differs from the generated one")
	}
	if n, err := chain.InsertChain(blocks[:1]); err != nil {
		t.Fatalf("block %d not imported: %v", n+1, err)
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	reward := statedb.GetBalance(account).ToBig()
	if reward.Sign() == 0 {
		t.Fatal("block 1 credits no reward to the account")
	}

	// The account spends its credited reward with an account transaction.
	if n, err := chain.InsertChain(blocks[1:]); err != nil {
		t.Fatalf("block %d not imported: %v", n+2, err)
	}
	if statedb, err = chain.State(); err != nil {
		t.Fatal(err)
	}
	receipt := receipts[1][0]
	if receipt.Status != types.ReceiptStatusSuccessful || receipt.ContractAddress != contract {
		t.Fatalf("contract creation: status %d, contract %v, want success at %v", receipt.Status, receipt.ContractAddress, contract)
	}
	if got := statedb.GetNonce(account); got != 1 {
		t.Errorf("account nonce %d, want 1", got)
	}
	if code, bal := statedb.GetCode(contract), statedb.GetBalance(contract); len(code) != 0 || !bal.IsZero() {
		t.Errorf("the contract keeps code %x and balance %v after SELFDESTRUCT", code, bal)
	}
	paid := new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), new(big.Int).Add(blocks[1].BaseFee(), tip))
	paid.Add(paid, value)
	if got, want := statedb.GetBalance(account).ToBig(), new(big.Int).Sub(reward, paid); got.Cmp(want) != 0 {
		t.Errorf("account balance %v after spending, want %v", got, want)
	}
	// The secp256k1 address holds the block reward, the tip and the
	// SELFDESTRUCT value, and nothing else.
	credited := new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), tip)
	credited.Add(credited, reward)
	credited.Add(credited, value)
	if got := statedb.GetBalance(secpAddr).ToBig(); got.Cmp(credited) != 0 {
		t.Fatalf("secp256k1 address balance %v, want reward %v + tip + value %v = %v", got, reward, value, credited)
	}

	// Each secp256k1 type signed with the key of the credited address, moving
	// part of its funds. The funds cover the value and the gas, so only the
	// type can make the block invalid.
	var (
		head    = chain.CurrentBlock()
		parent  = chain.GetBlock(head.Hash(), head.Number.Uint64())
		price   = new(big.Int).Mul(parent.BaseFee(), big.NewInt(2))
		send    = big.NewInt(1_000_000_000)
		oldSign = types.LatestSigner(config)
	)
	if need := new(big.Int).Add(send, new(big.Int).Mul(price, big.NewInt(21_000))); credited.Cmp(need) <= 0 {
		t.Fatalf("credited funds %v do not cover %v", credited, need)
	}
	txdata := []types.TxData{
		&types.LegacyTx{GasPrice: price, Gas: 21_000, To: &recipient, Value: send},
		&types.AccessListTx{ChainID: chainID, GasPrice: price, Gas: 21_000, To: &recipient, Value: send},
		&types.DynamicFeeTx{ChainID: chainID, GasTipCap: price, GasFeeCap: price, Gas: 21_000, To: &recipient, Value: send},
	}
	for _, data := range txdata {
		tx, err := types.SignTx(types.NewTx(data), oldSign, secpKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, r, s := tx.RawSignatureValues(); r.Sign() == 0 || s.Sign() == 0 {
			t.Fatalf("type %#x not signed", tx.Type())
		}
		// A valid account transaction does not make the block valid.
		spend := signAccountTx(config, genesisHash, accountKey, &types.GhostAccountTx{
			Nonce:     1,
			GasTipCap: tip,
			GasFeeCap: new(big.Int).Add(price, tip),
			Gas:       accountTransferGas,
			To:        &recipient,
			Value:     big.NewInt(1),
		})
		for _, txs := range []types.Transactions{{tx}, {spend, tx}} {
			bad := GenerateBadBlock(parent, engine, txs, config)
			if _, err := chain.InsertChain(types.Blocks{bad}); !errors.Is(err, types.ErrSecp256k1TxType) {
				t.Errorf("type %#x in a block of %d transactions: import error %v, want %v", tx.Type(), len(txs), err, types.ErrSecp256k1TxType)
			}
			if chain.CurrentBlock().Hash() != head.Hash() {
				t.Fatalf("type %#x: head moved to block %d", tx.Type(), chain.CurrentBlock().Number)
			}
			// The block is refused before the transaction is applied.
			st, err := chain.State()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := chain.Processor().Process(bad, st, vm.Config{}); !errors.Is(err, types.ErrSecp256k1TxType) {
				t.Errorf("type %#x: process error %v, want %v", tx.Type(), err, types.ErrSecp256k1TxType)
			}
			if got := st.GetNonce(secpAddr); got != 0 {
				t.Errorf("type %#x: secp256k1 address nonce %d, want 0", tx.Type(), got)
			}
			if got := st.GetBalance(recipient); got.Uint64() > 1 {
				t.Errorf("type %#x: recipient balance %v, the secp256k1 transfer was applied", tx.Type(), got)
			}
		}
	}
	if statedb, err = chain.State(); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(secpAddr).ToBig(); got.Cmp(credited) != 0 {
		t.Errorf("secp256k1 address balance %v after the refused blocks, want %v", got, credited)
	}
	if got := statedb.GetBalance(recipient); !got.IsZero() {
		t.Errorf("recipient balance %v after the refused blocks, want 0", got)
	}

	// An EIP-7702 transaction signed with the same key does not decode, and
	// neither does a block holding it.
	fields := []interface{}{chainID, uint64(0), price, price, uint64(21_000), recipient, send, []byte{}, types.AccessList{}, []interface{}{}}
	payload, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(crypto.Keccak256(append([]byte{0x04}, payload...)), secpKey)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err = rlp.EncodeToBytes(append(fields, uint64(sig[64]), new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]))); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte{0x04}, payload...)
	if err := new(types.Transaction).UnmarshalBinary(raw); !errors.Is(err, types.ErrTxTypeNotSupported) {
		t.Errorf("type 0x04 transaction: decode error %v, want %v", err, types.ErrTxTypeNotSupported)
	}
	envelope, err := rlp.EncodeToBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	header := GenerateBadBlock(parent, engine, nil, config).Header()
	enc, err := rlp.EncodeToBytes([]interface{}{header, []rlp.RawValue{envelope}, []*types.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rlp.DecodeBytes(enc, new(types.Block)); !errors.Is(err, types.ErrTxTypeNotSupported) {
		t.Errorf("block with a type 0x04 transaction: decode error %v, want %v", err, types.ErrTxTypeNotSupported)
	}
}
