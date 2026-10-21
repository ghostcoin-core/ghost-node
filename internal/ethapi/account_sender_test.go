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

package ethapi

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
)

// accountSenderGas is the gas of an account transfer signed with ML-DSA-44.
var accountSenderGas = vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// accountSenderBackend is a test backend whose pool holds one pending
// transaction of an account. With a genesis header set, it serves that header
// as block 0 in place of the chain's.
type accountSenderBackend struct {
	*testBackend
	pendingTx *types.Transaction
	sender    common.Address
	genesis   *types.Header
}

func (b accountSenderBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number == 0 && b.genesis != nil {
		return b.genesis, nil
	}
	return b.testBackend.HeaderByNumber(ctx, number)
}

func (b accountSenderBackend) GetTransaction(ctx context.Context, txHash common.Hash) (bool, *types.Transaction, common.Hash, uint64, uint64, error) {
	if txHash == b.pendingTx.Hash() {
		return false, nil, common.Hash{}, 0, 0, nil
	}
	return b.testBackend.GetTransaction(ctx, txHash)
}

func (b accountSenderBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	if txHash == b.pendingTx.Hash() {
		return b.pendingTx
	}
	return nil
}

func (b accountSenderBackend) GetPoolTransactions() (types.Transactions, error) {
	return types.Transactions{b.pendingTx}, nil
}

func (b accountSenderBackend) TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return map[common.Address][]*types.Transaction{b.sender: {b.pendingTx}}, map[common.Address][]*types.Transaction{}
}

func (b accountSenderBackend) TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	if addr != b.sender {
		return nil, nil
	}
	return []*types.Transaction{b.pendingTx}, nil
}

// callError returns the error of an API call, whatever its result.
func callError(result interface{}, err error) error {
	return err
}

// TestAccountSenderRPCFrom checks that the from of a block's, a receipt's and
// a pending account transaction is its account, and that a sender that
// cannot be derived is an error, never the zero address.
func TestAccountSenderRPCFrom(t *testing.T) {
	t.Parallel()

	key, pub, addr := testAccount(0x61)
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub); addr != want {
		t.Fatalf("account address %x, want %x", addr, want)
	}
	recipient := common.HexToAddress("0x5252525252525252525252525252525252525252")
	gspec := &genesisT.Genesis{
		Config:  params.TestChainConfig,
		Alloc:   genesisT.GenesisAlloc{addr: {Balance: big.NewInt(vars.Ether)}},
		BaseFee: big.NewInt(vars.InitialBaseFee),
	}
	// The test backend adds its keystore account to the genesis allocation,
	// so the genesis hash is read when signing.
	sign := func(nonce uint64) *types.Transaction {
		signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), core.GenesisToBlock(gspec, nil).Hash())
		tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
			ChainID:   gspec.Config.GetChainID(),
			Nonce:     nonce,
			GasTipCap: new(big.Int),
			GasFeeCap: big.NewInt(100 * vars.GWei),
			Gas:       accountSenderGas,
			To:        &recipient,
			Value:     big.NewInt(1000),
		})
		if err != nil {
			t.Fatalf("sign account transaction %d: %v", nonce, err)
		}
		return tx
	}
	var mined *types.Transaction
	base := newTestBackend(t, 1, gspec, ethash.NewFaker(), func(i int, b *core.BlockGen) {
		mined = sign(0)
		b.AddTx(mined)
	})
	defer base.chain.Stop()
	backend := accountSenderBackend{testBackend: base, pendingTx: sign(1), sender: addr}

	ctx := context.Background()
	chainAPI := NewBlockChainAPI(backend)
	txAPI := NewTransactionAPI(backend, new(AddrLocker))
	poolAPI := NewTxPoolAPI(backend)
	check := func(name string, got interface{}) {
		t.Helper()
		if got != addr {
			t.Errorf("%s: from %v, want the account %x", name, got, addr)
		}
	}

	// The block's transactions.
	block, err := chainAPI.GetBlockByNumber(ctx, 1, true)
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if len(block.Transactions) != 1 {
		t.Fatalf("block has %d transactions, want 1", len(block.Transactions))
	}
	rpcTx, ok := block.Transactions[0].(*RPCTransaction)
	if !ok {
		t.Fatalf("block transaction of type %T", block.Transactions[0])
	}
	check("block transaction", rpcTx.From)
	byHash, err := chainAPI.GetBlockByHash(ctx, base.chain.GetBlockByNumber(1).Hash(), true)
	if err != nil {
		t.Fatalf("block by hash: %v", err)
	}
	check("block by hash transaction", byHash.Transactions[0].(*RPCTransaction).From)
	if rpcTx, err = txAPI.GetTransactionByBlockNumberAndIndex(ctx, 1, 0); err != nil {
		t.Fatalf("transaction by block and index: %v", err)
	}
	check("transaction by block and index", rpcTx.From)
	if rpcTx, err = txAPI.GetTransactionByHash(ctx, mined.Hash()); err != nil {
		t.Fatalf("transaction by hash: %v", err)
	}
	check("transaction by hash", rpcTx.From)

	// The receipts.
	receipt, err := txAPI.GetTransactionReceipt(ctx, mined.Hash())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	check("receipt", receipt["from"])
	receipts, err := chainAPI.GetBlockReceipts(ctx, rpc.BlockNumberOrHashWithNumber(1))
	if err != nil {
		t.Fatalf("block receipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("%d block receipts, want 1", len(receipts))
	}
	check("block receipt", receipts[0]["from"])

	// The pending transaction.
	if rpcTx, err = txAPI.GetTransactionByHash(ctx, backend.pendingTx.Hash()); err != nil {
		t.Fatalf("pending transaction by hash: %v", err)
	}
	check("pending transaction", rpcTx.From)
	content, err := poolAPI.Content(ctx)
	if err != nil {
		t.Fatalf("pool content: %v", err)
	}
	check("pool content", content["pending"][addr.Hex()]["1"].From)
	contentFrom, err := poolAPI.ContentFrom(ctx, addr)
	if err != nil {
		t.Fatalf("pool content from: %v", err)
	}
	check("pool content from", contentFrom["pending"]["1"].From)

	// Bound to another genesis hash, the signatures do not verify.
	other := backend
	other.genesis = &types.Header{Number: new(big.Int), Extra: []byte("another chain")}
	chainAPI, txAPI, poolAPI = NewBlockChainAPI(other), NewTransactionAPI(other, new(AddrLocker)), NewTxPoolAPI(other)
	for name, call := range map[string]func() error{
		"block": func() error {
			return callError(chainAPI.GetBlockByNumber(ctx, 1, true))
		},
		"transaction by hash": func() error {
			return callError(txAPI.GetTransactionByHash(ctx, mined.Hash()))
		},
		"receipt": func() error {
			return callError(txAPI.GetTransactionReceipt(ctx, mined.Hash()))
		},
		"block receipts": func() error {
			return callError(chainAPI.GetBlockReceipts(ctx, rpc.BlockNumberOrHashWithNumber(1)))
		},
		"pending transaction": func() error {
			return callError(txAPI.GetTransactionByHash(ctx, backend.pendingTx.Hash()))
		},
		"pool content": func() error {
			return callError(poolAPI.Content(ctx))
		},
		"pending transactions": func() error {
			return callError(txAPI.PendingTransactions(ctx))
		},
	} {
		if err := call(); !errors.Is(err, types.ErrInvalidSig) {
			t.Errorf("underivable sender, %s: error %v, want %v", name, err, types.ErrInvalidSig)
		}
	}
}

// TestAccountSenderUnsignedTransaction checks that a transaction carrying no
// signature at all has no sender, while one whose signature values are
// invalid is an error, never the zero address.
func TestAccountSenderUnsignedTransaction(t *testing.T) {
	t.Parallel()

	signer := types.NewGhostAccountSigner(types.LatestSigner(params.TestChainConfig), common.HexToHash("0x01"))
	recipient := common.HexToAddress("0x5252525252525252525252525252525252525252")
	unsigned := types.NewTx(&types.LegacyTx{Nonce: 1, GasPrice: big.NewInt(1), Gas: vars.TxGas, To: &recipient})
	sender, err := rpcSender(signer, unsigned)
	if err != nil {
		t.Fatalf("unsigned transaction: %v", err)
	}
	if sender != (common.Address{}) {
		t.Errorf("unsigned transaction: sender %x, want none", sender)
	}

	invalid := types.NewTx(&types.LegacyTx{Nonce: 1, GasPrice: big.NewInt(1), Gas: vars.TxGas, To: &recipient, V: big.NewInt(27), R: new(big.Int), S: new(big.Int)})
	if sender, err := rpcSender(signer, invalid); !errors.Is(err, types.ErrInvalidSig) {
		t.Errorf("invalid signature: sender %x, error %v, want %v", sender, err, types.ErrInvalidSig)
	}
}
