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

package ethclient

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
)

// tamperedTxAPI serves one transaction JSON for every transaction lookup.
type tamperedTxAPI struct {
	tx json.RawMessage
}

func (api *tamperedTxAPI) GetTransactionByHash(hash common.Hash) json.RawMessage {
	return api.tx
}

func (api *tamperedTxAPI) GetTransactionByBlockHashAndIndex(hash common.Hash, index hexutil.Uint64) json.RawMessage {
	return api.tx
}

// newAccountTxNode starts a node whose block 1 holds an account transaction
// of the ML-DSA-44 account of a fixed seed, and returns the node, the
// transaction, its block hash and the account.
func newAccountTxNode(t *testing.T) (*node.Node, *types.Transaction, common.Hash, common.Address) {
	t.Helper()
	var seed [mldsa44.SeedSize]byte
	for i := range seed {
		seed[i] = 0x3c
	}
	pk, sk := mldsa44.NewKeyFromSeed(&seed)
	addr := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pk.Bytes())

	gspec := &genesisT.Genesis{
		Config:    params.TestChainConfig,
		Alloc:     genesisT.GenesisAlloc{addr: {Balance: big.NewInt(vars.Ether)}},
		ExtraData: []byte("account test genesis"),
		BaseFee:   big.NewInt(vars.InitialBaseFee),
	}
	signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), core.GenesisToBlock(gspec, nil).Hash())
	tx, err := types.SignGhostAccountTx(signer, sk, &types.GhostAccountTx{
		ChainID:   gspec.Config.GetChainID(),
		GasTipCap: big.NewInt(vars.GWei),
		GasFeeCap: big.NewInt(100 * vars.GWei),
		Gas:       vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44,
		To:        &common.Address{0x52},
		Value:     big.NewInt(1000),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 1, func(i int, g *core.BlockGen) {
		g.AddTx(tx)
	})

	n, err := node.New(&node.Config{})
	if err != nil {
		t.Fatalf("can't create new node: %v", err)
	}
	config := &ethconfig.Config{Genesis: gspec}
	config.Ethash.PowMode = ethash.ModeFake
	ethservice, err := eth.New(n, config)
	if err != nil {
		t.Fatalf("can't create new ethereum service: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("can't start test node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		t.Fatalf("can't import test blocks: %v", err)
	}
	for ; ; time.Sleep(10 * time.Millisecond) {
		progress, err := ethservice.BlockChain().TxIndexProgress()
		if err == nil && progress.Done() {
			break
		}
	}
	return n, tx, blocks[0].Hash(), addr
}

// TestEthclientFromDerivedFromPublicKey checks that the client decodes the
// 2-byte scheme of an account transaction, derives its sender from the
// scheme and the public key, and refuses a server from that disagrees.
func TestEthclientFromDerivedFromPublicKey(t *testing.T) {
	n, mined, blockHash, addr := newAccountTxNode(t)
	rpcClient := n.Attach()
	defer rpcClient.Close()
	ec := NewClient(rpcClient)
	ctx := context.Background()

	checkSender := func(name string, tx *types.Transaction) {
		t.Helper()
		if tx.Hash() != mined.Hash() {
			t.Fatalf("%s: transaction %v, want %v", name, tx.Hash(), mined.Hash())
		}
		sender, err := ec.TransactionSender(ctx, tx, blockHash, 0)
		if err != nil {
			t.Fatalf("%s: sender: %v", name, err)
		}
		if sender != addr {
			t.Errorf("%s: sender %v, want %v", name, sender, addr)
		}
	}
	tx, pending, err := ec.TransactionByHash(ctx, mined.Hash())
	if err != nil {
		t.Fatalf("transaction by hash: %v", err)
	}
	if pending {
		t.Error("mined transaction is pending")
	}
	checkSender("transaction by hash", tx)
	tx, err = ec.TransactionInBlock(ctx, blockHash, 0)
	if err != nil {
		t.Fatalf("transaction in block: %v", err)
	}
	checkSender("transaction in block", tx)
	block, err := ec.BlockByNumber(ctx, big.NewInt(1))
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if len(block.Transactions()) != 1 {
		t.Fatalf("block has %d transactions, want 1", len(block.Transactions()))
	}
	checkSender("block transaction", block.Transactions()[0])
	// Without a sender cached, the client asks the server and checks its from.
	raw, err := mined.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	uncached := new(types.Transaction)
	if err := uncached.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	checkSender("uncached transaction", uncached)

	// The server's JSON has the 2-byte scheme; a from that disagrees with
	// the scheme and public key, or a scheme that is not 2 bytes, is refused.
	var served json.RawMessage
	if err := rpcClient.CallContext(ctx, &served, "eth_getTransactionByHash", mined.Hash()); err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(served, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["scheme"] != "0x0001" {
		t.Fatalf("served scheme %v, want 0x0001", fields["scheme"])
	}
	tamper := func(key string, value interface{}) json.RawMessage {
		cpy := make(map[string]interface{}, len(fields))
		for k, v := range fields {
			cpy[k] = v
		}
		if value == nil {
			delete(cpy, key)
		} else {
			cpy[key] = value
		}
		enc, err := json.Marshal(cpy)
		if err != nil {
			t.Fatal(err)
		}
		return enc
	}
	other := common.Address{0x99}
	var decoded rpcTransaction
	if err := json.Unmarshal(tamper("from", other.Hex()), &decoded); !errors.Is(err, errAccountTxFrom) {
		t.Errorf("disagreeing from: error %v, want %v", err, errAccountTxFrom)
	}
	if err := json.Unmarshal(tamper("scheme", "0x01"), &decoded); err == nil {
		t.Error("1-byte scheme decoded")
	}
	decoded = rpcTransaction{}
	if err := json.Unmarshal(tamper("from", nil), &decoded); err != nil {
		t.Fatalf("no from: %v", err)
	}
	if decoded.From == nil || *decoded.From != addr {
		t.Errorf("no from: derived %v, want %v", decoded.From, addr)
	}

	// A server that names another sender is an error.
	srv := rpc.NewServer()
	defer srv.Stop()
	if err := srv.RegisterName("eth", &tamperedTxAPI{tx: tamper("from", other.Hex())}); err != nil {
		t.Fatal(err)
	}
	tampered := NewClient(rpc.DialInProc(srv))
	defer tampered.Close()
	if _, _, err := tampered.TransactionByHash(ctx, mined.Hash()); !errors.Is(err, errAccountTxFrom) {
		t.Errorf("tampered transaction by hash: error %v, want %v", err, errAccountTxFrom)
	}
	if sender, err := tampered.TransactionSender(ctx, uncached, blockHash, 0); !errors.Is(err, errAccountTxFrom) {
		t.Errorf("tampered sender: %v, error %v, want %v", sender, err, errAccountTxFrom)
	}
}
