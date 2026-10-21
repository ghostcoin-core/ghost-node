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
	"math/big"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// accountTxService answers eth_getTransactionByHash and
// eth_getTransactionByBlockHashAndIndex with a fixed response. It serves no
// other method, so a client that asks the server for a sender fails.
type accountTxService struct {
	response json.RawMessage
}

func (s *accountTxService) GetTransactionByHash(hash common.Hash) json.RawMessage {
	return s.response
}

func (s *accountTxService) GetTransactionByBlockHashAndIndex(block common.Hash, index hexutil.Uint64) json.RawMessage {
	return s.response
}

// TestEthclientFromDerivedFromPublicKey checks that ethclient decodes an
// account transaction of an RPC response, whose scheme is two bytes in hex,
// and derives its sender from its scheme and public key: with the server's
// from, without it, and refusing a response whose from is another address.
func TestEthclientFromDerivedFromPublicKey(t *testing.T) {
	var seed [mldsa44.SeedSize]byte
	seed[0] = 0x5a
	pub, key := mldsa44.NewKeyFromSeed(&seed)
	derived := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes())

	config := params.MergedTestChainConfig
	signer := types.NewGhostAccountSigner(types.LatestSigner(config), common.Hash{0x01})
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   config.GetChainID(),
		Nonce:     3,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       100000,
		To:        &common.Address{0x01},
		Value:     big.NewInt(9),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The node's RPC representation of the mined transaction.
	blockHash := common.Hash{0xbb}
	rpcTx := ethapi.NewRPCPendingTransaction(tx, nil, config)
	rpcTx.BlockHash = &blockHash
	rpcTx.BlockNumber = (*hexutil.Big)(big.NewInt(1))
	if rpcTx.From != derived {
		t.Fatalf("node derived from %x, want %x", rpcTx.From, derived)
	}
	honest, err := json.Marshal(rpcTx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(honest), `"scheme":"0x0001"`) {
		t.Fatalf("response has no two-byte scheme: %s", honest)
	}
	edit := func(f func(map[string]interface{})) json.RawMessage {
		m := make(map[string]interface{})
		if err := json.Unmarshal(honest, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	withoutFrom := edit(func(m map[string]interface{}) { delete(m, "from") })
	otherFrom := edit(func(m map[string]interface{}) { m["from"] = common.Address{0x99} })

	service := new(accountTxService)
	server := rpc.NewServer()
	defer server.Stop()
	if err := server.RegisterName("eth", service); err != nil {
		t.Fatal(err)
	}
	client := NewClient(rpc.DialInProc(server))
	defer client.Close()
	ctx := context.Background()

	for name, response := range map[string]json.RawMessage{"with from": honest, "without from": withoutFrom} {
		service.response = response

		got, pending, err := client.TransactionByHash(ctx, tx.Hash())
		if err != nil {
			t.Fatalf("%s: TransactionByHash: %v", name, err)
		}
		if got.Hash() != tx.Hash() || got.Type() != types.GhostAccountTxType || pending {
			t.Fatalf("%s: got transaction %x of type %#x (pending %v), want %x", name, got.Hash(), got.Type(), pending, tx.Hash())
		}
		scheme, publicKey, _, ok := got.GhostAccountAuth()
		if !ok || scheme != types.GhostSchemeMLDSA44 || types.GhostAccountAddressOf(scheme, publicKey) != derived {
			t.Fatalf("%s: decoded scheme %#04x and public key are not the transaction's", name, scheme)
		}
		// The sender comes without a call to the server, which serves
		// nothing that could answer it.
		from, err := client.TransactionSender(ctx, got, blockHash, 0)
		if err != nil || from != derived {
			t.Fatalf("%s: TransactionSender %x (error %v), want %x", name, from, err, derived)
		}
		if from, err := types.Sender(&senderFromServer{blockhash: blockHash}, got); err != nil || from != derived {
			t.Fatalf("%s: cached sender %x (error %v), want %x", name, from, err, derived)
		}

		inBlock, err := client.TransactionInBlock(ctx, blockHash, 0)
		if err != nil || inBlock.Hash() != tx.Hash() {
			t.Fatalf("%s: TransactionInBlock: %v", name, err)
		}
		if from, err := client.TransactionSender(ctx, inBlock, blockHash, 0); err != nil || from != derived {
			t.Fatalf("%s: TransactionSender of the block's transaction %x (error %v), want %x", name, from, err, derived)
		}
	}

	// A server that reports another sender is not believed.
	service.response = otherFrom
	if _, _, err := client.TransactionByHash(ctx, tx.Hash()); err == nil {
		t.Fatal("TransactionByHash took a response whose from is not the derived address")
	}
}
