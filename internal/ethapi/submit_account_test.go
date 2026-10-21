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
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// submitBackend is a pool that takes every transaction: it records what
// SendTx got and holds it.
type submitBackend struct {
	*backendMock
	mu   sync.Mutex
	sent []*types.Transaction
}

func (b *submitBackend) CurrentBlock() *types.Header { return b.current }

func (b *submitBackend) SendTx(ctx context.Context, tx *types.Transaction) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, tx)
	return nil
}

func (b *submitBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, tx := range b.sent {
		if tx.Hash() == hash {
			return tx
		}
	}
	return nil
}

// TestSendRawTransactionAccountTx checks that eth_sendRawTransaction of a
// signed account transaction, once the pool has taken it, answers its hash
// with no error, and that the node holds it.
func TestSendRawTransactionAccountTx(t *testing.T) {
	mock := newBackendMock()
	backend := &submitBackend{backendMock: mock}

	server := rpc.NewServer()
	defer server.Stop()
	if err := server.RegisterName("eth", NewTransactionAPI(backend, new(AddrLocker))); err != nil {
		t.Fatal(err)
	}
	client := rpc.DialInProc(server)
	defer client.Close()

	signer := types.NewGhostAccountSigner(types.LatestSigner(mock.config), common.Hash{0x01})
	tx := sigcheckTxs(t, signer, mock.config.GetChainID(), 1)[0]
	if tx.Type() != types.GhostAccountTxType {
		t.Fatalf("test transaction has type %#x, want %#x", tx.Type(), types.GhostAccountTxType)
	}
	// The plain signer of the head refuses the type: this is the case the
	// endpoint must not report as a failure.
	plain := types.MakeSigner(mock.config, mock.current.Number, mock.current.Time)
	if _, err := types.Sender(plain, tx); err == nil {
		t.Fatal("plain signer read the sender of an account transaction")
	}

	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var hash common.Hash
	if err := client.Call(&hash, "eth_sendRawTransaction", hexutil.Encode(raw)); err != nil {
		t.Fatalf("eth_sendRawTransaction of an account transaction the pool took: error %v", err)
	}
	if hash != tx.Hash() {
		t.Fatalf("eth_sendRawTransaction answered hash %x, want %x", hash, tx.Hash())
	}

	backend.mu.Lock()
	sent := len(backend.sent)
	backend.mu.Unlock()
	if sent != 1 {
		t.Fatalf("pool got %d transactions, want 1", sent)
	}
	held := backend.GetPoolTransaction(hash)
	if held == nil {
		t.Fatal("node does not hold the submitted transaction")
	}
	if held.Type() != types.GhostAccountTxType || held.Hash() != tx.Hash() {
		t.Fatalf("node holds %x of type %#x, want %x of type %#x", held.Hash(), held.Type(), tx.Hash(), types.GhostAccountTxType)
	}
}
