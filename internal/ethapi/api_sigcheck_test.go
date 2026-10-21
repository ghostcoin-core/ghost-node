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
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rpc"
)

// errSigcheckVerified is returned by sigcheckBackend for a transaction whose
// signature verified, so that the submission stops there.
var errSigcheckVerified = errors.New("verified")

// sigcheckBackend submits transactions to a signature verifier, in the RPC
// share of its queue, as the node's pool does. Without a verifier it reports
// every transaction verified.
type sigcheckBackend struct {
	*backendMock
	verifier *txpool.SigVerifier
	signer   types.Signer
}

func (b *sigcheckBackend) SendTx(ctx context.Context, tx *types.Transaction) error {
	if b.verifier != nil {
		if err := b.verifier.Verify(txpool.SigFromRPC, b.signer, []*types.Transaction{tx})[0]; err != nil {
			return err
		}
	}
	return errSigcheckVerified
}

// sigcheckTxs signs n account transactions for the chain of the backend mock.
func sigcheckTxs(t *testing.T, signer types.Signer, chainID *big.Int, n int) []*types.Transaction {
	t.Helper()
	var seed [mldsa44.SeedSize]byte
	seed[0] = 0x42
	_, key := mldsa44.NewKeyFromSeed(&seed)
	txs := make([]*types.Transaction, n)
	for i := range txs {
		tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
			ChainID:   chainID,
			Nonce:     uint64(i),
			GasTipCap: big.NewInt(1),
			GasFeeCap: big.NewInt(1),
			Gas:       100000,
			To:        &common.Address{0x01},
			Value:     new(big.Int),
		})
		if err != nil {
			t.Fatal(err)
		}
		txs[i] = tx
	}
	return txs
}

// TestRPCBusyWhenSignatureQueueFull checks that a transaction submitted by
// RPC while the RPC share of the signature queue is full is refused with the
// error signature queue busy and JSON-RPC code -32005, without touching the
// peers' share, and is taken again once the queue drains.
func TestRPCBusyWhenSignatureQueueFull(t *testing.T) {
	gate := make(chan struct{})
	var (
		mu       sync.Mutex
		verified int
	)
	verify := func(types.Signer, *types.Transaction) error {
		<-gate
		mu.Lock()
		verified++
		mu.Unlock()
		return nil
	}
	v := txpool.NewSigVerifier(ghost.SigVerifyWorkers, ghost.SigVerifyQueue, ghost.SigFailureCacheSize, verify)
	defer v.Close()

	mock := newBackendMock()
	signer := types.NewGhostAccountSigner(types.LatestSigner(mock.config), common.Hash{0x01})
	backend := &sigcheckBackend{backendMock: mock, verifier: v, signer: signer}

	server := rpc.NewServer()
	defer server.Stop()
	if err := server.RegisterName("eth", NewTransactionAPI(backend, new(AddrLocker))); err != nil {
		t.Fatal(err)
	}
	client := rpc.DialInProc(server)
	defer client.Close()

	share := v.Share(txpool.SigFromRPC)
	txs := sigcheckTxs(t, signer, mock.config.GetChainID(), share+1)

	// Fill the RPC share with checks waiting at the gate.
	done := make(chan []error, 1)
	go func() { done <- v.Verify(txpool.SigFromRPC, signer, txs[:share]) }()
	deadline := time.Now().Add(10 * time.Second)
	for v.InFlight(txpool.SigFromRPC) < share {
		if time.Now().After(deadline) {
			t.Fatal("timed out filling the RPC share")
		}
		runtime.Gosched()
	}

	raw, err := txs[share].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var hash common.Hash
	err = client.Call(&hash, "eth_sendRawTransaction", hexutil.Encode(raw))
	var rpcErr rpc.Error
	if !errors.As(err, &rpcErr) || rpcErr.ErrorCode() != -32005 || err.Error() != txpool.ErrSignatureQueueBusy.Error() {
		t.Fatalf("submission with a full RPC share: error %v, want %q with code -32005", err, txpool.ErrSignatureQueueBusy)
	}
	if n := v.InFlight(txpool.SigFromPeer); n != 0 {
		t.Fatalf("RPC submission took %d slots of the peers' share", n)
	}

	// Once the queue drains, the same transaction is verified.
	close(gate)
	for _, err := range <-done {
		if err != nil {
			t.Fatalf("queued check: %v", err)
		}
	}
	err = client.Call(&hash, "eth_sendRawTransaction", hexutil.Encode(raw))
	if err == nil || err.Error() != errSigcheckVerified.Error() {
		t.Fatalf("submission after the queue drained: error %v, want it verified", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if verified != share+1 {
		t.Fatalf("%d signatures verified, want %d", verified, share+1)
	}
}

// TestRPCSignatureBudgets checks the RPC budgets: each connection, told apart
// by its remote address, has its own budget, all of them share the overall
// budget, and both are refilled after a second.
func TestRPCSignatureBudgets(t *testing.T) {
	var (
		mu  sync.Mutex
		now = time.Unix(1_000_000, 0)
	)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	b := newSigBudgets(2, 3, clock)
	for i, want := range []bool{true, true, false} {
		if got := b.take("10.0.0.1:1000"); got != want {
			t.Fatalf("connection one, check %d: %v, want %v", i, got, want)
		}
	}
	if !b.take("10.0.0.2:1000") {
		t.Fatal("connection two refused within its own budget")
	}
	if b.take("10.0.0.3:1000") {
		t.Fatal("connection three taken beyond the overall budget")
	}
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	if !b.take("10.0.0.1:1000") {
		t.Fatal("connection one refused after a second")
	}

	// SubmitTransaction refuses an account transaction over the budget with
	// the JSON-RPC code -32005, before it reaches the pool.
	saved := rpcSigBudgets
	rpcSigBudgets = newSigBudgets(1, 1, clock)
	defer func() { rpcSigBudgets = saved }()

	mock := newBackendMock()
	signer := types.NewGhostAccountSigner(types.LatestSigner(mock.config), common.Hash{0x01})
	backend := &sigcheckBackend{backendMock: mock}
	txs := sigcheckTxs(t, signer, mock.config.GetChainID(), 2)
	if _, err := SubmitTransaction(context.Background(), backend, txs[0]); err != errSigcheckVerified {
		t.Fatalf("first submission: error %v, want it to reach the pool", err)
	}
	_, err := SubmitTransaction(context.Background(), backend, txs[1])
	if err != txpool.ErrSignatureBudget {
		t.Fatalf("submission over the budget: error %v, want %v", err, txpool.ErrSignatureBudget)
	}
	if coded, ok := err.(rpc.Error); !ok || coded.ErrorCode() != -32005 {
		t.Fatalf("budget error %v has no JSON-RPC code -32005", err)
	}
}
