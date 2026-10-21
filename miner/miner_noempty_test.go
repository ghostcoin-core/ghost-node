// Copyright 2026 The go-ethereum Authors
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

package miner

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/event"
)

// TestMinerNoEmptyFirstBlockHoldsPendingTx checks that with DisablePreseal set
// in the config the worker never seals an empty pre-seal block: the first task
// and the first sealed block hold the pending transaction. Without it, the
// worker still commits the empty pre-seal task first.
func TestMinerNoEmptyFirstBlockHoldsPendingTx(t *testing.T) {
	t.Run("noempty", func(t *testing.T) {
		receipts, mined := runFirstBlock(t, true)
		if receipts != 1 {
			t.Fatalf("first block 1 task has %d receipts, want 1 (no empty pre-seal)", receipts)
		}
		if mined != 1 {
			t.Fatalf("first sealed block holds %d transactions, want 1", mined)
		}
	})
	t.Run("default", func(t *testing.T) {
		receipts, _ := runFirstBlock(t, false)
		if receipts != 0 {
			t.Fatalf("first block 1 task has %d receipts, want 0 (empty pre-seal)", receipts)
		}
	})
}

// runFirstBlock starts a worker with one pending transaction in the pool and
// returns the receipt count of its first block 1 task and the transaction
// count of the first block it seals.
func runFirstBlock(t *testing.T, disablePreseal bool) (int, int) {
	engine := ethash.NewFaker()
	defer engine.Close()

	backend := newTestWorkerBackend(t, ethashChainConfig, engine, rawdb.NewMemoryDatabase(), 0)
	backend.txPool.Add(backend.pendingTxs(), true, false)

	config := *testConfig
	config.DisablePreseal = disablePreseal
	w := newWorker(&config, ethashChainConfig, engine, backend, new(event.TypeMux), nil, false)
	defer w.close()
	w.setEtherbase(testBankAddress)

	if w.noempty.Load() != disablePreseal {
		t.Fatalf("worker noempty is %v, want %v", w.noempty.Load(), disablePreseal)
	}
	taskCh := make(chan int, 16)
	w.newTaskHook = func(task *task) {
		if task.block.NumberU64() == 1 {
			select {
			case taskCh <- len(task.receipts):
			default:
			}
		}
	}
	// Give the empty pre-seal block, when there is one, time to seal first.
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	sub := w.mux.Subscribe(core.NewMinedBlockEvent{})
	defer sub.Unsubscribe()

	w.start()

	var receipts int
	select {
	case receipts = <-taskCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for the first block 1 task")
	}
	select {
	case ev := <-sub.Chan():
		block := ev.Data.(core.NewMinedBlockEvent).Block
		return receipts, len(block.Transactions())
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for the first sealed block")
	}
	return receipts, 0
}
