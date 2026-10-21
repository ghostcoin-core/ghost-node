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

package miner

import (
	"math"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// TestMinerNeverVotesAboveMaxGasLimit builds blocks on a chain whose gas
// limit is at the consensus maximum with a target gas ceiling above it, and
// checks that no block votes the limit above the maximum, while a ceiling
// under the maximum still moves the limit down.
func TestMinerNeverVotesAboveMaxGasLimit(t *testing.T) {
	gspec := ghost.InternalNetGenesis()
	if gspec.GasLimit != ghost.MaxBlockGasLimit {
		t.Fatalf("genesis gas limit %d, want the maximum %d", gspec.GasLimit, ghost.MaxBlockGasLimit)
	}
	engine := ethash.NewFaker()
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	// The worker builds on the chain at the maximum. The pool comes from a
	// test backend of its own chain; the blocks here take no transactions.
	backend := newTestWorkerBackend(t, ethashChainConfig, engine, rawdb.NewMemoryDatabase(), 0)
	backend.db, backend.chain, backend.genesis = db, chain, gspec

	config := *testConfig
	config.GasCeil = 2 * ghost.MaxBlockGasLimit
	w := newWorker(&config, gspec.Config, engine, backend, new(event.TypeMux), nil, false)
	defer w.close()

	build := func() *types.Block {
		t.Helper()
		parent := chain.CurrentBlock()
		res := w.getSealingBlock(&generateParams{
			parentHash: parent.Hash(),
			timestamp:  parent.Time + 1,
			coinbase:   common.Address{0xc0, 0x1b},
			noUncle:    true,
			noTxs:      true,
		})
		if res.err != nil {
			t.Fatalf("building block %d: %v", parent.Number.Uint64()+1, res.err)
		}
		return res.block
	}

	// A ceiling above the maximum, then the largest ceiling there is: each
	// block keeps the limit at the maximum.
	for i, ceil := range []uint64{2 * ghost.MaxBlockGasLimit, 2 * ghost.MaxBlockGasLimit, math.MaxUint64} {
		w.setGasCeil(ceil)
		block := build()
		if got := block.GasLimit(); got != ghost.MaxBlockGasLimit {
			t.Fatalf("block %d with ceiling %d: gas limit %d, want the maximum %d", i+1, ceil, got, ghost.MaxBlockGasLimit)
		}
		if _, err := chain.InsertChain(types.Blocks{block}); err != nil {
			t.Fatalf("block %d not imported: %v", i+1, err)
		}
	}

	// A ceiling under the maximum moves the limit down as before.
	w.setGasCeil(ghost.MaxBlockGasLimit / 2)
	if got := build().GasLimit(); got >= ghost.MaxBlockGasLimit || got != core.CalcGasLimit(ghost.MaxBlockGasLimit, ghost.MaxBlockGasLimit/2) {
		t.Fatalf("gas limit %d with a ceiling under the maximum, want %d", got, core.CalcGasLimit(ghost.MaxBlockGasLimit, ghost.MaxBlockGasLimit/2))
	}
}
