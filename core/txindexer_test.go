// Copyright 2024 The go-ethereum Authors
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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package core

import (
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestTxIndexer tests the functionalities for managing transaction indexes.
func TestTxIndexer(t *testing.T) {
	var (
		testBankKey, _  = crypto.GenerateKey()
		testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
		testBankFunds   = big.NewInt(1000000000000000000)

		gspec = &genesisT.Genesis{
			Config:  params.TestChainConfig,
			Alloc:   genesisT.GenesisAlloc{testBankAddress: {Balance: testBankFunds}},
			BaseFee: big.NewInt(vars.InitialBaseFee),
		}
		engine    = ethash.NewFaker()
		nonce     = uint64(0)
		chainHead = uint64(128)
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, engine, int(chainHead), func(i int, gen *BlockGen) {
		tx, _ := types.SignTx(types.NewTransaction(nonce, common.HexToAddress("0xdeadbeef"), big.NewInt(1000), vars.TxGas, big.NewInt(10*vars.InitialBaseFee), nil), types.HomesteadSigner{}, testBankKey)
		gen.AddTx(tx)
		nonce += 1
	})

	// verifyIndexes checks if the transaction indexes are present or not
	// of the specified block.
	verifyIndexes := func(db ethdb.Database, number uint64, exist bool) {
		if number == 0 {
			return
		}
		block := blocks[number-1]
		for _, tx := range block.Transactions() {
			lookup := rawdb.ReadTxLookupEntry(db, tx.Hash())
			if exist && lookup == nil {
				t.Fatalf("missing %d %x", number, tx.Hash().Hex())
			}
			if !exist && lookup != nil {
				t.Fatalf("unexpected %d %x", number, tx.Hash().Hex())
			}
		}
	}
	verify := func(db ethdb.Database, expTail uint64, indexer *txIndexer) {
		tail := rawdb.ReadTxIndexTail(db)
		if tail == nil {
			t.Fatal("Failed to write tx index tail")
		}
		if *tail != expTail {
			t.Fatalf("Unexpected tx index tail, want %v, got %d", expTail, *tail)
		}
		if *tail != 0 {
			for number := uint64(0); number < *tail; number += 1 {
				verifyIndexes(db, number, false)
			}
		}
		for number := *tail; number <= chainHead; number += 1 {
			verifyIndexes(db, number, true)
		}
		progress := indexer.report(chainHead, tail)
		if !progress.Done() {
			t.Fatalf("Expect fully indexed")
		}
	}

	var cases = []struct {
		limitA uint64
		tailA  uint64
		limitB uint64
		tailB  uint64
		limitC uint64
		tailC  uint64
	}{
		{
			// LimitA: 0
			// TailA:  0
			//
			// all blocks are indexed
			limitA: 0,
			tailA:  0,

			// LimitB: 1
			// TailB:  128
			//
			// block-128 is indexed
			limitB: 1,
			tailB:  128,

			// LimitB: 64
			// TailB:  65
			//
			// block [65, 128] are indexed
			limitC: 64,
			tailC:  65,
		},
		{
			// LimitA: 64
			// TailA:  65
			//
			// block [65, 128] are indexed
			limitA: 64,
			tailA:  65,

			// LimitB: 1
			// TailB:  128
			//
			// block-128 is indexed
			limitB: 1,
			tailB:  128,

			// LimitB: 64
			// TailB:  65
			//
			// block [65, 128] are indexed
			limitC: 64,
			tailC:  65,
		},
		{
			// LimitA: 127
			// TailA:  2
			//
			// block [2, 128] are indexed
			limitA: 127,
			tailA:  2,

			// LimitB: 1
			// TailB:  128
			//
			// block-128 is indexed
			limitB: 1,
			tailB:  128,

			// LimitB: 64
			// TailB:  65
			//
			// block [65, 128] are indexed
			limitC: 64,
			tailC:  65,
		},
		{
			// LimitA: 128
			// TailA:  1
			//
			// block [2, 128] are indexed
			limitA: 128,
			tailA:  1,

			// LimitB: 1
			// TailB:  128
			//
			// block-128 is indexed
			limitB: 1,
			tailB:  128,

			// LimitB: 64
			// TailB:  65
			//
			// block [65, 128] are indexed
			limitC: 64,
			tailC:  65,
		},
		{
			// LimitA: 129
			// TailA:  0
			//
			// block [0, 128] are indexed
			limitA: 129,
			tailA:  0,

			// LimitB: 1
			// TailB:  128
			//
			// block-128 is indexed
			limitB: 1,
			tailB:  128,

			// LimitB: 64
			// TailB:  65
			//
			// block [65, 128] are indexed
			limitC: 64,
			tailC:  65,
		},
	}
	for _, c := range cases {
		frdir := t.TempDir()
		gblock := GenesisToBlock(gspec, nil)
		db, _ := rawdb.NewDatabaseWithFreezer(rawdb.NewMemoryDatabase(), frdir, "", false)
		rawdb.WriteAncientBlocks(db, append([]*types.Block{gblock}, blocks...), append([]types.Receipts{{}}, receipts...), big.NewInt(0))

		// Index the initial blocks from ancient store
		indexer := &txIndexer{
			limit:    c.limitA,
			db:       db,
			progress: make(chan chan TxIndexProgress),
		}
		indexer.run(nil, 128, make(chan struct{}), make(chan struct{}))
		verify(db, c.tailA, indexer)

		indexer.limit = c.limitB
		indexer.run(rawdb.ReadTxIndexTail(db), 128, make(chan struct{}), make(chan struct{}))
		verify(db, c.tailB, indexer)

		indexer.limit = c.limitC
		indexer.run(rawdb.ReadTxIndexTail(db), 128, make(chan struct{}), make(chan struct{}))
		verify(db, c.tailC, indexer)

		// Recover all indexes
		indexer.limit = 0
		indexer.run(rawdb.ReadTxIndexTail(db), 128, make(chan struct{}), make(chan struct{}))
		verify(db, 0, indexer)

		db.Close()
		os.RemoveAll(frdir)
	}
}

// TestTxLookupNoDeadlock tests that transaction lookups running alongside a
// reorg, which rewrites the indexes, and the chain's shutdown, which stops
// the indexer, all return. Lookups here take no lock that a reorg holds (the
// lock the upstream deadlock was in), and a lookup on a stopped indexer
// returns at once.
func TestTxLookupNoDeadlock(t *testing.T) {
	var (
		testBankKey, _  = crypto.GenerateKey()
		testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
		testBankFunds   = big.NewInt(1000000000000000000)

		gspec = &genesisT.Genesis{
			Config:  params.TestChainConfig,
			Alloc:   genesisT.GenesisAlloc{testBankAddress: {Balance: testBankFunds}},
			BaseFee: big.NewInt(vars.InitialBaseFee),
		}
		engine = ethash.NewFaker()
		nonce  = uint64(0)
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 16, func(i int, gen *BlockGen) {
		tx, _ := types.SignTx(types.NewTransaction(nonce, common.HexToAddress("0xdeadbeef"), big.NewInt(1000), vars.TxGas, big.NewInt(10*vars.InitialBaseFee), nil), types.HomesteadSigner{}, testBankKey)
		gen.AddTx(tx)
		nonce += 1
	})
	_, fork, _ := GenerateChainWithGenesis(gspec, engine, 24, func(i int, gen *BlockGen) {
		gen.SetCoinbase(common.Address{0x01})
	})
	limit := uint64(0)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, &limit)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}
	var hashes []common.Hash
	for _, block := range blocks {
		for _, tx := range block.Transactions() {
			hashes = append(hashes, tx.Hash())
		}
	}

	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			for _, hash := range hashes {
				select {
				case <-quit:
					return
				default:
				}
				chain.GetTransactionLookup(hash)
			}
		}
	}()
	finished := make(chan error, 1)
	go func() {
		// Reorg onto the longer fork, which drops every indexed transaction,
		// then stop the chain while the lookups still run.
		_, err := chain.InsertChain(fork)
		chain.Stop()
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("failed to insert fork: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("reorg and shutdown deadlocked with concurrent tx lookups")
	}
	close(quit)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("tx lookup deadlocked")
	}
	// A lookup on the stopped chain returns at once.
	lookupDone := make(chan struct{})
	go func() {
		chain.GetTransactionLookup(common.Hash{0x01})
		close(lookupDone)
	}()
	select {
	case <-lookupDone:
	case <-time.After(30 * time.Second):
		t.Fatal("tx lookup on a stopped chain deadlocked")
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 24 {
		t.Fatalf("head %d after the reorg, want 24", head)
	}
	for _, hash := range hashes {
		if tx, _, _, _ := rawdb.ReadTransaction(chain.db, hash); tx != nil {
			t.Fatalf("transaction %x still indexed after the reorg", hash)
		}
	}
}

// TestTxIndexerUnindexLoop tests that a block whose body is missing does not
// stop the indexer for good: unindexing skips it and moves the tail to the
// limit, instead of stopping on the block again in every later run.
func TestTxIndexerUnindexLoop(t *testing.T) {
	var (
		testBankKey, _  = crypto.GenerateKey()
		testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
		testBankFunds   = big.NewInt(1000000000000000000)

		gspec = &genesisT.Genesis{
			Config:  params.TestChainConfig,
			Alloc:   genesisT.GenesisAlloc{testBankAddress: {Balance: testBankFunds}},
			BaseFee: big.NewInt(vars.InitialBaseFee),
		}
		engine    = ethash.NewFaker()
		nonce     = uint64(0)
		chainHead = uint64(16)
		limit     = uint64(8)
		missing   = uint64(3)
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, int(chainHead), func(i int, gen *BlockGen) {
		tx, _ := types.SignTx(types.NewTransaction(nonce, common.HexToAddress("0xdeadbeef"), big.NewInt(1000), vars.TxGas, big.NewInt(10*vars.InitialBaseFee), nil), types.HomesteadSigner{}, testBankKey)
		gen.AddTx(tx)
		nonce += 1
	})
	db := rawdb.NewMemoryDatabase()
	for _, block := range append([]*types.Block{GenesisToBlock(gspec, nil)}, blocks...) {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	}
	indexer := &txIndexer{
		limit:    0,
		db:       db,
		progress: make(chan chan TxIndexProgress),
	}
	stop := make(chan struct{})
	defer close(stop)

	indexer.run(nil, chainHead, stop, make(chan struct{}))
	if tail := rawdb.ReadTxIndexTail(db); tail == nil || *tail != 0 {
		t.Fatal("tail after indexing the whole chain is not 0")
	}
	// Lose the body of a block that is to be unindexed.
	rawdb.DeleteBody(db, blocks[missing-1].Hash(), missing)

	// Unindex down to the limit, twice: the tail must reach HEAD-limit+1 on
	// the first run and stay there.
	want := chainHead - limit + 1
	indexer.limit = limit
	for run := 0; run < 2; run++ {
		indexer.run(rawdb.ReadTxIndexTail(db), chainHead, stop, make(chan struct{}))
		tail := rawdb.ReadTxIndexTail(db)
		if tail == nil {
			t.Fatalf("run %d: no tail, want %d", run, want)
		}
		if *tail != want {
			t.Fatalf("run %d: tail %d, want %d", run, *tail, want)
		}
	}
	for number := uint64(1); number <= chainHead; number++ {
		for _, tx := range blocks[number-1].Transactions() {
			lookup := rawdb.ReadTxLookupEntry(db, tx.Hash())
			switch {
			case number == missing:
				// The block's hashes could not be read, its indexes stay.
			case number < want && lookup != nil:
				t.Fatalf("block %d: index of %x not removed", number, tx.Hash())
			case number >= want && lookup == nil:
				t.Fatalf("block %d: index of %x missing", number, tx.Hash())
			}
		}
	}
}
