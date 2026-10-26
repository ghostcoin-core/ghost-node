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

package ghosttree_test

import (
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/pruner"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
)

// treeEngine is the fake ethash engine with a hook that appends leaves to
// both trees in every block, when it is built and when it is imported, and
// sets the header roots of the blocks it builds. The records of the built
// blocks stand in for the ones the commit and reveal receipts will give.
type treeEngine struct {
	*ethash.Ethash
	t       *testing.T
	records map[uint64][]ghosttree.Record
}

func pruneLeaf(number uint64, i int) common.Hash {
	var b [12]byte
	binary.BigEndian.PutUint64(b[:], number)
	binary.BigEndian.PutUint32(b[8:], uint32(i))
	return ghosttree.K("ghost/test-prune-leaf", b[:])
}

func (e *treeEngine) appendLeaves(header *types.Header, st *state.StateDB) []ghosttree.Record {
	number := header.Number.Uint64()
	var records []ghosttree.Record
	for i := 0; i < 45; i++ {
		kind := ghosttree.Coin
		if i%9 == 0 {
			kind = ghosttree.Data
		}
		leaf := pruneLeaf(number, i)
		res, err := ghosttree.Append(st, kind, number, leaf)
		if err != nil {
			e.t.Errorf("block %d: append: %v", number, err)
			return nil
		}
		r := ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: leaf}
		copy(r.Note[:], leaf[:])
		records = append(records, r)
	}
	return records
}

func (e *treeEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	e.appendLeaves(header, st)
	e.Ethash.Finalize(chain, header, st, txs, uncles, withdrawals)
}

func (e *treeEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	e.records[header.Number.Uint64()] = e.appendLeaves(header, st)
	coin, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		return nil, err
	}
	data, err := ghosttree.Root(st, ghosttree.Data)
	if err != nil {
		return nil, err
	}
	marker, err := ghosttree.DataMarkerRoot(st)
	if err != nil {
		return nil, err
	}
	header.CoinTreeRoot, header.DataTreeRoot, header.DataMarkerRoot = &coin, &data, &marker
	return e.Ethash.FinalizeAndAssemble(chain, header, st, txs, uncles, receipts, withdrawals)
}

func countTrieNodeKeys(t *testing.T, db ethdb.Database) int {
	t.Helper()
	it := db.NewIterator(nil, nil)
	defer it.Release()
	n := 0
	for it.Next() {
		if len(it.Key()) == common.HashLength {
			n++
		}
	}
	return n
}

// TestNothingIsPruned runs a chain with the node's most aggressive pruning:
// full garbage collection of the trie with the shortest flush interval, one
// block of transaction index and state history, then the offline state
// pruner, which deletes every trie node and code entry outside the newest
// state. Every record of every block is still served afterwards.
func TestNothingIsPruned(t *testing.T) {
	const blocks = 200
	engine := &treeEngine{Ethash: ethash.NewFaker(), t: t, records: make(map[uint64][]ghosttree.Record)}
	gspec := &genesisT.Genesis{
		Config: &goethereum.ChainConfig{
			ChainID:             big.NewInt(1337),
			HomesteadBlock:      big.NewInt(0),
			EIP150Block:         big.NewInt(0),
			EIP155Block:         big.NewInt(0),
			EIP158Block:         big.NewInt(0),
			ByzantiumBlock:      big.NewInt(0),
			ConstantinopleBlock: big.NewInt(0),
			PetersburgBlock:     big.NewInt(0),
			IstanbulBlock:       big.NewInt(0),
			BerlinBlock:         big.NewInt(0),
			LondonBlock:         big.NewInt(0),
			Ethash:              new(ctypes.EthashConfig),
		},
		GasLimit:   8_000_000,
		Difficulty: big.NewInt(1),
		Alloc:      genesisT.GenesisAlloc{},
	}
	_, chainBlocks, _ := core.GenerateChainWithGenesis(gspec, engine, blocks, nil)

	db := rawdb.NewMemoryDatabase()
	txLookupLimit := uint64(1)
	cache := &core.CacheConfig{
		TrieCleanLimit: 1,
		TrieDirtyLimit: 1,
		TrieTimeLimit:  time.Nanosecond,
		SnapshotLimit:  16,
		SnapshotWait:   true,
		StateHistory:   1,
		StateScheme:    rawdb.HashScheme,
	}
	chain, err := core.NewBlockChain(db, cache, gspec, nil, engine, vm.Config{}, nil, &txLookupLimit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(chainBlocks); err != nil {
		chain.Stop()
		t.Fatal(err)
	}
	history := ghosttree.NewHistory(db)
	if err := history.ApplyBlock(chain.Genesis().Hash(), 0, nil); err != nil {
		t.Fatal(err)
	}
	for _, b := range chainBlocks {
		if err := history.ApplyBlock(b.Hash(), b.NumberU64(), engine.records[b.NumberU64()]); err != nil {
			t.Fatal(err)
		}
	}
	chain.Stop()

	before := countTrieNodeKeys(t, db)
	p, err := pruner.NewPruner(db, pruner.Config{Datadir: t.TempDir(), BloomSize: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prune(common.Hash{}); err != nil {
		t.Fatal(err)
	}
	if after := countTrieNodeKeys(t, db); after >= before {
		t.Fatalf("the pruner removed nothing: %d trie nodes before, %d after", before, after)
	}

	for _, b := range []*types.Block{chainBlocks[0], chainBlocks[blocks/2], chainBlocks[blocks-1]} {
		header := b.Header()
		for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
			var want []ghosttree.Record
			for n := uint64(1); n <= b.NumberU64(); n++ {
				for _, r := range engine.records[n] {
					if r.Kind == kind {
						want = append(want, r)
					}
				}
			}
			roots, err := history.PageRoots(kind, 0, header.Hash())
			if err != nil {
				t.Fatalf("%v page roots at %d: %v", kind, b.NumberU64(), err)
			}
			if ghosttree.RootFromPageRoots(kind, roots) != *ghosttree.HeaderRoot(header, kind) {
				t.Fatalf("%v at %d: page roots do not give the header root", kind, b.NumberU64())
			}
			var got []ghosttree.PageEntry
			for pg := range roots {
				page, err := history.Page(kind, 0, uint32(pg), header.Hash())
				if err != nil {
					t.Fatalf("%v page %d at %d: %v", kind, pg, b.NumberU64(), err)
				}
				got = append(got, page.Entries...)
			}
			if len(got) != len(want) {
				t.Fatalf("%v at %d: %d records served, want %d", kind, b.NumberU64(), len(got), len(want))
			}
			for i, r := range want {
				if got[i].Leaf != r.Leaf || got[i].Note != r.Note {
					t.Fatalf("%v at %d: record %d differs", kind, b.NumberU64(), i)
				}
			}
		}
	}
}
