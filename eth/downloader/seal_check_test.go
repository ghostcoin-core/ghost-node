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

package downloader

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// newTesterWithEngine is newTester with engine as the local chain's
// consensus engine.
func newTesterWithEngine(t *testing.T, engine consensus.Engine) *downloadTester {
	freezer := t.TempDir()
	db, err := rawdb.NewDatabaseWithFreezer(rawdb.NewMemoryDatabase(), freezer, "", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	gspec := &genesisT.Genesis{
		Config:  params.TestChainConfig,
		Alloc:   genesisT.GenesisAlloc{testAddress: {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(vars.InitialBaseFee),
	}
	chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tester := &downloadTester{
		freezer: freezer,
		chain:   chain,
		peers:   make(map[string]*downloadTesterPeer),
	}
	tester.downloader = New(0, db, new(event.TypeMux), tester.chain, nil, tester.dropPeer, nil)
	return tester
}

// TestSnapSyncChecksEverySeal snap syncs a chain whose local engine rejects
// the seal of one header far below the pivot, where a sparse check would
// look at it only by chance, and requires the sync to fail on that header
// every time: every seal is checked. A sync with every seal valid passes.
func TestSnapSyncChecksEverySeal(t *testing.T) {
	if fsHeaderCheckFrequency != 1 {
		t.Fatalf("snap sync checks one seal in %d, want every seal", fsHeaderCheckFrequency)
	}
	chain := testChainBase.shorten(800)
	pivot := uint64(len(chain.blocks)-1) - uint64(fsMinFullBlocks)

	// A sync with every seal valid passes.
	good := newTesterWithEngine(t, ethash.NewFaker())
	defer good.terminate()
	good.newPeer("peer", eth.ETH68, chain.blocks[1:])
	if err := good.sync("peer", nil, SnapSync); err != nil {
		t.Fatalf("snap sync with every seal valid failed: %v", err)
	}
	assertOwnChain(t, good, len(chain.blocks))

	// One bad seal deep below the pivot, at each of several heights, fails
	// the sync before the header is taken.
	for _, bad := range []uint64{50, 333, 517} {
		if bad+uint64(fsHeaderForceVerify) >= pivot {
			t.Fatalf("height %d is not far below the pivot %d", bad, pivot)
		}
		tester := newTesterWithEngine(t, ethash.NewFakeFailer(bad))
		tester.newPeer("peer", eth.ETH68, chain.blocks[1:])
		err := tester.sync("peer", nil, SnapSync)
		if !errors.Is(err, errInvalidChain) {
			tester.terminate()
			t.Fatalf("snap sync over a bad seal at %d: %v, want %v", bad, err, errInvalidChain)
		}
		if head := tester.chain.CurrentHeader().Number.Uint64(); head >= bad {
			tester.terminate()
			t.Fatalf("snap sync over a bad seal at %d kept headers up to %d", bad, head)
		}
		tester.terminate()
	}
}
