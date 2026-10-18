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

package randomx

import (
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestSealWaitsForTheClock checks that the sealer holds a block whose
// timestamp is beyond the future drift of the local clock, which every
// verifier would refuse for now, and seals it once the clock catches up.
func TestSealWaitsForTheClock(t *testing.T) {
	f := sealedChain(t)
	engine := newTestEngine(t, testParams())
	engine.SetThreads(1)
	chain, err := newTestBlockChain(engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if _, err := chain.InsertChain(f.blocks); err != nil {
		t.Fatal(err)
	}

	parent := chain.CurrentBlock()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + testBlockTime,
		Coinbase:   common.Address{0xbb},
		BaseFee:    eip1559.CalcBaseFee(chain.Config(), parent),
	}
	if err := engine.Prepare(chain, header); err != nil {
		t.Fatal(err)
	}
	statedb, err := chain.StateAt(parent.Root)
	if err != nil {
		t.Fatal(err)
	}
	block, err := engine.FinalizeAndAssemble(chain, header, statedb, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The clock is one second short of letting the block through.
	var clock atomic.Int64
	clock.Store(int64(header.Time - testParams().FutureDrift - 1))
	engine.now = func() time.Time { return time.Unix(clock.Load(), 0) }

	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := engine.Seal(chain, block, results, stop); err != nil {
		t.Fatal(err)
	}
	select {
	case <-results:
		t.Fatal("a block beyond the future drift was sealed")
	case <-time.After(1500 * time.Millisecond):
	}
	clock.Add(1)
	select {
	case sealed := <-results:
		if err := engine.VerifyHeader(chain, sealed.Header(), true); err != nil {
			t.Fatalf("block sealed after the wait is rejected: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the block was not sealed once the clock allowed it")
	}
}
