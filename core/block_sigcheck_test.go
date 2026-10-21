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

package core

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// gatedHeaderEngine holds back each header verification result of its
// engine until the test releases it on gate.
type gatedHeaderEngine struct {
	consensus.Engine
	gate chan struct{}
}

func (e *gatedHeaderEngine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, inner := e.Engine.VerifyHeaders(chain, headers, seals)
	out := make(chan error, len(headers))
	go func() {
		for range headers {
			err := <-inner
			<-e.gate
			out <- err
		}
	}()
	return abort, out
}

// recoveredTx is a transaction handed to the sender cacher, with the result
// of verifying it with the signer it came with.
type recoveredTx struct {
	hash common.Hash
	from common.Address
	err  error
}

// recordingSenderCacher returns a sender cacher with one worker that verifies
// every transaction it is given and reports it on the returned channel.
func recordingSenderCacher() (*txSenderCacher, <-chan recoveredTx) {
	var (
		cacher = &txSenderCacher{threads: 1, tasks: make(chan *txSenderCacherRequest, 1)}
		seen   = make(chan recoveredTx, 64)
	)
	go func() {
		for task := range cacher.tasks {
			for i := 0; i < len(task.txs); i += task.inc {
				from, err := types.Sender(task.signer, task.txs[i])
				seen <- recoveredTx{task.txs[i].Hash(), from, err}
			}
		}
	}()
	return cacher, seen
}

// A block's signatures are handed to the parallel sender cacher only once its
// header checks, the seal included, have passed; a block whose seal fails has
// none of its signatures verified.
func TestBlockSignaturesVerifiedOnlyAfterSeal(t *testing.T) {
	var (
		config         = *params.TestChainConfig
		key, _, sender = testAccount(1)
		recipient      = common.Address{0xbb}
		gspec          = &genesisT.Genesis{
			Config: &config,
			Alloc:  genesisT.GenesisAlloc{sender: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
		}
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 2, func(i int, b *BlockGen) {
		b.AddTx(blockTransfer(b, key, sender, recipient, big.NewInt(1000), accountTransferGas, nil))
		b.AddTx(blockTransfer(b, key, sender, recipient, big.NewInt(1000), accountTransferGas, nil))
	})

	cacher, seen := recordingSenderCacher()
	saved := SenderCacher
	SenderCacher = cacher
	defer func() { SenderCacher = saved }()

	// Block 2's seal is invalid.
	engine := &gatedHeaderEngine{Engine: ethash.NewFakeFailer(2), gate: make(chan struct{})}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()

	type result struct {
		n   int
		err error
	}
	inserted := make(chan result, 1)
	go func() {
		n, err := chain.InsertChain(blocks)
		inserted <- result{n, err}
	}()
	expectNone := func(when string) {
		select {
		case r := <-seen:
			t.Fatalf("%s: transaction %x handed to the sender cacher", when, r.hash)
		case <-time.After(200 * time.Millisecond):
		}
	}
	release := func() {
		select {
		case engine.gate <- struct{}{}:
		case <-time.After(5 * time.Second):
			t.Fatal("the import does not wait for a header result")
		}
	}

	// Nothing is verified before block 1's header result.
	expectNone("before any header result")

	// Block 1's header passes: both its transactions are verified, with a
	// signer that takes account transactions.
	release()
	want := map[common.Hash]bool{}
	for _, tx := range blocks[0].Transactions() {
		want[tx.Hash()] = true
	}
	for len(want) > 0 {
		select {
		case r := <-seen:
			if !want[r.hash] {
				t.Fatalf("transaction %x handed to the sender cacher, want one of block 1", r.hash)
			}
			if r.err != nil || r.from != sender {
				t.Fatalf("transaction %x recovered as %x, %v; want %x", r.hash, r.from, r.err, sender)
			}
			delete(want, r.hash)
		case <-time.After(5 * time.Second):
			t.Fatalf("%d transactions of block 1 not handed to the sender cacher", len(want))
		}
	}

	// Block 2's seal fails: the import stops and none of its signatures is
	// verified.
	release()
	select {
	case r := <-inserted:
		if r.n != 1 || r.err == nil || !strings.Contains(r.err.Error(), "invalid proof-of-work") {
			t.Fatalf("insert returned %d, %v; want block 2 refused for its seal", r.n, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the import did not finish")
	}
	expectNone("after block 2's seal failed")
	if got := chain.CurrentBlock().Number.Uint64(); got != 1 {
		t.Fatalf("head %d, want 1", got)
	}
}
