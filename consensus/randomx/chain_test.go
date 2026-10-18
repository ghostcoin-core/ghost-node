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
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// testChainLength is the length of the shared sealed chain. With E = 8 and
// L = 4, blocks 1..12 are keyed by genesis and blocks 13..16 by block 8.
const testChainLength = 16

// sealedChain is a chain sealed by the engine and inserted into a real
// blockchain, built once and shared so the package needs few cache builds.
type sealedChainFixture struct {
	engine  *RandomX
	gspec   *genesisT.Genesis
	genesis *types.Block
	blocks  []*types.Block // heights 1..testChainLength
}

var (
	fixtureOnce sync.Once
	fixture     *sealedChainFixture
	fixtureErr  error
)

func sealedChain(t *testing.T) *sealedChainFixture {
	t.Helper()
	fixtureOnce.Do(func() { fixture, fixtureErr = buildSealedChain() })
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return fixture
}

func testGenesis() *genesisT.Genesis {
	return &genesisT.Genesis{
		Config:     testConfig(),
		Timestamp:  testGenesisAt,
		GasLimit:   8_000_000,
		Difficulty: new(big.Int).Set(testDifficulty),
		Alloc:      genesisT.GenesisAlloc{},
	}
}

func newTestBlockChain(engine consensus.Engine, gspec *genesisT.Genesis) (*core.BlockChain, error) {
	return core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
}

func buildSealedChain() (*sealedChainFixture, error) {
	engine, err := New(Config{Params: testParams(), EpochLength: testEpoch, KeyLag: testLag})
	if err != nil {
		return nil, err
	}
	engine.SetThreads(2)
	gspec := testGenesis()
	chain, err := newTestBlockChain(engine, gspec)
	if err != nil {
		return nil, err
	}
	defer chain.Stop()

	f := &sealedChainFixture{engine: engine, gspec: gspec, genesis: chain.Genesis()}
	for i := 0; i < testChainLength; i++ {
		block, err := sealNext(engine, chain, chain.CurrentBlock(), common.Address{byte(i + 1)})
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i+1, err)
		}
		if _, err := chain.InsertChain(types.Blocks{block}); err != nil {
			return nil, fmt.Errorf("inserting block %d: %w", i+1, err)
		}
		f.blocks = append(f.blocks, block)
	}
	return f, nil
}

// sealNext builds an empty block on parent the way a miner does and seals it
// with the engine.
func sealNext(engine *RandomX, chain *core.BlockChain, parent *types.Header, coinbase common.Address) (*types.Block, error) {
	config := chain.Config()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + testBlockTime,
		Coinbase:   coinbase,
	}
	if config.IsEnabled(config.GetEIP1559Transition, header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(config, parent)
	}
	if err := engine.Prepare(chain, header); err != nil {
		return nil, err
	}
	statedb, err := chain.StateAt(parent.Root)
	if err != nil {
		return nil, err
	}
	block, err := engine.FinalizeAndAssemble(chain, header, statedb, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := engine.Seal(chain, block, results, stop); err != nil {
		return nil, err
	}
	select {
	case sealed := <-results:
		return sealed, nil
	case <-time.After(2 * time.Minute):
		return nil, errors.New("sealing timed out")
	}
}

// key returns the RandomX key of the fixture block at height, worked out
// from the key rule independently of the engine.
func (f *sealedChainFixture) key(height uint64) common.Hash {
	seed := SeedHeight(height, testEpoch, testLag)
	if seed == 0 {
		return f.genesis.Hash()
	}
	return f.blocks[seed-1].Hash()
}

func (f *sealedChainFixture) headers() []*types.Header {
	headers := make([]*types.Header, len(f.blocks))
	for i, b := range f.blocks {
		headers[i] = b.Header()
	}
	return headers
}

// withBadNonce returns a copy of header with the nearest higher nonce that
// does not seal it under key.
func withBadNonce(t *testing.T, engine *RandomX, header *types.Header, key common.Hash) *types.Header {
	t.Helper()
	h := types.CopyHeader(header)
	for n := header.Nonce.Uint64() + 1; n < header.Nonce.Uint64()+256; n++ {
		h.Nonce = types.EncodeNonce(n)
		err := engine.verifySeal(h, key)
		if errors.Is(err, errInvalidPoW) {
			return h
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("no bad nonce among 255 candidates")
	return nil
}

// TestInsertChainRejectsBadSeal inserts the sealed chain into a real
// blockchain, which accepts it, and checks that a block with a bad RandomX
// seal is rejected without moving the head, under both keys.
func TestInsertChainRejectsBadSeal(t *testing.T) {
	f := sealedChain(t)
	chain, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()

	inserted := 0
	for _, height := range []uint64{11, 14} {
		if _, err := chain.InsertChain(f.blocks[inserted : height-1]); err != nil {
			t.Fatalf("good blocks up to %d rejected: %v", height-1, err)
		}
		inserted = int(height - 1)
		head := chain.CurrentBlock().Hash()
		if head != f.blocks[height-2].Hash() {
			t.Fatalf("head is not block %d", height-1)
		}
		good := f.blocks[height-1]
		bad := good.WithSeal(withBadNonce(t, f.engine, good.Header(), f.key(height)))
		if _, err := chain.InsertChain(types.Blocks{bad}); !errors.Is(err, errInvalidPoW) {
			t.Errorf("block %d with a bad seal: error %v, want %v", height, err, errInvalidPoW)
		}
		if chain.CurrentBlock().Hash() != head {
			t.Errorf("block %d with a bad seal moved the head", height)
		}
		if chain.HasBlock(bad.Hash(), height) {
			t.Errorf("block %d with a bad seal was stored", height)
		}
	}
	if _, err := chain.InsertChain(f.blocks[inserted:]); err != nil {
		t.Fatalf("good blocks rejected after the bad ones: %v", err)
	}
	if head := chain.CurrentBlock(); head.Hash() != f.blocks[len(f.blocks)-1].Hash() {
		t.Fatalf("head is block %d, want %d", head.Number, len(f.blocks))
	}
}

// TestBadSealRejected changes a sealed header in every way and checks each
// change is rejected: a wrong nonce, a non-zero mix digest, and a change to
// any one other header field.
func TestBadSealRejected(t *testing.T) {
	f := sealedChain(t)
	for _, height := range []uint64{12, 16} { // the last block of each key
		good := f.blocks[height-1].Header()
		reader := newTestReader(testConfig(), f.genesis.Header(), f.headers()[:height-1]...)
		if err := f.engine.VerifyHeader(reader, good, true); err != nil {
			t.Fatalf("block %d: sealed header rejected: %v", height, err)
		}

		bad := withBadNonce(t, f.engine, good, f.key(height))
		if err := f.engine.VerifyHeader(reader, bad, true); !errors.Is(err, errInvalidPoW) {
			t.Errorf("block %d, wrong nonce: error %v, want %v", height, err, errInvalidPoW)
		}

		mixed := types.CopyHeader(good)
		mixed.MixDigest = common.Hash{31: 1}
		if err := f.engine.VerifyHeader(reader, mixed, true); !errors.Is(err, errInvalidMixDigest) {
			t.Errorf("block %d, non-zero mix digest: error %v, want %v", height, err, errInvalidMixDigest)
		}

		for _, name := range headerFields() {
			if name == "MixDigest" || name == "Nonce" {
				continue
			}
			// A change only the seal catches leaves a random hash, which
			// meets difficulty 16 one time in 16; a few values make a miss
			// vanishingly unlikely.
			rejected := false
			for variant := 0; variant < 8 && !rejected; variant++ {
				h := types.CopyHeader(good)
				mutateField(t, h, name, variant)
				rejected = f.engine.VerifyHeader(reader, h, true) != nil
			}
			if !rejected {
				t.Errorf("block %d: changing %s after sealing is accepted", height, name)
			}
		}
	}
}

// TestVerifyHeadersBatchMatchesSingle checks that a batch crossing a key
// change gives the same result per header as verifying each header alone.
func TestVerifyHeadersBatchMatchesSingle(t *testing.T) {
	f := sealedChain(t)
	if k := f.key(13); k != f.blocks[7].Hash() || f.key(12) != f.genesis.Hash() {
		t.Fatal("the test chain does not cross a key change at block 13")
	}
	good := f.headers()
	badAt := func(height uint64) []*types.Header {
		batch := append([]*types.Header{}, good...)
		batch[height-1] = withBadNonce(t, f.engine, good[height-1], f.key(height))
		return batch
	}
	for _, c := range []struct {
		name  string
		batch []*types.Header
		want  func(height uint64) error
	}{
		{"all sealed", good, func(uint64) error { return nil }},
		{"bad seal under the second key", badAt(16), func(h uint64) error {
			if h == 16 {
				return errInvalidPoW
			}
			return nil
		}},
		{"bad seal under the genesis key", badAt(12), func(h uint64) error {
			switch {
			case h < 12:
				return nil
			case h == 12:
				return errInvalidPoW
			default:
				return consensus.ErrUnknownAncestor // its ancestry is the rejected header's
			}
		}},
	} {
		genesis := f.genesis.Header()
		seals := make([]bool, len(c.batch))
		for i := range seals {
			seals[i] = true
		}
		// Fresh engines, so no key is remembered from elsewhere.
		_, results := newTestEngine(t, testParams()).VerifyHeaders(newTestReader(testConfig(), genesis), c.batch, seals)
		for i, header := range c.batch {
			var batchErr error
			select {
			case batchErr = <-results:
			case <-time.After(time.Minute):
				t.Fatalf("%s: no result for header %d", c.name, i+1)
			}
			single := newTestEngine(t, testParams()).VerifyHeader(newTestReader(testConfig(), genesis, c.batch[:i]...), header, true)
			if !sameError(batchErr, single) {
				t.Errorf("%s: header %d: batch %v, single %v", c.name, i+1, batchErr, single)
			}
			if want := c.want(uint64(i + 1)); !errors.Is(batchErr, want) {
				t.Errorf("%s: header %d: error %v, want %v", c.name, i+1, batchErr, want)
			}
		}
	}
}

func sameError(a, b error) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Error() == b.Error()
}

// TestSealProducesValidBlock seals a block on the chain, checks that it
// verifies and is accepted, and that a search stops on the stop channel and
// on a thread change without holding its cache afterwards.
func TestSealProducesValidBlock(t *testing.T) {
	f := sealedChain(t)
	chain, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if _, err := chain.InsertChain(f.blocks); err != nil {
		t.Fatal(err)
	}

	miner := common.Address{0xaa}
	before := f.engine.hashes.Load()
	block, err := sealNext(f.engine, chain, chain.CurrentBlock(), miner)
	if err != nil {
		t.Fatal(err)
	}
	if f.engine.hashes.Load() == before {
		t.Error("sealing counted no hashes")
	}
	height := block.NumberU64()
	if block.MixDigest() != (common.Hash{}) {
		t.Errorf("sealed block has mix digest %x", block.MixDigest())
	}
	if err := f.engine.verifySeal(block.Header(), f.key(height)); err != nil {
		t.Fatalf("sealed block fails the seal check under key %x: %v", f.key(height), err)
	}
	if err := f.engine.VerifyHeader(chain, block.Header(), true); err != nil {
		t.Fatalf("sealed block rejected: %v", err)
	}
	if _, err := chain.InsertChain(types.Blocks{block}); err != nil {
		t.Fatalf("sealed block not inserted: %v", err)
	}
	if chain.CurrentBlock().Hash() != block.Hash() {
		t.Fatal("sealed block is not the head")
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := statedb.GetBalance(miner), testParams().BlockReward(height); !got.Eq(want) {
		t.Errorf("miner balance %v, want the block reward %v", got, want)
	}

	// A block no one can seal: stop the search, once after a thread change.
	header := block.Header()
	header.ParentHash = chain.CurrentBlock().Hash()
	header.Number = new(big.Int).SetUint64(height + 1)
	header.Difficulty = new(big.Int).Lsh(common.Big1, 250)
	key := f.key(height + 1)
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	if err := f.engine.Seal(chain, types.NewBlockWithHeader(header), results, stop); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	f.engine.SetThreads(1)
	time.Sleep(100 * time.Millisecond)
	if refs := cacheRefs(f.engine.caches, key); refs == 0 {
		t.Error("a running sealer does not hold its cache")
	}
	close(stop)
	deadline := time.Now().Add(10 * time.Second)
	for cacheRefs(f.engine.caches, key) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sealer still holds its cache after stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-results:
		t.Error("an unsealable block was sealed")
	default:
	}
}

// cacheRefs returns how many holders the cache for key has.
func cacheRefs(s *cacheSet, key common.Hash) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.entries[key]; e != nil {
		return e.refs
	}
	return 0
}
