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
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
)

// remoteSetup returns an engine with local mining off and a blockchain on
// it holding the first n blocks of the sealed fixture chain.
func remoteSetup(t *testing.T, n int) (*sealedChainFixture, *RandomX, *core.BlockChain) {
	t.Helper()
	f := sealedChain(t)
	engine := newTestEngine(t, testParams())
	engine.SetThreads(-1)
	chain, err := newTestBlockChain(engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	if _, err := chain.InsertChain(f.blocks[:n]); err != nil {
		t.Fatal(err)
	}
	return f, engine, chain
}

// assembleNext builds an unsealed empty block on parent the way a miner
// does.
func assembleNext(t *testing.T, engine *RandomX, chain *core.BlockChain, parent *types.Header, coinbase common.Address) *types.Block {
	t.Helper()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + testBlockTime,
		Coinbase:   coinbase,
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
	return block
}

// handOut passes block to the engine's sealer, which makes it the remote
// work, and returns the channel the sealed block arrives on.
func handOut(t *testing.T, engine *RandomX, chain *core.BlockChain, block *types.Block) chan *types.Block {
	t.Helper()
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	t.Cleanup(func() { close(stop) })
	if err := engine.Seal(chain, block, results, stop); err != nil {
		t.Fatal(err)
	}
	return results
}

// solveWork searches nonces upward from zero for the first one whose
// RandomX hash under the package's key meets the package's target (valid)
// or misses it (!valid), the way a remote miner reads a work package: the
// input is the seal hash and the nonce as 8 big-endian bytes, the hash is
// read as a big-endian number.
func solveWork(t *testing.T, work [4]string, valid bool) (types.BlockNonce, common.Hash) {
	t.Helper()
	sealHash := common.HexToHash(work[0])
	key := common.HexToHash(work[1])
	target := new(big.Int).SetBytes(common.FromHex(work[2]))

	hasher, err := NewHasher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	defer hasher.Close()
	input := make([]byte, 40)
	copy(input, sealHash[:])
	for nonce := uint64(0); nonce < 10_000; nonce++ {
		binary.BigEndian.PutUint64(input[32:], nonce)
		out := hasher.Hash(input)
		if (new(big.Int).SetBytes(out[:]).Cmp(target) <= 0) == valid {
			return types.EncodeNonce(nonce), common.Hash(out)
		}
	}
	t.Fatal("no nonce found among 10000")
	return types.BlockNonce{}, common.Hash{}
}

func expectNoResult(t *testing.T, results <-chan *types.Block, what string) {
	t.Helper()
	select {
	case block := <-results:
		t.Fatalf("%s: block %d was handed to the miner", what, block.NumberU64())
	default:
	}
}

// TestRemoteSealGetWorkSubmit hands a block out as remote work, checks the
// package, solves it outside the engine, submits it and inserts the sealed
// block into the chain.
func TestRemoteSealGetWorkSubmit(t *testing.T) {
	f, engine, chain := remoteSetup(t, testChainLength)
	api := &API{engine}
	if _, err := api.GetWork(); err == nil {
		t.Fatal("work handed out before any block was sealed")
	}

	miner := common.Address{0xcc}
	block := assembleNext(t, engine, chain, chain.CurrentBlock(), miner)
	results := handOut(t, engine, chain, block)

	work, err := api.GetWork()
	if err != nil {
		t.Fatal(err)
	}
	height := block.NumberU64()
	want := [4]string{
		engine.SealHash(block.Header()).Hex(),
		f.key(height).Hex(),
		common.BytesToHash(ghostrules.SealTarget(testDifficulty).Bytes()).Hex(),
		hexutil.EncodeUint64(height),
	}
	if work != want {
		t.Fatalf("work package %v, want %v", work, want)
	}

	nonce, result := solveWork(t, work, true)
	if !api.SubmitWork(nonce, common.HexToHash(work[0]), result) {
		t.Fatal("a valid solution was refused")
	}
	var sealed *types.Block
	select {
	case sealed = <-results:
	case <-time.After(10 * time.Second):
		t.Fatal("the accepted solution did not reach the miner")
	}
	if sealed.Nonce() != nonce.Uint64() || engine.SealHash(sealed.Header()) != engine.SealHash(block.Header()) {
		t.Fatalf("sealed block has nonce %d and seal hash %x, want %d and %x", sealed.Nonce(), engine.SealHash(sealed.Header()), nonce.Uint64(), engine.SealHash(block.Header()))
	}
	if _, err := chain.InsertChain(types.Blocks{sealed}); err != nil {
		t.Fatalf("remotely sealed block not inserted: %v", err)
	}
	if chain.CurrentBlock().Hash() != sealed.Hash() {
		t.Fatal("remotely sealed block is not the head")
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := statedb.GetBalance(miner), testParams().BlockReward(height); !got.Eq(want) {
		t.Errorf("miner balance %v, want the block reward %v", got, want)
	}
}

// TestRemoteSealWrongNonceRefused submits a nonce that does not seal the
// work, and the right nonce with a result that is not its hash; both are
// refused and nothing reaches the miner, while the right pair is accepted.
func TestRemoteSealWrongNonceRefused(t *testing.T) {
	_, engine, chain := remoteSetup(t, testChainLength)
	api := &API{engine}
	block := assembleNext(t, engine, chain, chain.CurrentBlock(), common.Address{0xcd})
	results := handOut(t, engine, chain, block)
	work, err := api.GetWork()
	if err != nil {
		t.Fatal(err)
	}
	sealHash := common.HexToHash(work[0])

	bad, badResult := solveWork(t, work, false)
	if api.SubmitWork(bad, sealHash, badResult) {
		t.Fatal("a nonce that misses the target was accepted")
	}
	expectNoResult(t, results, "wrong nonce")

	good, result := solveWork(t, work, true)
	if api.SubmitWork(good, sealHash, common.Hash{0x01}) {
		t.Fatal("a valid nonce with a wrong result was accepted")
	}
	expectNoResult(t, results, "wrong result")

	if api.SubmitWork(good, common.Hash{0x02}, result) {
		t.Fatal("a solution for unknown work was accepted")
	}
	expectNoResult(t, results, "unknown work")

	if !api.SubmitWork(good, sealHash, result) {
		t.Fatal("the valid solution was refused")
	}
	select {
	case <-results:
	case <-time.After(10 * time.Second):
		t.Fatal("the accepted solution did not reach the miner")
	}
}

// TestRemoteSealStaleWorkRefused hands out work at two heights, then work
// staleThreshold blocks above the first: a solution for the first is
// refused as stale, one for work less than staleThreshold behind is still
// accepted, and getWork hands out only the newest work.
func TestRemoteSealStaleWorkRefused(t *testing.T) {
	f, engine, chain := remoteSetup(t, 9)
	api := &API{engine}

	old := assembleNext(t, engine, chain, chain.CurrentBlock(), common.Address{0xd0}) // height 10
	oldResults := handOut(t, engine, chain, old)
	oldWork, err := api.GetWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(f.blocks[9:10]); err != nil {
		t.Fatal(err)
	}
	recent := assembleNext(t, engine, chain, chain.CurrentBlock(), common.Address{0xd1}) // height 11
	recentResults := handOut(t, engine, chain, recent)
	recentWork, err := api.GetWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(f.blocks[10:]); err != nil {
		t.Fatal(err)
	}
	head := assembleNext(t, engine, chain, chain.CurrentBlock(), common.Address{0xd2}) // height 17
	if head.NumberU64() != old.NumberU64()+staleThreshold || head.NumberU64() >= recent.NumberU64()+staleThreshold {
		t.Fatalf("heights %d, %d and %d do not straddle the stale threshold", old.NumberU64(), recent.NumberU64(), head.NumberU64())
	}
	handOut(t, engine, chain, head)

	work, err := api.GetWork()
	if err != nil {
		t.Fatal(err)
	}
	if work[0] != engine.SealHash(head.Header()).Hex() {
		t.Fatalf("getWork hands out %s, want the newest work %s", work[0], engine.SealHash(head.Header()).Hex())
	}

	nonce, result := solveWork(t, oldWork, true)
	if api.SubmitWork(nonce, common.HexToHash(oldWork[0]), result) {
		t.Fatal("a solution for work staleThreshold blocks behind was accepted")
	}
	expectNoResult(t, oldResults, "stale work")

	nonce, result = solveWork(t, recentWork, true)
	if !api.SubmitWork(nonce, common.HexToHash(recentWork[0]), result) {
		t.Fatal("a solution for work within the stale threshold was refused")
	}
	select {
	case <-recentResults:
	case <-time.After(10 * time.Second):
		t.Fatal("the accepted solution did not reach the miner")
	}
}
