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

package ghostpriv_test

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// testEngine is the consensus engine of these tests: the RandomX engine's
// block reward and tree roots on the internal network's parameters, without
// the proof of work, so that blocks build and import without the RandomX
// library. Sealing hands the block back as it is.
type testEngine struct {
	params ghostrules.Params
}

func newTestEngine() *testEngine { return &testEngine{params: ghost.InternalNetParams()} }

func (e *testEngine) Author(h *types.Header) (common.Address, error) { return h.Coinbase, nil }

func (e *testEngine) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return nil
}

func (e *testEngine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))
	for range headers {
		results <- nil
	}
	return abort, results
}

func (e *testEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (e *testEngine) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Difficulty = big.NewInt(1)
	return nil
}

func (e *testEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	st.AddBalance(header.Coinbase, e.params.BlockReward(header.Number.Uint64()))
}

func (e *testEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	e.Finalize(chain, header, st, txs, uncles, withdrawals)
	coin, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		return nil, err
	}
	data, err := ghosttree.Root(st, ghosttree.Data)
	if err != nil {
		return nil, err
	}
	header.CoinTreeRoot, header.DataTreeRoot = &coin, &data
	header.Root = st.IntermediateRoot(true)
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

func (e *testEngine) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	results <- block
	return nil
}

func (e *testEngine) SealHash(header *types.Header) common.Hash { return header.Hash() }

func (e *testEngine) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

func (e *testEngine) APIs(chain consensus.ChainHeaderReader) []rpc.API { return nil }

func (e *testEngine) Close() error { return nil }

// Test amounts.
var (
	gwei     = big.NewInt(1_000_000_000)
	oneGhost = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	startBal = new(big.Int).Mul(big.NewInt(1000), oneGhost)
)

func testKey(name string) *ecdsa.PrivateKey {
	key, err := crypto.ToECDSA(crypto.Keccak256([]byte("ghost synthetic test account " + name)))
	if err != nil {
		panic(err)
	}
	return key
}

var (
	keyA  = testKey("a")
	keyB  = testKey("b")
	keyC  = testKey("c")
	addrA = crypto.PubkeyToAddress(keyA.PublicKey)
	addrB = crypto.PubkeyToAddress(keyB.PublicKey)
	addrC = crypto.PubkeyToAddress(keyC.PublicKey)
)

// fixture is a chain on the internal network's configuration, with three
// funded accounts and, when given, more allocations.
type fixture struct {
	t       *testing.T
	gspec   *genesisT.Genesis
	genesis *types.Block
	engine  *testEngine
	chainID uint64
	signer  types.Signer
}

func newFixture(t *testing.T, gasLimit uint64, extra genesisT.GenesisAlloc) *fixture {
	t.Helper()
	gspec := ghost.InternalNetGenesis()
	gspec.GasLimit = gasLimit
	gspec.Alloc = genesisT.GenesisAlloc{
		addrA: {Balance: new(big.Int).Set(startBal)},
		addrB: {Balance: new(big.Int).Set(startBal)},
		addrC: {Balance: new(big.Int).Set(startBal)},
	}
	for addr, acc := range extra {
		gspec.Alloc[addr] = acc
	}
	genesis := core.GenesisToBlock(gspec, nil)
	if genesis.Header().CoinTreeRoot == nil {
		t.Fatal("the internal network's genesis has no coin tree root")
	}
	return &fixture{
		t:       t,
		gspec:   gspec,
		genesis: genesis,
		engine:  newTestEngine(),
		chainID: gspec.Config.GetChainID().Uint64(),
		signer:  types.LatestSigner(gspec.Config),
	}
}

// allocTotal is the value the genesis issued.
func (f *fixture) allocTotal() *big.Int {
	sum := new(big.Int)
	for _, acc := range f.gspec.Alloc {
		sum.Add(sum, acc.Balance)
	}
	return sum
}

func (f *fixture) newChain() *core.BlockChain {
	f.t.Helper()
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, f.gspec, nil, f.engine, vm.Config{}, nil, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(chain.Stop)
	return chain
}

// generate builds n blocks on the genesis with the chain maker.
func (f *fixture) generate(n int, gen func(int, *core.BlockGen)) ([]*types.Block, []types.Receipts) {
	_, blocks, receipts := core.GenerateChainWithGenesis(f.gspec, f.engine, n, gen)
	return blocks, receipts
}

func (f *fixture) insert(chain *core.BlockChain, blocks []*types.Block) {
	f.t.Helper()
	if i, err := chain.InsertChain(blocks); err != nil {
		f.t.Fatalf("block %d not inserted: %v", blocks[i].NumberU64(), err)
	}
}

// coin is what a wallet keeps of a commitment it made.
type coin struct {
	f     common.Hash
	value *uint256.Int
	note  []byte
}

func (c coin) commitment() common.Hash { return ghostpriv.Commitment(c.f, c.value) }

func testNote(seed byte) []byte {
	note := make([]byte, ghostpriv.NoteSize)
	for i := range note {
		note[i] = seed + byte(i) | 1
	}
	return note
}

func testCoin(name string, value *big.Int) coin {
	return coin{
		f:     ghosttree.K("ghost/test-coin-f", []byte(name)),
		value: uint256.MustFromBig(value),
		note:  testNote(byte(len(name))),
	}
}

func testMarker(name string) common.Hash {
	return ghosttree.K("ghost/coin-marker/v1", []byte("synthetic r "+name), []byte("synthetic b "+name))
}

// commitTx is a commit of c from key, a dynamic-fee transaction to the
// commit entry address.
func (f *fixture) commitTx(key *ecdsa.PrivateKey, nonce uint64, c coin) *types.Transaction {
	f.t.Helper()
	data, err := ghostpriv.CommitData(c.f, c.note)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.callTx(key, nonce, ghost.CommitEntryAddress, c.value.ToBig(), data, 60_000)
}

func (f *fixture) callTx(key *ecdsa.PrivateKey, nonce uint64, to common.Address, value *big.Int, data []byte, gas uint64) *types.Transaction {
	return types.MustSignNewTx(key, f.signer, &types.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(f.chainID),
		Nonce:     nonce,
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       gas,
		To:        &to,
		Value:     value,
		Data:      data,
	})
}

// newReveal is a reveal of the given fields with the stub proof of its
// binding digest on this chain.
func (f *fixture) newReveal(root, marker common.Hash, remainder coin, recipient common.Address, out, fee *uint256.Int) *ghostpriv.Reveal {
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   f.chainID,
		Marker:    marker,
		Root:      root,
		Remainder: remainder.commitment(),
		Recipient: recipient,
		Out:       new(uint256.Int).Set(out),
		Fee:       new(uint256.Int).Set(fee),
	}
	copy(r.Note[:], remainder.note)
	f.prove(r)
	return r
}

// prove sets the stub proof of the reveal's binding digest.
func (f *fixture) prove(r *ghostpriv.Reveal) {
	r.Proof = ghostprivtest.Proof(r.BindingDigest(f.chainID, f.genesis.Hash()))
}

func envelope(t *testing.T, r *ghostpriv.Reveal) []byte {
	t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func revealTx(t *testing.T, r *ghostpriv.Reveal) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostRevealTx(envelope(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// genWindowFee is the fee of a reveal in the block being generated.
func genWindowFee(t *testing.T, b *core.BlockGen) ghostpriv.Fee {
	t.Helper()
	h := b.Number().Uint64()
	start := ghostpriv.WindowStart(h)
	bRef := b.BaseFee()
	if start != h {
		bRef = b.PrevBlock(int(start) - 1).BaseFee()
	}
	fee, err := ghostpriv.WindowFee(bRef)
	if err != nil {
		t.Fatal(err)
	}
	return fee
}

// genParentRoot is the coin root of the parent of the block being generated.
func genParentRoot(b *core.BlockGen) common.Hash {
	return *b.PrevBlock(int(b.Number().Uint64()) - 2).Header().CoinTreeRoot
}

// useStub makes the stub verifier the active one for the test.
func useStub(t *testing.T) {
	restore := ghostpriv.SetVerifier(ghostprivtest.Verifier{})
	t.Cleanup(restore)
}

// useDefault makes the default verifier the active one for the test.
func useDefault(t *testing.T) {
	restore := ghostpriv.SetVerifier(nil)
	t.Cleanup(restore)
}

// nextEnv is the environment of a block on parent in the chain, with the
// state after parent.
func nextEnv(t *testing.T, chain *core.BlockChain, parent *types.Header, coinbase common.Address) (*ghostpriv.BlockEnv, *state.StateDB) {
	t.Helper()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + 10,
		Coinbase:   coinbase,
		Difficulty: big.NewInt(1),
		BaseFee:    eip1559.CalcBaseFee(chain.Config(), parent),
	}
	st, err := chain.StateAt(parent.Root)
	if err != nil {
		t.Fatal(err)
	}
	return &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   chain,
		ChainID: chain.Config().GetChainID(),
		Genesis: chain.Genesis().Hash(),
	}, st
}

// chainWindowFee is the fee of a reveal in the block of env, on the
// canonical chain.
func chainWindowFee(t *testing.T, chain *core.BlockChain, header *types.Header) ghostpriv.Fee {
	t.Helper()
	h := header.Number.Uint64()
	bRef := header.BaseFee
	if start := ghostpriv.WindowStart(h); start != h {
		bRef = chain.GetHeaderByNumber(start).BaseFee
	}
	fee, err := ghostpriv.WindowFee(bRef)
	if err != nil {
		t.Fatal(err)
	}
	return fee
}

func u256(v *big.Int) *uint256.Int { return uint256.MustFromBig(v) }

func ghostAmount(num, den int64) *big.Int {
	return new(big.Int).Div(new(big.Int).Mul(oneGhost, big.NewInt(num)), big.NewInt(den))
}

// fillCoinTree makes the coin tree full, filled in the block at height, so
// that no append fits in that block.
func fillCoinTree(st *state.StateDB, height uint64) {
	addr := ghosttree.TreeAccount(ghosttree.Coin)
	st.SetNonce(addr, 1)
	st.SetState(addr, ghosttree.Slot(ghosttree.SlotLeafCount), common.BigToHash(new(big.Int).Lsh(big.NewInt(1), 32)))
	st.SetState(addr, ghosttree.Slot(ghosttree.SlotLastFilled), common.BigToHash(new(big.Int).SetUint64(height)))
	st.SetState(addr, ghosttree.Slot(ghosttree.SlotFinalRoot), ghosttree.K("ghost/test-final-root"))
	for l := uint64(0); l < ghosttree.MaxDepth; l++ {
		st.SetState(addr, ghosttree.Slot(ghosttree.SlotFrontier+l), ghosttree.K("ghost/test-frontier", []byte{byte(l)}))
	}
}

// totals reads the totals account.
func totals(st *state.StateDB) (in, out *big.Int) {
	i, o := ghostpriv.Totals(st)
	return i.ToBig(), o.ToBig()
}

func coinLeafCount(st *state.StateDB) uint64 {
	return st.GetState(ghosttree.TreeAccount(ghosttree.Coin), ghosttree.Slot(ghosttree.SlotLeafCount)).Big().Uint64()
}
