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

// Package linkage holds the linkage test of the coin rules (see
// docs/linkage-test.md): a commit, a partial reveal and a reveal of the
// remainder are mined on an in-process chain of the internal network, read
// back from the chain as raw bytes, and compared hop against hop for any
// value that would tie one hop to another.
package linkage

import (
	"encoding/binary"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

const (
	// blockSpacing is the timestamp step between blocks, in seconds, above
	// the internal network's target so the difficulty stays at its minimum.
	blockSpacing = 10

	// sealTimeout bounds the search for a nonce.
	sealTimeout = 2 * time.Minute

	commitGas = 60_000
)

// The names of the three hops.
const (
	hopCommit    = "commit"
	hopPartial   = "partial reveal"
	hopRemainder = "remainder reveal"
)

var gwei = big.NewInt(1_000_000_000)

// chain is a core.BlockChain on the internal network's genesis whose blocks
// are sealed by the RandomX engine.
type chain struct {
	t      *testing.T
	db     ethdb.Database
	bc     *core.BlockChain
	engine *randomx.RandomX
}

func newChain(t *testing.T) *chain {
	t.Helper()
	engine, err := randomx.New(randomx.Config{Params: ghost.InternalNetParams()})
	if err != nil {
		t.Fatalf("RandomX engine: %v", err)
	}
	engine.SetThreads(1)
	gspec := ghost.InternalNetGenesis()
	if gspec.GasLimit != 30_000_000 {
		t.Fatalf("internal network genesis gas limit %d, want 30,000,000", gspec.GasLimit)
	}
	db := rawdb.NewMemoryDatabase()
	bc, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bc.Stop)
	return &chain{t: t, db: db, bc: bc, engine: engine}
}

func (c *chain) head() *types.Header { return c.bc.CurrentBlock() }

func (c *chain) headState() *state.StateDB {
	c.t.Helper()
	st, err := c.bc.StateAt(c.head().Root)
	if err != nil {
		c.t.Fatal(err)
	}
	return st
}

// mine builds a block with txs on the head, seals it and imports it, which
// runs the chain's own block processing over it.
func (c *chain) mine(coinbase common.Address, txs ...*types.Transaction) *types.Block {
	t := c.t
	t.Helper()
	parent := c.head()
	config := c.bc.Config()
	header := c.nextHeader(parent, coinbase)
	if err := c.engine.Prepare(c.bc, header); err != nil {
		t.Fatalf("prepare block %d: %v", header.Number, err)
	}
	st, err := c.bc.StateAt(parent.Root)
	if err != nil {
		t.Fatal(err)
	}
	gp := new(core.GasPool).AddGas(header.GasLimit)
	var receipts []*types.Receipt
	for i, tx := range txs {
		st.SetTxContext(tx.Hash(), i)
		var receipt *types.Receipt
		if tx.Type() == types.GhostRevealTxType {
			receipt, err = c.applyReveal(gp, st, header, tx)
		} else {
			receipt, err = core.ApplyTransaction(config, c.bc, &header.Coinbase, gp, st, header, tx, &header.GasUsed, vm.Config{})
		}
		if err != nil {
			t.Fatalf("block %d: transaction %d: %v", header.Number, i, err)
		}
		receipts = append(receipts, receipt)
	}
	block, err := c.engine.FinalizeAndAssemble(c.bc, header, st, txs, nil, receipts, nil)
	if err != nil {
		t.Fatalf("assemble block %d: %v", header.Number, err)
	}
	block = c.seal(block)
	if _, err := c.bc.InsertChain(types.Blocks{block}); err != nil {
		t.Fatalf("import block %d: %v", block.NumberU64(), err)
	}
	if c.head().Hash() != block.Hash() {
		t.Fatalf("block %d did not become the head", block.NumberU64())
	}
	return block
}

func (c *chain) nextHeader(parent *types.Header, coinbase common.Address) *types.Header {
	return &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + blockSpacing,
		Coinbase:   coinbase,
		BaseFee:    eip1559.CalcBaseFee(c.bc.Config(), parent),
	}
}

// applyReveal is the miner's side of a reveal: G_PRIV gas, the reveal checks
// and change with the active verifier, and the receipt.
func (c *chain) applyReveal(gp *core.GasPool, st *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, error) {
	if err := gp.SubGas(types.GhostRevealGas); err != nil {
		return nil, err
	}
	env := &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   c.bc,
		ChainID: c.bc.Config().GetChainID(),
		Genesis: c.bc.Genesis().Hash(),
	}
	if err := ghostpriv.ApplyReveal(st, env, ghostpriv.ActiveVerifier(), tx.GhostRevealEnvelope()); err != nil {
		return nil, err
	}
	st.Finalise(true)
	header.GasUsed += types.GhostRevealGas
	receipt := &types.Receipt{
		Type:              types.GhostRevealTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: header.GasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           types.GhostRevealGas,
		EffectiveGasPrice: new(big.Int),
		Logs:              st.GetLogs(tx.Hash(), header.Number.Uint64(), common.Hash{}),
	}
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	return receipt, nil
}

func (c *chain) seal(block *types.Block) *types.Block {
	c.t.Helper()
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := c.engine.Seal(c.bc, block, results, stop); err != nil {
		c.t.Fatalf("seal block %d: %v", block.Number(), err)
	}
	select {
	case sealed := <-results:
		return sealed
	case <-time.After(sealTimeout):
		c.t.Fatalf("block %d not sealed in %v", block.Number(), sealTimeout)
		return nil
	}
}

// nextFee is the window fee of a reveal in the next block.
func (c *chain) nextFee() ghostpriv.Fee {
	c.t.Helper()
	parent := c.head()
	number := parent.Number.Uint64() + 1
	start := ghostpriv.WindowStart(number)
	bRef := eip1559.CalcBaseFee(c.bc.Config(), parent)
	if start != number {
		bRef = c.bc.GetHeaderByNumber(start).BaseFee
	}
	fee, err := ghostpriv.WindowFee(bRef)
	if err != nil {
		c.t.Fatal(err)
	}
	return fee
}

// rawHop is one hop as the chain stores it: the transaction's bytes from the
// block body and the logs of its receipt.
type rawHop struct {
	name string
	tx   []byte
	logs []*types.Log
}

// clone is a deep copy, for building linked variants.
func (h rawHop) clone() rawHop {
	out := rawHop{name: h.name, tx: common.CopyBytes(h.tx)}
	for _, l := range h.logs {
		cp := &types.Log{Address: l.Address, Data: common.CopyBytes(l.Data)}
		cp.Topics = append([]common.Hash(nil), l.Topics...)
		out.logs = append(out.logs, cp)
	}
	return out
}

// readHop reads the single transaction of a canonical block from the body
// in the database and the logs of its receipt.
func (c *chain) readHop(name string, number uint64) rawHop {
	t := c.t
	t.Helper()
	block := c.bc.GetBlockByNumber(number)
	if block == nil {
		t.Fatalf("%s: no canonical block %d", name, number)
	}
	txs, err := bodyTransactions(rawdb.ReadBodyRLP(c.db, block.Hash(), number))
	if err != nil {
		t.Fatalf("%s: body of block %d: %v", name, number, err)
	}
	if len(txs) != 1 || len(block.Transactions()) != 1 {
		t.Fatalf("%s: block %d holds %d transactions, want 1", name, number, len(txs))
	}
	// The stored bytes are the transaction the block commits to.
	decoded := new(types.Transaction)
	if err := decoded.UnmarshalBinary(txs[0]); err != nil {
		t.Fatalf("%s: stored transaction does not decode: %v", name, err)
	}
	if decoded.Hash() != block.Transactions()[0].Hash() {
		t.Fatalf("%s: stored transaction %x, block holds %x", name, decoded.Hash(), block.Transactions()[0].Hash())
	}
	receipts := c.bc.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("%s: block %d has %d receipts, want 1 successful", name, number, len(receipts))
	}
	return rawHop{name: name, tx: txs[0], logs: receipts[0].Logs}
}

// bodyTransactions splits a stored block body into the binary encodings of
// its transactions: a typed transaction is an RLP string holding its
// envelope, a legacy one an RLP list.
func bodyTransactions(body rlp.RawValue) ([][]byte, error) {
	content, _, err := rlp.SplitList(body)
	if err != nil {
		return nil, err
	}
	list, _, err := rlp.SplitList(content)
	if err != nil {
		return nil, err
	}
	var txs [][]byte
	for len(list) > 0 {
		kind, val, rest, err := rlp.Split(list)
		if err != nil {
			return nil, err
		}
		if kind == rlp.List {
			val = list[:len(list)-len(rest)]
		}
		txs = append(txs, common.CopyBytes(val))
		list = rest
	}
	return txs, nil
}

// The wallet is a stand-in for the real one, whose key derivation is not
// reimplemented: a seed gives each commitment number i a fingerprint, a
// reveal secret and a blinding under test tags. The marker is
// K("ghost/coin-marker/v1", secret, blinding); the note carries the value
// masked and a check value.
const (
	tagFingerprint = "ghost/test-linkage-wallet/fingerprint/v1"
	tagRevealKey   = "ghost/test-linkage-wallet/reveal-secret/v1"
	tagBlinding    = "ghost/test-linkage-wallet/blinding/v1"
	tagNoteMask    = "ghost/test-linkage-wallet/note-mask/v1"
	tagNoteCheck   = "ghost/test-linkage-wallet/note-check/v1"
	tagMarker      = "ghost/coin-marker/v1"
)

type wallet struct{ seed string }

func (w wallet) secret(tag string, i int) common.Hash {
	return ghosttree.K(tag, []byte(w.seed), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

// coin is commitment number index of the wallet with its value.
type coin struct {
	w     wallet
	index int
	value *uint256.Int
}

func (c coin) fingerprint() common.Hash { return c.w.secret(tagFingerprint, c.index) }

func (c coin) leaf() common.Hash { return ghostpriv.Commitment(c.fingerprint(), c.value) }

func (c coin) marker() common.Hash {
	r, b := c.w.secret(tagRevealKey, c.index), c.w.secret(tagBlinding, c.index)
	return ghosttree.K(tagMarker, r[:], b[:])
}

func (c coin) note() [ghostpriv.NoteSize]byte {
	var note [ghostpriv.NoteSize]byte
	word, mask, check := c.value.Bytes32(), c.w.secret(tagNoteMask, c.index), c.w.secret(tagNoteCheck, c.index)
	for j := range word {
		note[j] = word[j] ^ mask[j]
	}
	copy(note[32:64], check[:])
	return note
}

// fixture is the real design on the chain: the three hops read back, the
// coin tree roots of every canonical header and the chain id.
type fixture struct {
	hops    []rawHop
	roots   map[common.Hash]bool
	chainID uint64
}

var (
	fixtureOnce  sync.Once
	fixtureValue *fixture
)

// realDesign returns the fixture, built once for all tests of the package.
func realDesign(t *testing.T) *fixture {
	t.Helper()
	fixtureOnce.Do(func() { fixtureValue = buildFixture(t) })
	if fixtureValue == nil {
		t.Fatal("the chain of the real design could not be built; see the first test that ran")
	}
	return fixtureValue
}

func testAddress(label string) common.Address {
	return common.BytesToAddress(ghosttree.K("ghost/test-linkage/address", []byte(label)).Bytes()[12:])
}

// buildFixture mines a commit, a partial reveal of it and, in a later fee
// window, a reveal of the whole remainder, each in a block of its own, with
// real transactions from the commit and reveal code and stub proofs.
func buildFixture(t *testing.T) *fixture {
	defer ghostpriv.SetVerifier(ghostprivtest.Verifier{})()
	c := newChain(t)
	config := c.bc.Config()
	chainID := config.GetChainID().Uint64()
	genesis := c.bc.Genesis().Hash()

	key, err := crypto.ToECDSA(crypto.Keccak256([]byte("ghost synthetic linkage account payer")))
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	for range 3 {
		c.mine(payer)
	}
	miner := testAddress("miner")

	// The commit: a part of the payer's balance with an uneven tail.
	w := wallet{seed: "synthetic seed for the linkage wallet"}
	value := new(uint256.Int).Div(c.headState().GetBalance(payer), uint256.NewInt(3))
	value.AddUint64(value, 7_919)
	if value.Gt(ghostpriv.VMax) {
		value.Set(ghostpriv.VMax)
	}
	coin0 := coin{w: w, index: 0, value: value}
	note0 := coin0.note()
	data, err := ghostpriv.CommitData(coin0.fingerprint(), note0[:])
	if err != nil {
		t.Fatal(err)
	}
	to := ghost.CommitEntryAddress
	commitTx := types.MustSignNewTx(key, types.LatestSigner(config), &types.DynamicFeeTx{
		ChainID:   config.GetChainID(),
		Nonce:     c.headState().GetNonce(payer),
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       commitGas,
		To:        &to,
		Value:     value.ToBig(),
		Data:      data,
	})
	commitBlock := c.mine(miner, commitTx)

	reveal := func(spend, rest coin, recipient common.Address, out *uint256.Int, fee ghostpriv.Fee) *types.Transaction {
		r := &ghostpriv.Reveal{
			Version:   ghostpriv.Version,
			ChainID:   chainID,
			Marker:    spend.marker(),
			Root:      *c.head().CoinTreeRoot,
			Remainder: rest.leaf(),
			Recipient: recipient,
			Out:       out,
			Fee:       fee.Total,
			Note:      rest.note(),
		}
		r.Proof = ghostprivtest.Proof(r.BindingDigest(chainID, genesis))
		env, err := r.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		tx, err := types.NewGhostRevealTx(env)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}

	// The partial reveal: about a third out, the rest as commitment 1.
	fee1 := c.nextFee()
	out1 := new(uint256.Int).Div(value, uint256.NewInt(3))
	out1.AddUint64(out1, 4_327)
	coin1 := coin{w: w, index: 1, value: new(uint256.Int).Sub(value, new(uint256.Int).Add(out1, fee1.Total))}
	partialBlock := c.mine(miner, reveal(coin0, coin1, testAddress("first recipient"), out1, fee1))

	// The reveal of the remainder, in a later fee window, leaving a coin of
	// value zero as commitment 2.
	for ghostpriv.WindowStart(c.head().Number.Uint64()+1) == ghostpriv.WindowStart(partialBlock.NumberU64()) {
		c.mine(miner)
	}
	fee2 := c.nextFee()
	if fee2.Total.Gt(coin1.value) {
		t.Fatalf("the remainder %v does not pay the fee %v", coin1.value, fee2.Total)
	}
	out2 := new(uint256.Int).Sub(coin1.value, fee2.Total)
	coin2 := coin{w: w, index: 2, value: new(uint256.Int)}
	remainderBlock := c.mine(miner, reveal(coin1, coin2, testAddress("second recipient"), out2, fee2))

	f := &fixture{
		hops: []rawHop{
			c.readHop(hopCommit, commitBlock.NumberU64()),
			c.readHop(hopPartial, partialBlock.NumberU64()),
			c.readHop(hopRemainder, remainderBlock.NumberU64()),
		},
		roots:   make(map[common.Hash]bool),
		chainID: chainID,
	}
	for n := uint64(0); n <= c.head().Number.Uint64(); n++ {
		h := c.bc.GetHeaderByNumber(n)
		if h == nil || h.CoinTreeRoot == nil {
			t.Fatalf("block %d has no coin tree root", n)
		}
		f.roots[*h.CoinTreeRoot] = true
	}
	return f
}
