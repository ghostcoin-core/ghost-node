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

package core_test

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

// lookupEngine is the consensus engine of the lookup tests: no proof of
// work, and in Finalize the tree changes its write function makes for a
// header (appends with and without lookup tags, coin and data markers) as
// the coin and data rules would make them. FinalizeAndAssemble sets the
// seven Ghost fields from the state as the RandomX engine does, through
// ghosttree.ReadHeaderFields; block validation checks them on import.
type lookupEngine struct {
	write func(h *types.Header, st *state.StateDB) error
}

func (e *lookupEngine) Author(h *types.Header) (common.Address, error) { return h.Coinbase, nil }

func (e *lookupEngine) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return nil
}

func (e *lookupEngine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))
	for range headers {
		results <- nil
	}
	return abort, results
}

func (e *lookupEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (e *lookupEngine) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Difficulty = big.NewInt(1)
	return nil
}

func (e *lookupEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	if e.write != nil {
		if err := e.write(header, st); err != nil {
			panic(err)
		}
	}
}

func (e *lookupEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	e.Finalize(chain, header, st, txs, uncles, withdrawals)
	fields, err := ghosttree.ReadHeaderFields(st, header.Number.Uint64())
	if err != nil {
		return nil, err
	}
	fields.SetOn(header)
	header.Root = st.IntermediateRoot(true)
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

func (e *lookupEngine) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	results <- block
	return nil
}

func (e *lookupEngine) SealHash(header *types.Header) common.Hash { return header.Hash() }

func (e *lookupEngine) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

func (e *lookupEngine) APIs(chain consensus.ChainHeaderReader) []rpc.API { return nil }

func (e *lookupEngine) Close() error { return nil }

func lookupTag(name string) ghosttree.LookupTag {
	return ghosttree.DeriveLookupTag(ghosttree.K("ghost/test-lookup-key", []byte(name)), 0)
}

func lookupLeaf(name string) common.Hash { return ghosttree.K("ghost/test-lookup-leaf", []byte(name)) }
func lookupMarker(name string) common.Hash {
	return ghosttree.K("ghost/test-lookup-marker", []byte(name))
}

// treeOps are the tree changes of one block: coin and data leaves, each
// with its tag (zero for none), and coin and data markers. A coin marker
// names the coin leaf before it in the block, or none.
type treeOps struct {
	coin, data           []string
	untaggedCoin         bool // one more coin leaf without a tag
	coinMarks, dataMarks []string
}

func (o treeOps) apply(h *types.Header, st *state.StateDB) error {
	n := h.Number.Uint64()
	appended := ghosttree.NoGlobalPosition
	for _, name := range o.coin {
		res, err := ghosttree.AppendTagged(st, ghosttree.Coin, n, lookupLeaf(name), lookupTag(name))
		if err != nil {
			return err
		}
		if appended, err = ghosttree.GlobalPositionOf(res); err != nil {
			return err
		}
	}
	if o.untaggedCoin {
		if _, err := ghosttree.Append(st, ghosttree.Coin, n, lookupLeaf("untagged "+h.Coinbase.Hex())); err != nil {
			return err
		}
	}
	for _, name := range o.data {
		if _, err := ghosttree.AppendTagged(st, ghosttree.Data, n, lookupLeaf(name), lookupTag(name)); err != nil {
			return err
		}
	}
	for _, name := range o.coinMarks {
		if err := ghosttree.MarkSpent(st, ghosttree.Coin, n, lookupMarker(name), appended); err != nil {
			return err
		}
	}
	for _, name := range o.dataMarks {
		if err := ghosttree.MarkSpent(st, ghosttree.Data, n, lookupMarker(name), ghosttree.NoGlobalPosition); err != nil {
			return err
		}
	}
	return nil
}

// lookupPlan maps a coinbase and block number to the block's tree changes.
type lookupPlan map[common.Address]map[uint64]treeOps

func (p lookupPlan) engine() *lookupEngine {
	return &lookupEngine{write: func(h *types.Header, st *state.StateDB) error {
		return p[h.Coinbase][h.Number.Uint64()].apply(h, st)
	}}
}

func lookupGenesis() *genesisT.Genesis {
	g := ghost.InternalNetGenesis()
	g.Alloc = genesisT.GenesisAlloc{}
	return g
}

func lookupChain(t *testing.T, engine consensus.Engine) *core.BlockChain {
	t.Helper()
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, lookupGenesis(), nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	return chain
}

// lookupBlocks makes n blocks on the genesis, block i+1 with coinbase(i).
func lookupBlocks(engine consensus.Engine, n int, coinbase func(i int) common.Address) []*types.Block {
	_, blocks, _ := core.GenerateChainWithGenesis(lookupGenesis(), engine, n, func(i int, b *core.BlockGen) {
		b.SetCoinbase(coinbase(i))
	})
	return blocks
}

func ghostFields(h *types.Header) map[string]*common.Hash {
	return map[string]*common.Hash{
		"coinTreeRoot": h.CoinTreeRoot, "dataTreeRoot": h.DataTreeRoot, "dataMarkerRoot": h.DataMarkerRoot,
		"coinLookupRoot": h.CoinLookupRoot, "dataLookupRoot": h.DataLookupRoot, "coinMarkerRoot": h.CoinMarkerRoot, "lookupDigest": h.LookupDigest,
	}
}

// TestLookupBlockValidation imports a block that changes every list of the
// block lookup digest, once as built and once with each of the four lookup
// fields changed in one bit: the true block is accepted, each wrong one is
// rejected with an error naming its field and leaves the chain as it was.
func TestLookupBlockValidation(t *testing.T) {
	miner := common.Address{0x10}
	plan := lookupPlan{miner: {1: {
		coin:         []string{"coin a", "coin b"},
		untaggedCoin: true,
		data:         []string{"data a"},
		coinMarks:    []string{"spend a"},
		dataMarks:    []string{"reveal a"},
	}}}
	engine := plan.engine()
	blocks := lookupBlocks(engine, 1, func(int) common.Address { return miner })
	good := blocks[0]
	h := good.Header()
	if !h.HasLookupFields() {
		t.Fatal("the block has no lookup fields")
	}
	genesis := lookupChain(t, engine).Genesis().Header()
	for name, f := range ghostFields(h) {
		if g := ghostFields(genesis)[name]; f == nil || g == nil || *f == *g {
			t.Fatalf("%s %v did not change from the genesis %v", name, f, g)
		}
	}
	// The digest is that of the lists the block wrote.
	want := &ghosttree.BlockLookup{
		CoinTags:    []ghosttree.LookupTag{lookupTag("coin a"), lookupTag("coin b"), {}},
		DataTags:    []ghosttree.LookupTag{lookupTag("data a")},
		CoinMarkers: []common.Hash{lookupMarker("spend a")},
		DataMarkers: []common.Hash{lookupMarker("reveal a")},
	}
	if *h.LookupDigest != want.Digest() {
		t.Errorf("lookup digest %x, want %x", *h.LookupDigest, want.Digest())
	}

	for _, c := range []struct {
		field string
		get   func(h *types.Header) *common.Hash
	}{
		{"coinLookupRoot", func(h *types.Header) *common.Hash { return h.CoinLookupRoot }},
		{"dataLookupRoot", func(h *types.Header) *common.Hash { return h.DataLookupRoot }},
		{"coinMarkerRoot", func(h *types.Header) *common.Hash { return h.CoinMarkerRoot }},
		{"lookupDigest", func(h *types.Header) *common.Hash { return h.LookupDigest }},
	} {
		for _, bit := range []int{0, 255} {
			bad := types.CopyHeader(h)
			c.get(bad)[bit/8] ^= 1 << (7 - bit%8)
			block := types.NewBlockWithHeader(bad).WithBody(good.Transactions(), nil)
			chain := lookupChain(t, engine)
			_, err := chain.InsertChain(types.Blocks{block})
			if err == nil || !strings.Contains(err.Error(), "invalid "+c.field) {
				t.Errorf("%s, bit %d: InsertChain error %v, want one naming %s", c.field, bit, err, c.field)
			}
			if chain.CurrentBlock().Number.Sign() != 0 || chain.HasBlock(block.Hash(), 1) {
				t.Errorf("%s, bit %d: the block was stored", c.field, bit)
			}
		}
	}
	// The digest of another block's lists is wrong too: here the block's
	// lists without its untagged leaf.
	other := *want
	other.CoinTags = other.CoinTags[:2]
	bad := types.CopyHeader(h)
	d := other.Digest()
	bad.LookupDigest = &d
	if _, err := lookupChain(t, engine).InsertChain(types.Blocks{types.NewBlockWithHeader(bad).WithBody(good.Transactions(), nil)}); err == nil || !strings.Contains(err.Error(), "invalid lookupDigest") {
		t.Errorf("digest without the untagged leaf: %v", err)
	}

	// The true block is accepted.
	chain := lookupChain(t, engine)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("the true block: %v", err)
	}
	if chain.CurrentBlock().Hash() != good.Hash() {
		t.Fatal("the true block is not the head")
	}
}

// lookupSnapshot is what a node holds of the trees and of the lookup
// fields at its head.
func lookupSnapshot(t *testing.T, chain *core.BlockChain) map[string]common.Hash {
	t.Helper()
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	head := chain.CurrentBlock()
	fields, err := ghosttree.ReadHeaderFields(st, head.Number.Uint64())
	if err != nil {
		t.Fatal(err)
	}
	snap := map[string]common.Hash{
		"head":                      head.Hash(),
		"state coinLookupRoot":      fields.CoinLookupRoot,
		"state dataLookupRoot":      fields.DataLookupRoot,
		"state coinMarkerRoot":      fields.CoinMarkerRoot,
		"state lookupDigest":        fields.LookupDigest,
		"coin marker set count":     common.BigToHash(new(big.Int).SetUint64(ghosttree.CoinMarkerSetCount(st))),
		"data marker set count":     common.BigToHash(new(big.Int).SetUint64(ghosttree.MarkerSetCount(st))),
		"state root":                st.IntermediateRoot(true),
		"coin tree account storage": accountStorage(t, st, ghost.CoinTreeAccount),
		"coin marker storage":       accountStorage(t, st, ghost.CoinMarkerAccount),
		"data tree account storage": accountStorage(t, st, ghost.DataTreeAccount),
		"data marker storage":       accountStorage(t, st, ghost.DataMarkerAccount),
	}
	for name, f := range ghostFields(head) {
		if f == nil {
			t.Fatalf("head without %s", name)
		}
		snap["header "+name] = *f
	}
	return snap
}

// accountStorage is the storage root of an account, which covers every slot
// of the trees it holds.
func accountStorage(t *testing.T, st *state.StateDB, addr common.Address) common.Hash {
	t.Helper()
	return st.GetStorageRoot(addr)
}

// TestLookupReorg builds a trunk and two branches that change the lookup
// indices and both marker sets differently, branch A with a coin spend and
// a data spend that branch B never makes, and reorganises a node from A to
// the longer B. The node then holds the trees, lookup roots, marker sets
// and header fields of a node that only ever saw B; the spends of A alone
// are absent again, provably against B's roots, and can be made on B.
func TestLookupReorg(t *testing.T) {
	trunk, sideA, sideB := common.Address{0x70}, common.Address{0xa0}, common.Address{0xb0}
	plan := lookupPlan{
		trunk: {1: {coin: []string{"trunk coin"}, data: []string{"trunk data"}, coinMarks: []string{"trunk spend"}, dataMarks: []string{"trunk reveal"}}},
		sideA: {
			2: {coin: []string{"a coin 1", "a coin 2"}, untaggedCoin: true, data: []string{"a data"}, coinMarks: []string{"only a"}, dataMarks: []string{"only a reveal"}},
			3: {coin: []string{"a coin 3"}, coinMarks: []string{"only a later"}},
		},
		sideB: {
			3: {coin: []string{"b coin"}, coinMarks: []string{"b spend"}},
			4: {data: []string{"b data"}, dataMarks: []string{"b reveal"}},
		},
	}
	engine := plan.engine()
	branch := func(n int, side common.Address) []*types.Block {
		return lookupBlocks(engine, n, func(i int) common.Address {
			if i == 0 {
				return trunk
			}
			return side
		})
	}
	a, b := branch(3, sideA), branch(5, sideB)
	if a[0].Hash() != b[0].Hash() || a[1].Hash() == b[1].Hash() {
		t.Fatal("the branches do not fork after block 1")
	}
	if *a[2].Header().CoinLookupRoot == *b[2].Header().CoinLookupRoot || *a[1].Header().CoinMarkerRoot == *b[1].Header().CoinMarkerRoot {
		t.Fatal("the branches do not differ in their lookup fields")
	}

	reorged := lookupChain(t, engine)
	if _, err := reorged.InsertChain(a); err != nil {
		t.Fatal(err)
	}
	st, err := reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"only a", "only a later"} {
		if !ghosttree.IsSpent(st, ghosttree.Coin, lookupMarker(m)) {
			t.Fatalf("branch A did not spend %s", m)
		}
	}
	if !ghosttree.IsSpent(st, ghosttree.Data, lookupMarker("only a reveal")) {
		t.Fatal("branch A did not spend its data marker")
	}
	onA := lookupSnapshot(t, reorged)

	if _, err := reorged.InsertChain(b); err != nil {
		t.Fatal(err)
	}
	if reorged.CurrentBlock().Hash() != b[len(b)-1].Hash() {
		t.Fatal("the node did not reorganise to branch B")
	}
	onlyB := lookupChain(t, engine)
	if _, err := onlyB.InsertChain(b); err != nil {
		t.Fatal(err)
	}
	after, want := lookupSnapshot(t, reorged), lookupSnapshot(t, onlyB)
	for k, v := range want {
		if after[k] != v {
			t.Errorf("%s: %x after the reorganisation, %x on the node that saw only B", k, after[k], v)
		}
	}
	if after["state coinLookupRoot"] == onA["state coinLookupRoot"] || after["state coinMarkerRoot"] == onA["state coinMarkerRoot"] {
		t.Error("the trees did not change with the reorganisation")
	}
	// The state's trees give the head's header fields.
	for _, k := range []string{"coinLookupRoot", "dataLookupRoot", "coinMarkerRoot", "lookupDigest"} {
		if after["state "+k] != after["header "+k] {
			t.Errorf("%s: state %x, head header %x", k, after["state "+k], after["header "+k])
		}
	}
	// Every block of B carries the same fields on both nodes.
	for _, blk := range b {
		got, exp := reorged.GetHeaderByNumber(blk.NumberU64()), onlyB.GetHeaderByNumber(blk.NumberU64())
		for name, f := range ghostFields(exp) {
			if g := ghostFields(got)[name]; g == nil || *g != *f {
				t.Errorf("block %d %s: %v, want %x", blk.NumberU64(), name, g, *f)
			}
		}
	}

	// The spends of A alone are absent again, provably against B's roots.
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	head := reorged.CurrentBlock()
	for _, m := range []string{"only a", "only a later"} {
		if ghosttree.IsSpent(st, ghosttree.Coin, lookupMarker(m)) {
			t.Errorf("%s survived the reorganisation", m)
		}
		w, err := ghosttree.CoinMarkerAbsenceWitness(st, lookupMarker(m))
		if err != nil || !ghosttree.VerifyCoinMarkerAbsence(*head.CoinMarkerRoot, lookupMarker(m), w) {
			t.Errorf("absence of %s against the head's coin marker root (%v)", m, err)
		}
	}
	if ghosttree.IsSpent(st, ghosttree.Data, lookupMarker("only a reveal")) {
		t.Error("the data spend of A survived the reorganisation")
	}
	for _, m := range []string{"trunk spend", "b spend"} {
		if !ghosttree.IsSpent(st, ghosttree.Coin, lookupMarker(m)) {
			t.Errorf("%s is not spent on B", m)
		}
	}
	// A's tags are gone from the coin index, B's and the trunk's are there.
	for _, name := range []string{"a coin 1", "a coin 2", "a coin 3"} {
		w, err := ghosttree.LookupLowWitness(st, ghosttree.Coin, lookupTag(name))
		if err != nil || !ghosttree.VerifyLookupAbsence(ghosttree.Coin, *head.CoinLookupRoot, lookupTag(name), w) {
			t.Errorf("%s is not absent from the coin lookup index (%v)", name, err)
		}
	}
	for g, name := range []string{"trunk coin", "b coin"} {
		w, err := ghosttree.LookupMembershipWitness(st, ghosttree.Coin, uint64(g))
		if err != nil || !ghosttree.VerifyLookupMembership(ghosttree.Coin, *head.CoinLookupRoot, lookupTag(name), uint64(g), w) {
			t.Errorf("%s is not at %d in the coin lookup index (%v)", name, g, err)
		}
	}
	if w, err := ghosttree.LookupLowWitness(st, ghosttree.Data, lookupTag("a data")); err != nil || !ghosttree.VerifyLookupAbsence(ghosttree.Data, *head.DataLookupRoot, lookupTag("a data"), w) {
		t.Errorf("a data is not absent from the data lookup index (%v)", err)
	}

	// A spend made only on A can be made on B after the reorganisation.
	plan[sideB][6] = treeOps{coinMarks: []string{"only a"}}
	next := lookupBlocks(engine, 6, func(i int) common.Address {
		if i == 0 {
			return trunk
		}
		return sideB
	})
	if _, err := reorged.InsertChain(next[5:]); err != nil {
		t.Fatalf("spending %s on B: %v", "only a", err)
	}
	if st, err = reorged.State(); err != nil || !ghosttree.IsSpent(st, ghosttree.Coin, lookupMarker("only a")) {
		t.Errorf("the marker of A is not spent on B (%v)", err)
	}
}
