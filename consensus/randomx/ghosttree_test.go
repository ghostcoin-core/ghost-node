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
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rlp"
)

// treeWriter is the RandomX engine with a hook that writes tree state and
// markers while a block is finalised, both when it is built and when it is
// imported, so that test blocks carry tree changes a real chain re-executes.
// Nothing else writes the trees until the commit and reveal transactions.
type treeWriter struct {
	*RandomX
	write func(header *types.Header, st *state.StateDB)
}

func (e *treeWriter) Finalize(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	e.write(header, st)
	e.RandomX.Finalize(chain, header, st, txs, uncles, withdrawals)
}

func (e *treeWriter) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	e.write(header, st)
	return e.RandomX.FinalizeAndAssemble(chain, header, st, txs, uncles, receipts, withdrawals)
}

func testTreeLeaf(i int) common.Hash { return ghosttree.K("ghost/test-leaf", []byte{byte(i >> 8), byte(i)}) }

func testTreeMarker(i int) common.Hash { return ghosttree.K("ghost/test-marker", []byte{byte(i)}) }

// emptyPath is the sibling path of position 0 in a tree with one leaf: the
// empty subtrees, worked out here from the hash rule alone.
func emptyPath(kind ghosttree.Kind) [32]common.Hash {
	tag := ghosttree.TagCoinNode
	if kind == ghosttree.Data {
		tag = ghosttree.TagDataNode
	}
	var path [32]common.Hash
	z := ghosttree.EmptyLeaf
	for l := 0; l < 32; l++ {
		path[l] = z
		z = ghosttree.K(tag, []byte{byte(l)}, z[:], z[:])
	}
	return path
}

// mineOn seals a block on the chain's head with engine, which may wrap
// sealer, and inserts it when insert is set.
func mineOn(t *testing.T, engine consensus.Engine, sealer *RandomX, chain *core.BlockChain, coinbase common.Address, change func(*types.Header), insert bool) *types.Block {
	t.Helper()
	block, err := sealNextWith(engine, sealer, chain, chain.CurrentBlock(), coinbase, change)
	if err != nil {
		t.Fatal(err)
	}
	if insert {
		if _, err := chain.InsertChain(types.Blocks{block}); err != nil {
			t.Fatalf("block %d not inserted: %v", block.NumberU64(), err)
		}
	}
	return block
}

func flipBit(h *common.Hash, bit int) {
	h[bit/8] ^= 1 << (bit % 8)
}

// TestWrongTreeStateInHeaderIsRejected seals blocks whose coin or data tree
// root differs from the executed one by one bit, and one whose coin root
// leaves out a leaf the block appended: each is rejected and nothing of it
// is imported (TH-5).
func TestWrongTreeStateInHeaderIsRejected(t *testing.T) {
	f := sealedChain(t)
	appender := common.Address{0xc0}
	engine := &treeWriter{RandomX: f.engine, write: func(h *types.Header, st *state.StateDB) {
		if h.Coinbase == appender {
			if _, err := ghosttree.Append(st, ghosttree.Coin, h.Number.Uint64(), testTreeLeaf(1)); err != nil {
				t.Errorf("append: %v", err)
			}
		}
	}}
	chain, err := newTestBlockChain(engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if _, err := chain.InsertChain(f.blocks); err != nil {
		t.Fatal(err)
	}
	head := chain.CurrentBlock().Hash()

	for _, c := range []struct {
		name     string
		field    string
		coinbase common.Address
		change   func(h *types.Header)
	}{
		{"coin root, lowest bit", "coinTreeRoot", common.Address{0xc1}, func(h *types.Header) { flipBit(h.CoinTreeRoot, 0) }},
		{"coin root, highest bit", "coinTreeRoot", common.Address{0xc2}, func(h *types.Header) { flipBit(h.CoinTreeRoot, 255) }},
		{"data root, one bit", "dataTreeRoot", common.Address{0xc3}, func(h *types.Header) { flipBit(h.DataTreeRoot, 77) }},
		{"coin root of the parent after an append", "coinTreeRoot", appender, func(h *types.Header) {
			empty := ghosttree.EmptyRoot(ghosttree.Coin)
			h.CoinTreeRoot = &empty
		}},
	} {
		bad := mineOn(t, engine, f.engine, chain, c.coinbase, c.change, false)
		if err := f.engine.VerifyHeader(chain, bad.Header(), true); err != nil {
			t.Fatalf("%s: the header itself is rejected (%v); the test needs a sealed header", c.name, err)
		}
		_, err := chain.InsertChain(types.Blocks{bad})
		if err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: InsertChain error %v, want one naming %s", c.name, err, c.field)
		}
		if chain.CurrentBlock().Hash() != head {
			t.Errorf("%s: the head moved", c.name)
		}
		if chain.HasBlock(bad.Hash(), bad.NumberU64()) || chain.HasState(bad.Root()) {
			t.Errorf("%s: the block or its state was stored", c.name)
		}
	}
	// The same blocks with their true roots are accepted.
	good := mineOn(t, engine, f.engine, chain, appender, nil, true)
	if *good.Header().CoinTreeRoot == ghosttree.EmptyRoot(ghosttree.Coin) {
		t.Error("the append left the coin root empty")
	}
}

// TestTreeRootsAreSealed changes one bit of either root of a sealed header:
// the seal hash changes and the seal check fails (TH-6).
func TestTreeRootsAreSealed(t *testing.T) {
	f := sealedChain(t)
	for _, height := range []uint64{12, 16} {
		good := f.blocks[height-1].Header()
		if err := f.engine.verifySeal(good, f.key(height)); err != nil {
			t.Fatalf("block %d: %v", height, err)
		}
		for _, field := range []string{"CoinTreeRoot", "DataTreeRoot"} {
			// A changed seal hash gives a random RandomX hash, which meets
			// difficulty 16 one time in 16; several bits make a miss of every
			// one vanishingly unlikely.
			failed := 0
			for _, bit := range []int{0, 1, 63, 100, 128, 200, 254, 255} {
				h := types.CopyHeader(good)
				root := h.CoinTreeRoot
				if field == "DataTreeRoot" {
					root = h.DataTreeRoot
				}
				flipBit(root, bit)
				if f.engine.SealHash(h) == f.engine.SealHash(good) {
					t.Errorf("block %d: bit %d of %s is not in the seal hash", height, bit, field)
				}
				if err := f.engine.verifySeal(h, f.key(height)); errors.Is(err, errInvalidPoW) {
					failed++
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if failed < 4 {
				t.Errorf("block %d: only %d of 8 one-bit changes of %s fail the seal check", height, failed, field)
			}
		}
	}
}

// vectorItems splits a header vector into its items.
func vectorItems(t *testing.T, b []byte) [][]byte {
	t.Helper()
	content, _, err := rlp.SplitList(b)
	if err != nil {
		t.Fatal(err)
	}
	var items [][]byte
	for len(content) > 0 {
		_, item, rest, err := rlp.Split(content)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
		content = rest
	}
	return items
}

// headerForbiddenField is the vector header-forbidden-field of spec 05,
// section 11: block one with a withdrawals root after the base fee. Its logs
// bloom of 256 zero bytes is written with strings.Repeat.
var headerForbiddenField = "f90264a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333" +
	"b90100" + strings.Repeat("00", types.BloomByteLength) +
	"8401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a"

// TestMissingTreeRootsRejected checks that a header without either root, and
// one carrying the forbidden field of the header-forbidden-field vector,
// fail VerifyHeader.
func TestMissingTreeRootsRejected(t *testing.T) {
	f := sealedChain(t)
	const height = 16
	good := f.blocks[height-1].Header()
	reader := newTestReader(testConfig(), f.genesis.Header(), f.headers()[:height-1]...)
	if err := f.engine.VerifyHeader(reader, good, true); err != nil {
		t.Fatalf("sealed header rejected: %v", err)
	}
	for name, change := range map[string]func(h *types.Header){
		"no coin root": func(h *types.Header) { h.CoinTreeRoot = nil },
		"no data root": func(h *types.Header) { h.DataTreeRoot = nil },
		"no roots":     func(h *types.Header) { h.CoinTreeRoot, h.DataTreeRoot = nil, nil },
	} {
		h := types.CopyHeader(good)
		change(h)
		if err := f.engine.VerifyHeader(reader, h, true); !errors.Is(err, errMissingTreeRoot) {
			t.Errorf("%s: error %v, want %v", name, err, errMissingTreeRoot)
		}
		if err := f.engine.VerifyHeader(reader, h, false); !errors.Is(err, errMissingTreeRoot) {
			t.Errorf("%s, without the seal check: error %v, want %v", name, err, errMissingTreeRoot)
		}
	}

	vector, err := hexutil.Decode("0x" + headerForbiddenField)
	if err != nil {
		t.Fatal(err)
	}
	if err := rlp.DecodeBytes(vector, new(types.Header)); err == nil {
		t.Error("the ordinary decoder accepts the vector")
	}
	var reject *types.GhostHeaderError
	if _, err := types.DecodeGhostHeader(vector); !errors.As(err, &reject) || reject.Reason != types.GhostReasonItemCount {
		t.Errorf("strict decoder: %v, want %s", err, types.GhostReasonItemCount)
	}
	items := vectorItems(t, vector)
	if len(items) != 19 {
		t.Fatalf("vector has %d items", len(items))
	}
	withdrawals := common.BytesToHash(items[16])
	coin, data := common.BytesToHash(items[17]), common.BytesToHash(items[18])

	// The vector's own fields, read item by item.
	decoded := &types.Header{
		ParentHash:      common.BytesToHash(items[0]),
		UncleHash:       common.BytesToHash(items[1]),
		Coinbase:        common.BytesToAddress(items[2]),
		Root:            common.BytesToHash(items[3]),
		TxHash:          common.BytesToHash(items[4]),
		ReceiptHash:     common.BytesToHash(items[5]),
		Bloom:           types.BytesToBloom(items[6]),
		Difficulty:      new(big.Int).SetBytes(items[7]),
		Number:          new(big.Int).SetBytes(items[8]),
		GasLimit:        new(big.Int).SetBytes(items[9]).Uint64(),
		GasUsed:         new(big.Int).SetBytes(items[10]).Uint64(),
		Time:            new(big.Int).SetBytes(items[11]).Uint64(),
		Extra:           items[12],
		MixDigest:       common.BytesToHash(items[13]),
		Nonce:           types.BlockNonce(items[14]),
		BaseFee:         new(big.Int).SetBytes(items[15]),
		WithdrawalsHash: &withdrawals,
		CoinTreeRoot:    &coin,
		DataTreeRoot:    &data,
	}
	if err := f.engine.VerifyHeader(reader, decoded, true); err == nil {
		t.Error("the vector's header is accepted")
	}
	// Its forbidden field on a sealed header of the chain.
	h := types.CopyHeader(good)
	h.WithdrawalsHash = &withdrawals
	if err := f.engine.VerifyHeader(reader, h, true); !errors.Is(err, errUnsupportedField) {
		t.Errorf("forbidden field: error %v, want %v", err, errUnsupportedField)
	}
	if _, err := rlp.EncodeToBytes(h); err == nil {
		t.Error("a header with roots and a withdrawals root encodes")
	}

	// Only a chain without EIP-1559 goes without roots, and it may not have
	// them.
	if err := checkTreeRootFields(false, good); !errors.Is(err, errUnsupportedField) {
		t.Errorf("roots before EIP-1559: error %v, want %v", err, errUnsupportedField)
	}
	rootless := types.CopyHeader(good)
	rootless.CoinTreeRoot, rootless.DataTreeRoot, rootless.BaseFee = nil, nil, nil
	if err := checkTreeRootFields(false, rootless); err != nil {
		t.Errorf("no roots before EIP-1559: %v", err)
	}
}

// TestFinalizeAndAssembleSetsTreeRoots checks that the assembled header
// carries the roots of the final state, after the block reward and before
// the state root, and that a membership path verifies against it.
func TestFinalizeAndAssembleSetsTreeRoots(t *testing.T) {
	f := sealedChain(t)
	chain, err := newTestBlockChain(f.engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	parent := chain.CurrentBlock()
	newHeader := func() *types.Header {
		h := &types.Header{
			ParentHash: parent.Hash(),
			Number:     big.NewInt(1),
			GasLimit:   parent.GasLimit,
			Time:       parent.Time + testBlockTime,
			Coinbase:   common.Address{0xee},
			BaseFee:    eip1559.CalcBaseFee(chain.Config(), parent),
		}
		if err := f.engine.Prepare(chain, h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	newState := func() *state.StateDB {
		st, err := chain.StateAt(parent.Root)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Nothing appended: the empty roots.
	block, err := f.engine.FinalizeAndAssemble(chain, newHeader(), newState(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := block.Header()
	if h.CoinTreeRoot == nil || *h.CoinTreeRoot != ghosttree.EmptyRoot(ghosttree.Coin) || h.DataTreeRoot == nil || *h.DataTreeRoot != ghosttree.EmptyRoot(ghosttree.Data) {
		t.Errorf("empty block roots %v %v", h.CoinTreeRoot, h.DataTreeRoot)
	}

	// One leaf of each kind.
	st := newState()
	coinLeaf, dataLeaf := testTreeLeaf(1), testTreeLeaf(2)
	if _, err := ghosttree.Append(st, ghosttree.Coin, 1, coinLeaf); err != nil {
		t.Fatal(err)
	}
	if _, err := ghosttree.Append(st, ghosttree.Data, 1, dataLeaf); err != nil {
		t.Fatal(err)
	}
	block, err = f.engine.FinalizeAndAssemble(chain, newHeader(), st, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h = block.Header()
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		want, err := ghosttree.Root(st, kind)
		if err != nil {
			t.Fatal(err)
		}
		if got := ghosttree.HeaderRoot(h, kind); got == nil || *got != want || want == ghosttree.EmptyRoot(kind) {
			t.Errorf("%v root %v, want %x", kind, got, want)
		}
	}
	if !ghosttree.VerifyMembership(h, ghosttree.Coin, 0, coinLeaf, emptyPath(ghosttree.Coin)) {
		t.Error("the coin leaf does not verify against the assembled header")
	}
	if !ghosttree.VerifyMembership(h, ghosttree.Data, 0, dataLeaf, emptyPath(ghosttree.Data)) {
		t.Error("the data leaf does not verify against the assembled header")
	}
	if root := st.IntermediateRoot(true); h.Root != root {
		t.Errorf("state root %x, want %x", h.Root, root)
	}
	if !st.GetBalance(h.Coinbase).Eq(testParams().BlockReward(1)) {
		t.Error("the block reward was not paid")
	}
	if err := f.engine.VerifyHeader(chain, h, false); err != nil {
		t.Errorf("assembled header rejected: %v", err)
	}

	// Without a base fee the header could not be encoded; corrupt tree state
	// gives no root.
	noFee := newHeader()
	noFee.BaseFee = nil
	if _, err := f.engine.FinalizeAndAssemble(chain, noFee, newState(), nil, nil, nil, nil); !errors.Is(err, errMissingBaseFee) {
		t.Errorf("no base fee: %v, want %v", err, errMissingBaseFee)
	}
	corrupt := newState()
	corrupt.SetState(ghost.CoinTreeAccount, ghosttree.Slot(ghosttree.SlotLeafCount), common.Hash{31: 1})
	if _, err := f.engine.FinalizeAndAssemble(chain, newHeader(), corrupt, nil, nil, nil, nil); !errors.Is(err, ghosttree.ErrCorruptTreeState) {
		t.Errorf("corrupt tree state: %v, want %v", err, ghosttree.ErrCorruptTreeState)
	}

	// A chain without EIP-1559, as developer mode is, has no base fee and so
	// no Ghost layout: its blocks carry no roots.
	preLondon := testConfig()
	preLondon.SetEIP1559Transition(nil)
	reader := newTestReader(preLondon, parent)
	plain := newHeader()
	plain.BaseFee = nil
	block, err = f.engine.FinalizeAndAssemble(reader, plain, newState(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h := block.Header(); h.CoinTreeRoot != nil || h.DataTreeRoot != nil {
		t.Error("a block without a base fee has tree roots")
	}
}

// TestGenesisCarriesEmptyTreeRoots checks the internal network's and
// developer mode's genesis headers: the empty roots, the base fee, the Ghost
// layout, and for the internal network the empty state root; and that a
// RandomX chain starts from the internal network's genesis.
func TestGenesisCarriesEmptyTreeRoots(t *testing.T) {
	var (
		coin = common.HexToHash("8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8")
		data = common.HexToHash("3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03")
	)
	for name, g := range map[string]*genesisT.Genesis{
		"internal network": ghost.InternalNetGenesis(),
		"developer mode":   params.DeveloperGenesisBlock(11_500_000, nil),
	} {
		h := core.GenesisToBlock(g, nil).Header()
		if h.CoinTreeRoot == nil || *h.CoinTreeRoot != coin {
			t.Errorf("%s: coin root %v, want %x", name, h.CoinTreeRoot, coin)
		}
		if h.DataTreeRoot == nil || *h.DataTreeRoot != data {
			t.Errorf("%s: data root %v, want %x", name, h.DataTreeRoot, data)
		}
		if h.BaseFee == nil {
			t.Errorf("%s: no base fee", name)
		}
		enc, err := rlp.EncodeToBytes(h)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := types.DecodeGhostHeader(enc); err != nil {
			t.Errorf("%s: genesis header is not in the Ghost layout: %v", name, err)
		}
	}
	internal := core.GenesisToBlock(ghost.InternalNetGenesis(), nil)
	if internal.Root() != types.EmptyRootHash {
		t.Errorf("internal network state root %x, want the empty root", internal.Root())
	}
	// Other chains keep their genesis.
	otherID := ghost.InternalNetGenesis()
	if err := otherID.Config.SetChainID(big.NewInt(61)); err != nil {
		t.Fatal(err)
	}
	for name, g := range map[string]*genesisT.Genesis{
		"go-ethereum configuration with chain ID 1337": testGenesis(),
		"another chain ID":                             otherID,
	} {
		if h := core.GenesisToBlock(g, nil).Header(); h.CoinTreeRoot != nil || h.DataTreeRoot != nil {
			t.Errorf("%s: genesis has tree roots", name)
		}
	}

	// Two blocks on the internal network's genesis, with its parameters.
	engine, err := New(Config{Params: ghost.InternalNetParams()})
	if err != nil {
		t.Fatal(err)
	}
	engine.SetThreads(1)
	chain, err := newTestBlockChain(engine, ghost.InternalNetGenesis())
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if *chain.Genesis().Header().CoinTreeRoot != coin {
		t.Fatal("the stored genesis lost its roots")
	}
	for i := 0; i < 2; i++ {
		parent := chain.CurrentBlock()
		header := &types.Header{
			ParentHash: parent.Hash(),
			Number:     new(big.Int).Add(parent.Number, common.Big1),
			GasLimit:   parent.GasLimit,
			Time:       parent.Time + 1,
			Coinbase:   common.Address{0x01},
		}
		header.BaseFee = eip1559.CalcBaseFee(chain.Config(), parent)
		if err := engine.Prepare(chain, header); err != nil {
			t.Fatal(err)
		}
		st, err := chain.StateAt(parent.Root)
		if err != nil {
			t.Fatal(err)
		}
		block, err := engine.FinalizeAndAssemble(chain, header, st, nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		results, stop := make(chan *types.Block, 1), make(chan struct{})
		if err := engine.Seal(chain, block, results, stop); err != nil {
			t.Fatal(err)
		}
		sealed := <-results
		close(stop)
		if _, err := chain.InsertChain(types.Blocks{sealed}); err != nil {
			t.Fatalf("block %d on the internal network: %v", i+1, err)
		}
		if *sealed.Header().CoinTreeRoot != coin || *sealed.Header().DataTreeRoot != data {
			t.Errorf("block %d changed the empty roots", i+1)
		}
	}
}

// treeSnapshot reads every slot of the tree accounts, the given marker slots
// of both marker accounts, and the accounts' nonces.
func treeSnapshot(t *testing.T, chain *core.BlockChain, root common.Hash, markers []common.Hash) map[string]common.Hash {
	t.Helper()
	st, err := chain.StateAt(root)
	if err != nil {
		t.Fatal(err)
	}
	snap := make(map[string]common.Hash)
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		for i := uint64(0); i < ghosttree.SlotFrontier+ghosttree.MaxDepth; i++ {
			snap[fmt.Sprintf("%v tree slot %d", kind, i)] = st.GetState(ghosttree.TreeAccount(kind), ghosttree.Slot(i))
		}
		for _, m := range markers {
			snap[fmt.Sprintf("%v marker %x", kind, m)] = st.GetState(ghosttree.MarkerAccount(kind), m)
		}
		r, err := ghosttree.Root(st, kind)
		if err != nil {
			t.Fatal(err)
		}
		snap[fmt.Sprintf("%v root", kind)] = r
		snap[fmt.Sprintf("%v tree nonce", kind)] = common.BigToHash(new(big.Int).SetUint64(st.GetNonce(ghosttree.TreeAccount(kind))))
		snap[fmt.Sprintf("%v marker nonce", kind)] = common.BigToHash(new(big.Int).SetUint64(st.GetNonce(ghosttree.MarkerAccount(kind))))
	}
	return snap
}

func diffSnapshots(a, b map[string]common.Hash) []string {
	var diffs []string
	for k, v := range a {
		if b[k] != v {
			diffs = append(diffs, fmt.Sprintf("%s: %x vs %x", k, v, b[k]))
		}
	}
	return diffs
}

// TestTreeStateAndMarkersAfterForcedReorg builds a common trunk whose first
// block prefills a full coin tree and touches the data tree and a marker,
// a branch A with appends to both trees, the rollover of the full coin tree
// and markers of both kinds, and a heavier branch B with none of them. A
// node that followed A and then reorganised to B must hold exactly the tree
// state, markers and roots of a node that only ever saw B (TH-15).
func TestTreeStateAndMarkersAfterForcedReorg(t *testing.T) {
	f := sealedChain(t)
	var (
		trunk   = common.Address{0x70}
		sideA   = common.Address{0xa0}
		sideB   = common.Address{0xb0}
		markers = []common.Hash{testTreeMarker(0), testTreeMarker(1), testTreeMarker(2), testTreeMarker(3)}
		full    = uint64(1) << 32
	)
	appendLeaf := func(st *state.StateDB, kind ghosttree.Kind, height uint64, i int) {
		if _, err := ghosttree.Append(st, kind, height, testTreeLeaf(i)); err != nil {
			t.Errorf("block %d: %v append %d: %v", height, kind, i, err)
		}
	}
	mark := func(st *state.StateDB, kind ghosttree.Kind, m common.Hash) {
		if err := ghosttree.MarkSpent(st, kind, m); err != nil {
			t.Errorf("%v marker %x: %v", kind, m, err)
		}
	}
	engine := &treeWriter{RandomX: f.engine, write: func(h *types.Header, st *state.StateDB) {
		n := h.Number.Uint64()
		switch {
		case h.Coinbase == trunk && n == 1:
			// A full coin tree at index 0, filled in this block, with
			// arbitrary frontier values and final root (TH-3).
			addr := ghosttree.TreeAccount(ghosttree.Coin)
			st.SetNonce(addr, 1)
			st.SetState(addr, ghosttree.Slot(ghosttree.SlotLeafCount), common.BigToHash(new(big.Int).SetUint64(full)))
			st.SetState(addr, ghosttree.Slot(ghosttree.SlotLastFilled), common.BigToHash(big.NewInt(1)))
			st.SetState(addr, ghosttree.Slot(ghosttree.SlotFinalRoot), ghosttree.K("ghost/test-final-root"))
			for l := uint64(0); l < ghosttree.MaxDepth; l++ {
				st.SetState(addr, ghosttree.Slot(ghosttree.SlotFrontier+l), ghosttree.K("ghost/test-frontier", []byte{byte(l)}))
			}
			appendLeaf(st, ghosttree.Data, n, 100)
			mark(st, ghosttree.Coin, markers[0])
		case h.Coinbase == sideA && n == 3:
			appendLeaf(st, ghosttree.Coin, n, 1) // rolls over to tree 1
			appendLeaf(st, ghosttree.Coin, n, 2)
			appendLeaf(st, ghosttree.Data, n, 101)
			appendLeaf(st, ghosttree.Data, n, 102)
			mark(st, ghosttree.Coin, markers[1])
			mark(st, ghosttree.Data, markers[2])
		case h.Coinbase == sideA && n == 4:
			appendLeaf(st, ghosttree.Coin, n, 3)
			appendLeaf(st, ghosttree.Data, n, 103)
			mark(st, ghosttree.Data, markers[3])
			mark(st, ghosttree.Data, markers[0]) // a coin marker value, in the data set
		}
	}}

	reorged, err := newTestBlockChain(engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer reorged.Stop()
	onlyB, err := newTestBlockChain(engine, f.gspec)
	if err != nil {
		t.Fatal(err)
	}
	defer onlyB.Stop()

	// The trunk, built on the B-only node and imported by the other.
	trunkBlocks := types.Blocks{
		mineOn(t, engine, f.engine, onlyB, trunk, nil, true),
		mineOn(t, engine, f.engine, onlyB, trunk, nil, true),
	}
	if _, err := reorged.InsertChain(trunkBlocks); err != nil {
		t.Fatal(err)
	}
	ancestor := trunkBlocks[1]
	atAncestor := treeSnapshot(t, reorged, ancestor.Root(), markers)

	// Branch A on one node, the heavier branch B on the other.
	branchA := types.Blocks{
		mineOn(t, engine, f.engine, reorged, sideA, nil, true),
		mineOn(t, engine, f.engine, reorged, sideA, nil, true),
	}
	var branchB types.Blocks
	for i := 0; i < 3; i++ {
		branchB = append(branchB, mineOn(t, engine, f.engine, onlyB, sideB, nil, true))
	}

	// Branch A did change everything the reorganisation must undo.
	headA := reorged.CurrentBlock()
	if headA.Hash() != branchA[1].Hash() {
		t.Fatal("the first node does not follow branch A")
	}
	stA, err := reorged.StateAt(headA.Root)
	if err != nil {
		t.Fatal(err)
	}
	coinA := ghosttree.TreeAccount(ghosttree.Coin)
	if idx := stA.GetState(coinA, ghosttree.Slot(ghosttree.SlotTreeIndex)); idx != (common.Hash{31: 1}) {
		t.Fatalf("branch A did not roll the coin tree over: index %x", idx)
	}
	for i, m := range markers[1:] {
		kind := ghosttree.Data
		if i == 0 {
			kind = ghosttree.Coin
		}
		if !ghosttree.IsSpent(stA, kind, m) {
			t.Fatalf("branch A did not spend %v marker %d", kind, i+1)
		}
	}
	if diffs := diffSnapshots(atAncestor, treeSnapshot(t, reorged, headA.Root, markers)); len(diffs) == 0 {
		t.Fatal("branch A changed nothing")
	}
	if *headA.CoinTreeRoot == *ancestor.Header().CoinTreeRoot || *headA.DataTreeRoot == *ancestor.Header().DataTreeRoot {
		t.Fatal("branch A's head roots equal the ancestor's")
	}

	// The forced reorganisation.
	if _, err := reorged.InsertChain(branchB); err != nil {
		t.Fatalf("branch B: %v", err)
	}
	head := reorged.CurrentBlock()
	if head.Hash() != branchB[2].Hash() || onlyB.CurrentBlock().Hash() != head.Hash() {
		t.Fatalf("head is block %d %x, want branch B's head", head.Number, head.Hash())
	}
	afterReorg := treeSnapshot(t, reorged, head.Root, markers)
	for _, d := range diffSnapshots(afterReorg, treeSnapshot(t, onlyB, onlyB.CurrentBlock().Root, markers)) {
		t.Errorf("after the reorganisation, against the node that saw only B: %s", d)
	}
	for _, d := range diffSnapshots(afterReorg, atAncestor) {
		t.Errorf("after the reorganisation, against the common ancestor: %s", d)
	}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		stateRoot := afterReorg[fmt.Sprintf("%v root", kind)]
		if got := ghosttree.HeaderRoot(head, kind); got == nil || *got != stateRoot {
			t.Errorf("%v root of the head header %v, state %x", kind, got, stateRoot)
		}
		if got, want := ghosttree.HeaderRoot(head, kind), ghosttree.HeaderRoot(ancestor.Header(), kind); *got != *want {
			t.Errorf("%v root of the head header %x, ancestor %x", kind, *got, *want)
		}
	}
	st, err := reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Coin, markers[0]) {
		t.Error("the trunk's coin marker was undone")
	}
	for i, m := range markers[1:] {
		if ghosttree.IsSpent(st, ghosttree.Coin, m) || ghosttree.IsSpent(st, ghosttree.Data, m) {
			t.Errorf("marker %d of branch A is still spent", i+1)
		}
	}
	if ghosttree.IsSpent(st, ghosttree.Data, markers[0]) {
		t.Error("branch A's data marker is still spent")
	}
	if root, err := ghosttree.Root(st, ghosttree.Coin); err != nil || root != ghosttree.K("ghost/test-final-root") {
		t.Errorf("coin root after the reorganisation %x (%v), want the prefilled final root", root, err)
	}
}
