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

// Package datalifecycle holds the lifecycle, linkage and adversarial tests of
// a data commitment on the internal network: a file committed and its
// Phantom Key returned, proofs of holding, a one-time reveal, a restore from
// the digits alone, a revoke, the linkage test and the conformance cases of
// the data commitment specification (spec 04, CR-D1 to CR-D18).
//
// The network is three independent nodes, each a core.BlockChain with its
// own in-memory database and the internal network's genesis, whose blocks
// are sealed by the RandomX engine and handed from node to node with
// InsertChain. Data commits and data reveals go through the node's own
// block processing; reveals carry stub proofs (core/ghostpriv/ghostprivtest)
// and pay the window fee from the reserve their data commit burned.
//
// Everything that is not the node is a test-local stand-in: the wallet
// (wallet_test.go), the encrypted off-chain host and the endpoint that
// serves bulk chain data (host_test.go), the proof of holding with its
// verifier (holding_test.go) and the linkage checker (linkcheck_test.go).
package datalifecycle

import (
	"errors"
	"math/big"
	"strings"
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
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

const (
	// blockSpacing is the timestamp step between blocks, in seconds, above
	// the internal network's target so the difficulty stays at its minimum.
	blockSpacing = 10

	// sealTimeout bounds the search for a nonce.
	sealTimeout = 2 * time.Minute

	// networkSize is the number of nodes every test starts with.
	networkSize = 3
)

// node is one node of the internal network.
type node struct {
	t      *testing.T
	name   string
	chain  *core.BlockChain
	engine *randomx.RandomX
}

// newNode starts a node on the internal network's genesis, with its own
// in-memory database and its own RandomX engine.
func newNode(t *testing.T, name string) *node {
	t.Helper()
	engine, err := randomx.New(randomx.Config{Params: ghost.InternalNetParams()})
	if err != nil {
		t.Fatalf("node %s: RandomX engine: %v", name, err)
	}
	engine.SetThreads(1)
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, ghost.InternalNetGenesis(), nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("node %s: %v", name, err)
	}
	t.Cleanup(chain.Stop)
	if chain.Genesis().Header().DataTreeRoot == nil {
		t.Fatalf("node %s: the genesis has no data tree root", name)
	}
	return &node{t: t, name: name, chain: chain, engine: engine}
}

func (n *node) head() *types.Header { return n.chain.CurrentBlock() }

// stateAt is the state after the block of header.
func (n *node) stateAt(h *types.Header) *state.StateDB {
	n.t.Helper()
	st, err := n.chain.StateAt(h.Root)
	if err != nil {
		n.t.Fatalf("node %s: state of block %d: %v", n.name, h.Number, err)
	}
	return st
}

func (n *node) headState() *state.StateDB { return n.stateAt(n.head()) }

// insert imports blocks, which must all be accepted.
func (n *node) insert(blocks ...*types.Block) {
	n.t.Helper()
	if i, err := n.chain.InsertChain(blocks); err != nil {
		n.t.Fatalf("node %s did not import block %d: %v", n.name, blocks[i].NumberU64(), err)
	}
}

// reject imports a block on the node's head, which must refuse it for the
// reason want, leaving the head where it was.
func (n *node) reject(block *types.Block, want error) {
	n.t.Helper()
	head := n.head()
	if block.ParentHash() != head.Hash() {
		n.t.Fatalf("node %s: the rejected block is not built on the head, so it would not be executed", n.name)
	}
	_, err := n.chain.InsertChain(types.Blocks{block})
	requireErr(n.t, err, want, "node "+n.name+" importing block "+block.Number().String())
	if n.head().Hash() != head.Hash() {
		n.t.Fatalf("node %s: the head moved to the rejected block", n.name)
	}
}

// requireErr fails unless err is want, by value and by text.
func requireErr(t *testing.T, err, want error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want the error %q", what, want)
	}
	if !errors.Is(err, want) || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("%s: error %q, want %q", what, err, want)
	}
}

// blockPlan is what a node puts into a block it mines.
type blockPlan struct {
	coinbase  common.Address
	gasTarget uint64               // the gas limit to move towards; 0 keeps the parent's
	txs       []*types.Transaction // applied by the miner, which must accept each
	unchecked []*types.Transaction // carried after txs without being applied
}

// mineOn builds and seals a block on parent. The miner applies the
// transactions of the plan as block processing does and refuses any it
// cannot apply; unchecked transactions are only carried, so that a test can
// build a block the other nodes must reject.
func (n *node) mineOn(parent *types.Header, plan blockPlan) *types.Block {
	t := n.t
	t.Helper()
	config := n.chain.Config()
	header := n.nextHeader(parent, plan.coinbase)
	if plan.gasTarget != 0 {
		header.GasLimit = core.CalcGasLimit(parent.GasLimit, plan.gasTarget)
	}
	if err := n.engine.Prepare(n.chain, header); err != nil {
		t.Fatalf("node %s: prepare block %d: %v", n.name, header.Number, err)
	}
	st := n.stateAt(parent)
	gp := new(core.GasPool).AddGas(header.GasLimit)
	var receipts []*types.Receipt
	for i, tx := range plan.txs {
		st.SetTxContext(tx.Hash(), i)
		var (
			receipt *types.Receipt
			err     error
		)
		if tx.IsGhostReveal() {
			receipt, err = n.applyReveal(gp, st, header, tx)
		} else {
			receipt, err = core.ApplyTransaction(config, n.chain, &header.Coinbase, gp, st, header, tx, &header.GasUsed, vm.Config{})
		}
		if err != nil {
			t.Fatalf("node %s cannot build block %d: transaction %d: %v", n.name, header.Number, i, err)
		}
		receipts = append(receipts, receipt)
	}
	txs := append(append([]*types.Transaction{}, plan.txs...), plan.unchecked...)
	block, err := n.engine.FinalizeAndAssemble(n.chain, header, st, txs, nil, receipts, nil)
	if err != nil {
		t.Fatalf("node %s: assemble block %d: %v", n.name, header.Number, err)
	}
	return n.seal(block)
}

// mine builds a block on the node's head.
func (n *node) mine(plan blockPlan) *types.Block {
	n.t.Helper()
	return n.mineOn(n.head(), plan)
}

// nextHeader is the header of a block on parent before the engine prepares
// it.
func (n *node) nextHeader(parent *types.Header, coinbase common.Address) *types.Header {
	return &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + blockSpacing,
		Coinbase:   coinbase,
		BaseFee:    eip1559.CalcBaseFee(n.chain.Config(), parent),
	}
}

// applyReveal is the miner's side of a coin or data reveal: G_PRIV gas from
// the pool, the checks and change of the transaction's own type with the
// active verifier, and the receipt. Importing nodes run their own block
// processing over it.
func (n *node) applyReveal(gp *core.GasPool, st *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, error) {
	if err := gp.SubGas(types.GhostRevealGas); err != nil {
		return nil, err
	}
	var err error
	switch tx.Type() {
	case types.GhostDataRevealTxType:
		err = ghostpriv.ApplyDataReveal(st, n.env(header), ghostpriv.ActiveVerifier(), tx.GhostDataRevealEnvelope())
	default:
		err = ghostpriv.ApplyReveal(st, n.env(header), ghostpriv.ActiveVerifier(), tx.GhostRevealEnvelope())
	}
	if err != nil {
		return nil, err
	}
	st.Finalise(true)
	header.GasUsed += types.GhostRevealGas
	receipt := &types.Receipt{
		Type:              tx.Type(),
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

// env is the reveal environment of a block with header on this node.
func (n *node) env(header *types.Header) *ghostpriv.BlockEnv {
	return &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   n.chain,
		ChainID: n.chain.Config().GetChainID(),
		Genesis: n.chain.Genesis().Hash(),
	}
}

// revealFee is the reveal fee of the block with header on this node, split
// by the cover rule for its base fee: the fee of its window, whose first
// block is header itself or an ancestor on the node's chain.
func (n *node) revealFee(header *types.Header) ghostpriv.Fee {
	n.t.Helper()
	bRef := header.BaseFee
	if start := ghostpriv.WindowStart(header.Number.Uint64()); start != header.Number.Uint64() {
		h := header
		for h.Number.Uint64() > start {
			if h = n.chain.GetHeader(h.ParentHash, h.Number.Uint64()-1); h == nil {
				n.t.Fatalf("node %s: no ancestor at height %d", n.name, start)
			}
		}
		bRef = h.BaseFee
	}
	fee, err := ghostpriv.WindowFee(bRef)
	if err != nil {
		n.t.Fatal(err)
	}
	if fee, err = fee.Cover(header.BaseFee); err != nil {
		n.t.Fatal(err)
	}
	return fee
}

// nextRevealFee is the reveal fee of a block on the node's head.
func (n *node) nextRevealFee() *uint256.Int {
	n.t.Helper()
	return n.revealFee(n.nextHeader(n.head(), common.Address{})).Total
}

// checkNextData runs the data reveal checks for a block on the node's head
// against a copy of the head state, changing nothing.
func (n *node) checkNextData(r *ghostpriv.DataReveal) error {
	n.t.Helper()
	head := n.head()
	_, _, err := ghostpriv.CheckDataReveal(n.headState().Copy(), n.env(n.nextHeader(head, common.Address{})), ghostpriv.ActiveVerifier(), dataEnvelope(n.t, r))
	return err
}

// seal searches the block's RandomX nonce.
func (n *node) seal(block *types.Block) *types.Block {
	n.t.Helper()
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := n.engine.Seal(n.chain, block, results, stop); err != nil {
		n.t.Fatalf("node %s: seal block %d: %v", n.name, block.Number(), err)
	}
	select {
	case sealed := <-results:
		return sealed
	case <-time.After(sealTimeout):
		n.t.Fatalf("node %s: block %d not sealed in %v", n.name, block.Number(), sealTimeout)
		return nil
	}
}

// network is the internal network of a test.
type network struct {
	t     *testing.T
	nodes []*node
}

// newNetwork starts size nodes, at least three, with the stub verifier active
// for the test.
func newNetwork(t *testing.T, size int) *network {
	t.Helper()
	if size < 3 {
		t.Fatalf("a network of %d nodes, want at least 3", size)
	}
	t.Cleanup(ghostpriv.SetVerifier(ghostprivtest.Verifier{}))
	net := &network{t: t}
	for i := 0; i < size; i++ {
		net.nodes = append(net.nodes, newNode(t, string(rune('a'+i))))
	}
	for _, n := range net.nodes[1:] {
		if n.chain.Genesis().Hash() != net.nodes[0].chain.Genesis().Hash() {
			t.Fatal("the nodes do not share a genesis")
		}
	}
	return net
}

// mine has miner build a block on its head and hands it to every node.
func (net *network) mine(miner *node, plan blockPlan) *types.Block {
	net.t.Helper()
	block := miner.mine(plan)
	net.share(block)
	return block
}

// share imports blocks into every node and checks that each took the last
// block as its head; shareWith does the same for some nodes.
func (net *network) share(blocks ...*types.Block) {
	net.t.Helper()
	net.shareWith(net.nodes, blocks...)
}

func (net *network) shareWith(nodes []*node, blocks ...*types.Block) {
	net.t.Helper()
	last := blocks[len(blocks)-1]
	for _, n := range nodes {
		n.insert(blocks...)
		if n.head().Hash() != last.Hash() {
			n.t.Fatalf("node %s: head %d %x after import, want block %d %x", n.name, n.head().Number, n.head().Hash(), last.Number(), last.Hash())
		}
	}
}

// rejectAll has every node refuse a block built on the common head for the
// reason want.
func (net *network) rejectAll(block *types.Block, want error) {
	net.t.Helper()
	for _, n := range net.nodes {
		n.reject(block, want)
	}
}

// converged checks that every node has the same head, state root and tree
// roots, and that the data tree root matches the data tree in each node's
// state.
func (net *network) converged() {
	net.t.Helper()
	want := net.nodes[0].head()
	for _, n := range net.nodes {
		h := n.head()
		if h.Hash() != want.Hash() || h.Root != want.Root || *h.CoinTreeRoot != *want.CoinTreeRoot || *h.DataTreeRoot != *want.DataTreeRoot {
			net.t.Fatalf("node %s at block %d %x, node %s at block %d %x", n.name, h.Number, h.Hash(), net.nodes[0].name, want.Number, want.Hash())
		}
		root, err := ghosttree.Root(n.headState(), ghosttree.Data)
		if err != nil || root != *h.DataTreeRoot {
			net.t.Fatalf("node %s: data tree root %x in the state (%v), %x in the header", n.name, root, err, *h.DataTreeRoot)
		}
	}
}

func dataEnvelope(t *testing.T, r *ghostpriv.DataReveal) []byte {
	t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func dataRevealTx(t *testing.T, r *ghostpriv.DataReveal) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostDataRevealTx(dataEnvelope(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// address is a fresh address for a label, for miners and verifiers.
func address(label string) common.Address {
	return common.BytesToAddress(ghosttree.K("ghost/test-data-lifecycle/address", []byte(label)).Bytes()[12:])
}
