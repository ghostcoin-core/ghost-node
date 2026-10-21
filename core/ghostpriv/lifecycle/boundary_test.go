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

package lifecycle

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// requireHiddenEmpty checks on every node that nothing is left in the hidden
// set.
func (s *scenario) requireHiddenEmpty() {
	s.t.Helper()
	for _, n := range s.net.nodes {
		hidden, err := ghostpriv.Hidden(n.headState())
		if err != nil || !hidden.IsZero() {
			s.t.Fatalf("node %s: hidden set %v (%v), want empty", n.name, hidden, err)
		}
	}
}

// TestBoundaryFullReveal reveals a coin whole, out = v - fee with a zero
// remainder, after one wei more is refused by the backstop.
func TestBoundaryFullReveal(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(3, 1))
	s.commit(s.node(0), c)
	s.requireTotals(c.value, new(uint256.Int))

	miner, recipient := s.node(1), address("full recipient")
	fee := miner.feeOn(miner.head())
	over := newReveal(miner, c, s.owner.coin(1, new(uint256.Int)), *miner.head().CoinTreeRoot, recipient, add(sub(c.value, fee.Total), uint256.NewInt(1)), fee.Total)
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNext(over), ghostpriv.ErrRevealBackstop, "node "+n.name+": one wei above the coin")
	}
	block := miner.mine(blockPlan{coinbase: address("full miner"), unchecked: []*types.Transaction{revealTx(t, over)}})
	for _, n := range s.net.nodes {
		n.reject(block, ghostpriv.ErrRevealBackstop)
	}

	full := prepareReveal(t, miner, c, s.owner, 1, recipient, sub(c.value, fee.Total))
	if !full.rest.value.IsZero() {
		t.Fatalf("the full reveal leaves %v", full.rest.value)
	}
	s.reveal(miner, full, address("full miner"))
	s.net.converged()
	s.requireTotals(c.value, c.value)
	s.requireHiddenEmpty()
	for _, n := range s.net.nodes {
		if got := n.headState().GetBalance(recipient); !got.Eq(sub(c.value, fee.Total)) {
			t.Fatalf("node %s: the recipient holds %v, want %v", n.name, got, sub(c.value, fee.Total))
		}
		// The zero remainder is a leaf of the tree and the wallet's
		// current coin, of value 0.
		requireCurrent(t, n, s.owner, full.rest)
	}
}

// TestBoundaryZeroAmountClaim moves a coin to a new key with out = 0: the
// remainder is v - fee, nothing is minted and the total out grows by the fee
// alone.
func TestBoundaryZeroAmountClaim(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(2, 1))
	s.commit(s.node(0), c)

	newKey := newWallet("synthetic digits for the zero claim key")
	recipient := address("zero claim recipient")
	claim := prepareReveal(t, s.node(1), c, newKey, 0, recipient, new(uint256.Int))
	if want := sub(c.value, claim.fee.Total); !claim.rest.value.Eq(want) {
		t.Fatalf("the claim leaves %v, want %v", claim.rest.value, want)
	}
	s.reveal(s.node(1), claim, address("zero claim miner"))
	s.net.converged()
	s.requireTotals(c.value, claim.fee.Total)
	for _, n := range s.net.nodes {
		st := n.headState()
		if !st.GetBalance(recipient).IsZero() {
			t.Fatalf("node %s: the zero-amount claim minted %v", n.name, st.GetBalance(recipient))
		}
		if hidden, err := ghostpriv.Hidden(st); err != nil || !hidden.Eq(claim.rest.value) {
			t.Fatalf("node %s: hidden set %v (%v), want the claimed %v", n.name, hidden, err, claim.rest.value)
		}
		requireNothingUnspent(t, n, s.owner)
		requireCurrent(t, n, newKey, claim.rest)
	}
}

// TestBoundaryFeeUsesWholeBalance commits a coin worth exactly the window
// fee and reveals it with out = 0 and a zero remainder, after a fee one below
// the window fee and an out of one wei are refused.
func TestBoundaryFeeUsesWholeBalance(t *testing.T) {
	s := newScenario(t)
	s.net.alignBeforeWindow(address("whole filler"))
	fee := s.node(0).feeOn(s.node(0).head())
	c := s.owner.coin(0, fee.Total)
	s.commit(s.node(0), c) // the first block of the fee window

	miner, recipient := s.node(1), address("whole recipient")
	if got := miner.feeOn(miner.head()); !got.Total.Eq(fee.Total) {
		t.Fatalf("the reveal's block pays %v, the coin holds %v", got.Total, fee.Total)
	}
	root := *miner.head().CoinTreeRoot
	low := newReveal(miner, c, s.owner.coin(1, uint256.NewInt(1)), root, recipient, new(uint256.Int), sub(fee.Total, uint256.NewInt(1)))
	over := newReveal(miner, c, s.owner.coin(1, new(uint256.Int)), root, recipient, uint256.NewInt(1), fee.Total)
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNext(low), ghostpriv.ErrRevealFee, "node "+n.name+": a fee below the window fee")
		requireErr(t, n.checkNext(over), ghostpriv.ErrRevealBackstop, "node "+n.name+": one wei out beside the whole fee")
	}
	for _, r := range []struct {
		reveal *ghostpriv.Reveal
		want   error
	}{{low, ghostpriv.ErrRevealFee}, {over, ghostpriv.ErrRevealBackstop}} {
		block := miner.mine(blockPlan{coinbase: address("whole miner"), unchecked: []*types.Transaction{revealTx(t, r.reveal)}})
		for _, n := range s.net.nodes {
			n.reject(block, r.want)
		}
	}

	whole := prepareReveal(t, miner, c, s.owner, 1, recipient, new(uint256.Int))
	if !whole.rest.value.IsZero() || !whole.fee.Total.Eq(c.value) {
		t.Fatalf("the reveal leaves %v and pays %v of %v", whole.rest.value, whole.fee.Total, c.value)
	}
	s.reveal(miner, whole, address("whole miner"))
	s.net.converged()
	s.requireTotals(c.value, c.value)
	s.requireHiddenEmpty()
	for _, n := range s.net.nodes {
		if !n.headState().GetBalance(recipient).IsZero() {
			t.Fatalf("node %s: the recipient got %v", n.name, n.headState().GetBalance(recipient))
		}
		requireCurrent(t, n, s.owner, whole.rest)
	}
}

// withGasLimit is block with its gas limit set outright and sealed again,
// which may be a limit no node accepts.
func (n *node) withGasLimit(block *types.Block, gasLimit uint64) *types.Block {
	n.t.Helper()
	header := block.Header()
	header.GasLimit = gasLimit
	return n.seal(block.WithSeal(header))
}

// rejectAboveMaxGasLimit imports a block on the node's head, which must
// refuse it for a gas limit above the consensus maximum, leaving the head
// where it was.
func (n *node) rejectAboveMaxGasLimit(block *types.Block) {
	n.t.Helper()
	head := n.head()
	if block.GasLimit() <= ghost.MaxBlockGasLimit {
		n.t.Fatalf("node %s: gas limit %d is not above the consensus maximum", n.name, block.GasLimit())
	}
	_, err := n.chain.InsertChain(types.Blocks{block})
	if err == nil || !strings.Contains(err.Error(), "gas limit above the consensus maximum") {
		n.t.Fatalf("node %s importing block %d: error %v, want the gas limit above the consensus maximum", n.name, block.NumberU64(), err)
	}
	if n.head().Hash() != head.Hash() {
		n.t.Fatalf("node %s: the head moved to the rejected block", n.name)
	}
}

// process runs the node's block processing over a block on its head, against
// a copy of the head state, without the header checks.
func (n *node) process(block *types.Block) error {
	n.t.Helper()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		n.t.Fatalf("node %s: no parent for block %d", n.name, block.NumberU64())
	}
	_, _, _, err := core.NewStateProcessor(n.chain.Config(), n.chain, n.engine).Process(block, n.stateAt(parent).Copy(), vm.Config{})
	return err
}

// TestBoundaryCompetingReveals reveals one marker twice: as two blocks on
// two branches, each valid on its own; as one block holding both, which the
// gas limit and the marker each make invalid; and as the second reveal in a
// later block, which is refused. The network then settles on one branch,
// whose reveal alone stands.
func TestBoundaryCompetingReveals(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(5, 1))
	s.commit(s.node(0), c)

	var (
		a, b, third = s.node(0), s.node(1), s.node(2)
		newKey      = newWallet("synthetic digits for the competing key")
		toX, toY    = address("competing recipient x"), address("competing recipient y")
		minerA      = address("competing miner a")
		minerB      = address("competing miner b")
		out         = ghostAmount(1, 1)
		filler      = address("competing filler")
	)
	pair := func() (*revealStep, *revealStep) {
		return prepareReveal(t, third, c, s.owner, 1, toX, out), prepareReveal(t, third, c, newKey, 0, toY, out)
	}

	// At the genesis gas limit a block has room for one reveal only.
	r1, r2 := pair()
	if third.head().GasLimit >= 2*ghostpriv.GasPriv {
		t.Fatalf("gas limit %d already holds two reveals", third.head().GasLimit)
	}
	both := third.mine(blockPlan{coinbase: filler, txs: []*types.Transaction{r1.tx}, unchecked: []*types.Transaction{r2.tx}})
	for _, n := range s.net.nodes {
		n.reject(both, core.ErrGasLimitReached)
	}

	// A gas limit that holds two reveals is above the consensus maximum, so
	// every node refuses a block holding both on its header alone.
	s.net.alignWindow(filler)
	s.net.converged()
	r1, r2 = pair()
	if 2*ghostpriv.GasPriv <= ghost.MaxBlockGasLimit {
		t.Fatalf("the consensus maximum %d holds two reveals", ghost.MaxBlockGasLimit)
	}
	both = third.withGasLimit(third.mine(blockPlan{coinbase: filler, txs: []*types.Transaction{r1.tx}, unchecked: []*types.Transaction{r2.tx}}), 2*ghostpriv.GasPriv+1_000_000)
	for _, n := range s.net.nodes {
		n.rejectAboveMaxGasLimit(both)
	}
	// Past the header check, the marker alone makes that block invalid.
	for _, n := range s.net.nodes {
		requireErr(t, n.process(both), ghostpriv.ErrRevealMarker, "node "+n.name+": processing the block holding both reveals")
	}

	// Two blocks on two branches, each valid on its own.
	blockA := a.mine(blockPlan{coinbase: minerA, txs: []*types.Transaction{r1.tx}})
	a.insert(blockA)
	checkReveal(t, a, blockA, r1)
	blockB := b.mine(blockPlan{coinbase: minerB, txs: []*types.Transaction{r2.tx}})
	b.insert(blockB)
	checkReveal(t, b, blockB, r2)
	third.insert(blockA)
	checkReveal(t, third, blockA, r1)

	// The other reveal in a later block of each branch is refused.
	laterA := a.mine(blockPlan{coinbase: minerA, unchecked: []*types.Transaction{r2.tx}})
	a.reject(laterA, ghostpriv.ErrRevealMarker)
	third.reject(laterA, ghostpriv.ErrRevealMarker)
	laterB := b.mine(blockPlan{coinbase: minerB, unchecked: []*types.Transaction{r1.tx}})
	b.reject(laterB, ghostpriv.ErrRevealMarker)

	// Branch B grows heavier and the network settles on it.
	b2 := b.mine(blockPlan{coinbase: minerB})
	b.insert(b2)
	a.insert(blockB, b2)
	third.insert(blockB, b2)
	s.net.converged()
	for _, n := range s.net.nodes {
		st := n.headState()
		if !ghosttree.IsSpent(st, ghosttree.Coin, c.marker()) {
			t.Fatalf("node %s: the marker is unspent", n.name)
		}
		if !st.GetBalance(toX).IsZero() || !st.GetBalance(minerA).IsZero() || !st.GetBalance(toY).Eq(out) {
			t.Fatalf("node %s: recipient x %v, miner a %v, recipient y %v; want 0, 0, %v", n.name, st.GetBalance(toX), st.GetBalance(minerA), st.GetBalance(toY), out)
		}
		requireNothingUnspent(t, n, s.owner)
		requireCurrent(t, n, newKey, r2.rest)
	}

	// The losing reveal stays refused on the settled chain.
	if fee := a.feeOn(a.head()); !fee.Total.Eq(r1.fee.Total) {
		t.Fatalf("the late block is in another fee window: fee %v, the reveal pays %v", fee.Total, r1.fee.Total)
	}
	late := a.mine(blockPlan{coinbase: minerA, unchecked: []*types.Transaction{r1.tx}})
	for _, n := range s.net.nodes {
		n.reject(late, ghostpriv.ErrRevealMarker)
	}
}
