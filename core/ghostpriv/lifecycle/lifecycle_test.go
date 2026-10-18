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
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// TestLifecycleCommitAndReceiveKey commits a coin and has the receiving
// wallet, which holds only the digits, find it on every node.
func TestLifecycleCommitAndReceiveKey(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(5, 1))
	block := s.commit(s.node(0), c)
	s.net.converged()
	s.requireTotals(c.value, new(uint256.Int))

	receiver := newWallet(s.owner.digits)
	for _, n := range s.net.nodes {
		got := requireCurrent(t, n, receiver, c)
		if got.position != 0 || got.block != block.NumberU64() {
			t.Fatalf("node %s: the coin restored at position %d of block %d, want 0 of %d", n.name, got.position, got.block, block.NumberU64())
		}
		if coins := restore(t, n, newWallet("synthetic digits for another wallet")); len(coins) != 0 {
			t.Fatalf("node %s: a wallet with other digits found %d coins", n.name, len(coins))
		}
	}
}

// TestLifecyclePartialRevealsRepeated reveals part of a coin three times,
// each reveal mined by another node, and follows the remainder each time.
func TestLifecyclePartialRevealsRepeated(t *testing.T) {
	s := newScenario(t)
	start := s.owner.coin(0, ghostAmount(5, 1))
	s.commit(s.node(0), start)

	var (
		c        = start
		outs     = []*uint256.Int{ghostAmount(1, 1), ghostAmount(1, 2), ghostAmount(1, 4)}
		steps    = make([]*revealStep, 0, len(outs))
		totalOut = new(uint256.Int)
	)
	for k, out := range outs {
		miner := s.node(k + 1)
		step := prepareReveal(t, miner, c, s.owner, c.index+1, address(fmt.Sprintf("partial recipient %d", k)), out)
		s.reveal(miner, step, address(fmt.Sprintf("partial miner %d", k)))
		s.net.converged()
		for _, n := range s.net.nodes {
			requireCurrent(t, n, s.owner, step.rest)
		}
		totalOut = add(totalOut, add(out, step.fee.Total))
		steps = append(steps, step)
		c = step.rest
	}
	s.requireTotals(start.value, totalOut)
	if want := sub(start.value, totalOut); !c.value.Eq(want) {
		t.Fatalf("the remainder holds %v, want %v", c.value, want)
	}
	for _, n := range s.net.nodes {
		st := n.headState()
		hidden, err := ghostpriv.Hidden(st)
		if err != nil || !hidden.Eq(c.value) {
			t.Fatalf("node %s: hidden set %v (%v), want the remainder %v", n.name, hidden, err, c.value)
		}
		for _, step := range steps {
			if !st.GetBalance(step.recipient).Eq(step.out) {
				t.Fatalf("node %s: recipient %v holds %v, want %v", n.name, step.recipient, st.GetBalance(step.recipient), step.out)
			}
		}
		history := restore(t, n, s.owner)
		if len(history) != len(outs)+1 {
			t.Fatalf("node %s: %d commitments restored, want %d", n.name, len(history), len(outs)+1)
		}
		for i, r := range history {
			if r.coin.index != i || r.position != uint32(i) || r.spent != (i < len(outs)) {
				t.Fatalf("node %s: commitment %d at position %d spent %v", n.name, r.coin.index, r.position, r.spent)
			}
		}
	}
}

// TestLifecycleClaimToNewKey claims the remainder to a commitment of another
// wallet: the old wallet keeps nothing, the new one restores the coin and
// spends it, and the old marker cannot be revealed again.
func TestLifecycleClaimToNewKey(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(5, 1))
	s.commit(s.node(0), c)
	partial := prepareReveal(t, s.node(1), c, s.owner, 1, address("claim partial recipient"), ghostAmount(1, 1))
	s.reveal(s.node(1), partial, address("claim miner one"))

	newKey := newWallet("synthetic digits for the new key")
	recipient := address("claim recipient")
	claim := prepareReveal(t, s.node(2), partial.rest, newKey, 0, recipient, new(uint256.Int))
	s.reveal(s.node(2), claim, address("claim miner two"))
	s.net.converged()
	if want := sub(partial.rest.value, claim.fee.Total); !claim.rest.value.Eq(want) {
		t.Fatalf("the claimed coin holds %v, want %v", claim.rest.value, want)
	}
	for _, n := range s.net.nodes {
		requireNothingUnspent(t, n, s.owner)
		requireCurrent(t, n, newKey, claim.rest)
		if b := n.headState().GetBalance(recipient); !b.IsZero() {
			t.Fatalf("node %s: the claim minted %v", n.name, b)
		}
	}

	// The new key spends the claimed coin.
	spend := prepareReveal(t, s.node(0), claim.rest, newKey, 1, address("new key recipient"), ghostAmount(1, 2))
	s.reveal(s.node(0), spend, address("claim miner three"))
	for _, n := range s.net.nodes {
		requireCurrent(t, n, newKey, spend.rest)
	}

	// The old wallet cannot take the claimed coin back.
	back := prepareReveal(t, s.node(1), partial.rest, s.owner, 2, address("old key recipient"), new(uint256.Int))
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNext(back.reveal), ghostpriv.ErrRevealMarker, "node "+n.name+": the old key's reveal")
	}
	block := s.node(1).mine(blockPlan{coinbase: address("claim miner four"), unchecked: []*types.Transaction{back.tx}})
	for _, n := range s.net.nodes {
		n.reject(block, ghostpriv.ErrRevealMarker)
	}
}

// TestLifecycleRestoreOnCleanNode restores the current remainder from the
// digits alone on a node that only imported the network's blocks, spends it
// from there, and restores both wallets on a second clean node.
func TestLifecycleRestoreOnCleanNode(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(4, 1))
	s.commit(s.node(0), c)
	for k := 0; k < 2; k++ {
		step := prepareReveal(t, s.node(k+1), c, s.owner, c.index+1, address(fmt.Sprintf("restore recipient %d", k)), ghostAmount(1, 3))
		s.reveal(s.node(k+1), step, address(fmt.Sprintf("restore miner %d", k)))
		c = step.rest
	}
	s.net.converged()

	clean := s.cleanNode("clean one")
	digits := newWallet(s.owner.digits)
	got := requireCurrent(t, clean, digits, c)
	onClean, onNetwork := restore(t, clean, digits), restore(t, s.node(0), s.owner)
	if len(onClean) != 3 || len(onClean) != len(onNetwork) {
		t.Fatalf("%d commitments restored on the clean node, %d on the network, want 3", len(onClean), len(onNetwork))
	}
	for i := range onClean {
		a, b := onClean[i], onNetwork[i]
		if a.coin.index != b.coin.index || !a.coin.value.Eq(b.coin.value) || a.position != b.position || a.block != b.block || a.spent != b.spent {
			t.Fatalf("commitment %d restored differently on the clean node", i)
		}
	}

	// What the clean node restored is enough to reveal, from the clean node.
	newKey := newWallet("synthetic digits for the restored claim")
	step := prepareReveal(t, clean, got.coin, newKey, 0, address("restored recipient"), ghostAmount(1, 2))
	block := clean.mine(blockPlan{coinbase: address("clean miner"), txs: []*types.Transaction{step.tx}})
	clean.insert(block)
	s.net.share(block)
	for _, n := range append([]*node{clean}, s.net.nodes...) {
		checkReveal(t, n, block, step)
	}

	again := s.cleanNode("clean two")
	requireNothingUnspent(t, again, newWallet(s.owner.digits))
	requireCurrent(t, again, newWallet(newKey.digits), step.rest)
}

// cleanNode starts a node that has never seen the wallet and imports the
// canonical chain of the first node into it.
func (s *scenario) cleanNode(name string) *node {
	s.t.Helper()
	n := newNode(s.t, name)
	source := s.node(0)
	var blocks []*types.Block
	for num := uint64(1); num <= source.head().Number.Uint64(); num++ {
		blocks = append(blocks, source.chain.GetBlockByNumber(num))
	}
	n.insert(blocks...)
	if n.head().Hash() != source.head().Hash() {
		s.t.Fatalf("node %s did not reach the network's head", name)
	}
	return n
}

// TestLifecycleSecondRevealRejected reveals a coin and then tries its marker
// again, as a new reveal and as a replay of the first one: every node
// refuses both for the marker, and the remainder stays spendable.
func TestLifecycleSecondRevealRejected(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(5, 1))
	s.commit(s.node(0), c)
	s.net.alignWindow(address("second filler"))
	first := prepareReveal(t, s.node(1), c, s.owner, 1, address("first recipient"), ghostAmount(1, 1))
	s.reveal(s.node(1), first, address("second miner one"))
	in, out := ghostpriv.Totals(s.node(0).headState())

	recipient := address("second recipient")
	second := prepareReveal(t, s.node(2), c, s.owner, 2, recipient, ghostAmount(1, 1))
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNext(second.reveal), ghostpriv.ErrRevealMarker, "node "+n.name+": the second reveal")
		// With a fresh marker the same reveal passes: the marker is the
		// reason.
		fresh := newReveal(n, s.owner.coin(9, c.value), second.rest, second.reveal.Root, recipient, second.out, second.fee.Total)
		if err := n.checkNext(fresh); err != nil {
			t.Fatalf("node %s: the control reveal with a fresh marker: %v", n.name, err)
		}
	}
	block := s.node(2).mine(blockPlan{coinbase: address("second miner two"), unchecked: []*types.Transaction{second.tx}})
	for _, n := range s.net.nodes {
		n.reject(block, ghostpriv.ErrRevealMarker)
	}

	// The first reveal again, byte for byte, in its own fee window.
	if fee := s.node(0).feeOn(s.node(0).head()); !fee.Total.Eq(first.fee.Total) {
		t.Fatalf("the replay is in another fee window: fee %v, the first paid %v", fee.Total, first.fee.Total)
	}
	replay := s.node(0).mine(blockPlan{coinbase: address("second miner three"), unchecked: []*types.Transaction{first.tx}})
	for _, n := range s.net.nodes {
		n.reject(replay, ghostpriv.ErrRevealMarker)
		st := n.headState()
		gotIn, gotOut := ghostpriv.Totals(st)
		if !gotIn.Eq(in) || !gotOut.Eq(out) || !st.GetBalance(recipient).IsZero() || !st.GetBalance(first.recipient).Eq(first.out) {
			t.Fatalf("node %s: a rejected reveal changed the state", n.name)
		}
		requireCurrent(t, n, s.owner, first.rest)
	}

	next := prepareReveal(t, s.node(0), first.rest, s.owner, 2, address("second next recipient"), ghostAmount(1, 1))
	s.reveal(s.node(0), next, address("second miner four"))
	s.net.converged()
}

// TestLifecycleReorgRemovesReveal reveals on one branch, has a node switch
// to a heavier branch without the reveal, checks that the reveal is gone
// without a trace, and then includes the same reveal on the new branch.
func TestLifecycleReorgRemovesReveal(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(5, 1))
	s.commit(s.node(0), c)
	s.net.alignWindow(address("reorg filler"))
	s.net.converged()

	var (
		fork          = s.node(0).head()
		a, b, both    = s.node(0), s.node(1), s.node(2)
		recipient     = address("reorg recipient")
		minerA        = address("reorg miner a")
		minerB        = address("reorg miner b")
		forkIn, forkO = ghostpriv.Totals(a.stateAt(fork))
		forkLeaves    = leafCount(a.stateAt(fork))
	)
	step := prepareReveal(t, a, c, s.owner, 1, recipient, ghostAmount(2, 1))
	blockA := a.mine(blockPlan{coinbase: minerA, txs: []*types.Transaction{step.tx}})
	s.net.shareWith([]*node{a, both}, blockA)
	checkReveal(t, both, blockA, step)
	requireCurrent(t, both, s.owner, step.rest)

	b1 := b.mine(blockPlan{coinbase: minerB})
	b.insert(b1)
	b2 := b.mine(blockPlan{coinbase: minerB})
	b.insert(b2)
	both.insert(b1, b2)
	if both.head().Hash() != b2.Hash() {
		t.Fatal("the node did not switch to the heavier branch")
	}
	requireSameHead(t, both, b)
	st := both.headState()
	if ghosttree.IsSpent(st, ghosttree.Coin, c.marker()) {
		t.Fatal("the marker stayed spent")
	}
	if !st.GetBalance(recipient).IsZero() || !st.GetBalance(minerA).IsZero() {
		t.Fatalf("the mint %v or the tip and reward %v stayed", st.GetBalance(recipient), st.GetBalance(minerA))
	}
	if leafCount(st) != forkLeaves {
		t.Fatalf("%d leaves after the switch, want %d: the remainder stayed", leafCount(st), forkLeaves)
	}
	if in, out := ghostpriv.Totals(st); !in.Eq(forkIn) || !out.Eq(forkO) {
		t.Fatalf("totals %v/%v after the switch, want %v/%v", in, out, forkIn, forkO)
	}
	if *both.head().CoinTreeRoot != *fork.CoinTreeRoot {
		t.Fatal("the coin tree root is not the fork's")
	}
	if both.chain.GetBlockByNumber(blockA.NumberU64()).Hash() != b1.Hash() {
		t.Fatal("the reveal's block is still canonical")
	}
	requireCurrent(t, both, s.owner, c)

	// The same reveal, byte for byte, on the new branch.
	if fee := b.feeOn(b.head()); !fee.Total.Eq(step.fee.Total) {
		t.Fatalf("the new branch's block is in another fee window: fee %v, the reveal pays %v", fee.Total, step.fee.Total)
	}
	b3 := b.mine(blockPlan{coinbase: minerB, txs: []*types.Transaction{step.tx}})
	a.insert(b1, b2, b3)
	both.insert(b3)
	b.insert(b3)
	s.net.converged()
	for _, n := range s.net.nodes {
		checkReveal(t, n, b3, step)
		requireCurrent(t, n, s.owner, step.rest)
		if !n.headState().GetBalance(minerA).IsZero() {
			t.Fatalf("node %s: the removed block's coinbase kept its pay", n.name)
		}
	}
}

// TestLifecycleReorgKeepsStateConsistent removes a branch holding a commit
// and a reveal of the committed coin: every trace of both goes, the commit
// comes back on the new branch, a reveal naming a root of the removed branch
// is refused, and the coin is then revealed against the new branch.
func TestLifecycleReorgKeepsStateConsistent(t *testing.T) {
	s := newScenario(t)
	c := s.owner.coin(0, ghostAmount(5, 1))
	s.commit(s.node(0), c)
	s.net.alignWindow(address("consistent filler"))
	s.net.converged()

	var (
		fork        = s.node(0).head()
		a, b, both  = s.node(0), s.node(1), s.node(2)
		saver       = newWallet("synthetic digits for the saver wallet")
		x           = saver.coin(0, ghostAmount(2, 1))
		recipient   = address("consistent recipient")
		minerA      = address("consistent miner a")
		minerB      = address("consistent miner b")
		forkState   = a.stateAt(fork)
		payerAtFork = forkState.GetBalance(s.payer)
	)
	forkIn, forkOut := ghostpriv.Totals(forkState)
	commitX := s.commitTx(a, x)
	a1 := a.mine(blockPlan{coinbase: minerA, txs: []*types.Transaction{commitX}})
	a.insert(a1)
	spendX := prepareReveal(t, a, x, saver, 1, recipient, ghostAmount(1, 2))
	a2 := a.mine(blockPlan{coinbase: minerA, txs: []*types.Transaction{spendX.tx}})
	a.insert(a2)
	both.insert(a1, a2)
	checkCommit(t, both, a1, s.payer, x)
	checkReveal(t, both, a2, spendX)

	var branchB []*types.Block
	for range 3 {
		blk := b.mine(blockPlan{coinbase: minerB})
		b.insert(blk)
		branchB = append(branchB, blk)
	}
	both.insert(branchB...)
	requireSameHead(t, both, b)
	for _, n := range []*node{both, b} {
		st := n.headState()
		if leafCount(st) != leafCount(forkState) {
			t.Fatalf("node %s: %d leaves, want the fork's %d", n.name, leafCount(st), leafCount(forkState))
		}
		if in, out := ghostpriv.Totals(st); !in.Eq(forkIn) || !out.Eq(forkOut) {
			t.Fatalf("node %s: totals %v/%v, want the fork's %v/%v", n.name, in, out, forkIn, forkOut)
		}
		if !st.GetBalance(s.payer).Eq(payerAtFork) {
			t.Fatalf("node %s: the payer holds %v, want %v from before the commit", n.name, st.GetBalance(s.payer), payerAtFork)
		}
		if ghosttree.IsSpent(st, ghosttree.Coin, x.marker()) || !st.GetBalance(recipient).IsZero() || !st.GetBalance(minerA).IsZero() {
			t.Fatalf("node %s: the removed reveal left a trace", n.name)
		}
		if coins := restore(t, n, saver); len(coins) != 0 {
			t.Fatalf("node %s: the saver restored %d coins of the removed branch", n.name, len(coins))
		}
		requireCurrent(t, n, s.owner, c)
	}
	if *both.head().CoinTreeRoot != *fork.CoinTreeRoot {
		t.Fatal("the coin tree root is not the fork's")
	}

	// The same signed commit on the new branch: its nonce is free again.
	b4 := b.mine(blockPlan{coinbase: minerB, txs: []*types.Transaction{commitX}})
	b.insert(b4)
	a.insert(append(branchB, b4)...)
	both.insert(b4)
	s.net.converged()
	for _, n := range s.net.nodes {
		checkCommit(t, n, b4, s.payer, x)
		if got := requireCurrent(t, n, saver, x); uint64(got.position) != leafCount(forkState) {
			t.Fatalf("node %s: the commit came back at position %d, want %d", n.name, got.position, leafCount(forkState))
		}
	}

	// A reveal of x naming the coin root of the removed branch, after x's
	// remainder there, names no ancestor of the new branch.
	fee := b.feeOn(b.head())
	rest := saver.coin(1, sub(x.value, add(spendX.out, fee.Total)))
	stale := newReveal(b, x, rest, *a2.Header().CoinTreeRoot, recipient, spendX.out, fee.Total)
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNext(stale), ghostpriv.ErrRevealRoot, "node "+n.name+": the reveal with a removed root")
	}
	staleBlock := b.mine(blockPlan{coinbase: minerB, unchecked: []*types.Transaction{revealTx(t, stale)}})
	for _, n := range s.net.nodes {
		n.reject(staleBlock, ghostpriv.ErrRevealRoot)
	}

	again := prepareReveal(t, b, x, saver, 1, recipient, spendX.out)
	s.reveal(b, again, minerB)
	s.net.converged()
	for _, n := range s.net.nodes {
		requireCurrent(t, n, saver, again.rest)
		requireCurrent(t, n, s.owner, c)
	}
}

// requireSameHead checks that two nodes have the same head, state root and
// coin tree root.
func requireSameHead(t *testing.T, x, y *node) {
	t.Helper()
	hx, hy := x.head(), y.head()
	if hx.Hash() != hy.Hash() || hx.Root != hy.Root || *hx.CoinTreeRoot != *hy.CoinTreeRoot {
		t.Fatalf("node %s at %d %x, node %s at %d %x", x.name, hx.Number, hx.Hash(), y.name, hy.Number, hy.Hash())
	}
}
