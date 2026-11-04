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
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The Guard lifecycle (spec 10, section 12) on the internal network, with
// Guard created through the policy factory at its fixed salt: a Guard coin
// spends with the words and the override as a plain coin does; with the
// words alone it can only be swept into a Guard slot, which the stop card
// cancels before the hold, re-committing to a new key, and which otherwise
// pays instr once 8,640 blocks and 72 hours have passed.

// TestGuardLifecycleOverrideSpend commits a Guard coin and a plain coin and
// spends each with an ordinary reveal in the same fee window: the commits,
// the reveals, their receipts and what they change have one shape, byte for
// byte, and no slot is opened.
func TestGuardLifecycleOverrideSpend(t *testing.T) {
	s := newScenario(t)
	s.createGuard(s.node(0))
	var (
		owner     = newGuardOwner("synthetic words of the override owner", "synthetic stop card of the override owner")
		guarded   = owner.words.coin(0, ghostAmount(3, 1))
		plain     = s.owner.coin(0, ghostAmount(3, 1))
		zero      = new(uint256.Int)
		out       = ghostAmount(1, 1)
		recipient = address("override recipient")
	)
	// The commits: nothing tells a Guard coin from a plain one.
	gc, pc := s.commitTx(s.node(1), guarded), s.commitTx(s.node(1), plain)
	if gc.Type() != pc.Type() || gc.Gas() != pc.Gas() || len(gc.Data()) != len(pc.Data()) || *gc.To() != *pc.To() || gc.Value().Cmp(pc.Value()) != 0 {
		t.Fatal("the Guard coin's commit and the plain coin's differ in shape")
	}
	s.commit(s.node(1), guarded)
	s.commit(s.node(2), plain)
	wallets := []*wallet{owner.words, s.owner}
	hidden := add(guarded.value, plain.value)
	s.requireIdentity(hidden, zero, wallets...)

	s.net.alignWindow(address("override filler"))
	override := prepareReveal(t, s.node(0), guarded, owner.words, 1, recipient, out)
	blockG := s.reveal(s.node(0), override, address("override miner"))
	hidden = sub(hidden, add(out, override.fee.Total))
	s.requireIdentity(hidden, zero, wallets...)
	ordinary := prepareReveal(t, s.node(1), plain, s.owner, 1, address("plain recipient"), out)
	blockP := s.reveal(s.node(1), ordinary, address("plain miner"))
	hidden = sub(hidden, add(out, ordinary.fee.Total))
	s.requireIdentity(hidden, zero, wallets...)
	s.net.converged()
	if !override.fee.Total.Eq(ordinary.fee.Total) || blockG.NumberU64()/4 != blockP.NumberU64()/4 {
		t.Fatalf("the reveals are in blocks %d and %d with fees %v and %v, want one fee window", blockG.NumberU64(), blockP.NumberU64(), override.fee.Total, ordinary.fee.Total)
	}

	// The transactions: the same type, gas and envelope length, and the same
	// bytes once the fields of each coin are cleared.
	if override.tx.Type() != types.GhostRevealTxType || override.tx.Type() != ordinary.tx.Type() || override.tx.Gas() != ordinary.tx.Gas() || override.tx.Gas() != ghostpriv.GasPriv {
		t.Fatalf("override spend of type %#x and gas %d, plain spend of type %#x and gas %d", override.tx.Type(), override.tx.Gas(), ordinary.tx.Type(), ordinary.tx.Gas())
	}
	envG, envP := override.tx.GhostRevealEnvelope(), ordinary.tx.GhostRevealEnvelope()
	if len(envG) != len(envP) || len(envG) != types.GhostRevealEnvelopeSize {
		t.Fatalf("envelopes of %d and %d bytes, want %d", len(envG), len(envP), types.GhostRevealEnvelopeSize)
	}
	shape := func(env []byte) []byte {
		r, err := ghostpriv.DecodeReveal(env)
		if err != nil {
			t.Fatal(err)
		}
		if again := envelope(t, r); !bytes.Equal(again, env) {
			t.Fatal("the envelope does not encode back to itself")
		}
		in := r.VerifyInputs(r.ChainID, s.node(0).chain.Genesis().Hash())
		if r.Version != ghostpriv.RevealVersion || in.Purpose != ghostpriv.PurposeReveal || in.Policy != (common.Address{}) || in.ActionTag != (common.Hash{}) || in.Instr != (common.Hash{}) {
			t.Fatalf("a reveal of version %d and purpose %#x names a policy", r.Version, in.Purpose)
		}
		r.Marker, r.Root, r.Remainder, r.Recipient, r.Note, r.Proof = common.Hash{}, common.Hash{}, common.Hash{}, common.Address{}, [ghostpriv.NoteSize]byte{}, nil
		return envelope(t, r)
	}
	if !bytes.Equal(shape(envG), shape(envP)) {
		t.Fatal("the override spend and the plain spend differ beyond the fields of their coins")
	}

	// The receipts and the change, on every node.
	for _, n := range s.net.nodes {
		rg, rp := receiptOf(t, n, blockG, override.tx), receiptOf(t, n, blockP, ordinary.tx)
		if rg.Type != rp.Type || rg.Status != rp.Status || rg.GasUsed != rp.GasUsed || len(rg.Logs) != len(rp.Logs) || len(blockG.Transactions()) != len(blockP.Transactions()) {
			t.Fatalf("node %s: receipts of type %#x/%#x, status %d/%d, gas %d/%d and %d/%d logs", n.name, rg.Type, rp.Type, rg.Status, rp.Status, rg.GasUsed, rp.GasUsed, len(rg.Logs), len(rp.Logs))
		}
		for i := range rg.Logs {
			lg, lp := rg.Logs[i], rp.Logs[i]
			if lg.Address != lp.Address || len(lg.Topics) != len(lp.Topics) || lg.Topics[0] != lp.Topics[0] || len(lg.Data) != len(lp.Data) {
				t.Fatalf("node %s: log %d of the override spend differs in shape from the plain spend's", n.name, i)
			}
		}
		for _, b := range []*types.Block{blockG, blockP} {
			pre := n.stateAt(n.chain.GetHeader(b.ParentHash(), b.NumberU64()-1))
			post := n.stateAt(b.Header())
			if !ghostpriv.TotalEscrow(post).Eq(ghostpriv.TotalEscrow(pre)) || leafCount(post) != leafCount(pre)+1 {
				t.Fatalf("node %s: block %d moved total escrow or the coin tree by more than a remainder", n.name, b.NumberU64())
			}
		}
		st := n.headState()
		if _, ok := ghostpriv.ReadEscrowSlot(st, guarded.marker()); ok {
			t.Fatalf("node %s: the override spend opened a slot", n.name)
		}
		if !st.GetBalance(recipient).Eq(out) || !st.GetBalance(ghost.GuardAddress).IsZero() {
			t.Fatalf("node %s: the recipient holds %v and Guard %v", n.name, st.GetBalance(recipient), st.GetBalance(ghost.GuardAddress))
		}
	}
	s.requireGuardCurrent(owner.words, &override.rest)
	s.requireGuardCurrent(s.owner, &ordinary.rest)
}

// TestGuardLifecycleTheftCancelled has a thief who holds only the words
// sweep a Guard coin into Guard to the thief's address: the slot opens, the
// coin cannot be spent any more, a second sweep is refused and a release
// before the hold fails. The stop card's cancel then re-commits the slot to
// a new key, closing it for good: a second cancel and a release fail, and
// the new key spends its coin.
func TestGuardLifecycleTheftCancelled(t *testing.T) {
	s := newScenario(t)
	s.createGuard(s.node(0))
	var (
		owner   = newGuardOwner("synthetic words of the robbed owner", "synthetic stop card of the robbed owner")
		thief   = newWallet("synthetic words the thief made up")
		newKey  = newWallet("synthetic words of the new key")
		c       = owner.words.coin(0, ghostAmount(4, 1))
		zero    = new(uint256.Int)
		stolen  = address("guard thief")
		wallets = []*wallet{owner.words, thief, newKey}
	)
	s.commit(s.node(1), c)
	s.requireIdentity(c.value, zero, wallets...)

	// The thief's sweep with the words alone.
	sw := prepareSweep(t, s.node(2), c, owner, thief.coin(0, zero), stolen)
	swept, _ := s.net.mineGuard(s.node(2), guardPlan{coinbase: address("theft sweep miner"), txs: []*types.Transaction{sw.tx}})
	for _, n := range s.net.nodes {
		checkSweep(t, n, swept, sw)
	}
	s.requireIdentity(zero, sw.out, wallets...)
	s.requireGuardCurrent(owner.words, nil)

	// The coin is gone: the owner's override spend of it is refused for its
	// marker, and so is a second sweep, which the miner leaves out.
	late := prepareReveal(t, s.node(0), c, owner.words, 1, address("too late recipient"), ghostAmount(1, 1))
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNext(late.reveal), ghostpriv.ErrRevealMarker, "node "+n.name+": the override spend after the sweep")
	}
	again := prepareSweep(t, s.node(0), c, owner, thief.coin(1, zero), stolen)

	// Before the hold, the thief's release fails, in a block every node
	// takes.
	release := s.payerCall(s.node(0), s.payerNonce(s.node(0)), ghost.GuardAddress, guardReleaseIn(c.marker()), guardReleaseGas)
	block, refused := s.net.mineGuard(s.node(0), guardPlan{coinbase: address("theft release miner"), txs: []*types.Transaction{release}, candidates: []*types.Transaction{again.tx}})
	if len(refused) != 1 || !errors.Is(refused[again.tx.Hash()], ghostpriv.ErrPolicyRevealMarker) || len(block.Transactions()) != 1 {
		t.Fatalf("the miner left out %v, want the second sweep for its marker", refused)
	}
	for _, n := range s.net.nodes {
		checkReleaseRefused(t, n, block, release, c.marker(), stolen)
	}
	s.requireIdentity(zero, sw.out, wallets...)

	// The stop card cancels, before the hold, to the new key.
	cancel := prepareCancel(t, s.node(1), s.node(1).head(), sw, newKey, 0)
	if s.node(1).head().Number.Uint64()+1 >= swept.NumberU64()+ghost.GuardHoldBlocks {
		t.Fatal("the cancel is not before the hold")
	}
	block, _ = s.net.mineGuard(s.node(1), guardPlan{coinbase: address("theft cancel miner"), txs: []*types.Transaction{cancel.tx}})
	for _, n := range s.net.nodes {
		checkCancel(t, n, block, cancel)
		if !n.headState().GetBalance(stolen).IsZero() {
			t.Fatalf("node %s: the thief got %v", n.name, n.headState().GetBalance(stolen))
		}
	}
	s.requireIdentity(cancel.coin.value, zero, wallets...)
	s.requireGuardCurrent(newKey, &cancel.coin)

	// The old slot is closed: the cancel again is refused by the miner and
	// makes a block that carries it invalid, and a release fails.
	release = s.payerCall(s.node(2), s.payerNonce(s.node(2)), ghost.GuardAddress, guardReleaseIn(c.marker()), guardReleaseGas)
	forced, _ := s.node(2).mineGuardOn(s.node(2).head(), guardPlan{coinbase: address("theft forced miner"), unchecked: []*types.Transaction{cancel.tx}})
	for _, n := range s.net.nodes {
		n.reject(forced, ghostpriv.ErrActionSlot)
	}
	block, refused = s.net.mineGuard(s.node(2), guardPlan{coinbase: address("theft closed miner"), txs: []*types.Transaction{release}, candidates: []*types.Transaction{cancel.tx}})
	if len(refused) != 1 || !errors.Is(refused[cancel.tx.Hash()], ghostpriv.ErrActionSlot) {
		t.Fatalf("the miner left out %v, want the second cancel for the closed slot", refused)
	}
	for _, n := range s.net.nodes {
		checkReleaseRefused(t, n, block, release, c.marker(), stolen)
	}
	s.requireIdentity(cancel.coin.value, zero, wallets...)

	// The new key's coin spends as any coin.
	spend := prepareReveal(t, s.node(0), cancel.coin, newKey, 1, address("new key recipient"), ghostAmount(1, 1))
	s.reveal(s.node(0), spend, address("new key miner"))
	s.requireIdentity(spend.rest.value, zero, wallets...)
	s.requireGuardCurrent(newKey, &spend.rest)
	s.net.converged()
}

// TestGuardLifecycleReleaseAfterHold sweeps two Guard coins with the words
// alone and waits out the hold in blocks of 30 seconds. Release fails before
// the hold, one block short of it at its time floor and one second short of
// it at its block floor; at both floors it pays instr all of the slot. A
// release and the stop card's cancel then race in one block, in either
// order: the first lands, the miner refuses or the call reverts for the
// second with the slot closed, and every node takes the block.
func TestGuardLifecycleReleaseAfterHold(t *testing.T) {
	s := newScenario(t)
	s.createGuard(s.node(0))
	var (
		owner   = newGuardOwner("synthetic words of the release owner", "synthetic stop card of the release owner")
		racer   = newGuardOwner("synthetic words of the race owner", "synthetic stop card of the race owner")
		newKey  = newWallet("synthetic words of the race new key")
		a       = owner.words.coin(0, ghostAmount(3, 1))
		b       = racer.words.coin(0, ghostAmount(2, 1))
		destA   = address("guard release destination")
		destB   = address("guard race destination")
		filler  = address("guard hold miner")
		zero    = new(uint256.Int)
		wallets = []*wallet{owner.words, racer.words, newKey}
	)
	s.commit(s.node(1), a)
	s.commit(s.node(2), b)
	s.requireIdentity(add(a.value, b.value), zero, wallets...)

	// The race's slot first, then the slot under test, so that every block
	// from the latter's on is 30 seconds after its parent.
	swB := prepareSweep(t, s.node(0), b, racer, racer.words.coin(1, zero), destB)
	openedB, _ := s.net.mineGuard(s.node(0), guardPlan{coinbase: address("race sweep miner"), txs: []*types.Transaction{swB.tx}})
	for _, n := range s.net.nodes {
		checkSweep(t, n, openedB, swB)
	}
	s.requireIdentity(a.value, swB.out, wallets...)
	swA := prepareSweep(t, s.node(1), a, owner, owner.words.coin(1, zero), destA)
	opened, _ := s.net.mineGuard(s.node(1), guardPlan{coinbase: address("release sweep miner"), txs: []*types.Transaction{swA.tx}})
	for _, n := range s.net.nodes {
		checkSweep(t, n, opened, swA)
	}
	escrow := add(swA.out, swB.out)
	s.requireIdentity(zero, escrow, wallets...)
	var (
		floorHeight = opened.NumberU64() + ghost.GuardHoldBlocks
		floorTime   = opened.Time() + ghost.GuardHoldSeconds
	)

	// Before the hold, release fails.
	var block *types.Block
	early := s.payerCall(s.node(2), s.payerNonce(s.node(2)), ghost.GuardAddress, guardReleaseIn(a.marker()), guardReleaseGas)
	block, _ = s.net.mineGuard(s.node(2), guardPlan{coinbase: filler, txs: []*types.Transaction{early}})
	for _, n := range s.net.nodes {
		checkReleaseRefused(t, n, block, early, a.marker(), destA)
	}

	// The hold, to two blocks before the block floor.
	s.net.hold(s.node(0), floorHeight-2-s.node(0).head().Number.Uint64(), filler)
	s.net.converged()
	head := s.node(0).head()
	if head.Number.Uint64() != floorHeight-2 || head.Time != floorTime-2*guardSpacing {
		t.Fatalf("the hold ends at block %d time %d, want %d and %d", head.Number, head.Time, floorHeight-2, floorTime-2*guardSpacing)
	}
	s.requireIdentity(zero, escrow, wallets...)

	// One block short of the block floor, at the time floor: a block of 60
	// seconds that every node finds valid, whose release reverts.
	release := s.payerCall(s.node(1), s.payerNonce(s.node(1)), ghost.GuardAddress, guardReleaseIn(a.marker()), guardReleaseGas)
	side, _ := s.node(1).mineGuardOn(head, guardPlan{coinbase: filler, spacing: 2 * guardSpacing, txs: []*types.Transaction{release}})
	if side.NumberU64() != floorHeight-1 || side.Time() != floorTime {
		t.Fatalf("the side block is at %d time %d", side.NumberU64(), side.Time())
	}
	for _, n := range s.net.nodes {
		requireReleaseRevertsIn(t, n, side, a.marker(), destA)
	}
	// One block and 30 seconds short: the release reverts in the network's
	// block.
	block, _ = s.net.mineGuard(s.node(1), guardPlan{coinbase: filler, txs: []*types.Transaction{release}})
	for _, n := range s.net.nodes {
		checkReleaseRefused(t, n, block, release, a.marker(), destA)
	}
	// At the block floor, one second short of the time floor.
	head = s.node(2).head()
	release = s.payerCall(s.node(2), s.payerNonce(s.node(2)), ghost.GuardAddress, guardReleaseIn(a.marker()), guardReleaseGas)
	side, _ = s.node(2).mineGuardOn(head, guardPlan{coinbase: filler, spacing: guardSpacing - 1, txs: []*types.Transaction{release}})
	if side.NumberU64() != floorHeight || side.Time() != floorTime-1 {
		t.Fatalf("the side block is at %d time %d", side.NumberU64(), side.Time())
	}
	for _, n := range s.net.nodes {
		requireReleaseRevertsIn(t, n, side, a.marker(), destA)
	}

	// At both floors, the release and the card's cancel of slot A race, the
	// release first: it pays instr all of the slot, and the miner refuses
	// the cancel for the closed slot. A block carrying the cancel anyway is
	// invalid on every node; the block the miner builds is valid on all.
	cancelA := prepareCancel(t, s.node(2), head, swA, newKey, 0)
	forced, _ := s.node(2).mineGuardOn(head, guardPlan{coinbase: filler, txs: []*types.Transaction{release}, unchecked: []*types.Transaction{cancelA.tx}})
	for _, n := range s.net.nodes {
		n.reject(forced, ghostpriv.ErrActionSlot)
	}
	block, refused := s.net.mineGuard(s.node(2), guardPlan{coinbase: filler, candidates: []*types.Transaction{release, cancelA.tx}})
	if len(refused) != 1 || !errors.Is(refused[cancelA.tx.Hash()], ghostpriv.ErrActionSlot) || len(block.Transactions()) != 1 {
		t.Fatalf("the miner left out %v, want the cancel for the closed slot", refused)
	}
	if block.NumberU64() != floorHeight || block.Time() != floorTime {
		t.Fatalf("the release is in block %d at %d, want the floors %d and %d", block.NumberU64(), block.Time(), floorHeight, floorTime)
	}
	for _, n := range s.net.nodes {
		checkReleasePaid(t, n, block, release, s.payer, a.marker(), destA, swA.out)
	}
	escrow = sub(escrow, swA.out)
	s.requireIdentity(zero, escrow, wallets...)

	// The card's cancel of slot B and its release race in one block, the
	// cancel first: it re-commits to the new key, and the release reverts
	// with the slot closed, in a block every node takes.
	cancelB := prepareCancel(t, s.node(0), s.node(0).head(), swB, newKey, 0)
	release = s.payerCall(s.node(0), s.payerNonce(s.node(0)), ghost.GuardAddress, guardReleaseIn(b.marker()), guardReleaseGas)
	block, refused = s.net.mineGuard(s.node(0), guardPlan{coinbase: filler, candidates: []*types.Transaction{cancelB.tx, release}})
	if len(refused) != 0 || len(block.Transactions()) != 2 {
		t.Fatalf("the miner left out %v", refused)
	}
	if block.NumberU64() < openedB.NumberU64()+ghost.GuardHoldBlocks || block.Time() < openedB.Time()+ghost.GuardHoldSeconds {
		t.Fatal("slot B is not past its hold")
	}
	for _, n := range s.net.nodes {
		checkCancel(t, n, block, cancelB)
		if r := receiptOf(t, n, block, release); r.Status != types.ReceiptStatusFailed || len(r.Logs) != 0 {
			t.Fatalf("node %s: the release after the cancel did not revert", n.name)
		}
		if !n.headState().GetBalance(destB).IsZero() {
			t.Fatalf("node %s: instr of slot B got %v", n.name, n.headState().GetBalance(destB))
		}
	}
	escrow = sub(escrow, swB.out)
	s.requireIdentity(cancelB.coin.value, escrow, wallets...)
	s.requireGuardCurrent(newKey, &cancelB.coin)

	// Both slots are closed: their releases revert, and the miner refuses
	// the cancel of the paid slot.
	nonce := s.payerNonce(s.node(1))
	againA := s.payerCall(s.node(1), nonce, ghost.GuardAddress, guardReleaseIn(a.marker()), guardReleaseGas)
	againB := s.payerCall(s.node(1), nonce+1, ghost.GuardAddress, guardReleaseIn(b.marker()), guardReleaseGas)
	block, refused = s.net.mineGuard(s.node(1), guardPlan{coinbase: filler, txs: []*types.Transaction{againA, againB}, candidates: []*types.Transaction{cancelA.tx}})
	if len(refused) != 1 || !errors.Is(refused[cancelA.tx.Hash()], ghostpriv.ErrActionSlot) {
		t.Fatalf("the miner left out %v, want the cancel of the paid slot", refused)
	}
	for _, n := range s.net.nodes {
		checkReleaseRefused(t, n, block, againA, a.marker(), destA)
		checkReleaseRefused(t, n, block, againB, b.marker(), destB)
		st := n.headState()
		if !st.GetBalance(destA).Eq(swA.out) || !st.GetBalance(destB).IsZero() {
			t.Fatalf("node %s: instr of slot A holds %v and of slot B %v", n.name, st.GetBalance(destA), st.GetBalance(destB))
		}
	}
	s.requireIdentity(cancelB.coin.value, zero, wallets...)
	s.net.converged()
}

// checkReleaseRefused checks on a node that release, in block, reverted: a
// failed receipt without logs, and the slot of marker, total_escrow, the
// balance of instr dest and Guard's balance as they were.
func checkReleaseRefused(t *testing.T, n *node, block *types.Block, release *types.Transaction, marker common.Hash, dest common.Address) {
	t.Helper()
	rc := receiptOf(t, n, block, release)
	if rc.Status != types.ReceiptStatusFailed || len(rc.Logs) != 0 {
		t.Fatalf("node %s: the release in block %d has status %d and %d logs, want a revert", n.name, block.NumberU64(), rc.Status, len(rc.Logs))
	}
	pre := n.stateAt(n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1))
	post := n.stateAt(block.Header())
	before, _ := ghostpriv.ReadEscrowSlot(pre, marker)
	after, _ := ghostpriv.ReadEscrowSlot(post, marker)
	if before == nil || after == nil || *before.Remaining != *after.Remaining || before.Open != after.Open || *before.Paid != *after.Paid {
		t.Fatalf("node %s: a refused release changed the slot", n.name)
	}
	if !ghostpriv.TotalEscrow(pre).Eq(ghostpriv.TotalEscrow(post)) || delta(pre, post, dest).Sign() != 0 || !post.GetBalance(ghost.GuardAddress).IsZero() {
		t.Fatalf("node %s: a refused release moved value", n.name)
	}
}

// requireReleaseRevertsIn checks that a node finds block, which holds one
// release and is not imported, valid, and that the release reverted in it
// with the slot of marker still open and nothing paid to dest.
func requireReleaseRevertsIn(t *testing.T, n *node, block *types.Block, marker common.Hash, dest common.Address) {
	t.Helper()
	receipts, st := n.validate(block)
	if len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusFailed || len(receipts[0].Logs) != 0 {
		t.Fatalf("node %s: the release in block %d did not revert", n.name, block.NumberU64())
	}
	pre := n.stateAt(n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1))
	slot, ok := ghostpriv.ReadEscrowSlot(st, marker)
	if !ok || !slot.Open || !slot.Paid.IsZero() || !st.GetBalance(dest).Eq(pre.GetBalance(dest)) {
		t.Fatalf("node %s: a release before the floors paid", n.name)
	}
}

// checkReleasePaid checks on a node that release, in block, paid amount,
// all of the slot of marker, to dest: the receipt and its slot-paid log, the
// slot closed with paid equal to out, total_escrow, the balances of dest,
// of Guard and of sender, who pays the gas alone.
func checkReleasePaid(t *testing.T, n *node, block *types.Block, release *types.Transaction, sender common.Address, marker common.Hash, dest common.Address, amount *uint256.Int) {
	t.Helper()
	rc := receiptOf(t, n, block, release)
	if rc.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("node %s: the release at the floors failed", n.name)
	}
	var paid int
	for _, l := range rc.Logs {
		if l.Address == ghost.EscrowAccount && l.Topics[0] == slotPaidTopic {
			paid++
			want := append(common.LeftPadBytes(dest[:], 32), common.LeftPadBytes(amount.Bytes(), 32)...)
			if len(l.Topics) != 2 || l.Topics[1] != marker || !bytes.Equal(l.Data, want) {
				t.Fatalf("node %s: slot-paid log %x", n.name, l.Data)
			}
		}
	}
	if paid != 1 {
		t.Fatalf("node %s: %d slot-paid logs, want 1", n.name, paid)
	}
	pre := n.stateAt(n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1))
	post := n.stateAt(block.Header())
	slot, ok := ghostpriv.ReadEscrowSlot(post, marker)
	if !ok || slot.Open || !slot.Remaining.IsZero() || !slot.Paid.Eq(amount) || !slot.Out.Eq(amount) || !slot.Recommitted.IsZero() || !slot.Balanced() {
		t.Fatalf("node %s: slot after the release %+v", n.name, slot)
	}
	if got := sub(ghostpriv.TotalEscrow(pre), ghostpriv.TotalEscrow(post)); !got.Eq(amount) {
		t.Fatalf("node %s: total escrow down by %v, want %v", n.name, got, amount)
	}
	if got := delta(pre, post, dest); got.Cmp(amount.ToBig()) != 0 {
		t.Fatalf("node %s: instr got %v, want %v", n.name, got, amount)
	}
	gas := new(uint256.Int).Mul(uint256.NewInt(rc.GasUsed), uint256.MustFromBig(rc.EffectiveGasPrice))
	if got := delta(post, pre, sender); got.Cmp(gas.ToBig()) != 0 {
		t.Fatalf("node %s: the sender paid %v, want the gas %v alone", n.name, got, gas)
	}
	if !post.GetBalance(ghost.GuardAddress).IsZero() {
		t.Fatalf("node %s: Guard holds %v", n.name, post.GetBalance(ghost.GuardAddress))
	}
	requireRootMatchesState(t, n, block.Header(), post)
}
