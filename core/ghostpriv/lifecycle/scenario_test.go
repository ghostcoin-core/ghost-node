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
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

const commitGas = 60_000

var (
	oneGhost = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	gwei     = big.NewInt(1_000_000_000)
)

// ghostAmount is num/den GHOST.
func ghostAmount(num, den int64) *uint256.Int {
	return uint256.MustFromBig(new(big.Int).Div(new(big.Int).Mul(oneGhost, big.NewInt(num)), big.NewInt(den)))
}

// payerSeed is the seed of the payer's account key.
const payerSeed = 0x9a

// scenario is a network with a funded account and the wallet of the coin
// the lifecycle follows.
type scenario struct {
	t      *testing.T
	net    *network
	funder *mldsa44.PrivateKey
	payer  common.Address
	owner  *wallet
}

// newScenario starts a network and funds the payer with the rewards of the
// first blocks, one mined by each node: the internal network's genesis
// allocates nothing.
func newScenario(t *testing.T) *scenario {
	t.Helper()
	s := &scenario{
		t:     t,
		net:   newNetwork(t, networkSize),
		owner: newWallet("synthetic digits for the owner wallet"),
	}
	s.funder, _, s.payer = testAccount(payerSeed)
	for _, n := range s.net.nodes {
		s.net.mine(n, blockPlan{coinbase: s.payer})
	}
	s.net.converged()
	return s
}

func (s *scenario) node(i int) *node { return s.net.nodes[i%len(s.net.nodes)] }

// commitTx is the payer's commit of c, signed with the payer's next nonce on
// n's head.
func (s *scenario) commitTx(n *node, c coin) *types.Transaction {
	s.t.Helper()
	note := c.note()
	data, err := ghostpriv.SaltedCommitData(c.owner.fingerprint(c.index), make([]byte, ghostpriv.SaltSize), note[:])
	if err != nil {
		s.t.Fatal(err)
	}
	return accountCallTx(s.t, n.chain, s.funder, n.headState().GetNonce(s.payer), ghost.CommitEntryAddress, c.value.ToBig(), data, commitGas)
}

// commit has miner commit c in a block of its own and checks the commit on
// every node.
func (s *scenario) commit(miner *node, c coin) *types.Block {
	s.t.Helper()
	tx := s.commitTx(miner, c)
	block := s.net.mine(miner, blockPlan{coinbase: address("miner " + miner.name), txs: []*types.Transaction{tx}})
	for _, n := range s.net.nodes {
		checkCommit(s.t, n, block, s.payer, c)
	}
	return block
}

// checkCommit checks a block holding one commit of c by from on a node: the
// receipt log, the leaf, the totals, the debit and the coin tree root.
func checkCommit(t *testing.T, n *node, block *types.Block, from common.Address, c coin) {
	t.Helper()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	pre, post := n.stateAt(parent), n.stateAt(block.Header())
	receipts := n.chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("node %s: commit block %d has %d receipts, want 1 successful", n.name, block.NumberU64(), len(receipts))
	}
	var logs []leafLog
	for _, l := range receipts[0].Logs {
		if leaf, reveal, ok := parseCoinLog(t, l); ok {
			if reveal != nil || !leaf.commit {
				t.Fatalf("node %s: a commit wrote a reveal log", n.name)
			}
			logs = append(logs, leaf)
		}
	}
	if len(logs) != 1 {
		t.Fatalf("node %s: %d commit logs, want 1", n.name, len(logs))
	}
	l := logs[0]
	if l.tree != 0 || uint64(l.position) != leafCount(pre) || l.leaf != c.leaf() || !l.amount.Eq(c.value) || l.note != c.note() {
		t.Fatalf("node %s: commit log at %d/%d of leaf %x and %v, want 0/%d, %x and %v", n.name, l.tree, l.position, l.leaf, l.amount, leafCount(pre), c.leaf(), c.value)
	}
	if leafCount(post) != leafCount(pre)+1 {
		t.Fatalf("node %s: %d leaves after the commit, want %d", n.name, leafCount(post), leafCount(pre)+1)
	}
	inPre, outPre := ghostpriv.Totals(pre)
	inPost, outPost := ghostpriv.Totals(post)
	if !new(uint256.Int).Sub(inPost, inPre).Eq(c.value) || !outPost.Eq(outPre) {
		t.Fatalf("node %s: totals %v/%v to %v/%v, want total in up by %v", n.name, inPre, outPre, inPost, outPost, c.value)
	}
	paid := new(uint256.Int).Mul(uint256.NewInt(receipts[0].GasUsed), uint256.MustFromBig(receipts[0].EffectiveGasPrice))
	paid.Add(paid, c.value)
	if spent := new(uint256.Int).Sub(pre.GetBalance(from), post.GetBalance(from)); !spent.Eq(paid) {
		t.Fatalf("node %s: the sender paid %v, want the value and gas %v", n.name, spent, paid)
	}
	if ghosttree.IsSpent(post, ghosttree.Coin, c.marker()) {
		t.Fatalf("node %s: the marker of a fresh commit is spent", n.name)
	}
	requireRootMatchesState(t, n, block.Header(), post)
	if *block.Header().CoinTreeRoot == *parent.CoinTreeRoot {
		t.Fatalf("node %s: the commit did not change the coin tree root", n.name)
	}
}

// revealStep is one reveal the scenario mines.
type revealStep struct {
	spend     coin
	rest      coin
	recipient common.Address
	out       *uint256.Int
	fee       ghostpriv.Fee
	reveal    *ghostpriv.Reveal
	tx        *types.Transaction
}

// prepareReveal builds a reveal of spend for a block on miner's head: out to
// recipient, the window fee, and the remainder spend - out - fee as
// commitment restIndex of restOwner. The root is the head's coin tree root.
func prepareReveal(t *testing.T, miner *node, spend coin, restOwner *wallet, restIndex int, recipient common.Address, out *uint256.Int) *revealStep {
	t.Helper()
	head := miner.head()
	fee := miner.feeOn(head)
	need := new(uint256.Int).Add(out, fee.Total)
	if need.Gt(spend.value) {
		t.Fatalf("the reveal takes %v from a coin of %v", need, spend.value)
	}
	rest := restOwner.coin(restIndex, new(uint256.Int).Sub(spend.value, need))
	r := newReveal(miner, spend, rest, *head.CoinTreeRoot, recipient, out, fee.Total)
	return &revealStep{spend: spend, rest: rest, recipient: recipient, out: new(uint256.Int).Set(out), fee: fee, reveal: r, tx: revealTx(t, r)}
}

// reveal has miner reveal in a block of its own, mined by coinbase, and
// checks the reveal on every node.
func (s *scenario) reveal(miner *node, step *revealStep, coinbase common.Address) *types.Block {
	s.t.Helper()
	block := s.net.mine(miner, blockPlan{coinbase: coinbase, txs: []*types.Transaction{step.tx}})
	for _, n := range s.net.nodes {
		checkReveal(s.t, n, block, step)
	}
	return block
}

// checkReveal checks a block holding one reveal on a node: the receipt and
// its log, the marker, the mint, the tip, the remainder leaf, the totals and
// the coin tree root.
func checkReveal(t *testing.T, n *node, block *types.Block, step *revealStep) {
	t.Helper()
	header := block.Header()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	pre, post := n.stateAt(parent), n.stateAt(header)
	receipts := n.chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 {
		t.Fatalf("node %s: reveal block %d has %d receipts, want 1", n.name, block.NumberU64(), len(receipts))
	}
	rc := receipts[0]
	if rc.Type != types.GhostRevealTxType || rc.Status != types.ReceiptStatusSuccessful || rc.GasUsed != ghostpriv.GasPriv || header.GasUsed != ghostpriv.GasPriv {
		t.Fatalf("node %s: reveal receipt of type %#x, status %d, gas %d, block gas %d", n.name, rc.Type, rc.Status, rc.GasUsed, header.GasUsed)
	}
	var found []revealLog
	for _, l := range rc.Logs {
		leaf, reveal, ok := parseCoinLog(t, l)
		if !ok {
			continue
		}
		if reveal == nil {
			t.Fatalf("node %s: a reveal wrote a commit log", n.name)
		}
		if leaf.tree != 0 || uint64(leaf.position) != leafCount(pre) || leaf.note != step.rest.note() {
			t.Fatalf("node %s: remainder logged at %d/%d, want 0/%d with the remainder's note", n.name, leaf.tree, leaf.position, leafCount(pre))
		}
		found = append(found, *reveal)
	}
	if len(found) != 1 {
		t.Fatalf("node %s: %d reveal logs, want 1", n.name, len(found))
	}
	l := found[0]
	if l.marker != step.spend.marker() || l.remainder != step.rest.leaf() || l.recipient != step.recipient || !l.out.Eq(step.out) {
		t.Fatalf("node %s: reveal log of marker %x, remainder %x, recipient %v, out %v", n.name, l.marker, l.remainder, l.recipient, l.out)
	}
	if ghosttree.IsSpent(pre, ghosttree.Coin, step.spend.marker()) || !ghosttree.IsSpent(post, ghosttree.Coin, step.spend.marker()) {
		t.Fatalf("node %s: the marker was not unspent before and spent after", n.name)
	}
	if got := delta(pre, post, step.recipient); got.Cmp(step.out.ToBig()) != 0 {
		t.Fatalf("node %s: the recipient got %v, want %v", n.name, got, step.out)
	}
	wantCoinbase := new(uint256.Int).Add(reward(header.Number.Uint64()), step.fee.Tip)
	if got := delta(pre, post, header.Coinbase); got.Cmp(wantCoinbase.ToBig()) != 0 {
		t.Fatalf("node %s: the coinbase got %v, want the reward and the tip %v", n.name, got, wantCoinbase)
	}
	if leafCount(post) != leafCount(pre)+1 {
		t.Fatalf("node %s: %d leaves after the reveal, want %d", n.name, leafCount(post), leafCount(pre)+1)
	}
	inPre, outPre := ghostpriv.Totals(pre)
	inPost, outPost := ghostpriv.Totals(post)
	taken := new(uint256.Int).Add(step.out, step.fee.Total)
	if !inPost.Eq(inPre) || !new(uint256.Int).Sub(outPost, outPre).Eq(taken) {
		t.Fatalf("node %s: totals %v/%v to %v/%v, want total out up by %v", n.name, inPre, outPre, inPost, outPost, taken)
	}
	hiddenPre, err := ghostpriv.Hidden(pre)
	if err != nil {
		t.Fatal(err)
	}
	hiddenPost, err := ghostpriv.Hidden(post)
	if err != nil {
		t.Fatal(err)
	}
	if !new(uint256.Int).Sub(hiddenPre, hiddenPost).Eq(taken) {
		t.Fatalf("node %s: the hidden set went from %v to %v, want down by %v", n.name, hiddenPre, hiddenPost, taken)
	}
	requireRootMatchesState(t, n, header, post)
}

// delta is the change of an account's balance between two states.
func delta(pre, post *state.StateDB, addr common.Address) *big.Int {
	return new(big.Int).Sub(post.GetBalance(addr).ToBig(), pre.GetBalance(addr).ToBig())
}

func requireRootMatchesState(t *testing.T, n *node, header *types.Header, st *state.StateDB) {
	t.Helper()
	root, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		t.Fatal(err)
	}
	if header.CoinTreeRoot == nil || root != *header.CoinTreeRoot {
		t.Fatalf("node %s: block %d header coin root differs from the state's %x", n.name, header.Number, root)
	}
}

// requireTotals checks the totals of the hidden set on every node.
func (s *scenario) requireTotals(in, out *uint256.Int) {
	s.t.Helper()
	for _, n := range s.net.nodes {
		gotIn, gotOut := ghostpriv.Totals(n.headState())
		if !gotIn.Eq(in) || !gotOut.Eq(out) {
			s.t.Fatalf("node %s: totals in %v, out %v; want %v, %v", n.name, gotIn, gotOut, in, out)
		}
	}
}

func add(a, b *uint256.Int) *uint256.Int { return new(uint256.Int).Add(a, b) }

func sub(a, b *uint256.Int) *uint256.Int { return new(uint256.Int).Sub(a, b) }
