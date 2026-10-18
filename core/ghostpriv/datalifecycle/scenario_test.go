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

package datalifecycle

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
)

const dataCommitGas = 60_000

var gwei = big.NewInt(1_000_000_000)

func testKey(name string) *ecdsa.PrivateKey {
	key, err := crypto.ToECDSA(crypto.Keccak256([]byte("ghost synthetic data lifecycle account " + name)))
	if err != nil {
		panic(err)
	}
	return key
}

// scenario is a network with a funded payer, the off-chain host and the
// proof system of a test.
type scenario struct {
	t      *testing.T
	net    *network
	funder *ecdsa.PrivateKey
	payer  common.Address
	host   *host
	sys    *proofSystem
}

// newScenario starts a network and funds the payer with the rewards of the
// first blocks, one mined by each node: the internal network's genesis
// allocates nothing.
func newScenario(t *testing.T) *scenario {
	t.Helper()
	s := &scenario{
		t:      t,
		net:    newNetwork(t, networkSize),
		funder: testKey("payer"),
		host:   newHost(),
		sys:    newProofSystem("synthetic proof system " + t.Name()),
	}
	s.payer = crypto.PubkeyToAddress(s.funder.PublicKey)
	for _, n := range s.net.nodes {
		s.net.mine(n, blockPlan{coinbase: s.payer})
	}
	s.net.converged()
	return s
}

func (s *scenario) node(i int) *node { return s.net.nodes[i%len(s.net.nodes)] }

func (s *scenario) chainID() uint64 { return s.node(0).chain.Config().GetChainID().Uint64() }

// held is a committed file as its holder knows it: the Phantom Key, and for
// the test's own checks the plaintext and the commit block.
type held struct {
	key       phantomKey
	plaintext []byte
	block     *types.Block
	tx        *types.Transaction
}

// wallet opens the holder's wallet from the digits.
func (s *scenario) wallet(h *held) *wallet { return openWallet(h.key, s.chainID()) }

// dataCommitTx is the payer's call to the data commit entry address with the
// given data and value, signed with the payer's next nonce on n's head.
func (s *scenario) dataCommitTx(n *node, data []byte, value *big.Int) *types.Transaction {
	s.t.Helper()
	config := n.chain.Config()
	to := ghost.DataCommitEntryAddress
	return types.MustSignNewTx(s.funder, types.LatestSigner(config), &types.DynamicFeeTx{
		ChainID:   config.GetChainID(),
		Nonce:     n.headState().GetNonce(s.payer),
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       dataCommitGas,
		To:        &to,
		Value:     value,
		Data:      data,
	})
}

// commitData is the 190 bytes of the data commit of a wallet's file.
func commitData(t *testing.T, w *wallet, plaintext []byte) []byte {
	t.Helper()
	note := w.note(plaintext)
	data, err := ghostpriv.CommitData(w.fingerprint(contentFingerprint(plaintext)), note[:])
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// commitFile is the holder's commit of a file: fresh digits, the file
// encrypted under k_data and handed to the host, the data commit mined by
// miner and checked on every node. It returns the Phantom Key.
func (s *scenario) commitFile(miner *node, label string, plaintext []byte) *held {
	s.t.Helper()
	key := newPhantomKey(label)
	w := openWallet(key, s.chainID())
	s.host.put(w.locator(), w.encryptFile(plaintext))
	tx := s.dataCommitTx(miner, commitData(s.t, w, plaintext), new(big.Int))
	block := s.net.mine(miner, blockPlan{coinbase: address("miner " + miner.name), txs: []*types.Transaction{tx}})
	h := &held{key: key, plaintext: common.CopyBytes(plaintext), block: block, tx: tx}
	for _, n := range s.net.nodes {
		s.checkDataCommit(n, h)
	}
	return h
}

// checkDataCommit checks the block of a data commit on a node: one
// successful receipt with one data commit log of C and the note at the next
// position, the data tree one leaf longer with its root in the header, the
// marker unspent, and the coin tree, the totals and every balance but the
// payer's gas untouched.
func (s *scenario) checkDataCommit(n *node, h *held) {
	t := s.t
	t.Helper()
	w := s.wallet(h)
	block := h.block
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	pre, post := n.stateAt(parent), n.stateAt(block.Header())
	receipts := n.chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("node %s: data commit block %d has %d receipts, want 1 successful", n.name, block.NumberU64(), len(receipts))
	}
	var recs []noteRecord
	for _, l := range receipts[0].Logs {
		if rec, ok := parseDataCommitLog(t, l); ok {
			recs = append(recs, rec)
		} else {
			t.Fatalf("node %s: a data commit wrote a log of %v", n.name, l.Address)
		}
	}
	if len(recs) != 1 {
		t.Fatalf("node %s: %d data commit logs, want 1", n.name, len(recs))
	}
	rec := recs[0]
	if rec.tree != 0 || uint64(rec.position) != dataLeafCount(pre) || rec.leaf != w.commitment(contentFingerprint(h.plaintext)) || rec.note != w.note(h.plaintext) {
		t.Fatalf("node %s: data commit log at %d/%d of leaf %x, want 0/%d and the wallet's C and note", n.name, rec.tree, rec.position, rec.leaf, dataLeafCount(pre))
	}
	if dataLeafCount(post) != dataLeafCount(pre)+1 {
		t.Fatalf("node %s: %d data leaves after the commit, want %d", n.name, dataLeafCount(post), dataLeafCount(pre)+1)
	}
	header := block.Header()
	if *header.DataTreeRoot == *parent.DataTreeRoot {
		t.Fatalf("node %s: the data commit did not change the data tree root", n.name)
	}
	if root, err := ghosttree.Root(post, ghosttree.Data); err != nil || root != *header.DataTreeRoot {
		t.Fatalf("node %s: data tree root %x in the state (%v), %x in the header", n.name, root, err, *header.DataTreeRoot)
	}
	if *header.CoinTreeRoot != *parent.CoinTreeRoot {
		t.Fatalf("node %s: a data commit changed the coin tree root", n.name)
	}
	requireTotalsUnchanged(t, n, pre, post)
	if ghosttree.IsSpent(post, ghosttree.Data, w.marker()) {
		t.Fatalf("node %s: the marker of a fresh data commitment is spent", n.name)
	}
	gas := new(big.Int).Mul(new(big.Int).SetUint64(receipts[0].GasUsed), receipts[0].EffectiveGasPrice)
	if spent := new(big.Int).Neg(delta(pre, post, s.payer)); spent.Cmp(gas) != 0 {
		t.Fatalf("node %s: the payer paid %v, want only the gas %v", n.name, spent, gas)
	}
	if post.Exist(ghost.DataCommitEntryAddress) {
		t.Fatalf("node %s: the data commit entry address holds an account", n.name)
	}
}

// reveal has miner include a data reveal of the holder's commitment for
// purpose, made for verifier against the head's data tree root, in a block
// of its own, and checks it on every node.
func (s *scenario) reveal(miner *node, h *held, purpose byte, verifier common.Address) *types.Block {
	s.t.Helper()
	r := s.wallet(h).dataReveal(miner, *miner.head().DataTreeRoot, purpose, verifier)
	block := s.net.mine(miner, blockPlan{coinbase: address("miner " + miner.name), txs: []*types.Transaction{dataRevealTx(s.t, r)}})
	for _, n := range s.net.nodes {
		checkDataReveal(s.t, n, block, r.Marker, purpose, verifier)
	}
	return block
}

// checkDataReveal checks a block holding one data reveal on a node: the
// receipt and its log, the marker spent, and nothing else changed: no tree,
// no total, no balance but the block reward.
func checkDataReveal(t *testing.T, n *node, block *types.Block, marker common.Hash, purpose byte, verifier common.Address) {
	t.Helper()
	header := block.Header()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	pre, post := n.stateAt(parent), n.stateAt(header)
	receipts := n.chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 {
		t.Fatalf("node %s: data reveal block %d has %d receipts, want 1", n.name, block.NumberU64(), len(receipts))
	}
	rc := receipts[0]
	if rc.Type != types.GhostDataRevealTxType || rc.Status != types.ReceiptStatusSuccessful || rc.GasUsed != types.GhostDataRevealGas || len(rc.Logs) != 1 {
		t.Fatalf("node %s: data reveal receipt of type %#x, status %d, gas %d, %d logs", n.name, rc.Type, rc.Status, rc.GasUsed, len(rc.Logs))
	}
	l, ok := parseDataRevealLog(t, rc.Logs[0])
	if !ok || l.marker != marker || l.purpose != purpose || l.verifier != verifier {
		t.Fatalf("node %s: data reveal log of marker %x, purpose %#x, verifier %v", n.name, l.marker, l.purpose, l.verifier)
	}
	if ghosttree.IsSpent(pre, ghosttree.Data, marker) || !ghosttree.IsSpent(post, ghosttree.Data, marker) {
		t.Fatalf("node %s: the data marker was not unspent before and spent after", n.name)
	}
	if ghosttree.IsSpent(post, ghosttree.Coin, marker) {
		t.Fatalf("node %s: a data reveal spent a coin marker", n.name)
	}
	if *header.DataTreeRoot != *parent.DataTreeRoot || *header.CoinTreeRoot != *parent.CoinTreeRoot {
		t.Fatalf("node %s: a data reveal changed a tree root", n.name)
	}
	requireTotalsUnchanged(t, n, pre, post)
	if got := delta(pre, post, verifier); got.Sign() != 0 {
		t.Fatalf("node %s: the verifier field was credited %v", n.name, got)
	}
	want := ghost.InternalNetParams().BlockReward(header.Number.Uint64()).ToBig()
	if got := delta(pre, post, header.Coinbase); got.Cmp(want) != 0 {
		t.Fatalf("node %s: the coinbase got %v, want the block reward %v alone", n.name, got, want)
	}
}

// rejectTx has miner build a block on the common head carrying tx without
// applying it, and has every node refuse it for the reason want.
func (s *scenario) rejectTx(miner *node, want error, applied []*types.Transaction, tx *types.Transaction) {
	s.t.Helper()
	block := miner.mine(blockPlan{coinbase: address("miner " + miner.name), txs: applied, unchecked: []*types.Transaction{tx}})
	s.net.rejectAll(block, want)
}

// dataLeafCount is the number of leaves in the current data tree.
func dataLeafCount(st ghosttree.StateDB) uint64 {
	return new(big.Int).SetBytes(st.GetState(dataTreeAccount, ghosttree.Slot(ghosttree.SlotLeafCount)).Bytes()).Uint64()
}

// requireTotalsUnchanged checks that the coin totals did not move.
func requireTotalsUnchanged(t *testing.T, n *node, pre, post *state.StateDB) {
	t.Helper()
	inPre, outPre := ghostpriv.Totals(pre)
	inPost, outPost := ghostpriv.Totals(post)
	if !inPre.Eq(inPost) || !outPre.Eq(outPost) {
		t.Fatalf("node %s: totals %v/%v to %v/%v, want unchanged", n.name, inPre, outPre, inPost, outPost)
	}
}

// delta is the change of an account's balance between two states.
func delta(pre, post *state.StateDB, addr common.Address) *big.Int {
	return new(big.Int).Sub(post.GetBalance(addr).ToBig(), pre.GetBalance(addr).ToBig())
}

// requireHold makes a proof of holding of h on n for verifier v against the
// head and has v accept it.
func (s *scenario) requireHold(n *node, h *held, v *holdingVerifier) holdingProof {
	s.t.Helper()
	p, err := proveHolding(s.t, s.sys, n, n.head(), s.wallet(h), v.id, v.issue())
	if err != nil {
		s.t.Fatalf("node %s: proof of holding: %v", n.name, err)
	}
	if err := v.verify(p); err != nil {
		s.t.Fatalf("verifier %v rejected a proof of holding: %v", v.id, err)
	}
	return p
}

// requireNoHold checks that no proof of holding of h can be made on n
// against the head, and that the earlier proof old, presented under a fresh
// challenge of v, is rejected at the root check.
func (s *scenario) requireNoHold(n *node, h *held, v *holdingVerifier, old holdingProof) {
	s.t.Helper()
	c := v.issue()
	if _, err := proveHolding(s.t, s.sys, n, n.head(), s.wallet(h), v.id, c); !errors.Is(err, errNoProof) {
		s.t.Fatalf("node %s: a proof of holding was made for a spent marker: %v", n.name, err)
	}
	old.Challenge = c
	requireErr(s.t, v.verify(old), errHoldRoot, "an old proof of holding under a fresh challenge")
}
