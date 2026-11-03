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
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// bundleMiner is the coinbase of the blocks that carry the bundles.
var bundleMiner = common.Address{0xcb, 0x55}

// bundleTo is a recipient of a bundled reveal.
func bundleTo(n byte) common.Address { return common.Address{0xb0, 0x55, n} }

// revealOnly is a verifier of reveals that is no bundle verifier: it accepts
// the stub proofs of reveals and has no VerifyBundle.
type revealOnly struct{}

func (revealOnly) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	return stub.VerifyReveal(in, proof)
}

// bundleChain is a chain whose block 1 commits three coins of one GHOST, so
// that the hidden set holds three GHOST, imported. The tests build block 2
// with the chain maker, under a gas limit that holds their bundles.
type bundleChain struct {
	f      *fixture
	chain  *core.BlockChain
	block1 *types.Block
	root   common.Hash
	fee    ghostpriv.Fee
}

func newBundleChain(t *testing.T, gasLimit uint64, extra genesisT.GenesisAlloc) *bundleChain {
	t.Helper()
	f := newFixture(t, gasLimit, extra)
	s := &bundleChain{f: f}
	blocks, _ := s.generate(t, 1, nil)
	s.chain = f.newChain()
	f.insert(s.chain, blocks)
	s.block1 = blocks[0]
	s.root = *s.block1.Header().CoinTreeRoot
	env, _ := s.env(t)
	s.fee = chainWindowFee(t, s.chain, env.Header)
	return s
}

func (s *bundleChain) generate(t *testing.T, n int, gen func(b *core.BlockGen)) ([]*types.Block, []types.Receipts) {
	t.Helper()
	return s.f.generate(n, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(s.f.commitTx(keyA, 0, testCoin("bundle coin a", oneGhost)))
			b.AddTx(s.f.commitTx(keyB, 0, testCoin("bundle coin b", oneGhost)))
			b.AddTx(s.f.commitTx(keyC, 0, testCoin("bundle coin c", oneGhost)))
		case 1:
			b.SetCoinbase(bundleMiner)
			gen(b)
		}
	})
}

// build generates block 1 and a block 2 of gen on it, and checks that block
// 1 is the chain's.
func (s *bundleChain) build(t *testing.T, gen func(b *core.BlockGen)) ([]*types.Block, []types.Receipts) {
	t.Helper()
	blocks, receipts := s.generate(t, 2, gen)
	if blocks[0].Hash() != s.block1.Hash() {
		t.Fatal("block 1 did not rebuild identically")
	}
	return blocks, receipts
}

// insertBad imports block 1 of blocks and then its invalid block 2 on a
// chain of their own, one invalid block per chain as in the other block
// tests, and returns the import error of block 2. The head stays block 1.
func (s *bundleChain) insertBad(t *testing.T, name string, blocks []*types.Block) error {
	t.Helper()
	chain := s.f.newChain()
	s.f.insert(chain, blocks[:1])
	_, err := chain.InsertChain(blocks[1:])
	if chain.CurrentBlock().Hash() != s.block1.Hash() {
		t.Fatalf("%s: the head moved", name)
	}
	return err
}

// env is the environment of a block 2 on the chain, with the state after
// block 1.
func (s *bundleChain) env(t *testing.T) (*ghostpriv.BlockEnv, *state.StateDB) {
	t.Helper()
	return nextEnv(t, s.chain, s.block1.Header(), bundleMiner)
}

// reveal is a version 2 reveal of block 1's coin root, paying the window fee
// of block 2, with the marker of name.
func (s *bundleChain) reveal(name string, to common.Address, out *uint256.Int) *ghostpriv.Reveal {
	return s.f.newReveal(s.root, testMarker("bundle "+name), testCoin("bundle rest "+name, ghostAmount(1, 2)), to, out, s.fee.Total)
}

// bundle is a bundle of the reveals, in order, with the stub root proof of
// its inputs on this chain.
func (s *bundleChain) bundle(reveals ...*ghostpriv.Reveal) *ghostpriv.Bundle {
	b := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: s.f.chainID, Reveals: reveals}
	b.Proof = ghostprivtest.BundleProof(b.Inputs(s.f.chainID, s.f.genesis.Hash()).Binding)
	return b
}

// apply applies a bundle envelope with verifier on the state after block 1
// and checks that a failure leaves the state as it was.
func (s *bundleChain) apply(t *testing.T, verifier ghostpriv.Verifier, envelope []byte) (*state.StateDB, []ghostpriv.BundleSkip, error) {
	t.Helper()
	env, st := s.env(t)
	before := st.IntermediateRoot(true)
	skips, err := ghostpriv.ApplyBundle(st, env, verifier, envelope)
	if err != nil {
		if after := st.IntermediateRoot(true); after != before || len(st.Logs()) != 0 {
			t.Fatalf("a refused bundle changed the state: %v", err)
		}
	}
	return st, skips, err
}

func bundleEnvelope(t *testing.T, b *ghostpriv.Bundle) []byte {
	t.Helper()
	env, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func bundleTx(t *testing.T, b *ghostpriv.Bundle) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostBundleTx(bundleEnvelope(t, b))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestBundleRootBindsListCountChainAndVersion checks that the root's inputs,
// which the node builds itself, bind the exact ordered list of reveals, the
// count, the chain id and domain and the bundle and reveal versions: a
// change, reordering, addition or removal of any one gives other inputs,
// for which the root proof of the bundle fails, and a block carrying such a
// bundle is invalid. The bundle as proven imports.
func TestBundleRootBindsListCountChainAndVersion(t *testing.T) {
	useStub(t)
	s := newBundleChain(t, 5*ghostpriv.GasPriv, nil)
	out := u256(ghostAmount(1, 10))
	r1, r2, r3, r4 := s.reveal("bind one", bundleTo(1), out), s.reveal("bind two", bundleTo(2), out), s.reveal("bind three", bundleTo(3), out), s.reveal("bind four", bundleTo(4), out)
	base := s.bundle(r1, r2, r3)
	chainID, genesis := s.f.chainID, s.f.genesis.Hash()
	in := base.Inputs(chainID, genesis)
	stubV := ghostprivtest.Verifier{}
	if err := stubV.VerifyBundle(in, base.Proof); err != nil {
		t.Fatalf("the root proof of the bundle: %v", err)
	}

	changedOut := clone(r2)
	changedOut.Out = new(uint256.Int).AddUint64(r2.Out, 1)
	changedNote := clone(r3)
	changedNote.Note[ghostpriv.NoteSize-1] ^= 1
	changedRecipient := clone(r1)
	changedRecipient.Recipient = bundleTo(9)
	withField := func(f func(in *ghostpriv.BundleInputs)) *ghostpriv.BundleInputs {
		cp := *in
		f(&cp)
		cp.Binding = ghosttree.K(ghostpriv.TagBundleBinding, cp.BindingInput())
		return &cp
	}
	for _, c := range []struct {
		name     string
		in       *ghostpriv.BundleInputs
		contents bool
	}{
		{"reordered", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r2, r1, r3}), true},
		{"last two swapped", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r1, r3, r2}), true},
		{"out changed", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r1, changedOut, r3}), true},
		{"note changed", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r1, r2, changedNote}), true},
		{"recipient changed", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{changedRecipient, r2, r3}), true},
		{"added", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r1, r2, r3, r4}), true},
		{"repeated", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r1, r2, r3, r3}), true},
		{"removed", ghostpriv.NewBundleInputs(chainID, genesis, []*ghostpriv.Reveal{r1, r2}), true},
		{"other chain id", ghostpriv.NewBundleInputs(chainID+1, genesis, []*ghostpriv.Reveal{r1, r2, r3}), true},
		{"other domain", ghostpriv.NewBundleInputs(chainID, common.Hash{0x0d}, []*ghostpriv.Reveal{r1, r2, r3}), true},
		{"count", withField(func(in *ghostpriv.BundleInputs) { in.Count = 4 }), false},
		{"bundle version", withField(func(in *ghostpriv.BundleInputs) { in.Version = 2 }), false},
		{"reveal version", withField(func(in *ghostpriv.BundleInputs) { in.RevealVersion = 1 }), false},
		{"chain id field", withField(func(in *ghostpriv.BundleInputs) { in.ChainID++ }), false},
		{"domain field", withField(func(in *ghostpriv.BundleInputs) { in.Domain[0] ^= 1 }), false},
	} {
		if c.in.Binding == in.Binding {
			t.Errorf("%s: the binding did not change", c.name)
		}
		if (c.in.Contents != in.Contents) != c.contents {
			t.Errorf("%s: contents changed %v, want %v", c.name, c.in.Contents != in.Contents, c.contents)
		}
		if err := stubV.VerifyBundle(c.in, base.Proof); err == nil {
			t.Errorf("%s: the root proof of the bundle verified", c.name)
		}
	}

	// In a block: the bundle carries other bodies than its root proof is of,
	// or its root proof is of another chain or domain.
	withProof := func(b *ghostpriv.Bundle, proof []byte) *ghostpriv.Bundle {
		b.Proof = common.CopyBytes(proof)
		return b
	}
	otherChain := ghostprivtest.BundleProof(ghostpriv.NewBundleInputs(chainID+1, genesis, base.Reveals).Binding)
	otherDomain := ghostprivtest.BundleProof(ghostpriv.NewBundleInputs(chainID, common.Hash{0x0d}, base.Reveals).Binding)
	for _, c := range []struct {
		name   string
		bundle *ghostpriv.Bundle
	}{
		{"reordered", withProof(s.bundle(r2, r1, r3), base.Proof)},
		{"one body changed", withProof(s.bundle(r1, changedOut, r3), base.Proof)},
		{"added", withProof(s.bundle(r1, r2, r3, r4), base.Proof)},
		{"removed", withProof(s.bundle(r1, r2), base.Proof)},
		{"proof of another chain", withProof(s.bundle(r1, r2, r3), otherChain)},
		{"proof of another domain", withProof(s.bundle(r1, r2, r3), otherDomain)},
	} {
		env := bundleEnvelope(t, c.bundle)
		if _, _, err := s.apply(t, stub, env); !errors.Is(err, ghostpriv.ErrBundleProof) {
			t.Fatalf("%s: applied with %v, want %v", c.name, err, ghostpriv.ErrBundleProof)
		}
		tx, err := types.NewGhostBundleTx(env)
		if err != nil {
			t.Fatal(err)
		}
		blocks, _ := s.build(t, func(b *core.BlockGen) { b.AddUncheckedTx(tx) })
		if err := s.insertBad(t, c.name, blocks); !errors.Is(err, ghostpriv.ErrBundleProof) {
			t.Fatalf("%s: block imported with %v, want %v", c.name, err, ghostpriv.ErrBundleProof)
		}
	}

	// The bundle as proven imports, every reveal applied.
	blocks, _ := s.build(t, func(b *core.BlockGen) { b.AddTx(bundleTx(t, base)) })
	s.f.insert(s.chain, blocks[1:])
	st, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range base.Reveals {
		if !ghosttree.IsSpent(st, ghosttree.Coin, r.Marker) || !st.GetBalance(r.Recipient).Eq(out) {
			t.Fatalf("reveal %d of the proven bundle not applied", i)
		}
	}
}

// TestBundleSkippedRevealDoesNotStopTheRest checks the late failure rule: a
// bundled reveal whose state-dependent checks fail on the state the reveals
// before it left (a fee that is not the window fee, a repeat of an earlier
// marker of the bundle, a root that is not an ancestor's, a registered policy
// as recipient, the backstop, a full coin tree) is skipped with no change at
// all, and the rest of the bundle runs in order. The block is valid; its one
// receipt of type 0x55 has status 1, the bundle's whole gas and the logs of
// the applied reveals only. A skipped reveal pays nothing and writes no log
// and no total.
func TestBundleSkippedRevealDoesNotStopTheRest(t *testing.T) {
	useStub(t)
	s := newBundleChain(t, 8*ghostpriv.GasPriv, policyAlloc())
	out := u256(ghostAmount(1, 10))
	first := s.reveal("skip first", bundleTo(1), out)
	wrongFee := s.reveal("skip fee", bundleTo(2), out)
	wrongFee.Fee = new(uint256.Int).AddUint64(s.fee.Total, 1)
	s.f.prove(wrongFee)
	repeat := s.f.newReveal(s.root, first.Marker, testCoin("bundle rest skip repeat", ghostAmount(1, 2)), bundleTo(3), out, s.fee.Total)
	notARoot := s.f.newReveal(ghosttree.K("ghost/test-not-a-root"), testMarker("bundle skip root"), testCoin("bundle rest skip root", ghostAmount(1, 2)), bundleTo(4), out, s.fee.Total)
	toPolicy := s.reveal("skip policy", testPolicy, out)
	overdraw := s.reveal("skip backstop", bundleTo(6), u256(ghostAmount(3, 1)))
	last := s.reveal("skip last", bundleTo(7), out)
	bundle := s.bundle(first, wrongFee, repeat, notARoot, toPolicy, overdraw, last)
	env := bundleEnvelope(t, bundle)

	// On the state: which reveals are skipped, and why.
	_, skips, err := s.apply(t, stub, env)
	if err != nil {
		t.Fatalf("bundle refused: %v", err)
	}
	wantSkips := []struct {
		index int
		err   error
	}{
		{1, ghostpriv.ErrRevealFee},
		{2, ghostpriv.ErrRevealMarker},
		{3, ghostpriv.ErrRevealRoot},
		{4, ghostpriv.ErrRevealRecipient},
		{5, ghostpriv.ErrRevealBackstop},
	}
	if len(skips) != len(wantSkips) {
		t.Fatalf("%d reveals skipped, want %d: %v", len(skips), len(wantSkips), skips)
	}
	for k, w := range wantSkips {
		if skips[k].Index != w.index || !errors.Is(skips[k].Err, w.err) {
			t.Errorf("skip %d: reveal %d with %v, want reveal %d with %v", k, skips[k].Index, skips[k].Err, w.index, w.err)
		}
	}

	// In a block.
	tx := bundleTx(t, bundle)
	blocks, _ := s.build(t, func(b *core.BlockGen) { b.AddTx(tx) })
	s.f.insert(s.chain, blocks[1:])
	block := s.chain.GetBlockByNumber(2)
	if block == nil || block.Hash() != blocks[1].Hash() {
		t.Fatal("the block with the bundle is not the head")
	}
	if block.GasUsed() != 7*ghostpriv.GasPriv {
		t.Fatalf("block gas used %d, want 7 * G_PRIV", block.GasUsed())
	}
	receipts := s.chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 {
		t.Fatalf("%d receipts", len(receipts))
	}
	r := receipts[0]
	if r.Type != types.GhostBundleTxType || r.Status != types.ReceiptStatusSuccessful || r.GasUsed != 7*ghostpriv.GasPriv || r.TxHash != tx.Hash() {
		t.Fatalf("receipt: type %#x, status %d, gas %d", r.Type, r.Status, r.GasUsed)
	}
	if len(r.Logs) != 2 {
		t.Fatalf("%d logs, want those of the two applied reveals", len(r.Logs))
	}
	for k, applied := range []*ghostpriv.Reveal{first, last} {
		l := r.Logs[k]
		if l.Topics[1] != applied.Marker || l.TxHash != tx.Hash() || !bytes.Equal(l.Data[8+32+ghostpriv.NoteSize:8+32+ghostpriv.NoteSize+20], applied.Recipient[:]) {
			t.Fatalf("log %d is not the reveal's", k)
		}
	}

	st, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.chain.StateAt(s.block1.Root())
	if err != nil {
		t.Fatal(err)
	}
	for _, applied := range []*ghostpriv.Reveal{first, last} {
		if !ghosttree.IsSpent(st, ghosttree.Coin, applied.Marker) || !st.GetBalance(applied.Recipient).Eq(out) {
			t.Fatalf("reveal %x not applied", applied.Marker)
		}
	}
	for _, skipped := range []*ghostpriv.Reveal{wrongFee, notARoot, toPolicy, overdraw} {
		if ghosttree.IsSpent(st, ghosttree.Coin, skipped.Marker) {
			t.Fatalf("skipped reveal's marker %x spent", skipped.Marker)
		}
	}
	for _, skipped := range []*ghostpriv.Reveal{wrongFee, repeat, notARoot, toPolicy, overdraw} {
		if !st.GetBalance(skipped.Recipient).IsZero() {
			t.Fatalf("skipped reveal credited %v", skipped.Recipient)
		}
	}
	if got := coinLeafCount(st) - coinLeafCount(before); got != 2 {
		t.Fatalf("%d remainders appended, want 2", got)
	}
	// The totals and the coinbase see the two applied reveals only.
	spent := new(uint256.Int).Add(out, s.fee.Total)
	spent.Mul(spent, uint256.NewInt(2))
	_, outBefore := totals(before)
	if _, outAfter := totals(st); new(uint256.Int).Sub(u256(outAfter), u256(outBefore)).Cmp(spent) != 0 {
		t.Fatalf("total out grew by %v, want %v", new(uint256.Int).Sub(u256(outAfter), u256(outBefore)), spent)
	}
	split, err := s.fee.CoverGas(block.BaseFee(), ghostpriv.GasPriv)
	if err != nil {
		t.Fatal(err)
	}
	wantMiner := new(uint256.Int).Mul(split.Tip, uint256.NewInt(2))
	wantMiner.Add(wantMiner, newTestEngine().params.BlockReward(2))
	if got := st.GetBalance(bundleMiner); !got.Eq(wantMiner) {
		t.Fatalf("coinbase %v, want the reward and two tips %v", got, wantMiner)
	}

	// A full coin tree: every reveal is skipped, nothing changes, and the
	// bundle is still valid.
	envB, stB := s.env(t)
	fillCoinTree(stB, envB.Header.Number.Uint64())
	root := stB.IntermediateRoot(true)
	full, err := ghostpriv.ApplyBundle(stB, envB, stub, bundleEnvelope(t, s.bundle(s.reveal("full one", bundleTo(8), out), s.reveal("full two", bundleTo(9), out))))
	if err != nil {
		t.Fatalf("bundle on a full tree refused: %v", err)
	}
	if len(full) != 2 || !errors.Is(full[0].Err, ghostpriv.ErrRevealTree) || !errors.Is(full[1].Err, ghostpriv.ErrRevealTree) {
		t.Fatalf("skips on a full tree: %v", full)
	}
	if stB.IntermediateRoot(true) != root || len(stB.Logs()) != 0 {
		t.Fatal("a skipped reveal changed the state")
	}
}

// TestBundleStructuralFailureInvalidatesBlock checks that a bundle whose
// structure fails makes its block invalid, before any change: a length that
// is not that of its count, a count of 0, a version other than 1, the
// bundle's or a body's chain id not this chain's, a body that is not a
// version 2 reveal, and a root proof the verifier rejects. The reveals of
// each bad bundle are valid, and the same reveals in a good bundle import.
func TestBundleStructuralFailureInvalidatesBlock(t *testing.T) {
	useStub(t)
	s := newBundleChain(t, 4*ghostpriv.GasPriv, nil)
	out := u256(ghostAmount(1, 10))
	r1, r2 := s.reveal("structural one", bundleTo(1), out), s.reveal("structural two", bundleTo(2), out)
	good := bundleEnvelope(t, s.bundle(r1, r2))

	patched := func(at int, b ...byte) []byte {
		env := common.CopyBytes(good)
		copy(env[at:], b)
		return env
	}
	versionTwo := s.bundle(r1, r2)
	versionTwo.Version = 2
	otherChain := s.bundle(r1, r2)
	otherChain.ChainID++
	foreign := clone(r2)
	foreign.ChainID++
	noProof := s.bundle(r1, r2)
	noProof.Proof = nil
	firstBody := 1 + types.GhostBundleFixedSize
	for _, c := range []struct {
		name string
		env  []byte
		want error
	}{
		{"count 3 with two bodies", patched(1+10, 0, 3), ghostpriv.ErrBundleLength},
		{"count 1 with two bodies", patched(1+10, 0, 1), ghostpriv.ErrBundleLength},
		{"count 0", patched(1+10, 0, 0)[:firstBody], ghostpriv.ErrBundleCount},
		{"version 2", bundleEnvelope(t, versionTwo), ghostpriv.ErrBundleVersion},
		{"bundle chain id", bundleEnvelope(t, otherChain), ghostpriv.ErrBundleChainID},
		{"body chain id", bundleEnvelope(t, s.bundle(r1, foreign)), ghostpriv.ErrBundleChainID},
		{"body version 1", patched(firstBody+ghostpriv.BundleBodySize+1, 1), ghostpriv.ErrBundleBody},
		{"body out of 2^96", patched(firstBody+126, 1), ghostpriv.ErrBundleBody},
		{"body fee of 2^96", patched(firstBody+ghostpriv.BundleBodySize+158+19, 1), ghostpriv.ErrBundleBody},
		{"root proof rejected", bundleEnvelope(t, noProof), ghostpriv.ErrBundleProof},
	} {
		if _, _, err := s.apply(t, stub, c.env); !errors.Is(err, c.want) {
			t.Fatalf("%s: applied with %v, want %v", c.name, err, c.want)
		}
		// The type's own decoder takes no bundle of a wrong length or count;
		// such a payload still reaches a block that is built by hand.
		tx, err := types.NewGhostBundleTx(c.env)
		if err != nil {
			tx = types.NewTx(&types.GhostBundleTx{Payload: c.env[1:]})
		}
		blocks, _ := s.build(t, func(b *core.BlockGen) { b.AddUncheckedTx(tx) })
		if len(blocks[1].Transactions()) != 1 {
			t.Fatalf("%s: the block does not carry the bundle", c.name)
		}
		if err := s.insertBad(t, c.name, blocks); !errors.Is(err, c.want) {
			t.Fatalf("%s: block imported with %v, want %v", c.name, err, c.want)
		}
	}

	// The good bundle of the same reveals imports.
	tx, err := types.NewGhostBundleTx(good)
	if err != nil {
		t.Fatal(err)
	}
	blocks, _ := s.build(t, func(b *core.BlockGen) { b.AddTx(tx) })
	s.f.insert(s.chain, blocks[1:])
	st, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*ghostpriv.Reveal{r1, r2} {
		if !ghosttree.IsSpent(st, ghosttree.Coin, r.Marker) || !st.GetBalance(r.Recipient).Eq(out) {
			t.Fatal("the good bundle was not applied")
		}
	}
}

// TestBundleWithoutBundleVerifierIsInvalid checks that the root is verified
// through the optional BundleVerifier of the active verifier: a verifier
// without it, one that verifies reveals only or the node's default, fails
// every bundle closed with ErrBundleUnsupported, so the block is invalid,
// while the same block imports under the stub, a bundle verifier.
func TestBundleWithoutBundleVerifierIsInvalid(t *testing.T) {
	useStub(t)
	s := newBundleChain(t, 3*ghostpriv.GasPriv, nil)
	out := u256(ghostAmount(1, 10))
	r1, r2 := s.reveal("verifier one", bundleTo(1), out), s.reveal("verifier two", bundleTo(2), out)
	bundle := s.bundle(r1, r2)
	env := bundleEnvelope(t, bundle)
	in := bundle.Inputs(s.f.chainID, s.f.genesis.Hash())
	tx := bundleTx(t, bundle)
	blocks, _ := s.build(t, func(b *core.BlockGen) { b.AddTx(tx) })

	if _, ok := ghostpriv.Verifier(revealOnly{}).(ghostpriv.BundleVerifier); ok {
		t.Fatal("the reveal-only verifier verifies bundles")
	}
	if err := (revealOnly{}).VerifyReveal(r1.VerifyInputs(s.f.chainID, s.f.genesis.Hash()), r1.Proof); err != nil {
		t.Fatalf("the reveal-only verifier refuses a reveal: %v", err)
	}
	if _, ok := ghostpriv.DefaultVerifier().(ghostpriv.BundleVerifier); ok {
		t.Fatal("the default verifier verifies bundles")
	}
	for _, c := range []struct {
		name     string
		verifier ghostpriv.Verifier
	}{
		{"reveal-only verifier", revealOnly{}},
		{"default verifier", nil},
	} {
		if err := ghostpriv.VerifyBundleRoot(c.verifier, in, bundle.Proof); !errors.Is(err, ghostpriv.ErrBundleUnsupported) || errors.Is(err, ghostpriv.ErrBundleProof) {
			t.Fatalf("%s: root %v, want %v", c.name, err, ghostpriv.ErrBundleUnsupported)
		}
		if _, _, err := s.apply(t, c.verifier, env); !errors.Is(err, ghostpriv.ErrBundleUnsupported) {
			t.Fatalf("%s: applied with %v, want %v", c.name, err, ghostpriv.ErrBundleUnsupported)
		}
		restore := ghostpriv.SetVerifier(c.verifier)
		err := s.insertBad(t, c.name, blocks)
		restore()
		if !errors.Is(err, ghostpriv.ErrBundleUnsupported) {
			t.Fatalf("%s: block imported with %v, want %v", c.name, err, ghostpriv.ErrBundleUnsupported)
		}
	}

	// Under the stub the same block imports, on a chain that never saw it.
	chain := s.f.newChain()
	s.f.insert(chain, blocks)
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Coin, r1.Marker) || !ghosttree.IsSpent(st, ghosttree.Coin, r2.Marker) {
		t.Fatal("the bundle was not applied under the stub")
	}
}

// TestBundleMatchesLoneReveals checks that the change an applied bundled
// reveal makes is a lone reveal's: block 2 with a bundle of three reveals
// has the state root, coin tree root and logs of block 2 with the same three
// reveals one by one, at the same gas. A bundle with a reveal that is
// skipped has the state root of the lone reveals without it: the skipped
// reveal pays nothing and changes nothing, though its gas stays taken.
func TestBundleMatchesLoneReveals(t *testing.T) {
	useStub(t)
	s := newBundleChain(t, 4*ghostpriv.GasPriv, nil)
	r1 := s.reveal("lone one", bundleTo(1), u256(ghostAmount(1, 10)))
	r2 := s.reveal("lone two", bundleTo(2), u256(ghostAmount(2, 10)))
	r3 := s.reveal("lone three", bundleTo(3), u256(ghostAmount(1, 20)))
	skipped := clone(r2)
	skipped.Marker = testMarker("bundle lone skipped")
	skipped.Fee = new(uint256.Int).AddUint64(s.fee.Total, 1)
	s.f.prove(skipped)

	logsOf := func(receipts types.Receipts) []*types.Log {
		var logs []*types.Log
		for _, r := range receipts {
			logs = append(logs, r.Logs...)
		}
		return logs
	}
	for _, c := range []struct {
		name    string
		bundle  []*ghostpriv.Reveal
		lone    []*ghostpriv.Reveal
		applied int
	}{
		{"three reveals", []*ghostpriv.Reveal{r1, r2, r3}, []*ghostpriv.Reveal{r1, r2, r3}, 3},
		{"one skipped", []*ghostpriv.Reveal{r1, skipped, r3}, []*ghostpriv.Reveal{r1, r3}, 2},
	} {
		bundled, bundledReceipts := s.build(t, func(b *core.BlockGen) { b.AddTx(bundleTx(t, s.bundle(c.bundle...))) })
		lone, loneReceipts := s.build(t, func(b *core.BlockGen) {
			for _, r := range c.lone {
				b.AddTx(revealTx(t, r))
			}
		})
		if bundled[1].Root() != lone[1].Root() {
			t.Fatalf("%s: state root of the bundle %x, of the lone reveals %x", c.name, bundled[1].Root(), lone[1].Root())
		}
		if *bundled[1].Header().CoinTreeRoot != *lone[1].Header().CoinTreeRoot {
			t.Fatalf("%s: coin tree roots differ", c.name)
		}
		if bundled[1].GasUsed() != uint64(len(c.bundle))*ghostpriv.GasPriv || lone[1].GasUsed() != uint64(len(c.lone))*ghostpriv.GasPriv {
			t.Fatalf("%s: gas used %d by the bundle, %d by the lone reveals", c.name, bundled[1].GasUsed(), lone[1].GasUsed())
		}
		if len(bundledReceipts[1]) != 1 || bundledReceipts[1][0].Type != types.GhostBundleTxType {
			t.Fatalf("%s: the bundle's block has %d receipts", c.name, len(bundledReceipts[1]))
		}
		have, want := logsOf(bundledReceipts[1]), logsOf(loneReceipts[1])
		if len(have) != c.applied || len(want) != c.applied {
			t.Fatalf("%s: %d logs from the bundle, %d from the lone reveals, want %d", c.name, len(have), len(want), c.applied)
		}
		for k := range have {
			if have[k].Address != want[k].Address || !bytes.Equal(have[k].Data, want[k].Data) || len(have[k].Topics) != len(want[k].Topics) {
				t.Fatalf("%s: log %d differs", c.name, k)
			}
			for j := range have[k].Topics {
				if have[k].Topics[j] != want[k].Topics[j] {
					t.Fatalf("%s: log %d topic %d differs", c.name, k, j)
				}
			}
		}
		// Both blocks are valid.
		for _, blocks := range [][]*types.Block{bundled, lone} {
			chain := s.f.newChain()
			s.f.insert(chain, blocks)
		}
	}
}
