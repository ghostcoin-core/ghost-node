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

package ghostpool

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// rootCounter is the stub verifier counting its reveal proof checks and its
// bundle root checks apart.
type rootCounter struct {
	ghostprivtest.Verifier
	reveals atomic.Int64
	roots   atomic.Int64
}

func (v *rootCounter) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	v.reveals.Add(1)
	return v.Verifier.VerifyReveal(in, proof)
}

func (v *rootCounter) VerifyBundle(in *ghostpriv.BundleInputs, proof []byte) error {
	v.roots.Add(1)
	return v.Verifier.VerifyBundle(in, proof)
}

// bundledReveal is a version 2 coin reveal of marker, of the genesis coin
// root and the fee, as a bundle carries it: without a proof.
func (f *fixture) bundledReveal(marker common.Hash, fee *uint256.Int) *ghostpriv.Reveal {
	return &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersion,
		ChainID:   f.gspec.Config.GetChainID().Uint64(),
		Marker:    marker,
		Root:      *f.genesis.Header().CoinTreeRoot,
		Remainder: ghosttree.K("ghost/test-remainder", marker[:]),
		Recipient: recipient(int(marker[0])),
		Out:       uint256.NewInt(1000),
		Fee:       new(uint256.Int).Set(fee),
	}
}

// bundleOf is a bundle of the reveals on the fixture's chain with the stub
// root proof of its inputs.
func (f *fixture) bundleOf(reveals ...*ghostpriv.Reveal) *ghostpriv.Bundle {
	chainID := f.gspec.Config.GetChainID().Uint64()
	b := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: chainID, Reveals: reveals}
	b.Proof = ghostprivtest.BundleProof(b.Inputs(chainID, f.genesis.Hash()).Binding)
	return b
}

// bundleTx is the transaction of a bundle's fields as they are.
func bundleTx(t *testing.T, b *ghostpriv.Bundle) *types.Transaction {
	t.Helper()
	env, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return bundleEnvelopeTx(t, env)
}

func bundleEnvelopeTx(t *testing.T, env []byte) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostBundleTx(env)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestGhostPoolBundleRootAdmission checks the admission of private bundles:
// that an invalid root costs exactly one native verification and no reveal
// proof check, is refused, is remembered and refused again unverified, and
// counts as a failed proof of the peer under the limit it shares with the
// reveals; that what a bundle's bytes decide is refused before any
// verification; that a bundle whose every marker is spent, a full bundle cap
// or a node that does not verify roots costs no verification and no failed
// proof; that a valid bundle is held after one verification and not
// verified again; and that the pool takes no account transaction, which
// keeps to the legacy pool's raw-signature bounds, nor a direct reveal.
func TestGhostPoolBundleRootAdmission(t *testing.T) {
	f := newFixture(t, 1, nil)
	verifier := new(rootCounter)
	p := f.newCountedPool(f.chain, verifier)
	fee := f.windowFee(2)
	chainID := f.gspec.Config.GetChainID().Uint64()

	// expect checks the verifications since the last call.
	expect := func(what string, reveals, roots int64) {
		t.Helper()
		if r, b := verifier.reveals.Swap(0), verifier.roots.Swap(0); r != reveals || b != roots {
			t.Fatalf("%s: %d reveal proofs and %d roots verified, want %d and %d", what, r, b, reveals, roots)
		}
	}
	// failedOf checks the failed proofs counted to a peer.
	failedOf := func(what, peer string, want int) {
		t.Helper()
		if b := peerState(p, peer); b.failed != want || b.validating != 0 {
			t.Fatalf("%s: peer %s has %d failed proofs and %d checks running, want %d and none", what, peer, b.failed, b.validating, want)
		}
	}

	// An invalid root: the root field of a bundle whose bodies are all fine
	// but whose proof is zeros. One native verification, no reveal proof,
	// refused, charged to the peer and counted as its failed proof.
	invalid := bundleTx(t, &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: chainID,
		Reveals: []*ghostpriv.Reveal{f.bundledReveal(testMarker(1), fee), f.bundledReveal(testMarker(2), fee)}})
	err := addOne(p, "peer-a", invalid)
	requireErr(t, err, ghostpriv.ErrBundleProof, "invalid root")
	if errors.Is(err, ErrPeerFailLimit) {
		t.Fatalf("invalid root: the first failed proof reached the limit: %v", err)
	}
	expect("invalid root", 0, 1)
	if p.Has(invalid.Hash()) || len(p.PendingReveals()) != 0 {
		t.Fatal("a bundle with an invalid root is held")
	}
	failedOf("invalid root", "peer-a", 1)
	if tokens := peerState(p, "peer-a").tokens; tokens != PeerRevealsPerBlock-1 {
		t.Fatalf("invalid root: peer has %d tokens left, want %d", tokens, PeerRevealsPerBlock-1)
	}
	if len(p.remoteSlots) != 0 || len(p.bundleChecks) != 0 {
		t.Fatal("the check of an invalid root kept its slot or its place")
	}

	// Sent again, by another peer or by the node, it is refused by its hash
	// with no verification; the other peer is charged but counted no failed
	// proof of the first one's.
	requireErr(t, addOne(p, "peer-b", invalid), ErrRejectedBefore, "invalid root again from another peer")
	requireErr(t, addOne(p, "", invalid), ghostpriv.ErrBundleProof, "invalid root again from the node")
	expect("invalid root sent again", 0, 0)
	failedOf("invalid root again", "peer-b", 0)
	if tokens := peerState(p, "peer-b").tokens; tokens != PeerRevealsPerBlock-1 {
		t.Fatalf("invalid root again: peer has %d tokens left, want %d", tokens, PeerRevealsPerBlock-1)
	}

	// The root binds the bodies the node reads: a valid root of the same
	// reveals in the other order is refused, after one verification.
	r3, r4 := f.bundledReveal(testMarker(3), fee), f.bundledReveal(testMarker(4), fee)
	swapped := f.bundleOf(r3, r4)
	swapped.Reveals = []*ghostpriv.Reveal{r4, r3}
	requireErr(t, addOne(p, "peer-b", bundleTx(t, swapped)), ghostpriv.ErrBundleProof, "root of the reveals in another order")
	expect("root of the reveals in another order", 0, 1)
	failedOf("root of the reveals in another order", "peer-b", 1)

	// The failed proof limit is shared with the reveals, in either order:
	// a failed reveal proof and two invalid roots, or two invalid roots and a
	// failed reveal proof, reach it at the third.
	genesisRoot := *f.genesis.Header().CoinTreeRoot
	badRoot := func(i int) *types.Transaction {
		return bundleTx(t, &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: chainID,
			Reveals: []*ghostpriv.Reveal{f.bundledReveal(testMarker(i), fee)}})
	}
	requireErr(t, addOne(p, "peer-c", f.unproven(testMarker(10), fee, genesisRoot)), ghostpriv.ErrRevealProof, "failed reveal proof")
	expect("failed reveal proof", 1, 0)
	err = addOne(p, "peer-c", badRoot(11))
	requireErr(t, err, ghostpriv.ErrBundleProof, "invalid root after a failed reveal proof")
	if errors.Is(err, ErrPeerFailLimit) {
		t.Fatalf("second failed proof reached the limit: %v", err)
	}
	err = addOne(p, "peer-c", badRoot(12))
	requireErr(t, err, ErrPeerFailLimit, "third failed proof, an invalid root")
	requireErr(t, err, ghostpriv.ErrBundleProof, "third failed proof, an invalid root")
	expect("two invalid roots", 0, 2)
	// At the limit the peer has nothing checked, a valid bundle included.
	valid := bundleTx(t, f.bundleOf(f.bundledReveal(testMarker(13), fee)))
	requireErr(t, addOne(p, "peer-c", valid), ErrPeerFailLimit, "valid bundle of a peer at the limit")
	expect("valid bundle of a peer at the limit", 0, 0)
	if p.Has(valid.Hash()) {
		t.Fatal("a peer at the limit had a bundle held")
	}

	requireErr(t, addOne(p, "peer-d", badRoot(14)), ghostpriv.ErrBundleProof, "first invalid root")
	requireErr(t, addOne(p, "peer-d", badRoot(15)), ghostpriv.ErrBundleProof, "second invalid root")
	err = addOne(p, "peer-d", f.unproven(testMarker(16), fee, genesisRoot))
	requireErr(t, err, ErrPeerFailLimit, "third failed proof, a reveal's")
	requireErr(t, err, ghostpriv.ErrRevealProof, "third failed proof, a reveal's")
	expect("two invalid roots and a failed reveal proof", 1, 2)

	// What a bundle's bytes decide is refused before any verification, the
	// peer charged but counted no failed proof, and remembered.
	foreign := f.bundledReveal(testMarker(20), fee)
	foreign.ChainID = chainID + 1
	otherChain := f.bundleOf(f.bundledReveal(testMarker(21), fee))
	otherChain.ChainID = chainID + 1
	versionTwo := f.bundleOf(f.bundledReveal(testMarker(22), fee))
	versionTwo.Version = 2
	bodyV1, err := f.bundleOf(f.bundledReveal(testMarker(23), fee)).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(bodyV1[1+types.GhostBundleFixedSize:], 1)
	for i, c := range []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"bundle of another chain", bundleTx(t, otherChain), ghostpriv.ErrBundleChainID},
		{"body of another chain", bundleTx(t, f.bundleOf(f.bundledReveal(testMarker(24), fee), foreign)), ghostpriv.ErrBundleChainID},
		{"bundle version 2", bundleTx(t, versionTwo), ghostpriv.ErrBundleVersion},
		{"version 1 body", bundleEnvelopeTx(t, bodyV1), ghostpriv.ErrBundleBody},
	} {
		peer := "peer-shape-" + string(rune('a'+i))
		requireErr(t, addOne(p, peer, c.tx), c.want, c.name)
		expect(c.name, 0, 0)
		failedOf(c.name, peer, 0)
		if tokens := peerState(p, peer).tokens; tokens != PeerRevealsPerBlock-1 {
			t.Fatalf("%s: peer has %d tokens left, want %d", c.name, tokens, PeerRevealsPerBlock-1)
		}
		requireErr(t, addOne(p, peer, c.tx), ErrRejectedBefore, c.name+" again")
		expect(c.name+" again", 0, 0)
	}

	// A bundle every one of whose markers is spent on the head would change
	// nothing: refused without its root verified, and not remembered.
	m30, m31 := testMarker(30), testMarker(31)
	spent := bundleTx(t, f.bundleOf(f.bundledReveal(m30, fee), f.bundledReveal(m31, fee)))
	p.mu.Lock()
	unspent := p.state
	st := unspent.Copy()
	for _, m := range []common.Hash{m30, m31} {
		if err := ghosttree.MarkSpent(st, ghosttree.Coin, m); err != nil {
			p.mu.Unlock()
			t.Fatal(err)
		}
	}
	p.state = st
	p.mu.Unlock()
	requireErr(t, addOne(p, "peer-e", spent), ErrBundleSpent, "bundle of spent markers")
	expect("bundle of spent markers", 0, 0)
	failedOf("bundle of spent markers", "peer-e", 0)
	if err := bundleLive(st, []common.Hash{m30, testMarker(32)}); err != nil {
		t.Fatalf("a bundle with an unspent marker is not live: %v", err)
	}
	p.mu.Lock()
	p.state = unspent
	p.mu.Unlock()

	// A node whose verifier does not verify roots refuses every bundle, but
	// it is not the peer's fault: no failed proof, nothing remembered.
	later := bundleTx(t, f.bundleOf(f.bundledReveal(testMarker(40), fee)))
	p.verifier = func() ghostpriv.Verifier { return revealsOnly{} }
	err = addOne(p, "peer-f", later)
	requireErr(t, err, ghostpriv.ErrBundleUnsupported, "bundle on a node that does not verify roots")
	if errors.Is(err, ghostpriv.ErrBundleProof) {
		t.Fatalf("an unsupported root reported as a rejected one: %v", err)
	}
	failedOf("bundle on a node that does not verify roots", "peer-f", 0)
	p.verifier = func() ghostpriv.Verifier { return verifier }

	// A valid bundle is held after one root verification and no reveal
	// proof, offered to the miner, and not verified again: not when sent
	// again, not on the recheck of a new head.
	if err := addOne(p, "peer-f", later); err != nil {
		t.Fatalf("valid bundle refused after a node without a root verifier refused it: %v", err)
	}
	expect("valid bundle", 0, 1)
	if !p.Has(later.Hash()) || p.Get(later.Hash()) != later {
		t.Fatal("valid bundle not held")
	}
	if pending := p.PendingReveals(); len(pending) != 1 || pending[0].Hash() != later.Hash() {
		t.Fatalf("pending: %d transactions, want the bundle", len(pending))
	}
	if held := peerState(p, "peer-f").held; held != 1 {
		t.Fatalf("peer holds %d transactions, want the bundle", held)
	}
	requireErr(t, addOne(p, "peer-g", later), txpool.ErrAlreadyKnown, "held bundle sent again")
	head := f.chain.CurrentBlock()
	f.reset(p, head)
	expect("held bundle sent again and rechecked", 0, 0)
	if !p.Has(later.Hash()) {
		t.Fatal("a held bundle with unspent markers was dropped on recheck")
	}

	// The bundle cap: a local bundle fills it, and the next is refused before
	// its root is verified.
	local := bundleTx(t, f.bundleOf(f.bundledReveal(testMarker(41), fee)))
	if err := addOne(p, "", local); err != nil {
		t.Fatalf("local bundle refused: %v", err)
	}
	expect("local bundle", 0, 1)
	requireErr(t, addOne(p, "peer-h", bundleTx(t, f.bundleOf(f.bundledReveal(testMarker(42), fee)))), ErrPoolFull, "bundle over the cap")
	expect("bundle over the cap", 0, 0)
	if n, _ := p.Stats(); n != MaxBundles {
		t.Fatalf("pool holds %d transactions, want %d bundles", n, MaxBundles)
	}
	p.mu.Lock()
	p.remove(local.Hash())
	if p.bundles != MaxBundles-1 {
		p.mu.Unlock()
		t.Fatalf("%d bundles counted after a removal, want %d", p.bundles, MaxBundles-1)
	}
	p.mu.Unlock()

	// An announced bundle is charged like the pool's other types: one of the
	// size of a count is fetched, one of no count's size is not.
	sized := uint32(invalid.Size())
	keep := p.FilterAnnounced("peer-i",
		[]byte{types.GhostBundleTxType, types.GhostBundleTxType, types.GhostBundleTxType},
		[]uint32{sized, sized + 1, uint32(1 + types.GhostBundleFixedSize)},
		[]common.Hash{{0x55, 1}, {0x55, 2}, {0x55, 3}})
	if !keep[0] || keep[1] || keep[2] {
		t.Fatalf("announced bundles kept %v, want only the one of a count's size", keep)
	}
	if tokens := peerState(p, "peer-i").tokens; tokens != PeerRevealsPerBlock-1 {
		t.Fatalf("announced bundle: peer has %d tokens left, want %d", tokens, PeerRevealsPerBlock-1)
	}

	// The pool takes no account transaction: it stays with the legacy pool
	// and its raw-signature bounds, charging nothing here. Nor does it take
	// a binding transaction or a direct reveal.
	signer := types.NewGhostAccountSigner(types.LatestSigner(f.gspec.Config), f.genesis.Hash())
	account := commitTx(t, poolKey, signer, 1, oneGhost)
	direct := make([]byte, types.GhostDirectRevealEnvelopeSize)
	direct[0] = types.GhostDirectRevealTxType
	binary.BigEndian.PutUint16(direct[1:], types.GhostDirectRevealVersion)
	directTx, err := types.NewGhostDirectRevealTx(direct)
	if err != nil {
		t.Fatal(err)
	}
	binding := types.NewTx(&types.GhostBindingTx{ChainID: f.gspec.Config.GetChainID(), GasTipCap: oneGhost, GasFeeCap: oneGhost, Value: oneGhost})
	for _, tx := range []*types.Transaction{account, binding, directTx} {
		if p.Filter(tx) {
			t.Fatalf("type %#x taken by the reveal pool", tx.Type())
		}
		requireErr(t, addOne(p, "peer-j", tx), core.ErrTxTypeNotSupported, "account-side transaction from a peer")
		requireErr(t, addOne(p, "", tx), core.ErrTxTypeNotSupported, "account-side transaction from the node")
	}
	p.mu.RLock()
	_, charged := p.peers["peer-j"]
	p.mu.RUnlock()
	if charged {
		t.Fatal("an account-side transaction was charged to a peer's reveal budget")
	}
	expect("account-side transactions", 0, 0)
	if !p.Filter(invalid) {
		t.Fatal("the bundle type is not the reveal pool's")
	}
}
