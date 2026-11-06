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
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
)

// rootVerifier is the stub verifier counting the public root proofs it
// verifies.
type rootVerifier struct {
	ghostprivtest.Verifier
	roots atomic.Int64
}

func (v *rootVerifier) VerifyPublicRoot(in *ghostpriv.PublicRootInputs, proof []byte) error {
	v.roots.Add(1)
	return v.Verifier.VerifyPublicRoot(in, proof)
}

// revealsOnly is a verifier of reveals that is no public root verifier.
type revealsOnly struct{}

func (revealsOnly) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	return ghostprivtest.Verifier{}.VerifyReveal(in, proof)
}

// newRootFixture is a chain whose block 2 registers the key of the pool
// tests' account, imported up to it.
func newRootFixture(t *testing.T) *fixture {
	t.Helper()
	f := newSpec(t)
	signer := types.NewGhostAccountSigner(types.LatestSigner(f.gspec.Config), f.genesis.Hash())
	registry := types.GhostKeyRegistryAccount
	register := signAccountTransfer(signer, poolKey, 1, &registry, new(big.Int), big.NewInt(1_000_000_000), big.NewInt(100_000_000_000), 30_000+accountTxExtraGas, nil)
	f.generate(2, func(i int, b *core.BlockGen) { b.AddTx(register) })
	f.insert(2)
	st, err := f.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if types.GhostRecordedKeyIdentity(st, poolAddr) != poolIdentity() {
		t.Fatal("block 2 did not record the key of the pool tests' account")
	}
	return f
}

// poolIdentity is the key identity of the pool tests' account.
func poolIdentity() common.Hash {
	_, pub, _ := testAccount(0x01)
	return types.GhostAccountKeyIdentityOf(types.GhostSchemeMLDSA44, pub)
}

// rootBinding is a binding of account and identity for the synthetic
// transaction hash of n.
func rootBinding(account common.Address, identity common.Hash, n int) types.GhostBinding {
	return types.NewGhostBinding(account, identity, ghosttree.K("ghost/test-binding-tx", []byte(fmt.Sprintf("synthetic tx %d", n))))
}

// publicRoot is the public root of bindings on chainID with proof; a nil
// proof is the stub proof of the root's own inputs on the fixture's chain.
func (f *fixture) publicRoot(chainID uint64, proof []byte, bindings ...types.GhostBinding) *types.Transaction {
	f.t.Helper()
	r := &ghostpriv.PublicRoot{Version: ghostpriv.PublicRootVersion, ChainID: chainID, Proof: proof, Bindings: bindings}
	if proof == nil {
		r.Proof = ghostprivtest.PublicRootProof(r.Inputs(chainID, f.genesis.Hash()).Binding)
	}
	env, err := r.MarshalBinary()
	if err != nil {
		f.t.Fatal(err)
	}
	tx, err := types.NewGhostPublicRootTx(env)
	if err != nil {
		f.t.Fatal(err)
	}
	return tx
}

// badProof is a root proof that verifies for no inputs: a nonzero field
// that is no stub proof.
func badProof() []byte {
	p := make([]byte, ghostpriv.ProofSize)
	p[0] = 0x01
	return p
}

// TestGhostPoolRefusesInvalidPublicRootWithOneVerification checks the pool
// admission of a public root (0x56): a root whose proof is invalid costs
// exactly one native verification and is refused with ErrPublicRootProof,
// a failed proof of its peer, and is refused again without any verification
// from any peer or the node; a root refused by its shape, its chain id, a
// count no block holds or a key identity that is not the recorded one is
// refused without any verification; a valid root is verified once and never
// held; a node with no public root verifier fails closed without remembering
// the root; and a peer at the failed proof limit is refused.
func TestGhostPoolRefusesInvalidPublicRootWithOneVerification(t *testing.T) {
	f := newRootFixture(t)
	verifier := new(rootVerifier)
	p := f.newCountedPool(f.chain, verifier)
	chainID := f.gspec.Config.GetChainID().Uint64()
	id := poolIdentity()
	_, _, stranger := testAccount(0x7e)

	if !p.Filter(f.publicRoot(chainID, nil, rootBinding(poolAddr, id, 0))) {
		t.Fatal("the pool's Filter does not take a public root")
	}

	refusedWith := func(what, peer string, tx *types.Transaction, want error, checks int64) error {
		t.Helper()
		verifier.roots.Store(0)
		err := addOne(p, peer, tx)
		requireErr(t, err, want, what)
		if got := verifier.roots.Load(); got != checks {
			t.Fatalf("%s: %d root proofs verified, want %d", what, got, checks)
		}
		if p.Has(tx.Hash()) {
			t.Fatalf("%s: the pool holds the root", what)
		}
		return err
	}

	// An invalid proof: one verification, refused, a failed proof of the peer.
	invalid := f.publicRoot(chainID, badProof(), rootBinding(poolAddr, id, 1))
	err := refusedWith("invalid root proof", "peer-a", invalid, ghostpriv.ErrPublicRootProof, 1)
	if errors.Is(err, ErrPeerFailLimit) {
		t.Fatal("one failed proof reached the peer's limit")
	}
	p.mu.RLock()
	failedA := p.peers["peer-a"].failed
	p.mu.RUnlock()
	if failedA != 1 {
		t.Fatalf("peer-a has %d failed proofs, want 1", failedA)
	}
	// Again, from the peer, another and the node: no verification.
	for _, peer := range []string{"peer-a", "peer-b", ""} {
		err := refusedWith("invalid root again from "+peer, peer, invalid, ErrRejectedBefore, 0)
		requireErr(t, err, ghostpriv.ErrPublicRootProof, "invalid root again from "+peer)
	}
	// A proof of another chain's domain is as invalid.
	otherDomain := ghostprivtest.PublicRootProof(ghostpriv.NewPublicRootInputs(chainID, common.Hash{0x0d}, []types.GhostBinding{rootBinding(poolAddr, id, 2)}).Binding)
	refusedWith("root proof of another domain", "", f.publicRoot(chainID, otherDomain, rootBinding(poolAddr, id, 2)), ghostpriv.ErrPublicRootProof, 1)

	// The checks that verify nothing come first.
	tooMany := make([]types.GhostBinding, f.chain.CurrentBlock().GasLimit/minBindingTxGas()+1)
	for i := range tooMany {
		tooMany[i] = rootBinding(poolAddr, id, 100+i)
	}
	for _, c := range []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"root of another chain", f.publicRoot(chainID+1, badProof(), rootBinding(poolAddr, id, 3)), ghostpriv.ErrPublicRootChainID},
		{"binding of an account with no key recorded", f.publicRoot(chainID, badProof(), rootBinding(stranger, id, 4)), ghostpriv.ErrPublicKeyIdentity},
		{"binding of another key identity", f.publicRoot(chainID, badProof(), rootBinding(poolAddr, common.Hash{0x1d}, 5)), ghostpriv.ErrPublicKeyIdentity},
		{"a later binding of another key identity", f.publicRoot(chainID, badProof(), rootBinding(poolAddr, id, 6), rootBinding(poolAddr, common.Hash{0x1d}, 7)), ghostpriv.ErrPublicKeyIdentity},
		{"more bindings than a block holds", f.publicRoot(chainID, badProof(), tooMany...), ghostpriv.ErrPublicRootCount},
	} {
		refusedWith(c.name+" from a peer", "peer-c-"+c.name, c.tx, c.want, 0)
		refusedWith(c.name+" from the node", "", c.tx, c.want, 0)
		// None of these is held against a peer as a failed proof.
		p.mu.RLock()
		failed := p.peers["peer-c-"+c.name].failed
		p.mu.RUnlock()
		if failed != 0 {
			t.Fatalf("%s: %d failed proofs counted to the peer", c.name, failed)
		}
	}
	badVersion := f.publicRoot(chainID, badProof(), rootBinding(poolAddr, id, 8))
	env := badVersion.GhostPublicRootEnvelope()
	env[2] = 0x02 // version 2
	badVersion, err = types.NewGhostPublicRootTx(env)
	if err != nil {
		t.Fatal(err)
	}
	refusedWith("root of another version", "", badVersion, ghostpriv.ErrPublicRootVersion, 0)
	refusedWith("root of another version again", "", badVersion, ErrRejectedBefore, 0)

	// A valid root is verified once and never held, and costs nothing again.
	valid := f.publicRoot(chainID, nil, rootBinding(poolAddr, id, 9), rootBinding(poolAddr, id, 10))
	refusedWith("valid root", "peer-d", valid, ErrPublicRootNotPooled, 1)
	refusedWith("valid root again", "", valid, ErrRejectedBefore, 0)
	p.mu.RLock()
	failedD := p.peers["peer-d"].failed
	p.mu.RUnlock()
	if failedD != 0 {
		t.Fatalf("a valid root counted %d failed proofs to its peer", failedD)
	}
	if run, _ := p.Stats(); run != 0 || len(p.PendingReveals()) != 0 {
		t.Fatalf("the pool holds %d transactions after the roots, want none", run)
	}

	// A node with no public root verifier fails closed, verifies nothing and
	// forgets the root, which it verifies once it has one.
	unsupported := f.publicRoot(chainID, badProof(), rootBinding(poolAddr, id, 11))
	p.verifier = func() ghostpriv.Verifier { return revealsOnly{} }
	err = refusedWith("root on a node without a public root verifier", "peer-e", unsupported, ghostpriv.ErrPublicRootUnsupported, 0)
	if errors.Is(err, ghostpriv.ErrPublicRootProof) {
		t.Fatal("a node without a public root verifier counted a failed proof")
	}
	p.verifier = func() ghostpriv.Verifier { return verifier }
	refusedWith("root on the node with a verifier", "peer-e", unsupported, ghostpriv.ErrPublicRootProof, 1)

	// A peer whose root proofs fail PeerMaxFailedProofs times on one head is
	// refused with ErrPeerFailLimit, each root at one verification.
	for i := 0; i < PeerMaxFailedProofs; i++ {
		err := refusedWith(fmt.Sprintf("invalid root %d of peer-f", i), "peer-f", f.publicRoot(chainID, badProof(), rootBinding(poolAddr, id, 20+i)), ghostpriv.ErrPublicRootProof, 1)
		if limit := errors.Is(err, ErrPeerFailLimit); limit != (i == PeerMaxFailedProofs-1) {
			t.Fatalf("invalid root %d of peer-f: fail limit %v", i, limit)
		}
	}
	refusedWith("root of a peer at its limit", "peer-f", f.publicRoot(chainID, nil, rootBinding(poolAddr, id, 30)), ErrPeerFailLimit, 0)

	// Through the transaction pool: the ghost pool takes the root, the
	// legacy pool does not, and the invalid root is refused unverified.
	config := legacypool.DefaultConfig
	config.Journal = ""
	legacy := legacypool.New(config, f.chain)
	if legacy.Filter(invalid) {
		t.Fatal("the legacy pool takes a public root")
	}
	pool, err := txpool.New(config.PriceLimit, f.chain, []txpool.SubPool{legacy, p})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	verifier.roots.Store(0)
	requireErr(t, pool.Add([]*types.Transaction{invalid}, true, true)[0], ErrRejectedBefore, "invalid root through the transaction pool")
	if got := verifier.roots.Load(); got != 0 || pool.Has(invalid.Hash()) {
		t.Fatalf("invalid root through the transaction pool: %d verifications, held %v", got, pool.Has(invalid.Hash()))
	}
}
