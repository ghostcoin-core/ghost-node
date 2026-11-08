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

//go:build cgo && (ghostrelease || ghostproofs) && (linux || darwin)

package ghostpriv_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// rootFixtureEnv names the folder the root fixture generator wrote:
//
//	cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example rootfixture -- DIR
//
// The tests of the linked root verifiers fail without it: the real root
// proofs are made at test time, never committed.
const rootFixtureEnv = "GHOST_ROOT_FIXTURE_DIR"

// Lengths of the bundle root fixture's fields before the proof: the key, the
// chain parameters, F, the coin's value and the version 2 reveal statement of
// ghost_proofs.h.
const (
	rootFixtureParams    = 42
	rootFixtureStatement = 560
	bundleFixtureHead    = ghostpriv.RootKeySize + rootFixtureParams + 32 + 32 + rootFixtureStatement
	publicFixtureHead    = ghostpriv.RootKeySize + 8 + ghostpriv.PublicBindingSize
)

// bundleRootFixture is the real test-shape bundle root of one version 2
// reveal (ghostverifier/examples/rootfixture.rs): the bundle root key, the
// chain, the spent coin's F and value, the reveal and the shrink proof.
type bundleRootFixture struct {
	key     []byte
	chainID uint64
	genesis common.Hash
	f       common.Hash
	value   *uint256.Int
	reveal  *ghostpriv.Reveal
	proof   []byte
}

// publicRootFixture is the real test-shape public root of one transaction:
// the public root key, the chain id, the binding and the shrink proof.
type publicRootFixture struct {
	key     []byte
	chainID uint64
	binding types.GhostBinding
	proof   []byte
}

func readRootFixture(t *testing.T, name string, head int) []byte {
	t.Helper()
	dir := os.Getenv(rootFixtureEnv)
	if dir == "" {
		t.Fatalf("%s is not set: run `cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example rootfixture -- DIR` and set it to DIR", rootFixtureEnv)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("root fixture: %v", err)
	}
	if len(b) <= head || len(b) > head+ghostpriv.ProofSize {
		t.Fatalf("root fixture %s of %d bytes, want %d and a proof of at most %d", name, len(b), head, ghostpriv.ProofSize)
	}
	return b
}

func loadBundleRoot(t *testing.T) *bundleRootFixture {
	t.Helper()
	b := readRootFixture(t, "bundle_root.bin", bundleFixtureHead)
	key, rest := b[:ghostpriv.RootKeySize], b[ghostpriv.RootKeySize:]
	params, rest := rest[:rootFixtureParams], rest[rootFixtureParams:]
	if v := binary.BigEndian.Uint16(params[8:10]); v != ghostpriv.RevealVersion {
		t.Fatalf("bundle root fixture of version %d", v)
	}
	fx := &bundleRootFixture{
		key:     key,
		chainID: binary.BigEndian.Uint64(params[:8]),
		genesis: common.BytesToHash(params[10:42]),
		f:       common.BytesToHash(rest[:32]),
		value:   new(uint256.Int).SetBytes(rest[32:64]),
		proof:   rest[64+rootFixtureStatement:],
	}
	s := rest[64 : 64+rootFixtureStatement]
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersion,
		ChainID:   fx.chainID,
		Root:      common.BytesToHash(s[0:32]),
		Marker:    common.BytesToHash(s[32:64]),
		Remainder: common.BytesToHash(s[64:96]),
		Recipient: common.BytesToAddress(s[476:496]),
		Out:       new(uint256.Int).SetBytes(s[496:528]),
		Fee:       new(uint256.Int).SetBytes(s[528:560]),
	}
	copy(r.Note[:], s[96:476])
	fx.reveal = r
	return fx
}

func loadPublicRoot(t *testing.T) *publicRootFixture {
	t.Helper()
	b := readRootFixture(t, "public_root.bin", publicFixtureHead)
	fx := &publicRootFixture{
		key:     b[:ghostpriv.RootKeySize],
		chainID: binary.BigEndian.Uint64(b[ghostpriv.RootKeySize:]),
		proof:   b[publicFixtureHead:],
	}
	copy(fx.binding[:], b[ghostpriv.RootKeySize+8:publicFixtureHead])
	return fx
}

// linkedRootVerifier is the linked verifier with the keys the fixture wrote.
func linkedRootVerifier(t *testing.T, b *bundleRootFixture, p *publicRootFixture) *ghostpriv.RootVerifier {
	t.Helper()
	v, err := ghostpriv.NewRootVerifier(b.key, p.key)
	if err != nil {
		t.Fatalf("the fixture's keys: %v", err)
	}
	return v
}

func flipped(b []byte, at int) []byte {
	c := common.CopyBytes(b)
	c[at] ^= 1
	return c
}

// TestLinkedRootKeys checks that the linked root verifier takes only a key of
// each root's own path and length, and that the default verifier, which has
// no key, verifies no root: it fails both roots closed, a real one too.
func TestLinkedRootKeys(t *testing.T) {
	b, p := loadBundleRoot(t), loadPublicRoot(t)
	for _, c := range []struct {
		name           string
		bundle, public []byte
	}{
		{"keys swapped", p.key, b.key},
		{"bundle key short", b.key[:ghostpriv.RootKeySize-1], p.key},
		{"public key long", b.key, append(common.CopyBytes(p.key), 0)},
		{"no bundle key", nil, p.key},
		{"no public key", b.key, nil},
	} {
		if _, err := ghostpriv.NewRootVerifier(c.bundle, c.public); !errors.Is(err, ghostpriv.ErrRootKey) {
			t.Fatalf("%s: %v, want %v", c.name, err, ghostpriv.ErrRootKey)
		}
	}

	def := ghostpriv.DefaultVerifier()
	if _, ok := def.(ghostpriv.BundleVerifier); ok {
		t.Fatal("the default verifier verifies bundle roots without a key")
	}
	if _, ok := def.(ghostpriv.PublicRootVerifier); ok {
		t.Fatal("the default verifier verifies public roots without a key")
	}
	in := ghostpriv.NewBundleInputs(b.chainID, b.genesis, []*ghostpriv.Reveal{b.reveal})
	if err := ghostpriv.VerifyBundleRoot(def, in, b.proof); !errors.Is(err, ghostpriv.ErrBundleUnsupported) {
		t.Fatalf("default verifier, real bundle root: %v, want %v", err, ghostpriv.ErrBundleUnsupported)
	}
	pin := ghostpriv.NewPublicRootInputs(p.chainID, b.genesis, []types.GhostBinding{p.binding})
	if err := ghostpriv.VerifyPublicRoot(def, pin, p.proof); !errors.Is(err, ghostpriv.ErrPublicRootUnsupported) {
		t.Fatalf("default verifier, real public root: %v, want %v", err, ghostpriv.ErrPublicRootUnsupported)
	}
}

// TestLinkedRootBundle checks the linked bundle root verifier on a real
// test-shape root: it accepts the root for the inputs the node builds from
// the bundle, and refuses a changed proof byte, a changed key, inputs of a
// changed reveal, of the reveal twice, of another chain id or genesis, and
// the public root's proof.
func TestLinkedRootBundle(t *testing.T) {
	b, p := loadBundleRoot(t), loadPublicRoot(t)
	v := linkedRootVerifier(t, b, p)
	inputs := func(chainID uint64, genesis common.Hash, reveals ...*ghostpriv.Reveal) *ghostpriv.BundleInputs {
		return ghostpriv.NewBundleInputs(chainID, genesis, reveals)
	}
	in := inputs(b.chainID, b.genesis, b.reveal)
	if err := ghostpriv.VerifyBundleRoot(v, in, b.proof); err != nil {
		t.Fatalf("the real bundle root: %v", err)
	}
	// The proof as the field carries it, padded with zeros.
	bundle := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: b.chainID, Proof: b.proof, Reveals: []*ghostpriv.Reveal{b.reveal}}
	decoded, err := ghostpriv.DecodeBundle(bundleEnvelope(t, bundle))
	if err != nil {
		t.Fatal(err)
	}
	if err := ghostpriv.VerifyBundleRoot(v, decoded.Inputs(b.chainID, b.genesis), decoded.Proof); err != nil {
		t.Fatalf("the real bundle root from its envelope: %v", err)
	}

	changedOut, changedNote, changedMarker := clone(b.reveal), clone(b.reveal), clone(b.reveal)
	changedOut.Out = new(uint256.Int).AddUint64(b.reveal.Out, 1)
	changedNote.Note[100] ^= 1
	changedMarker.Marker[0] ^= 1
	otherKey := linkedRootVerifierWith(t, flipped(b.key, 4*13), p.key)
	for _, c := range []struct {
		name     string
		verifier ghostpriv.Verifier
		in       *ghostpriv.BundleInputs
		proof    []byte
	}{
		{"proof byte 0", v, in, flipped(b.proof, 0)},
		{"proof byte in the middle", v, in, flipped(b.proof, len(b.proof)/2)},
		{"last proof byte", v, in, flipped(b.proof, len(b.proof)-1)},
		{"padding byte", v, in, append(common.CopyBytes(b.proof), 1)},
		{"key word", otherKey, in, b.proof},
		{"out", v, inputs(b.chainID, b.genesis, changedOut), b.proof},
		{"note", v, inputs(b.chainID, b.genesis, changedNote), b.proof},
		{"marker", v, inputs(b.chainID, b.genesis, changedMarker), b.proof},
		{"the reveal twice", v, inputs(b.chainID, b.genesis, b.reveal, b.reveal), b.proof},
		{"another chain id", v, inputs(b.chainID+1, b.genesis, b.reveal), b.proof},
		{"another genesis", v, inputs(b.chainID, common.Hash{0x0d}, b.reveal), b.proof},
		{"the public root's proof", v, in, p.proof},
	} {
		err := ghostpriv.VerifyBundleRoot(c.verifier, c.in, c.proof)
		if !errors.Is(err, ghostpriv.ErrBundleProof) || !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Fatalf("%s: %v, want %v", c.name, err, ghostpriv.ErrBundleProof)
		}
	}
}

func linkedRootVerifierWith(t *testing.T, bundleKey, publicKey []byte) *ghostpriv.RootVerifier {
	t.Helper()
	v, err := ghostpriv.NewRootVerifier(bundleKey, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestLinkedRootPublic checks the linked public root verifier on a real
// test-shape root: it accepts the root for the inputs the node builds from
// the binding, and refuses a changed proof byte, a changed key, a changed
// account, key identity or transaction hash, the binding twice, another
// chain id and the bundle root's proof.
func TestLinkedRootPublic(t *testing.T) {
	b, p := loadBundleRoot(t), loadPublicRoot(t)
	v := linkedRootVerifier(t, b, p)
	inputs := func(chainID uint64, bindings ...types.GhostBinding) *ghostpriv.PublicRootInputs {
		return ghostpriv.NewPublicRootInputs(chainID, b.genesis, bindings)
	}
	in := inputs(p.chainID, p.binding)
	if err := ghostpriv.VerifyPublicRoot(v, in, p.proof); err != nil {
		t.Fatalf("the real public root: %v", err)
	}
	changed := func(at int) types.GhostBinding {
		c := p.binding
		c[at] ^= 1
		return c
	}
	otherKey := linkedRootVerifierWith(t, b.key, flipped(p.key, 4*22))
	for _, c := range []struct {
		name     string
		verifier ghostpriv.Verifier
		in       *ghostpriv.PublicRootInputs
		proof    []byte
	}{
		{"proof byte 0", v, in, flipped(p.proof, 0)},
		{"last proof byte", v, in, flipped(p.proof, len(p.proof)-1)},
		{"key word", otherKey, in, p.proof},
		{"account", v, inputs(p.chainID, changed(0)), p.proof},
		{"key identity", v, inputs(p.chainID, changed(30)), p.proof},
		{"transaction hash", v, inputs(p.chainID, changed(83)), p.proof},
		{"the binding twice", v, inputs(p.chainID, p.binding, p.binding), p.proof},
		{"another chain id", v, inputs(p.chainID+1, p.binding), p.proof},
		{"the bundle root's proof", v, in, b.proof},
	} {
		err := ghostpriv.VerifyPublicRoot(c.verifier, c.in, c.proof)
		if !errors.Is(err, ghostpriv.ErrPublicRootProof) || !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Fatalf("%s: %v, want %v", c.name, err, ghostpriv.ErrPublicRootProof)
		}
	}
}

// TestLinkedRootBundleBlock checks a block carrying the real bundle root
// under the linked verifier: on a chain whose block 1 commits the bundled
// reveal's coin, block 2 carrying the bundle imports and applies the reveal;
// the same block 2 with one byte of the root proof changed is invalid, and
// under the default verifier, which has no root key, the good block 2 is
// invalid too.
func TestLinkedRootBundleBlock(t *testing.T) {
	b, p := loadBundleRoot(t), loadPublicRoot(t)
	restore := ghostpriv.SetVerifier(linkedRootVerifier(t, b, p))
	t.Cleanup(restore)

	f := newFixture(t, 5*ghostpriv.GasPriv, nil)
	if b.chainID != f.chainID || b.genesis != f.genesis.Hash() {
		t.Fatalf("the fixture is for chain %d, genesis %x; the test chain is chain %d, genesis %x: set CHAIN_ID and GENESIS_HEX in ghostverifier/examples/rootfixture.rs",
			b.chainID, b.genesis, f.chainID, f.genesis.Hash())
	}
	c := coin{f: b.f, value: b.value, note: testNote(1)}
	bundle := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: f.chainID, Proof: b.proof, Reveals: []*ghostpriv.Reveal{b.reveal}}
	good := bundleTx(t, bundle)
	bad, err := types.NewGhostBundleTx(flipped(bundleEnvelope(t, bundle), 1+types.GhostBundleHeaderSize+len(b.proof)/2))
	if err != nil {
		t.Fatal(err)
	}
	build := func(tx *types.Transaction, checked bool) []*types.Block {
		blocks, _ := f.generate(2, func(i int, g *core.BlockGen) {
			switch i {
			case 0:
				g.AddTx(f.commitTx(keyA, 0, c))
			case 1:
				if root := genParentRoot(g); root != b.reveal.Root {
					t.Fatalf("block 1's coin root %x is not the fixture reveal's %x", root, b.reveal.Root)
				}
				if fee := genWindowFee(t, g); !fee.Total.Eq(b.reveal.Fee) {
					t.Fatalf("the fixture reveal pays %v, the window fee of block 2 is %v: set FEE in ghostverifier/examples/rootfixture.rs", b.reveal.Fee, fee.Total)
				}
				g.SetCoinbase(bundleMiner)
				if checked {
					g.AddTx(tx)
				} else {
					g.AddUncheckedTx(tx)
				}
			}
		})
		return blocks
	}

	// The good block imports and applies the reveal.
	blocks := build(good, true)
	chain := f.newChain()
	f.insert(chain, blocks)
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks[1].Transactions()) != 1 {
		t.Fatal("block 2 does not carry the bundle")
	}
	if !ghosttree.IsSpent(st, ghosttree.Coin, b.reveal.Marker) || !st.GetBalance(b.reveal.Recipient).Eq(b.reveal.Out) {
		t.Fatal("the real bundle was not applied")
	}

	insertBad := func(name string, blocks []*types.Block, want error) {
		t.Helper()
		chain := f.newChain()
		f.insert(chain, blocks[:1])
		if _, err := chain.InsertChain(blocks[1:]); !errors.Is(err, want) {
			t.Fatalf("%s: block 2 imported with %v, want %v", name, err, want)
		}
		if chain.CurrentBlock().Hash() != blocks[0].Hash() {
			t.Fatalf("%s: the head moved", name)
		}
	}
	insertBad("changed root proof byte", build(bad, false), ghostpriv.ErrBundleProof)

	ghostpriv.SetVerifier(nil)
	insertBad("default verifier", blocks, ghostpriv.ErrBundleUnsupported)
}
