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

package ghostprivtest_test

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// The offset of the coin type in a coin reveal's binding input: after the
// chain id (8), the version (2), the domain (32) and the statement and its
// version (2).
const bindingTypeOffset = 8 + 2 + 32 + 2

// fixedReveal is a version 2 coin reveal with every field set.
func fixedReveal() *ghostpriv.Reveal {
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersion,
		ChainID:   7,
		Marker:    common.HexToHash("0x11"),
		Root:      common.HexToHash("0x22"),
		Remainder: common.HexToHash("0x33"),
		Recipient: common.HexToAddress("0x44"),
		Out:       uint256.NewInt(5000),
		Fee:       uint256.NewInt(21),
	}
	r.Note[0], r.Note[ghostpriv.NoteSize-1] = 0x55, 0x66
	return r
}

// proofUnder returns a stub-shaped proof under another tag.
func proofUnder(tag string, binding common.Hash) []byte {
	proof := make([]byte, ghostpriv.ProofSize)
	k := ghosttree.K(tag, binding[:])
	copy(proof, k[:])
	return proof
}

// The version 2 coin reveal has one binding, of type COIN version 2; the
// stub accepts its stub and nothing else, not the stub of the same input
// with the version 1 type 0x01 0x01.
func TestStubAcceptsSaltedCoinBinding(t *testing.T) {
	genesis := common.HexToHash("0x99")
	r := fixedReveal()
	in := r.VerifyInputs(r.ChainID, genesis)

	bin := r.BindingInput(r.ChainID, genesis)
	if got := bin[bindingTypeOffset : bindingTypeOffset+2]; !bytes.Equal(got, ghostpriv.CoinV2[:]) {
		t.Fatalf("binding type %x, want %x", got, ghostpriv.CoinV2)
	}
	binding := r.BindingDigest(r.ChainID, genesis)
	if want := ghosttree.K(ghostpriv.TagRevealBinding, bin); binding != want || in.Binding != want {
		t.Fatalf("binding %x, want %x", binding, want)
	}
	v1In := bytes.Clone(bin)
	copy(v1In[bindingTypeOffset:], ghostpriv.Coin[:])
	v1 := ghosttree.K(ghostpriv.TagRevealBinding, v1In)

	var v ghostprivtest.Verifier
	if err := v.VerifyReveal(in, ghostprivtest.Proof(binding)); err != nil {
		t.Errorf("stub rejected: %v", err)
	}
	for name, proof := range map[string][]byte{
		"zero proof":           make([]byte, ghostpriv.ProofSize),
		"version 1 type":       ghostprivtest.Proof(v1),
		"under bad tag":        proofUnder("ghost/test-proof/v2", binding),
		"under the binding":    proofUnder(ghostpriv.TagRevealBinding, binding),
		"untagged":             append(binding.Bytes(), make([]byte, ghostpriv.ProofSize-32)...),
		"short of the field":   ghostprivtest.Proof(binding)[:ghostpriv.ProofSize-1],
		"another reveal's tag": ghostprivtest.Proof(ghosttree.K(ghostpriv.TagPolicyRevealBinding, bin)),
	} {
		if err := v.VerifyReveal(in, proof); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// A stub with a stray byte after the digest is not the stub.
	stray := ghostprivtest.Proof(binding)
	stray[ghostpriv.ProofSize-1] = 1
	if err := v.VerifyReveal(in, stray); err == nil {
		t.Error("stub with a nonzero tail accepted")
	}

	// The stub of one reveal does not verify another: change the out, or
	// one byte of the 380-byte note.
	other := fixedReveal()
	other.Out = uint256.NewInt(5001)
	if err := v.VerifyReveal(other.VerifyInputs(other.ChainID, genesis), ghostprivtest.Proof(binding)); err == nil {
		t.Error("stub of another reveal accepted")
	}
	other = fixedReveal()
	other.Note[200] ^= 1
	if err := v.VerifyReveal(other.VerifyInputs(other.ChainID, genesis), ghostprivtest.Proof(binding)); err == nil {
		t.Error("stub of a reveal with another note accepted")
	}
}

// fixedRevealV1 is a version 1 coin reveal with every field set and its
// 156-byte note.
func fixedRevealV1() *ghostpriv.Reveal {
	r := fixedReveal()
	r.Version = ghostpriv.RevealVersionV1
	r.Note = [ghostpriv.NoteSize]byte{}
	r.Note[0], r.Note[ghostpriv.RevealNoteSize-1] = 0x55, 0x66
	return r
}

// The version 1 coin reveal keeps its two bindings: the stub accepts the
// stub of its unsalted (type COIN version 1) binding and of its salted (type
// COIN version 2) binding, as the real verifier accepts both, and nothing
// else; neither verifies the version 2 reveal of the same fields.
func TestStubAcceptsSaltedCoinBindingV1(t *testing.T) {
	genesis := common.HexToHash("0x99")
	r := fixedRevealV1()
	in := r.VerifyInputs(r.ChainID, genesis)
	if in.Version != ghostpriv.RevealVersionV1 {
		t.Fatalf("inputs version %d", in.Version)
	}

	// The salted binding is the version 1 input with the type 0x02 0x01.
	v1In := r.BindingInput(r.ChainID, genesis)
	if len(v1In) != ghostpriv.BindingSizeV1 || ghostpriv.BindingSizeV1 != 415 {
		t.Fatalf("version 1 binding input of %d bytes", len(v1In))
	}
	if got := v1In[bindingTypeOffset : bindingTypeOffset+2]; !bytes.Equal(got, ghostpriv.Coin[:]) {
		t.Fatalf("version 1 binding type %x, want %x", got, ghostpriv.Coin)
	}
	saltedIn := bytes.Clone(v1In)
	copy(saltedIn[bindingTypeOffset:], ghostpriv.CoinV2[:])
	v1 := r.BindingDigest(r.ChainID, genesis)
	salted := r.SaltedBindingDigest(r.ChainID, genesis)
	if want := ghosttree.K(ghostpriv.TagRevealBindingV1, v1In); v1 != want || in.Binding != want {
		t.Fatalf("version 1 binding %x, want %x", v1, want)
	}
	if want := ghosttree.K(ghostpriv.TagRevealBindingV1, saltedIn); salted != want {
		t.Fatalf("salted binding %x, want %x", salted, want)
	}
	if v1 == salted {
		t.Fatal("unsalted and salted bindings are equal")
	}

	var v ghostprivtest.Verifier
	if err := v.VerifyReveal(in, ghostprivtest.Proof(v1)); err != nil {
		t.Errorf("version 1 stub rejected: %v", err)
	}
	if err := v.VerifyReveal(in, ghostprivtest.Proof(salted)); err != nil {
		t.Errorf("salted stub rejected: %v", err)
	}
	for name, proof := range map[string][]byte{
		"zero proof":              make([]byte, ghostpriv.ProofSize),
		"under bad tag":           proofUnder("ghost/test-proof/v2", v1),
		"salted under bad tag":    proofUnder("ghost/test-proof/v2", salted),
		"salted under real tag":   proofUnder(ghostpriv.TagRevealBindingV1, salted),
		"salted untagged":         append(salted.Bytes(), make([]byte, ghostpriv.ProofSize-32)...),
		"the version 2 tag's":     ghostprivtest.Proof(ghosttree.K(ghostpriv.TagRevealBinding, v1In)),
		"salted, nonzero padding": append(ghostprivtest.Proof(salted)[:ghostpriv.ProofSize-1], 1),
	} {
		if err := v.VerifyReveal(in, proof); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// The stubs of the version 1 reveal do not verify the version 2 reveal
	// of the same fields, nor another version 1 reveal.
	v2 := fixedRevealV1()
	v2.Version = ghostpriv.RevealVersion
	for _, p := range []common.Hash{v1, salted} {
		if err := v.VerifyReveal(v2.VerifyInputs(v2.ChainID, genesis), ghostprivtest.Proof(p)); err == nil {
			t.Error("version 1 stub accepted for the version 2 reveal")
		}
	}
	other := fixedRevealV1()
	other.Out = uint256.NewInt(5001)
	if err := v.VerifyReveal(other.VerifyInputs(other.ChainID, genesis), ghostprivtest.Proof(salted)); err == nil {
		t.Error("salted stub of another reveal accepted")
	}

	// A data reveal has no salted binding: the coin's salted stub does not
	// verify it, while its own stub still does.
	data := *in
	data.Kind = ghosttree.Data
	if err := v.VerifyReveal(&data, ghostprivtest.Proof(salted)); err == nil {
		t.Error("coin salted stub accepted for a data reveal")
	}
	if err := v.VerifyReveal(&data, ghostprivtest.Proof(v1)); err != nil {
		t.Errorf("data reveal stub rejected: %v", err)
	}
}
