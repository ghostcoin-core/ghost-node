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
