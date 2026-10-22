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

// fixedReveal is a coin reveal with every field set.
func fixedReveal() *ghostpriv.Reveal {
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
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

// coinInputs returns the inputs CheckReveal gives the verifier for r.
func coinInputs(r *ghostpriv.Reveal, genesis common.Hash) *ghostpriv.VerifyInputs {
	return &ghostpriv.VerifyInputs{
		Kind:      ghosttree.Coin,
		Purpose:   ghostpriv.PurposeReveal,
		Binding:   r.BindingDigest(r.ChainID, genesis),
		ChainID:   r.ChainID,
		Domain:    genesis,
		Root:      r.Root,
		Marker:    r.Marker,
		Remainder: r.Remainder,
		Recipient: r.Recipient,
		Out:       new(uint256.Int).Set(r.Out),
		Fee:       new(uint256.Int).Set(r.Fee),
		Note:      r.Note,
	}
}

// proofUnder returns a stub-shaped proof under another tag.
func proofUnder(tag string, binding common.Hash) []byte {
	proof := make([]byte, ghostpriv.ProofSize)
	k := ghosttree.K(tag, binding[:])
	copy(proof, k[:])
	return proof
}

// The stub accepts the stub of a coin reveal's unsalted (V1) binding and of
// its salted (V2) binding, as the real verifier accepts both, and nothing
// else.
func TestStubAcceptsSaltedCoinBinding(t *testing.T) {
	genesis := common.HexToHash("0x99")
	r := fixedReveal()
	in := coinInputs(r, genesis)

	// The V2 binding is the V1 input with the type 0x02 0x01.
	v1In := r.BindingInput(r.ChainID, genesis)
	if got := v1In[bindingTypeOffset : bindingTypeOffset+2]; !bytes.Equal(got, ghostpriv.Coin[:]) {
		t.Fatalf("V1 binding type %x, want %x", got, ghostpriv.Coin)
	}
	v2In := bytes.Clone(v1In)
	copy(v2In[bindingTypeOffset:], ghostpriv.CoinV2[:])
	v1 := r.BindingDigest(r.ChainID, genesis)
	v2 := r.SaltedBindingDigest(r.ChainID, genesis)
	if want := ghosttree.K(ghostpriv.TagRevealBinding, v1In); v1 != want {
		t.Fatalf("V1 binding %x, want %x", v1, want)
	}
	if want := ghosttree.K(ghostpriv.TagRevealBinding, v2In); v2 != want {
		t.Fatalf("V2 binding %x, want %x", v2, want)
	}
	if v1 == v2 {
		t.Fatal("V1 and V2 bindings are equal")
	}

	var v ghostprivtest.Verifier
	if err := v.VerifyReveal(in, ghostprivtest.Proof(v1)); err != nil {
		t.Errorf("V1 stub rejected: %v", err)
	}
	if err := v.VerifyReveal(in, ghostprivtest.Proof(v2)); err != nil {
		t.Errorf("V2 stub rejected: %v", err)
	}

	for name, proof := range map[string][]byte{
		"zero proof":        make([]byte, ghostpriv.ProofSize),
		"V1 under bad tag":  proofUnder("ghost/test-proof/v2", v1),
		"V2 under bad tag":  proofUnder("ghost/test-proof/v2", v2),
		"V2 under real tag": proofUnder(ghostpriv.TagRevealBinding, v2),
		"V2 untagged":       append(v2.Bytes(), make([]byte, ghostpriv.ProofSize-32)...),
	} {
		if err := v.VerifyReveal(in, proof); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// A V2 stub with a stray byte after the digest is not the stub.
	stray := ghostprivtest.Proof(v2)
	stray[ghostpriv.ProofSize-1] = 1
	if err := v.VerifyReveal(in, stray); err == nil {
		t.Error("V2 stub with a nonzero tail accepted")
	}

	// The V2 stub of one reveal does not verify another: change the out.
	other := fixedReveal()
	other.Out = uint256.NewInt(5001)
	if err := v.VerifyReveal(coinInputs(other, genesis), ghostprivtest.Proof(v2)); err == nil {
		t.Error("V2 stub of another reveal accepted")
	}

	// A data reveal has no salted binding: the coin V2 stub does not verify
	// it, while its own stub still does.
	data := &ghostpriv.VerifyInputs{
		Kind:      ghosttree.Data,
		Purpose:   ghostpriv.PurposeReveal,
		Binding:   v1,
		ChainID:   in.ChainID,
		Domain:    in.Domain,
		Root:      in.Root,
		Marker:    in.Marker,
		Remainder: in.Remainder,
		Recipient: in.Recipient,
		Out:       in.Out,
		Fee:       in.Fee,
		Note:      in.Note,
	}
	if err := v.VerifyReveal(data, ghostprivtest.Proof(v2)); err == nil {
		t.Error("coin V2 stub accepted for a data reveal")
	}
	if err := v.VerifyReveal(data, ghostprivtest.Proof(v1)); err != nil {
		t.Errorf("data reveal stub rejected: %v", err)
	}
}
