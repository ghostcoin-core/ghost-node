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
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

var (
	preimageChainID = uint64(6777972)
	preimageGenesis = common.HexToHash("0x9e6e515e00000000000000000000000000000000000000000000000000000001")
	preimagePolicy  = common.HexToAddress("0x00000000000000000000000000000000c0ffee01")
)

// testPreimage returns a statement over y = K(tag, x) for a fixed x and a
// context of distinct bytes.
func testPreimage() *ghostpriv.Preimage {
	p := &ghostpriv.Preimage{Y: ghostpriv.PreimageY(common.HexToHash("0x5ec2e7"))}
	for i := range p.Context {
		p.Context[i] = byte(0x80 + i)
	}
	return p
}

// TestPreimageBindingLayout checks the statement constants, the 161 bytes
// of the binding input field by field, the digest's tag, and that the
// checker input of 917,601 bytes decodes back to the statement.
func TestPreimageBindingLayout(t *testing.T) {
	if ghostpriv.StatementPreimage != 0x06 || ghostpriv.PurposePreimage != 0x07 || ghostpriv.PreimageVersion != 1 {
		t.Fatalf("statement %#x, purpose %#x, version %d", ghostpriv.StatementPreimage, ghostpriv.PurposePreimage, ghostpriv.PreimageVersion)
	}
	if size := ghostpriv.PreimageInputSize; size != 917_601 {
		t.Fatalf("checker input of %d bytes, want 917,601", size)
	}
	if size := 1 + 32 + 64 + ghostpriv.ActionProofSize; size != ghostpriv.PreimageInputSize {
		t.Fatalf("statement, y, context and the action's proof field make %d bytes", size)
	}
	x := common.HexToHash("0x5ec2e7")
	if got, want := ghostpriv.PreimageY(x), ghosttree.K("ghost/policy-preimage/v1", x[:]); got != want {
		t.Fatalf("y %x, want %x", got, want)
	}

	p := testPreimage()
	in := p.BindingInput(preimageChainID, preimageGenesis, preimagePolicy)
	if ghostpriv.PreimageBindingSize != 161 {
		t.Fatalf("binding size constant %d, want 161", ghostpriv.PreimageBindingSize)
	}
	if len(in) != 161 {
		t.Fatalf("binding input of %d bytes, want 161", len(in))
	}
	var want []byte
	want = binary.BigEndian.AppendUint64(want, preimageChainID)
	want = append(want, 0x00, 0x01)
	want = append(want, preimageGenesis[:]...)
	want = append(want, 0x06, 0x01, 0x07)
	want = append(want, preimagePolicy[:]...)
	want = append(want, p.Y[:]...)
	want = append(want, p.Context[:]...)
	if !bytes.Equal(in, want) {
		t.Fatalf("binding input\n have %x\n want %x", in, want)
	}
	digest := p.BindingDigest(preimageChainID, preimageGenesis, preimagePolicy)
	if digest != ghosttree.K("ghost/preimage-binding/v1", want) {
		t.Fatal("binding digest is not K(\"ghost/preimage-binding/v1\", input)")
	}
	// Every field the node supplies or the statement carries moves the digest.
	q := testPreimage()
	q.Context[63] ^= 1
	r := testPreimage()
	r.Y[0] ^= 1
	for name, other := range map[string]common.Hash{
		"chain id": p.BindingDigest(preimageChainID+1, preimageGenesis, preimagePolicy),
		"genesis":  p.BindingDigest(preimageChainID, common.Hash{1}, preimagePolicy),
		"policy":   p.BindingDigest(preimageChainID, preimageGenesis, common.Address{1}),
		"context":  q.BindingDigest(preimageChainID, preimageGenesis, preimagePolicy),
		"y":        r.BindingDigest(preimageChainID, preimageGenesis, preimagePolicy),
	} {
		if other == digest {
			t.Errorf("the %s is not bound", name)
		}
	}

	// The verifier's inputs carry the statement and nothing else.
	vin := p.VerifyInputs(preimageChainID, preimageGenesis, preimagePolicy)
	if vin.Kind != ghosttree.Coin || vin.Purpose != ghostpriv.PurposePreimage || vin.Binding != digest ||
		vin.ChainID != preimageChainID || vin.Domain != preimageGenesis || vin.Policy != preimagePolicy ||
		vin.Y != p.Y || vin.Context != p.Context || vin.Marker != (common.Hash{}) || vin.CalldataHash != (common.Hash{}) {
		t.Fatalf("verify inputs %+v", vin)
	}

	// The checker input round-trips, and any other length or statement is
	// refused.
	p.Proof = ghostprivtest.PreimageProof(digest)
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(input) != 917_601 || input[0] != 0x06 || !bytes.Equal(input[1:33], p.Y[:]) || !bytes.Equal(input[33:97], p.Context[:]) {
		t.Fatalf("checker input layout: %d bytes, statement %#x", len(input), input[0])
	}
	back, err := ghostpriv.DecodePreimageInput(input)
	if err != nil || back.Y != p.Y || back.Context != p.Context || !bytes.Equal(back.Proof, p.Proof) {
		t.Fatalf("decode: %v", err)
	}
	for name, bad := range map[string][]byte{
		"short":     input[:len(input)-1],
		"long":      append(append([]byte{}, input...), 0),
		"empty":     nil,
		"statement": append([]byte{0x05}, input[1:]...),
	} {
		if _, err := ghostpriv.DecodePreimageInput(bad); !errors.Is(err, ghostpriv.ErrPreimageInput) {
			t.Errorf("%s input: error %v, want ErrPreimageInput", name, err)
		}
	}
}

// TestPreimageBindingSeparatedFromAction checks that the statement and the
// policy action's KNOW_ACTION have separate bindings: the statement codes
// and purposes differ in the bytes the binding hashes, and a stub proof made
// for one never verifies the other, nor a statement made for another policy
// or chain.
func TestPreimageBindingSeparatedFromAction(t *testing.T) {
	p := testPreimage()
	a := &ghostpriv.Action{
		Version:           ghostpriv.PolicyActionVersion,
		ChainID:           preimageChainID,
		Marker:            common.Hash{0xaa},
		ExpectedRemaining: uint256.NewInt(10),
		Debit:             uint256.NewInt(1),
		Expiry:            100,
	}
	slot := &ghostpriv.EscrowSlot{Policy: preimagePolicy}
	actionIn := a.BindingInput(preimageChainID, preimageGenesis, slot)
	preimageIn := p.BindingInput(preimageChainID, preimageGenesis, preimagePolicy)
	// chain id (8), version (2), domain (32), then the statement, its
	// version and the purpose.
	if actionIn[42] != 0x05 || preimageIn[42] != 0x06 || actionIn[44] != ghostpriv.PurposeAction || preimageIn[44] != ghostpriv.PurposePreimage {
		t.Fatalf("statement and purpose bytes: action %x, statement %x", actionIn[42:45], preimageIn[42:45])
	}
	actionDigest := a.BindingDigest(preimageChainID, preimageGenesis, slot)
	preimageDigest := p.BindingDigest(preimageChainID, preimageGenesis, preimagePolicy)
	if actionDigest == preimageDigest {
		t.Fatal("the action and the statement share a binding digest")
	}

	v := ghostprivtest.Verifier{}
	actionInputs := a.VerifyInputs(preimageChainID, preimageGenesis, slot)
	preimageInputs := p.VerifyInputs(preimageChainID, preimageGenesis, preimagePolicy)
	actionProof := ghostprivtest.ActionProof(actionDigest)
	preimageProof := ghostprivtest.PreimageProof(preimageDigest)
	if err := v.VerifyReveal(actionInputs, actionProof); err != nil {
		t.Fatalf("the action's own stub proof: %v", err)
	}
	if err := v.VerifyReveal(preimageInputs, preimageProof); err != nil {
		t.Fatalf("the statement's own stub proof: %v", err)
	}
	if err := v.VerifyReveal(preimageInputs, actionProof); err == nil {
		t.Error("an action's proof verifies the statement")
	}
	if err := v.VerifyReveal(actionInputs, preimageProof); err == nil {
		t.Error("the statement's proof verifies an action")
	}
	// A reveal-sized proof field never verifies the statement.
	if err := v.VerifyReveal(preimageInputs, ghostprivtest.Proof(preimageDigest)); err == nil {
		t.Error("a reveal-sized proof field verifies the statement")
	}

	// Through the checker's path: the statement verifies for its own policy
	// and chain only, and the action's proof in the checker's input not at
	// all.
	p.Proof = preimageProof
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := ghostpriv.VerifyPreimage(v, preimageChainID, preimageGenesis, preimagePolicy, input); err != nil {
		t.Fatalf("valid statement: %v", err)
	}
	for name, err := range map[string]error{
		"other policy":  ghostpriv.VerifyPreimage(v, preimageChainID, preimageGenesis, common.Address{0x01}, input),
		"other chain":   ghostpriv.VerifyPreimage(v, preimageChainID+1, preimageGenesis, preimagePolicy, input),
		"other genesis": ghostpriv.VerifyPreimage(v, preimageChainID, common.Hash{0x01}, preimagePolicy, input),
	} {
		if !errors.Is(err, ghostpriv.ErrPreimageProof) {
			t.Errorf("%s: error %v, want ErrPreimageProof", name, err)
		}
	}
	p.Proof = actionProof
	withAction, _ := p.MarshalBinary()
	if err := ghostpriv.VerifyPreimage(v, preimageChainID, preimageGenesis, preimagePolicy, withAction); !errors.Is(err, ghostpriv.ErrPreimageProof) {
		t.Errorf("the action's proof in the checker input: error %v, want ErrPreimageProof", err)
	}
	// Without a genesis hash the check fails closed.
	p.Proof = preimageProof
	if err := ghostpriv.VerifyPreimage(v, preimageChainID, common.Hash{}, preimagePolicy, input); !errors.Is(err, ghostpriv.ErrPreimageDomain) {
		t.Errorf("zero genesis: error %v, want ErrPreimageDomain", err)
	}
	// A verifier without a proof system for the statement is never asked.
	asked := false
	plain := verifierFunc(func(*ghostpriv.VerifyInputs, []byte) error { asked = true; return nil })
	if err := ghostpriv.VerifyPreimage(plain, preimageChainID, preimageGenesis, preimagePolicy, input); !errors.Is(err, ghostpriv.ErrStatementUnsupported) || asked {
		t.Errorf("verifier without the statement: error %v, asked %v", err, asked)
	}
}

// verifierFunc is a ghostpriv.Verifier that is not a PreimageVerifier.
type verifierFunc func(*ghostpriv.VerifyInputs, []byte) error

func (f verifierFunc) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	return f(in, proof)
}
