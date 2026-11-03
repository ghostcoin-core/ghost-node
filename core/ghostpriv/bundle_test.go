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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// bundleLayoutReveal is a version 2 reveal of recognisable fields on the
// chain of chainID, with a stub proof over genesis, for the layout tests.
func bundleLayoutReveal(chainID uint64, genesis common.Hash, seed byte) *ghostpriv.Reveal {
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersion,
		ChainID:   chainID,
		Marker:    common.Hash{0x11, seed},
		Root:      common.Hash{0x22, seed},
		Remainder: common.Hash{0x33, seed},
		Recipient: common.Address{0x44, seed},
		Out:       uint256.NewInt(1_000 + uint64(seed)),
		Fee:       uint256.NewInt(7 + uint64(seed)),
	}
	copy(r.Note[:], testNote(seed))
	r.Proof = ghostprivtest.Proof(r.BindingDigest(chainID, genesis))
	return r
}

// TestBundleInputsLayout checks the public inputs of a bundle's root as the
// node builds them: the contents digest over the reveals' own binding
// digests in order, and the 79-byte binding input, field by field, under the
// bundle binding tag, which is no reveal's tag. The stub root proof of the
// binding verifies, and no reveal's stub proof stands in for it.
func TestBundleInputsLayout(t *testing.T) {
	if ghostpriv.BundleVersion != 0x0001 || ghostpriv.BundleMaxReveals != 1_408 || ghostpriv.BundleBodySize != 570 ||
		ghostpriv.BundleBindingSize != 79 || ghostpriv.PurposeBundle != 0x08 {
		t.Fatalf("version %d, max %d, body %d, binding %d, purpose %#x", ghostpriv.BundleVersion, ghostpriv.BundleMaxReveals,
			ghostpriv.BundleBodySize, ghostpriv.BundleBindingSize, ghostpriv.PurposeBundle)
	}
	if ghostpriv.TagBundleContents != "ghost/bundle-contents/v1" || ghostpriv.TagBundleBinding != "ghost/bundle-binding/v1" {
		t.Fatalf("tags %q, %q", ghostpriv.TagBundleContents, ghostpriv.TagBundleBinding)
	}
	for _, tag := range []string{ghostpriv.TagRevealBinding, ghostpriv.TagRevealBindingV1, ghostpriv.TagPolicyRevealBinding,
		ghostpriv.TagDataRevealBinding, ghostprivtest.TagTestProof} {
		if tag == ghostpriv.TagBundleBinding || tag == ghostpriv.TagBundleContents {
			t.Fatalf("the bundle shares the tag %q", tag)
		}
	}
	const chainID = 0x0a0b0c0d0e0f1011
	genesis := common.Hash{0xde, 0xad, 0xbe, 0xef}
	reveals := []*ghostpriv.Reveal{bundleLayoutReveal(chainID, genesis, 1), bundleLayoutReveal(chainID, genesis, 2), bundleLayoutReveal(chainID, genesis, 3)}
	in := ghostpriv.NewBundleInputs(chainID, genesis, reveals)
	if in.ChainID != chainID || in.Domain != genesis || in.Version != 1 || in.RevealVersion != 2 || in.Count != 3 {
		t.Fatalf("inputs %+v", in)
	}

	// The contents: K(contents tag, b_1 || b_2 || b_3), each b_i the Binding
	// of the reveal's own VerifyInputs on this chain, as for a lone reveal.
	var digests []byte
	for _, r := range reveals {
		b := r.VerifyInputs(chainID, genesis).Binding
		if b != r.BindingDigest(chainID, genesis) {
			t.Fatal("the reveal's binding is not its verify inputs'")
		}
		digests = append(digests, b[:]...)
	}
	if want := ghosttree.K("ghost/bundle-contents/v1", digests); in.Contents != want {
		t.Fatalf("contents %x, want %x", in.Contents, want)
	}

	// The binding input, byte by byte.
	// The chain id, the bundle version, the domain, the statement, its
	// version and the purpose, the count and the contents.
	want := make([]byte, 0, 79)
	want = append(want, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11)
	want = append(want, 0x00, 0x01)
	want = append(want, genesis[:]...)
	want = append(want, 0x01, 0x02, 0x08)
	want = append(want, 0x00, 0x03)
	want = append(want, in.Contents[:]...)
	input := in.BindingInput()
	if len(input) != 79 || !bytes.Equal(input, want) {
		t.Fatalf("binding input\n%x\nwant\n%x", input, want)
	}
	if in.Binding != ghosttree.K("ghost/bundle-binding/v1", want) {
		t.Fatalf("binding %x", in.Binding)
	}
	if in.Binding == ghosttree.K(ghostpriv.TagRevealBinding, want) {
		t.Fatal("the bundle binds with the reveal tag")
	}
	// The decoded bundle builds the same inputs.
	bundle := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: chainID, Reveals: reveals}
	if got := bundle.Inputs(chainID, genesis); *got != *in {
		t.Fatalf("bundle inputs %+v, want %+v", got, in)
	}
	// A count of 1,408 fits the two-byte count.
	many := make([]*ghostpriv.Reveal, ghostpriv.BundleMaxReveals)
	for i := range many {
		many[i] = reveals[i%3]
	}
	if largest := ghostpriv.NewBundleInputs(chainID, genesis, many); largest.Count != 1_408 || binary.BigEndian.Uint16(largest.BindingInput()[45:47]) != 1_408 {
		t.Fatalf("count of the largest bundle %d", largest.Count)
	}

	// The stub root proof of the binding verifies; a reveal's stub proof, or
	// the root proof of a reveal, does not.
	stubV := ghostprivtest.Verifier{}
	proof := ghostprivtest.BundleProof(in.Binding)
	if len(proof) != ghostpriv.ProofSize {
		t.Fatalf("root proof of %d bytes", len(proof))
	}
	if err := stubV.VerifyBundle(in, proof); err != nil {
		t.Fatalf("stub root proof refused: %v", err)
	}
	if err := ghostpriv.VerifyBundleRoot(stubV, in, proof); err != nil {
		t.Fatalf("stub root proof refused through the node: %v", err)
	}
	for i, r := range reveals {
		if err := stubV.VerifyBundle(in, r.Proof); err == nil {
			t.Fatalf("reveal %d's proof verified the root", i)
		}
		if err := stubV.VerifyReveal(r.VerifyInputs(chainID, genesis), proof); err == nil {
			t.Fatalf("the root proof verified reveal %d", i)
		}
	}
	trailing := common.CopyBytes(proof)
	trailing[len(trailing)-1] = 1
	for _, c := range []struct {
		name  string
		proof []byte
	}{
		{"short", proof[:len(proof)-1]},
		{"long", append(common.CopyBytes(proof), 0)},
		{"trailing byte", trailing},
		{"zero", make([]byte, ghostpriv.ProofSize)},
	} {
		if err := stubV.VerifyBundle(in, c.proof); err == nil {
			t.Errorf("%s root proof verified", c.name)
		}
		if err := ghostpriv.VerifyBundleRoot(stubV, in, c.proof); !errors.Is(err, ghostpriv.ErrBundleProof) {
			t.Errorf("%s root proof: %v, want %v", c.name, err, ghostpriv.ErrBundleProof)
		}
	}
	if err := stubV.VerifyBundle(nil, proof); err == nil {
		t.Error("no inputs verified")
	}
}

// TestBundleBodyIsRevealWithoutProof checks that a bundled reveal is a
// version 2 reveal payload without its 1,310,720-byte proof field: its
// payload's bytes 0 to 190 and its 380-byte note, 570 bytes. It decodes to
// the same reveal with a zero proof field, which binds as the lone reveal
// does; anything but a version 2 reveal with amount words below 2^96 is no
// body. It also pins the bundle envelope layout.
func TestBundleBodyIsRevealWithoutProof(t *testing.T) {
	const chainID = 77
	genesis := common.Hash{0x9e}
	r := bundleLayoutReveal(chainID, genesis, 5)
	env := envelope(t, r)
	if len(env) != types.GhostRevealEnvelopeSize {
		t.Fatalf("reveal envelope of %d bytes", len(env))
	}
	payload := env[1:]
	body, err := ghostpriv.BundleBody(r)
	if err != nil {
		t.Fatal(err)
	}
	want := append(common.CopyBytes(payload[0:190]), payload[1_310_910:1_311_290]...)
	if len(body) != 570 || !bytes.Equal(body, want) {
		t.Fatalf("body of %d bytes is not the payload without its proof field", len(body))
	}
	if !bytes.Equal(body[190:], r.Note[:]) {
		t.Fatal("the body does not end with the note")
	}

	// The body decodes to the reveal with its proof field zero, which binds
	// exactly as the lone reveal.
	dec, err := ghostpriv.DecodeBundleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Version != r.Version || dec.ChainID != r.ChainID || dec.Marker != r.Marker || dec.Root != r.Root ||
		dec.Remainder != r.Remainder || dec.Recipient != r.Recipient || !dec.Out.Eq(r.Out) || !dec.Fee.Eq(r.Fee) || dec.Note != r.Note {
		t.Fatalf("decoded body %+v differs from %+v", dec, r)
	}
	for _, b := range dec.Proof {
		if b != 0 {
			t.Fatal("decoded body carries a proof")
		}
	}
	if dec.VerifyInputs(chainID, genesis).Binding != r.VerifyInputs(chainID, genesis).Binding {
		t.Fatal("the body binds otherwise than the lone reveal")
	}
	zeroed := common.CopyBytes(env)
	copy(zeroed[1+190:1+190+ghostpriv.ProofSize], make([]byte, ghostpriv.ProofSize))
	if decEnv := envelope(t, dec); !bytes.Equal(decEnv, zeroed) {
		t.Fatal("the decoded body is not the reveal with a zero proof field")
	}

	// No body: a version 1 reveal, another version, an amount word of 2^96
	// or more, a wrong length.
	v1 := clone(r)
	v1.Version = ghostpriv.RevealVersionV1
	if _, err := ghostpriv.BundleBody(v1); !errors.Is(err, ghostpriv.ErrBundleBody) {
		t.Fatalf("version 1 reveal as a body: %v", err)
	}
	patch := func(f func(b []byte)) []byte {
		b := common.CopyBytes(body)
		f(b)
		return b
	}
	for _, c := range []struct {
		name string
		body []byte
		want error
	}{
		{"version 1", patch(func(b []byte) { b[1] = 1 }), ghostpriv.ErrRevealVersion},
		{"version 3", patch(func(b []byte) { b[1] = 3 }), ghostpriv.ErrRevealVersion},
		{"version 0x0102", patch(func(b []byte) { b[0] = 1 }), ghostpriv.ErrRevealVersion},
		{"out of 2^96", patch(func(b []byte) { b[126+19] = 1 }), ghostpriv.ErrRevealAmount},
		{"fee of 2^255", patch(func(b []byte) { b[158] = 0x80 }), ghostpriv.ErrRevealAmount},
		{"569 bytes", body[:569], ghostpriv.ErrBundleBody},
		{"571 bytes", append(common.CopyBytes(body), 0), ghostpriv.ErrBundleBody},
		{"a full reveal payload", payload, ghostpriv.ErrBundleBody},
	} {
		if _, err := ghostpriv.DecodeBundleBody(c.body); !errors.Is(err, ghostpriv.ErrBundleBody) || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v and %v", c.name, err, ghostpriv.ErrBundleBody, c.want)
		}
	}
	// The largest amount word below 2^96 is a body.
	if _, err := ghostpriv.DecodeBundleBody(patch(func(b []byte) {
		for i := 126 + 20; i < 158; i++ {
			b[i] = 0xff
		}
	})); err != nil {
		t.Fatalf("out of 2^96 - 1: %v", err)
	}

	// The envelope: 0x55, version, chain id, count, root proof, bodies.
	second := bundleLayoutReveal(chainID, genesis, 6)
	bundle := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: chainID, Reveals: []*ghostpriv.Reveal{r, second}}
	bundle.Proof = ghostprivtest.BundleProof(bundle.Inputs(chainID, genesis).Binding)
	benv, err := bundle.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(benv) != 1+1_310_732+2*570 || benv[0] != 0x55 {
		t.Fatalf("bundle envelope of %d bytes, type %#x", len(benv), benv[0])
	}
	p := benv[1:]
	if binary.BigEndian.Uint16(p[0:]) != 1 || binary.BigEndian.Uint64(p[2:]) != chainID || binary.BigEndian.Uint16(p[10:]) != 2 {
		t.Fatalf("bundle header %x", p[:12])
	}
	if !bytes.Equal(p[12:12+ghostpriv.ProofSize], bundle.Proof) {
		t.Fatal("root proof field")
	}
	secondBody, _ := ghostpriv.BundleBody(second)
	if !bytes.Equal(p[1_310_732:1_310_732+570], body) || !bytes.Equal(p[1_310_732+570:], secondBody) {
		t.Fatal("bodies are not in order after the root proof")
	}
	tx, err := types.NewGhostBundleTx(benv)
	if err != nil || tx.Gas() != 2*ghostpriv.GasPriv {
		t.Fatalf("bundle transaction: %v", err)
	}
	back, err := ghostpriv.DecodeBundle(benv)
	if err != nil {
		t.Fatal(err)
	}
	if back.Version != 1 || back.ChainID != chainID || len(back.Reveals) != 2 || !bytes.Equal(back.Proof, bundle.Proof) ||
		*back.Inputs(chainID, genesis) != *bundle.Inputs(chainID, genesis) {
		t.Fatal("bundle round trip")
	}
	// A version 1 reveal cannot be bundled, and a bundle holds 1 to 1,408.
	if _, err := (&ghostpriv.Bundle{Version: 1, ChainID: chainID, Reveals: []*ghostpriv.Reveal{v1}}).MarshalBinary(); !errors.Is(err, ghostpriv.ErrBundleBody) {
		t.Fatalf("bundle of a version 1 reveal: %v", err)
	}
	if _, err := (&ghostpriv.Bundle{Version: 1, ChainID: chainID}).MarshalBinary(); !errors.Is(err, ghostpriv.ErrBundleCount) {
		t.Fatalf("empty bundle: %v", err)
	}

	// The shape checks of DecodeBundle.
	withBytes := func(at int, b ...byte) []byte {
		e := common.CopyBytes(benv)
		copy(e[at:], b)
		return e
	}
	for _, c := range []struct {
		name string
		env  []byte
		want error
	}{
		{"empty", nil, ghostpriv.ErrBundleLength},
		{"reveal type byte", append([]byte{types.GhostRevealTxType}, benv[1:]...), ghostpriv.ErrBundleLength},
		{"no root proof", benv[:1+12], ghostpriv.ErrBundleLength},
		{"count 0", withBytes(1+10, 0, 0), ghostpriv.ErrBundleCount},
		{"count 1,409", withBytes(1+10, 0x05, 0x81), ghostpriv.ErrBundleCount},
		{"count 1, two bodies", withBytes(1+10, 0, 1), ghostpriv.ErrBundleLength},
		{"count 3, two bodies", withBytes(1+10, 0, 3), ghostpriv.ErrBundleLength},
		{"one byte short", benv[:len(benv)-1], ghostpriv.ErrBundleLength},
		{"version 0", withBytes(1, 0, 0), ghostpriv.ErrBundleVersion},
		{"version 2", withBytes(1, 0, 2), ghostpriv.ErrBundleVersion},
		{"second body version 1", withBytes(1+1_310_732+570+1, 1), ghostpriv.ErrBundleBody},
	} {
		if _, err := ghostpriv.DecodeBundle(c.env); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
