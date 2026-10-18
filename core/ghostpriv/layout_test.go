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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

func filled(b byte) common.Hash {
	var h common.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// layoutReveal is a reveal with a distinct byte in every field.
func layoutReveal() *ghostpriv.Reveal {
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   0x0102030405060708,
		Marker:    filled(0x11),
		Root:      filled(0x22),
		Remainder: filled(0x33),
		Recipient: common.BytesToAddress(bytes.Repeat([]byte{0x44}, 20)),
		Out:       uint256.NewInt(0x5555),
		Fee:       uint256.NewInt(0x6666),
		Proof:     bytes.Repeat([]byte{0x99}, 100),
	}
	copy(r.Note[:], bytes.Repeat([]byte{0x77}, ghostpriv.NoteSize))
	return r
}

func word(v uint64) []byte {
	w := uint256.NewInt(v).Bytes32()
	return w[:]
}

// TestBindingDigestLayout checks the 415 bytes of the binding digest field by
// field, the tag, that the node supplies the chain id, version, domain and
// rule, and that every field the digest covers changes it.
func TestBindingDigestLayout(t *testing.T) {
	r := layoutReveal()
	const chainID = 6_777_971
	genesis := filled(0x88)
	in := r.BindingInput(chainID, genesis)
	if len(in) != 415 || ghostpriv.BindingSize != 415 {
		t.Fatalf("binding input of %d bytes", len(in))
	}
	// chain_id, version, domain, statement and statement_version, type
	// COIN, purpose, then the fields.
	var want []byte
	want = binary.BigEndian.AppendUint64(want, chainID)
	want = append(want, 0x00, 0x01)
	want = append(want, genesis[:]...)
	want = append(want, 0x01, 0x01)
	want = append(want, 0x01, 0x01)
	want = append(want, 0x01)
	want = append(want, r.Root[:]...)
	want = append(want, r.Marker[:]...)
	want = append(want, r.Remainder[:]...)
	want = append(want, r.Recipient[:]...)
	want = append(want, word(0x5555)...)
	want = append(want, word(0x6666)...)
	want = append(want, make([]byte, 32)...) // the empty rule
	want = append(want, r.Note[:]...)
	if !bytes.Equal(in, want) {
		t.Fatalf("binding input\n%x\nwant\n%x", in, want)
	}
	for _, f := range []struct {
		name     string
		from, to int
	}{
		{"chain_id", 0, 8}, {"version", 8, 10}, {"domain", 10, 42}, {"statement", 42, 43},
		{"statement_version", 43, 44}, {"type", 44, 46}, {"purpose", 46, 47}, {"root", 47, 79},
		{"marker", 79, 111}, {"remainder", 111, 143}, {"recipient", 143, 163}, {"out", 163, 195},
		{"fee", 195, 227}, {"rule", 227, 259}, {"note", 259, 415},
	} {
		if !bytes.Equal(in[f.from:f.to], want[f.from:f.to]) {
			t.Errorf("field %s at %d to %d", f.name, f.from, f.to)
		}
	}

	// The tagged hash: one length byte, the tag, the input.
	tag := "ghost/coin-reveal-binding/v1"
	digest := r.BindingDigest(chainID, genesis)
	if raw := crypto.Keccak256Hash([]byte{byte(len(tag))}, []byte(tag), in); digest != raw {
		t.Fatalf("digest %x, want %x", digest, raw)
	}
	if digest != ghosttree.K(ghostpriv.TagRevealBinding, in) {
		t.Fatal("digest is not K over the input")
	}

	// The node supplies the chain id and version: the payload's fields do
	// not enter, nor does the proof.
	other := layoutReveal()
	other.ChainID, other.Version, other.Proof = 1, 9, nil
	if other.BindingDigest(chainID, genesis) != digest {
		t.Fatal("the payload's chain id, version or proof entered the digest")
	}

	// Every covered field changes the digest.
	for name, change := range map[string]func(r *ghostpriv.Reveal){
		"marker":    func(r *ghostpriv.Reveal) { r.Marker[0] ^= 1 },
		"root":      func(r *ghostpriv.Reveal) { r.Root[31] ^= 1 },
		"remainder": func(r *ghostpriv.Reveal) { r.Remainder[5] ^= 1 },
		"recipient": func(r *ghostpriv.Reveal) { r.Recipient[19] ^= 1 },
		"out":       func(r *ghostpriv.Reveal) { r.Out.AddUint64(r.Out, 1) },
		"fee":       func(r *ghostpriv.Reveal) { r.Fee.AddUint64(r.Fee, 1) },
		"note":      func(r *ghostpriv.Reveal) { r.Note[155] ^= 1 },
	} {
		m := layoutReveal()
		change(m)
		if m.BindingDigest(chainID, genesis) == digest {
			t.Errorf("changing the %s leaves the digest", name)
		}
	}
	if r.BindingDigest(chainID+1, genesis) == digest || r.BindingDigest(chainID, filled(0x89)) == digest {
		t.Error("the chain id or domain does not enter the digest")
	}

	// The stub proof of a digest.
	proof := ghostprivtest.Proof(digest)
	if len(proof) != ghostpriv.ProofSize || common.BytesToHash(proof[:32]) != ghosttree.K("ghost/test-proof/v1", digest[:]) || !bytes.Equal(proof[32:], make([]byte, ghostpriv.ProofSize-32)) {
		t.Fatal("stub proof layout")
	}
}

// TestEnvelopeSizeAndPadding checks the envelope's size and the offset of
// every payload field, that only the exact length decodes, that amount
// words must have their 20 leading bytes zero, and that the proof field's
// padding must be zero.
func TestEnvelopeSizeAndPadding(t *testing.T) {
	if ghostpriv.EnvelopeSize != 1_311_067 || ghostpriv.PayloadSize != 1_311_066 || ghostpriv.ProofSize != 1_310_720 {
		t.Fatalf("sizes %d %d %d", ghostpriv.EnvelopeSize, ghostpriv.PayloadSize, ghostpriv.ProofSize)
	}
	// The data reveal keeps an envelope of the coin reveal's size.
	if types.GhostDataRevealEnvelopeSize != 1_311_067 || types.GhostDataRevealPayloadSize != 1_311_066 {
		t.Fatalf("data reveal sizes %d %d", types.GhostDataRevealEnvelopeSize, types.GhostDataRevealPayloadSize)
	}
	// G_PRIV = 16 x 1,311,067 + 21,000 + 92,300 = 21,090,372.
	if ghostpriv.GasPriv != 16*1_311_067+21_000+92_300 || types.GhostRevealGas != ghostpriv.GasPriv {
		t.Fatalf("G_PRIV %d", ghostpriv.GasPriv)
	}
	r := layoutReveal()
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1_311_067 || env[0] != 0x50 {
		t.Fatalf("envelope of %d bytes, type %#x", len(env), env[0])
	}
	p := env[1:]
	for _, f := range []struct {
		name     string
		from, to int
		want     []byte
	}{
		{"version", 0, 2, []byte{0, 1}},
		{"chain_id", 2, 10, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"marker", 10, 42, r.Marker[:]},
		{"root", 42, 74, r.Root[:]},
		{"remainder", 74, 106, r.Remainder[:]},
		{"recipient", 106, 126, r.Recipient[:]},
		{"out", 126, 158, word(0x5555)},
		{"fee", 158, 190, word(0x6666)},
		{"proof", 190, 290, r.Proof},
		{"proof padding", 290, 1_310_910, make([]byte, 1_310_910-290)},
		{"note", 1_310_910, 1_311_066, r.Note[:]},
	} {
		if !bytes.Equal(p[f.from:f.to], f.want) {
			t.Errorf("payload field %s at %d to %d", f.name, f.from, f.to)
		}
	}
	dec, err := ghostpriv.DecodeReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ChainID != r.ChainID || dec.Marker != r.Marker || dec.Root != r.Root || dec.Remainder != r.Remainder ||
		dec.Recipient != r.Recipient || !dec.Out.Eq(r.Out) || !dec.Fee.Eq(r.Fee) || dec.Note != r.Note ||
		!bytes.Equal(dec.Proof[:100], r.Proof) || len(dec.Proof) != ghostpriv.ProofSize {
		t.Fatal("decode does not give back the fields")
	}
	again, err := dec.MarshalBinary()
	if err != nil || !bytes.Equal(again, env) {
		t.Fatal("re-encoding differs")
	}

	// Only the exact length, with the type byte, decodes.
	for name, bad := range map[string][]byte{
		"one byte short": env[:len(env)-1],
		"one byte long":  append(append([]byte{}, env...), 0),
		"no type byte":   env[1:],
		"other type":     append([]byte{types.DynamicFeeTxType}, env[1:]...),
		"empty":          nil,
	} {
		if _, err := ghostpriv.DecodeReveal(bad); !errors.Is(err, ghostpriv.ErrRevealLength) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := types.NewGhostRevealTx(bad); err == nil {
			t.Errorf("%s: wrapped into a transaction", name)
		}
	}
	if _, err := types.NewGhostRevealTx(env); err != nil {
		t.Fatal(err)
	}

	// Amount words: any of the 20 leading bytes set is rejected; V_MAX is
	// the largest amount.
	for _, field := range []struct {
		name string
		at   int
	}{{"out", 1 + 126}, {"fee", 1 + 158}} {
		for i := 0; i < 20; i++ {
			e := append([]byte{}, env...)
			e[field.at+i] = 0x80
			if _, err := ghostpriv.DecodeReveal(e); !errors.Is(err, ghostpriv.ErrRevealAmount) {
				t.Errorf("%s with byte %d set: %v", field.name, i, err)
			}
		}
	}
	vmax := layoutReveal()
	vmax.Out, vmax.Fee = ghostpriv.VMax.Clone(), ghostpriv.VMax.Clone()
	if _, err := ghostpriv.DecodeReveal(envelope(t, vmax)); err != nil {
		t.Errorf("V_MAX amounts: %v", err)
	}
	over := layoutReveal()
	over.Out = new(uint256.Int).AddUint64(ghostpriv.VMax, 1)
	if _, err := ghostpriv.DecodeReveal(envelope(t, over)); !errors.Is(err, ghostpriv.ErrRevealAmount) {
		t.Errorf("2^96: %v", err)
	}

	// The proof field: a proof longer than the field does not encode, and
	// the stub accepts only zero padding.
	long := layoutReveal()
	long.Proof = make([]byte, ghostpriv.ProofSize+1)
	if _, err := long.MarshalBinary(); err == nil {
		t.Error("a proof longer than the field encoded")
	}
	in := &ghostpriv.VerifyInputs{Binding: r.BindingDigest(6_777_971, filled(0x88))}
	good := ghostprivtest.Proof(in.Binding)
	if err := (ghostprivtest.Verifier{}).VerifyReveal(in, good); err != nil {
		t.Fatalf("stub proof rejected: %v", err)
	}
	for _, at := range []int{32, 1000, ghostpriv.ProofSize - 1} {
		bad := common.CopyBytes(good)
		bad[at] = 1
		if err := (ghostprivtest.Verifier{}).VerifyReveal(in, bad); err == nil {
			t.Errorf("padding byte %d set: accepted", at)
		}
	}
	if err := (ghostprivtest.Verifier{}).VerifyReveal(in, good[:len(good)-1]); err == nil {
		t.Error("a short proof field was accepted")
	}
}
