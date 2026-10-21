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
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// decodedInputs are the inputs CheckReveal computes for a decoded reveal on
// the chain of the given id and genesis hash.
func decodedInputs(r *ghostpriv.Reveal, chainID uint64, genesis common.Hash) *ghostpriv.VerifyInputs {
	return &ghostpriv.VerifyInputs{
		Kind:      ghosttree.Coin,
		Purpose:   ghostpriv.PurposeReveal,
		Binding:   r.BindingDigest(chainID, genesis),
		ChainID:   chainID,
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

// TestRealProofRevealRoundTrip puts the known-answer proof of the pinned
// prover, of each commitment format, into a reveal's proof field: the
// envelope holds it, decodes back to the same fields and the full proof
// field, padding included, and the default verifier accepts what it decodes
// to. One flipped proof byte in the envelope is rejected.
func TestRealProofRevealRoundTrip(t *testing.T) {
	for _, f := range knownAnswerFiles {
		t.Run(f.name, func(t *testing.T) { testRealProofRevealRoundTrip(t, loadKnownAnswerFile(t, f.file)) })
	}
}

func testRealProofRevealRoundTrip(t *testing.T, ka knownAnswer) {
	in := ka.inputs(t)
	if len(ka.proof) > ghostpriv.ProofSize {
		t.Fatalf("proof of %d bytes, the field holds %d", len(ka.proof), ghostpriv.ProofSize)
	}
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   in.ChainID,
		Marker:    in.Marker,
		Root:      in.Root,
		Remainder: in.Remainder,
		Recipient: in.Recipient,
		Out:       in.Out,
		Fee:       in.Fee,
		Proof:     common.CopyBytes(ka.proof),
		Note:      in.Note,
	}
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != ghostpriv.EnvelopeSize || env[0] != types.GhostRevealTxType {
		t.Fatalf("envelope of %d bytes, type %#x", len(env), env[0])
	}
	tx, err := types.NewGhostRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tx.GhostRevealEnvelope(), env) {
		t.Fatal("the transaction does not carry the envelope")
	}

	decode := func(t *testing.T, env []byte) *ghostpriv.Reveal {
		t.Helper()
		dec, err := ghostpriv.DecodeReveal(env)
		if err != nil {
			t.Fatal(err)
		}
		return dec
	}
	dec := decode(t, tx.GhostRevealEnvelope())
	if dec.ChainID != r.ChainID || dec.Marker != r.Marker || dec.Root != r.Root || dec.Remainder != r.Remainder ||
		dec.Recipient != r.Recipient || !dec.Out.Eq(r.Out) || !dec.Fee.Eq(r.Fee) || dec.Note != r.Note {
		t.Fatal("decode does not give back the fields")
	}
	if len(dec.Proof) != ghostpriv.ProofSize || !bytes.Equal(dec.Proof[:len(ka.proof)], ka.proof) ||
		!bytes.Equal(dec.Proof[len(ka.proof):], make([]byte, ghostpriv.ProofSize-len(ka.proof))) {
		t.Fatal("decoded proof field is not the proof followed by zeros")
	}
	again, err := dec.MarshalBinary()
	if err != nil || !bytes.Equal(again, env) {
		t.Fatal("re-encoding differs")
	}

	v := ghostpriv.DefaultVerifier()
	if err := v.VerifyReveal(decodedInputs(dec, in.ChainID, in.Domain), dec.Proof); err != nil {
		t.Fatalf("the decoded reveal: %v", err)
	}

	t.Run("flipped proof byte rejected", func(t *testing.T) {
		const offProof = 1 + 190 // the type byte, then the payload's proof field
		for _, at := range []int{0, len(ka.proof) / 2, len(ka.proof) - 1} {
			bad := common.CopyBytes(env)
			bad[offProof+at] ^= 1
			dec := decode(t, bad)
			if err := v.VerifyReveal(decodedInputs(dec, in.ChainID, in.Domain), dec.Proof); !errors.Is(err, ghostpriv.ErrProofRejected) {
				t.Errorf("proof byte %d flipped: %v, want %v", at, err, ghostpriv.ErrProofRejected)
			}
		}
	})
}
