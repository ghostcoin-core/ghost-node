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
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// errDefaultDataVerifier is the default verifier's answer to a data reveal:
// the linked proof verifier rejects every one until the data reveal fee is
// settled, or as malformed.
var errDefaultDataVerifier = ghostpriv.ErrProofRejected

// Lengths of the chain parameters and of the coin reveal statement in the
// layout of ghost_proofs.h.
const (
	chainParamsBytes = 42
	coinRevealBytes  = 368
)

// knownAnswer is one honest coin reveal made by the pinned ghost-proofs
// prover (ghostverifier/examples/knownanswer.rs): the chain parameters and
// statement in the layout of ghost_proofs.h, and the full proof.
type knownAnswer struct {
	params, statement, proof []byte
}

// knownAnswerFiles are the known-answer fixtures by commitment format: a
// salted (version 2) coin only, since the node takes no version 1 coin.
var knownAnswerFiles = []struct{ name, file string }{
	{"salted version 2", "salted_coin_reveal.bin.gz"},
}

// loadKnownAnswer loads the salted fixture.
func loadKnownAnswer(t *testing.T) knownAnswer {
	t.Helper()
	return loadKnownAnswerFile(t, "salted_coin_reveal.bin.gz")
}

func loadKnownAnswerFile(t *testing.T, name string) knownAnswer {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= chainParamsBytes+coinRevealBytes {
		t.Fatalf("fixture of %d bytes", len(raw))
	}
	return knownAnswer{
		params:    raw[:chainParamsBytes],
		statement: raw[chainParamsBytes : chainParamsBytes+coinRevealBytes],
		proof:     raw[chainParamsBytes+coinRevealBytes:],
	}
}

// inputs reads the fixture into the inputs the node computes for the reveal,
// field by field at the offsets of ghost_proofs.h.
func (ka knownAnswer) inputs(t *testing.T) *ghostpriv.VerifyInputs {
	t.Helper()
	p, s := ka.params, ka.statement
	if v := binary.BigEndian.Uint16(p[8:10]); v != ghostpriv.Version {
		t.Fatalf("fixture version %d", v)
	}
	in := &ghostpriv.VerifyInputs{
		Kind:      ghosttree.Coin,
		Purpose:   ghostpriv.PurposeReveal,
		ChainID:   binary.BigEndian.Uint64(p[0:8]),
		Domain:    common.BytesToHash(p[10:42]),
		Root:      common.BytesToHash(s[0:32]),
		Marker:    common.BytesToHash(s[32:64]),
		Remainder: common.BytesToHash(s[64:96]),
		Recipient: common.BytesToAddress(s[252:272]),
		Out:       new(uint256.Int).SetBytes(s[272:304]),
		Fee:       new(uint256.Int).SetBytes(s[304:336]),
		Rule:      common.BytesToHash(s[336:368]),
	}
	copy(in.Note[:], s[96:252])
	return in
}

// TestGhostDataVerifier checks that data reveals and revokes reach the linked
// proof verifier through ghost_data.h and that it rejects every one, naming
// the unsettled fee, whatever the proof: the accept path is in the
// ghostverifier crate's tests (ghostverifier/tests/data_reveal.rs) only. A
// well-formed proof here is the coin fixture's; a malformed one is rejected
// as malformed, not for the fee.
func TestGhostDataVerifier(t *testing.T) {
	ka := loadKnownAnswer(t)
	coin := ka.inputs(t)
	v := ghostpriv.DefaultVerifier()
	data := func(purpose byte) *ghostpriv.VerifyInputs {
		return &ghostpriv.VerifyInputs{
			Kind:      ghosttree.Data,
			Purpose:   purpose,
			ChainID:   coin.ChainID,
			Domain:    coin.Domain,
			Root:      coin.Root,
			Marker:    coin.Marker,
			Recipient: coin.Recipient,
			Out:       new(uint256.Int),
			Fee:       new(uint256.Int),
			Cf:        common.Hash{0: 0xcf, 31: 0x01},
		}
	}
	proof := func() []byte { return common.CopyBytes(ka.proof) }

	for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		for name, p := range map[string][]byte{
			"proof":              proof(),
			"proof and zeros":    append(proof(), make([]byte, 4096)...),
			"proof field":        append(proof(), make([]byte, ghostpriv.ProofSize-len(ka.proof))...),
			"fee-carrying input": proof(),
		} {
			in := data(purpose)
			if name == "fee-carrying input" {
				in.Fee = uint256.NewInt(21)
			}
			for vname, verifier := range map[string]ghostpriv.Verifier{"default": v, "active": ghostpriv.ActiveVerifier()} {
				err := verifier.VerifyReveal(in, p)
				if !errors.Is(err, ghostpriv.ErrProofRejected) || !errors.Is(err, ghostpriv.ErrProofDataFeeUnsettled) {
					t.Errorf("purpose %#x, %s, %s verifier: %v, want %v", purpose, name, vname, err, ghostpriv.ErrProofDataFeeUnsettled)
				}
			}
		}

		n := len(ka.proof)
		padded := append(proof(), make([]byte, 64)...)
		padded[n+10] = 1
		for name, p := range map[string][]byte{
			"non-zero padding": padded,
			"truncated":        proof()[:n-1],
			"empty":            nil,
			"oversized":        make([]byte, 2<<20+1),
		} {
			err := v.VerifyReveal(data(purpose), p)
			if !errors.Is(err, ghostpriv.ErrProofRejected) || errors.Is(err, ghostpriv.ErrProofDataFeeUnsettled) {
				t.Errorf("purpose %#x, %s: %v, want %v and not the fee", purpose, name, err, ghostpriv.ErrProofRejected)
			}
		}
	}

	// What the verifier does not verify is not passed to it.
	for _, purpose := range []byte{0x00, 0x03, 0x04, 0xff} {
		if err := v.VerifyReveal(data(purpose), proof()); !errors.Is(err, ghostpriv.ErrProofStatement) {
			t.Errorf("data purpose %#x: %v, want %v", purpose, err, ghostpriv.ErrProofStatement)
		}
	}
	in := data(ghostpriv.PurposeReveal)
	in.Kind = ghosttree.Kind(7)
	if err := v.VerifyReveal(in, proof()); !errors.Is(err, ghostpriv.ErrProofStatement) {
		t.Errorf("unknown kind: %v, want %v", err, ghostpriv.ErrProofStatement)
	}
}

// TestGhostVerifierKnownAnswer checks the linked proof verifier against a
// real proof of each commitment format: it accepts the proof for its own
// statement, followed by zeros or not, and rejects a changed proof, every
// changed statement field and chain parameter, and every data reveal.
func TestGhostVerifierKnownAnswer(t *testing.T) {
	for _, f := range knownAnswerFiles {
		t.Run(f.name, func(t *testing.T) { testGhostVerifierKnownAnswer(t, loadKnownAnswerFile(t, f.file)) })
	}
}

func testGhostVerifierKnownAnswer(t *testing.T, ka knownAnswer) {
	base := ka.inputs(t)
	// The example's chain: id 1234 and a genesis hash of 0x47 bytes.
	if base.ChainID != 1234 || base.Domain != common.BytesToHash(bytes.Repeat([]byte{0x47}, 32)) {
		t.Fatalf("fixture chain parameters %d, %x", base.ChainID, base.Domain)
	}
	if base.Rule != (common.Hash{}) || base.Out.IsZero() || base.Fee.IsZero() {
		t.Fatalf("fixture rule %x, out %v, fee %v", base.Rule, base.Out, base.Fee)
	}
	v := ghostpriv.DefaultVerifier()
	clone := func() *ghostpriv.VerifyInputs {
		in := *base
		in.Out = new(uint256.Int).Set(base.Out)
		in.Fee = new(uint256.Int).Set(base.Fee)
		return &in
	}
	proof := func() []byte { return common.CopyBytes(ka.proof) }
	rejected := func(t *testing.T, name string, err error, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}

	t.Run("valid proof accepted", func(t *testing.T) {
		if err := v.VerifyReveal(clone(), proof()); err != nil {
			t.Fatalf("the proof: %v", err)
		}
		if err := v.VerifyReveal(clone(), append(proof(), make([]byte, 4096)...)); err != nil {
			t.Fatalf("the proof followed by zeros: %v", err)
		}
		if err := ghostpriv.ActiveVerifier().VerifyReveal(clone(), proof()); err != nil {
			t.Fatalf("the active verifier: %v", err)
		}
	})

	t.Run("flipped proof byte rejected", func(t *testing.T) {
		n := len(ka.proof)
		for _, at := range []int{0, 1, n / 3, n / 2, 2 * n / 3, n - 40, n - 1} {
			p := proof()
			p[at] ^= 1
			rejected(t, "flipped byte", v.VerifyReveal(clone(), p), ghostpriv.ErrProofRejected)
		}
		padded := append(proof(), make([]byte, 64)...)
		padded[n+10] = 1
		rejected(t, "non-zero padding", v.VerifyReveal(clone(), padded), ghostpriv.ErrProofRejected)
		rejected(t, "truncated", v.VerifyReveal(clone(), proof()[:n-1]), ghostpriv.ErrProofRejected)
		rejected(t, "empty", v.VerifyReveal(clone(), nil), ghostpriv.ErrProofRejected)
	})

	t.Run("changed statement field rejected", func(t *testing.T) {
		for name, change := range map[string]func(in *ghostpriv.VerifyInputs){
			"chain id":  func(in *ghostpriv.VerifyInputs) { in.ChainID++ },
			"domain":    func(in *ghostpriv.VerifyInputs) { in.Domain[31] ^= 1 },
			"root":      func(in *ghostpriv.VerifyInputs) { in.Root[0] ^= 1 },
			"marker":    func(in *ghostpriv.VerifyInputs) { in.Marker[31] ^= 1 },
			"remainder": func(in *ghostpriv.VerifyInputs) { in.Remainder[7] ^= 1 },
			"note":      func(in *ghostpriv.VerifyInputs) { in.Note[ghostpriv.NoteSize-1] ^= 1 },
			"recipient": func(in *ghostpriv.VerifyInputs) { in.Recipient[19] ^= 1 },
			"out":       func(in *ghostpriv.VerifyInputs) { in.Out.AddUint64(in.Out, 1) },
			"fee":       func(in *ghostpriv.VerifyInputs) { in.Fee.SubUint64(in.Fee, 1) },
			"rule":      func(in *ghostpriv.VerifyInputs) { in.Rule[31] = 1 },
			"out range": func(in *ghostpriv.VerifyInputs) { in.Out.Lsh(uint256.NewInt(1), 96) },
		} {
			in := clone()
			change(in)
			rejected(t, name, v.VerifyReveal(in, proof()), ghostpriv.ErrProofRejected)
		}
		in := clone()
		in.Purpose = ghostpriv.PurposeRevoke
		rejected(t, "revoke purpose", v.VerifyReveal(in, proof()), ghostpriv.ErrProofStatement)
		rejected(t, "no inputs", v.VerifyReveal(nil, proof()), ghostpriv.ErrProofStatement)
	})

	t.Run("data reveal rejected", func(t *testing.T) {
		for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
			in := clone()
			in.Kind = ghosttree.Data
			in.Purpose = purpose
			rejected(t, "data reveal", v.VerifyReveal(in, proof()), errDefaultDataVerifier)
		}
	})
}
