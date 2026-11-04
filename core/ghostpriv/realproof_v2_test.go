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
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/holiman/uint256"
)

// Lengths of the version 2 statements, as ghost_proofs.h and ghost_policy.h
// give them.
const (
	coinRevealV2Bytes = 560
	policyRevealBytes = 720
)

// v2Fixture is a known-answer file of ghostverifier/examples/v2fixture.rs:
// the chain parameters, the statement and the proof.
type v2Fixture struct {
	chainID   uint64
	version   uint16
	domain    common.Hash
	statement []byte
	proof     []byte
}

func loadV2Fixture(t testing.TB, name string, statementLen int) v2Fixture {
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
	if len(raw) <= chainParamsBytes+statementLen {
		t.Fatalf("fixture of %d bytes", len(raw))
	}
	fx := v2Fixture{
		chainID:   binary.BigEndian.Uint64(raw[0:8]),
		version:   binary.BigEndian.Uint16(raw[8:10]),
		domain:    common.BytesToHash(raw[10:42]),
		statement: raw[chainParamsBytes : chainParamsBytes+statementLen],
		proof:     raw[chainParamsBytes+statementLen:],
	}
	if fx.chainID != 1234 || fx.domain != common.BytesToHash(bytes.Repeat([]byte{0x47}, 32)) {
		t.Fatalf("fixture chain parameters %d, %x", fx.chainID, fx.domain)
	}
	if len(fx.proof) > ghostpriv.ProofSize {
		t.Fatalf("proof of %d bytes, the field holds %d", len(fx.proof), ghostpriv.ProofSize)
	}
	return fx
}

// ordinaryV2 is the version 2 ordinary reveal of the fixture, as the node
// decodes it from its envelope.
func ordinaryV2(t testing.TB, fx v2Fixture) *ghostpriv.Reveal {
	t.Helper()
	if fx.version != ghostpriv.RevealVersion {
		t.Fatalf("fixture version %d", fx.version)
	}
	s := fx.statement
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersion,
		ChainID:   fx.chainID,
		Root:      common.BytesToHash(s[0:32]),
		Marker:    common.BytesToHash(s[32:64]),
		Remainder: common.BytesToHash(s[64:96]),
		Recipient: common.BytesToAddress(s[476:496]),
		Out:       new(uint256.Int).SetBytes(s[496:528]),
		Fee:       new(uint256.Int).SetBytes(s[528:560]),
		Proof:     common.CopyBytes(fx.proof),
	}
	copy(r.Note[:], s[96:476])
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ghostpriv.DecodeReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

// policyV1 is the policy reveal of the fixture, as the node decodes it from
// its envelope.
func policyV1(t testing.TB, fx v2Fixture) *ghostpriv.PolicyReveal {
	t.Helper()
	if fx.version != ghostpriv.PolicyRevealVersion {
		t.Fatalf("fixture version %d", fx.version)
	}
	s := fx.statement
	r := &ghostpriv.PolicyReveal{
		Version:    ghostpriv.PolicyRevealVersion,
		ChainID:    fx.chainID,
		Root:       common.BytesToHash(s[0:32]),
		Marker:     common.BytesToHash(s[32:64]),
		Remainder:  common.BytesToHash(s[64:96]),
		Out:        new(uint256.Int).SetBytes(s[96:128]),
		Fee:        new(uint256.Int).SetBytes(s[128:160]),
		Policy:     common.BytesToAddress(s[160:180]),
		CodeHash:   common.BytesToHash(s[180:212]),
		ParamsHash: common.BytesToHash(s[212:244]),
		ActionTag:  common.BytesToHash(s[244:276]),
		ActionSalt: common.BytesToHash(s[276:308]),
		Instr:      common.BytesToHash(s[308:340]),
		Proof:      common.CopyBytes(fx.proof),
	}
	copy(r.Note[:], s[340:720])
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ghostpriv.DecodePolicyReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

// TestRealProofOrdinaryV2 checks that the default verifier accepts the
// pinned prover's version 2 ordinary reveal through the inputs the node
// builds for its decoded envelope, padded proof field included, and rejects
// it with any public field changed, with a flipped proof byte, as version 1
// or under another chain's parameters.
func TestRealProofOrdinaryV2(t *testing.T) {
	fx := loadV2Fixture(t, "coin_reveal_v2.bin.gz", coinRevealV2Bytes)
	r := ordinaryV2(t, fx)
	v := ghostpriv.DefaultVerifier()
	in := func() *ghostpriv.VerifyInputs { return r.VerifyInputs(fx.chainID, fx.domain) }

	start := time.Now()
	if err := v.VerifyReveal(in(), r.Proof); err != nil {
		t.Fatalf("version 2 reveal: %v", err)
	}
	t.Logf("version 2 ordinary reveal verified in %v (proof of %d bytes)", time.Since(start), len(fx.proof))

	changes := map[string]func(*ghostpriv.VerifyInputs){
		"root":      func(in *ghostpriv.VerifyInputs) { in.Root[0] ^= 1 },
		"marker":    func(in *ghostpriv.VerifyInputs) { in.Marker[0] ^= 1 },
		"remainder": func(in *ghostpriv.VerifyInputs) { in.Remainder[0] ^= 1 },
		"recipient": func(in *ghostpriv.VerifyInputs) { in.Recipient[0] ^= 1 },
		"out":       func(in *ghostpriv.VerifyInputs) { in.Out.AddUint64(in.Out, 1) },
		"fee":       func(in *ghostpriv.VerifyInputs) { in.Fee.AddUint64(in.Fee, 1) },
		"note end":  func(in *ghostpriv.VerifyInputs) { in.Note[ghostpriv.NoteSize-1] ^= 1 },
		"chain id":  func(in *ghostpriv.VerifyInputs) { in.ChainID++ },
		"domain":    func(in *ghostpriv.VerifyInputs) { in.Domain[0] ^= 1 },
	}
	for name, change := range changes {
		x := in()
		change(x)
		if err := v.VerifyReveal(x, r.Proof); !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Errorf("%s changed: %v, want %v", name, err, ghostpriv.ErrProofRejected)
		}
	}
	x := in()
	x.Version = ghostpriv.RevealVersionV1
	x.Note = [ghostpriv.NoteSize]byte{}
	if err := v.VerifyReveal(x, r.Proof); !errors.Is(err, ghostpriv.ErrProofRejected) {
		t.Errorf("as version 1: %v, want %v", err, ghostpriv.ErrProofRejected)
	}
	x = in()
	x.Purpose = ghostpriv.PurposePolicySpend
	if err := v.VerifyReveal(x, r.Proof); err == nil {
		t.Error("the ordinary proof was accepted as a policy reveal")
	}
	for _, at := range []int{0, len(fx.proof) / 2, len(fx.proof) - 1} {
		bad := common.CopyBytes(r.Proof)
		bad[at] ^= 1
		if err := v.VerifyReveal(in(), bad); !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Errorf("proof byte %d flipped: %v, want %v", at, err, ghostpriv.ErrProofRejected)
		}
	}
}

// TestRealProofPolicyReveal checks that the default verifier accepts the
// pinned prover's policy reveal (S4) through the inputs the node builds for
// its decoded envelope, and rejects it with any public field changed, with a
// flipped proof byte, as another version or as an ordinary reveal.
func TestRealProofPolicyReveal(t *testing.T) {
	fx := loadV2Fixture(t, "policy_reveal.bin.gz", policyRevealBytes)
	r := policyV1(t, fx)
	v := ghostpriv.DefaultVerifier()
	in := func() *ghostpriv.VerifyInputs { return r.VerifyInputs(fx.chainID, fx.domain) }

	start := time.Now()
	if err := v.VerifyReveal(in(), r.Proof); err != nil {
		t.Fatalf("policy reveal: %v", err)
	}
	t.Logf("policy reveal verified in %v (proof of %d bytes)", time.Since(start), len(fx.proof))

	changes := map[string]func(*ghostpriv.VerifyInputs){
		"root":        func(in *ghostpriv.VerifyInputs) { in.Root[0] ^= 1 },
		"marker":      func(in *ghostpriv.VerifyInputs) { in.Marker[0] ^= 1 },
		"remainder":   func(in *ghostpriv.VerifyInputs) { in.Remainder[0] ^= 1 },
		"out":         func(in *ghostpriv.VerifyInputs) { in.Out.AddUint64(in.Out, 1) },
		"fee":         func(in *ghostpriv.VerifyInputs) { in.Fee.AddUint64(in.Fee, 1) },
		"policy":      func(in *ghostpriv.VerifyInputs) { in.Policy[0] ^= 1 },
		"code hash":   func(in *ghostpriv.VerifyInputs) { in.PolicyCodeHash[0] ^= 1 },
		"params hash": func(in *ghostpriv.VerifyInputs) { in.ParamsHash[0] ^= 1 },
		"action tag":  func(in *ghostpriv.VerifyInputs) { in.ActionTag[0] ^= 1 },
		"action salt": func(in *ghostpriv.VerifyInputs) { in.ActionSalt[0] ^= 1 },
		"instr":       func(in *ghostpriv.VerifyInputs) { in.Instr[0] ^= 1 },
		"note end":    func(in *ghostpriv.VerifyInputs) { in.Note[ghostpriv.NoteSize-1] ^= 1 },
		"chain id":    func(in *ghostpriv.VerifyInputs) { in.ChainID++ },
	}
	for name, change := range changes {
		x := in()
		change(x)
		if err := v.VerifyReveal(x, r.Proof); !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Errorf("%s changed: %v, want %v", name, err, ghostpriv.ErrProofRejected)
		}
	}
	x := in()
	x.Version = 2
	if err := v.VerifyReveal(x, r.Proof); !errors.Is(err, ghostpriv.ErrStatementUnsupported) {
		t.Errorf("as version 2: %v, want %v", err, ghostpriv.ErrStatementUnsupported)
	}
	x = in()
	x.Purpose = ghostpriv.PurposeReveal
	x.Version = ghostpriv.RevealVersion
	if err := v.VerifyReveal(x, r.Proof); !errors.Is(err, ghostpriv.ErrProofRejected) {
		t.Errorf("as an ordinary reveal: %v, want %v", err, ghostpriv.ErrProofRejected)
	}
	for _, at := range []int{0, len(fx.proof) / 2, len(fx.proof) - 1} {
		bad := common.CopyBytes(r.Proof)
		bad[at] ^= 1
		if err := v.VerifyReveal(in(), bad); !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Errorf("proof byte %d flipped: %v, want %v", at, err, ghostpriv.ErrProofRejected)
		}
	}
}

// BenchmarkVerifyOrdinaryV2 and BenchmarkVerifyPolicyReveal measure one
// verification of each real proof through the C interface (spec 10, section
// 10.2).
func BenchmarkVerifyOrdinaryV2(b *testing.B) {
	fx := loadV2Fixture(b, "coin_reveal_v2.bin.gz", coinRevealV2Bytes)
	r := ordinaryV2(b, fx)
	in := r.VerifyInputs(fx.chainID, fx.domain)
	v := ghostpriv.DefaultVerifier()
	for b.Loop() {
		if err := v.VerifyReveal(in, r.Proof); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPolicyReveal(b *testing.B) {
	fx := loadV2Fixture(b, "policy_reveal.bin.gz", policyRevealBytes)
	r := policyV1(b, fx)
	in := r.VerifyInputs(fx.chainID, fx.domain)
	v := ghostpriv.DefaultVerifier()
	for b.Loop() {
		if err := v.VerifyReveal(in, r.Proof); err != nil {
			b.Fatal(err)
		}
	}
}
