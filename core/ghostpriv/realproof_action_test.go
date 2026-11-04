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
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// actionStatementBytes is the length of a KNOW_ACTION_v1 statement in the
// layout of ghost_action.h.
const actionStatementBytes = 228

const realActionRegenerate = `regenerate the fixture: GHOST_REAL_PROOF_REQUEST=/tmp/know_action.req CGO_ENABLED=1 go test -tags ghostproofs -run '^TestRealProofPolicyAction$' ./core/ghostpriv/, then cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example actionfixture -- /tmp/know_action.req know_action.bin and gzip -n -9 know_action.bin into core/ghostpriv/testdata/ (see ghostverifier/examples/actionfixture.rs)`

// actionRequest is the chain parameters and the KNOW_ACTION_v1 statement of
// in, in the layout of ghost_action.h, as the node builds them.
func actionRequest(in *ghostpriv.VerifyInputs) []byte {
	b := binary.BigEndian.AppendUint64(nil, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, ghostpriv.PolicyActionVersion)
	b = append(b, in.Domain[:]...)
	b = append(b, in.Policy[:]...)
	b = append(b, in.Marker[:]...)
	b = binary.BigEndian.AppendUint64(b, in.ActionNonce)
	b = append(b, in.ActionTag[:]...)
	b = append(b, in.ActionSalt[:]...)
	e, d := in.ExpectedRemaining.Bytes32(), in.Debit.Bytes32()
	b = append(b, e[:]...)
	b = append(b, d[:]...)
	b = binary.BigEndian.AppendUint64(b, in.Expiry)
	return append(b, in.CalldataHash[:]...)
}

// realActionProof returns the recorded proof of the action fixture, after
// checking that it was made for exactly request. With
// GHOST_REAL_PROOF_REQUEST set it writes request and the action root to that
// file and skips the test.
func realActionProof(t *testing.T, fixture string, request []byte, root common.Hash) []byte {
	t.Helper()
	if out := os.Getenv("GHOST_REAL_PROOF_REQUEST"); out != "" {
		if err := os.WriteFile(out, append(common.CopyBytes(request), root[:]...), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote the action proof request to %s", out)
	}
	f, err := os.Open(fixture)
	if err != nil {
		t.Fatalf("%v; %s", err, realActionRegenerate)
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
	if len(raw) <= len(request) || !bytes.Equal(raw[:len(request)], request) {
		t.Fatalf("the fixture is not for this action; %s", realActionRegenerate)
	}
	proof := raw[len(request):]
	if len(proof) > ghostpriv.ActionProofSize {
		t.Fatalf("proof of %d bytes, the field holds %d", len(proof), ghostpriv.ActionProofSize)
	}
	return proof
}

// TestRealProofPolicyAction checks that the default verifier accepts the
// pinned prover's KNOW_ACTION_v1 proof of a 0x54 action on a slot opened in
// a chain, through the inputs the node builds for its decoded envelope with
// the proof field padded, and that the action then executes: the slot pays
// the debit and spends its nonce. It rejects the proof with any public field
// changed, with a flipped proof byte or as another version, and an action
// with a flipped proof byte changes nothing. It logs the median and slowest
// of GHOST_ACTION_VERIFY_RUNS verifications (10 by default), for the 11.0 ms
// bound of spec 10, section 10.2.
func TestRealProofPolicyAction(t *testing.T) {
	useStub(t)
	s := newActionScenario(t, actionPolicyA)
	marker := actionMarker(actionPolicyA)
	slot := s.slot(t, actionPolicyA)
	a := s.next(t, actionPolicyA, vm.ActionMarkerSelector[:])
	in := func() *ghostpriv.VerifyInputs { return a.VerifyInputs(s.f.chainID, s.f.genesis.Hash(), slot) }
	request := actionRequest(in())
	if len(request) != 42+actionStatementBytes {
		t.Fatalf("request of %d bytes", len(request))
	}
	a.Proof = realActionProof(t, filepath.Join("testdata", "know_action.bin.gz"), request, testActionRoot(marker))

	// The proof as the node decodes it from the envelope: the full field.
	dec, err := ghostpriv.DecodeAction(actionEnvelope(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Proof) != ghostpriv.ActionProofSize {
		t.Fatalf("decoded proof field of %d bytes", len(dec.Proof))
	}
	v := ghostpriv.DefaultVerifier()
	runs := 10
	if n, err := strconv.Atoi(os.Getenv("GHOST_ACTION_VERIFY_RUNS")); err == nil && n > 0 {
		runs = n
	}
	times := make([]time.Duration, runs)
	decIn := dec.VerifyInputs(s.f.chainID, s.f.genesis.Hash(), slot)
	for i := range times {
		start := time.Now()
		if err := v.VerifyReveal(decIn, dec.Proof); err != nil {
			t.Fatalf("policy action: %v", err)
		}
		times[i] = time.Since(start)
	}
	slices.Sort(times)
	t.Logf("policy action verified %d times (proof of %d bytes in a field of %d): median %v, slowest %v",
		runs, len(a.Proof), len(dec.Proof), times[runs/2], times[runs-1])

	changes := map[string]func(*ghostpriv.VerifyInputs){
		"policy":             func(in *ghostpriv.VerifyInputs) { in.Policy[0] ^= 1 },
		"marker":             func(in *ghostpriv.VerifyInputs) { in.Marker[0] ^= 1 },
		"action nonce":       func(in *ghostpriv.VerifyInputs) { in.ActionNonce++ },
		"action tag":         func(in *ghostpriv.VerifyInputs) { in.ActionTag[0] ^= 1 },
		"action salt":        func(in *ghostpriv.VerifyInputs) { in.ActionSalt[0] ^= 1 },
		"expected remaining": func(in *ghostpriv.VerifyInputs) { in.ExpectedRemaining.AddUint64(in.ExpectedRemaining, 1) },
		"debit":              func(in *ghostpriv.VerifyInputs) { in.Debit.AddUint64(in.Debit, 1) },
		"expiry":             func(in *ghostpriv.VerifyInputs) { in.Expiry++ },
		"calldata hash":      func(in *ghostpriv.VerifyInputs) { in.CalldataHash[0] ^= 1 },
		"chain id":           func(in *ghostpriv.VerifyInputs) { in.ChainID++ },
		"domain":             func(in *ghostpriv.VerifyInputs) { in.Domain[0] ^= 1 },
	}
	for name, change := range changes {
		x := in()
		change(x)
		if err := v.VerifyReveal(x, a.Proof); !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Errorf("%s changed: %v, want %v", name, err, ghostpriv.ErrProofRejected)
		}
	}
	x := in()
	x.Version = 2
	if err := v.VerifyReveal(x, a.Proof); !errors.Is(err, ghostpriv.ErrStatementUnsupported) {
		t.Errorf("as version 2: %v, want %v", err, ghostpriv.ErrStatementUnsupported)
	}
	x = in()
	x.Purpose = ghostpriv.PurposePolicySpend
	if err := v.VerifyReveal(x, a.Proof); err == nil {
		t.Error("the action proof was accepted as a policy reveal")
	}
	for _, at := range []int{0, len(a.Proof) / 2, len(a.Proof) - 1} {
		bad := common.CopyBytes(a.Proof)
		bad[at] ^= 1
		if err := v.VerifyReveal(in(), bad); !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Errorf("proof byte %d flipped: %v, want %v", at, err, ghostpriv.ErrProofRejected)
		}
	}

	// Execution with the default verifier active: a flipped proof byte is
	// refused at check 10 and changes nothing; the recorded proof executes.
	useDefault(t)
	before := s.fingerprint()
	bad := *a
	bad.Proof = common.CopyBytes(a.Proof)
	bad.Proof[len(bad.Proof)/2] ^= 1
	if _, _, err := s.apply(t, &bad, new(core.GasPool).AddGas(ghostpriv.GasAction), vm.Config{}); !errors.Is(err, ghostpriv.ErrActionProof) {
		t.Fatalf("action with a flipped proof byte: %v, want %v", err, ghostpriv.ErrActionProof)
	}
	if after := s.fingerprint(); after != before {
		t.Fatal("the refused action changed the state")
	}
	receipt, _, err := s.apply(t, a, new(core.GasPool).AddGas(ghostpriv.GasAction), vm.Config{})
	if err != nil {
		t.Fatalf("real-proof action: %v", err)
	}
	res := resultOf(t, receipt.Logs, marker)
	if !res.success || res.nonce != slot.ActionNonce || res.retHash != ghostpriv.ActionReturnHash(append(word(1), marker[:]...)) {
		t.Fatalf("action result %+v", res)
	}
	after := s.slot(t, actionPolicyA)
	if want := new(uint256.Int).Sub(slot.Remaining, a.Debit); !after.Remaining.Eq(want) || after.ActionNonce != slot.ActionNonce+1 {
		t.Fatalf("slot remaining %v nonce %d after the action", after.Remaining, after.ActionNonce)
	}
}
