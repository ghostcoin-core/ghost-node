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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/vm"
)

// The verification measurement of spec 10, section 10.2: at least 1,000
// verifications of each statement in the node's own verifier, valid and
// invalid, whose slowest must be at most the statement's verification charge
// divided by 10,000 gas per millisecond. It runs only with
// GHOST_VERIFY_TIMING_RUNS set (the number of valid and of invalid runs per
// statement), because 1,000 runs take a minute per statement:
//
//	GHOST_VERIFY_TIMING_RUNS=1000 CGO_ENABLED=1 go test -tags ghostproofs \
//	    -run '^TestVerifyTiming' -v ./core/ghostpriv/
//
// The measured figures and the machine are recorded in spec 10, section
// 10.2, of the ghost repository, whose charges the constants carry.

func timingRuns(t *testing.T) int {
	t.Helper()
	n, err := strconv.Atoi(os.Getenv("GHOST_VERIFY_TIMING_RUNS"))
	if err != nil || n <= 0 {
		t.Skip("set GHOST_VERIFY_TIMING_RUNS to measure verification times")
	}
	return n
}

// timeVerify verifies runs times with valid inputs and runs times with
// invalid ones (alternating a changed public field and a flipped proof
// byte), checks every answer, logs the median and slowest of each and checks
// the slowest of all against verifyGas.
func timeVerify(t *testing.T, name string, runs int, verifyGas uint64, in func() *ghostpriv.VerifyInputs, change func(*ghostpriv.VerifyInputs), proof []byte) {
	t.Helper()
	v := ghostpriv.DefaultVerifier()
	bad := common.CopyBytes(proof)
	bad[len(bad)/2] ^= 1
	valid := make([]time.Duration, runs)
	invalid := make([]time.Duration, runs)
	good := in()
	changed := in()
	change(changed)
	// One warm-up of each, not counted: the first call loads the
	// verifier's tables.
	if err := v.VerifyReveal(good, proof); err != nil {
		t.Fatalf("%s warm-up: %v", name, err)
	}
	_ = v.VerifyReveal(changed, proof)
	for i := 0; i < runs; i++ {
		start := time.Now()
		err := v.VerifyReveal(good, proof)
		valid[i] = time.Since(start)
		if err != nil {
			t.Fatalf("%s run %d: %v", name, i, err)
		}
		x, p := changed, proof
		if i%2 == 1 {
			x, p = good, bad
		}
		start = time.Now()
		err = v.VerifyReveal(x, p)
		invalid[i] = time.Since(start)
		if !errors.Is(err, ghostpriv.ErrProofRejected) {
			t.Fatalf("%s invalid run %d: %v, want %v", name, i, err, ghostpriv.ErrProofRejected)
		}
	}
	slices.Sort(valid)
	slices.Sort(invalid)
	p99 := func(d []time.Duration) time.Duration { return d[len(d)*99/100] }
	slowest := max(valid[runs-1], invalid[runs-1])
	bound := time.Duration(verifyGas) * time.Millisecond / gasPerMs
	t.Logf("%s on %s/%s, %d CPUs: valid %d runs median %v 99th %v slowest %v; invalid %d runs median %v 99th %v slowest %v; bound %v (%d gas)",
		name, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runs, valid[runs/2], p99(valid), valid[runs-1],
		runs, invalid[runs/2], p99(invalid), invalid[runs-1], bound, verifyGas)
	if slowest > bound {
		t.Errorf("%s: slowest verification %v is above %v, the charge of %d gas", name, slowest, bound, verifyGas)
	}
}

func TestVerifyTimingOrdinaryV2(t *testing.T) {
	runs := timingRuns(t)
	fx := loadV2Fixture(t, "coin_reveal_v2.bin.gz", coinRevealV2Bytes)
	r := ordinaryV2(t, fx)
	timeVerify(t, "version 2 ordinary reveal", runs, verifyGasOrd,
		func() *ghostpriv.VerifyInputs { return r.VerifyInputs(fx.chainID, fx.domain) },
		func(in *ghostpriv.VerifyInputs) { in.Marker[0] ^= 1 }, r.Proof)
}

func TestVerifyTimingPolicyReveal(t *testing.T) {
	runs := timingRuns(t)
	fx := loadV2Fixture(t, "policy_reveal.bin.gz", policyRevealBytes)
	r := policyV1(t, fx)
	timeVerify(t, "policy reveal", runs, verifyGasPolicy,
		func() *ghostpriv.VerifyInputs { return r.VerifyInputs(fx.chainID, fx.domain) },
		func(in *ghostpriv.VerifyInputs) { in.Marker[0] ^= 1 }, r.Proof)
}

func TestVerifyTimingPolicyAction(t *testing.T) {
	runs := timingRuns(t)
	useStub(t)
	s := newActionScenario(t, actionPolicyA)
	marker := actionMarker(actionPolicyA)
	slot := s.slot(t, actionPolicyA)
	a := s.next(t, actionPolicyA, vm.ActionMarkerSelector[:])
	request := actionRequest(a.VerifyInputs(s.f.chainID, s.f.genesis.Hash(), slot))
	a.Proof = realActionProof(t, filepath.Join("testdata", "know_action.bin.gz"), request, testActionRoot(marker))
	dec, err := ghostpriv.DecodeAction(actionEnvelope(t, a))
	if err != nil {
		t.Fatal(err)
	}
	timeVerify(t, "policy action", runs, verifyGasAction,
		func() *ghostpriv.VerifyInputs { return dec.VerifyInputs(s.f.chainID, s.f.genesis.Hash(), slot) },
		func(in *ghostpriv.VerifyInputs) { in.Marker[0] ^= 1 }, dec.Proof)
}
