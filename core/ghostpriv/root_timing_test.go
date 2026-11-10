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
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
)

const (
	// rootProofDirEnv names a folder written in the layout of the root
	// fixture generator that holds a real-shape shrink proof. Without it the
	// test-shape fixture of GHOST_ROOT_FIXTURE_DIR is timed on the same path.
	rootProofDirEnv = "GHOST_ROOT_PROOF_DIR"

	rootsPerBlock = 4
	timingRounds  = 10
	rootBudget    = 3000 * time.Millisecond
)

// cpuModel is the machine's CPU model as /proc/cpuinfo names it.
func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" {
				return strings.TrimSpace(v)
			}
		}
	}
	return "unknown (" + runtime.GOARCH + ")"
}

// TestLinkedRootVerifierTiming times the four root verifications of one block
// through the linked verifier, for ten rounds, and reports the median and the
// worst against the 3,000 ms of spec 07 section 4. It fails, never skips, when
// no proof can be loaded.
func TestLinkedRootVerifierTiming(t *testing.T) {
	if dir := os.Getenv(rootProofDirEnv); dir != "" {
		t.Setenv(rootFixtureEnv, dir)
	}
	b, p := loadBundleRoot(t), loadPublicRoot(t)
	v := linkedRootVerifier(t, b, p)
	in := ghostpriv.NewBundleInputs(b.chainID, b.genesis, []*ghostpriv.Reveal{b.reveal})

	// Once outside the timing: the proof must verify, or the numbers mean nothing.
	if err := ghostpriv.VerifyBundleRoot(v, in, b.proof); err != nil {
		t.Fatalf("the saved root proof: %v", err)
	}
	times := make([]time.Duration, timingRounds)
	for i := range times {
		start := time.Now()
		for j := 0; j < rootsPerBlock; j++ {
			if err := ghostpriv.VerifyBundleRoot(v, in, b.proof); err != nil {
				t.Fatalf("round %d, root %d: %v", i, j, err)
			}
		}
		times[i] = time.Since(start)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	median := (times[timingRounds/2-1] + times[timingRounds/2]) / 2
	worst := times[timingRounds-1]

	t.Logf("measured: %d root verifications per block, %d rounds, proof of %d bytes", rootsPerBlock, timingRounds, len(b.proof))
	t.Logf("measured: median %d ms, worst %d ms against the %d ms budget", median.Milliseconds(), worst.Milliseconds(), rootBudget.Milliseconds())
	t.Logf("machine: %s, %d cores", cpuModel(), runtime.NumCPU())
}
