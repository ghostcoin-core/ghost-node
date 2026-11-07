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

//go:build cgo && ghostproofs && (linux || darwin)

package lifecycle

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
)

// TestRealProofGuardLifecycle runs the Guard lifecycle of guard_test.go on
// the real linked verifier, every proof a real one of the pinned prover from
// the fixture of ghostverifier/examples/guardfixture.rs: the override spend
// beside a plain spend, the cancelled theft and the release after the hold,
// each on a network of its own, with the same steps and checks as on the
// stub verifier. Each proof must be for the very statement and opening the
// run builds, so the fixture regenerates byte for byte from the request this
// run writes.
//
// With GHOST_REAL_PROOF_REQUEST set it runs the lifecycle on the stub
// verifier, writes the request there and skips. Without the fixture, which
// is made on a host, it skips saying how to make it.
func TestRealProofGuardLifecycle(t *testing.T) {
	var (
		out      = os.Getenv(realProofRequestEnv)
		proofs   = new(realProofs)
		verifier ghostpriv.Verifier // the default, the linked verifier
		raw      []byte
	)
	if out != "" {
		verifier = ghostprivtest.Verifier{}
	} else {
		var err error
		raw, err = readGzipFile(realGuardFixture)
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("no fixture %s yet; %s", realGuardFixture, realGuardRegenerate)
		}
		if err != nil {
			t.Fatalf("%v; %s", err, realGuardRegenerate)
		}
		proofs.load(t, raw)
	}

	parts := []struct {
		name string
		run  func(*testing.T, *scenario)
	}{
		{"override spend", guardOverrideSpend},
		{"theft cancelled", guardTheftCancelled},
		{"release after hold", guardReleaseAfterHold},
	}
	for _, part := range parts {
		ok := t.Run(part.name, func(t *testing.T) {
			s := newScenarioOn(t, newNetworkWith(t, networkSize, verifier), proofs)
			if out == "" && ghostpriv.ActiveVerifier() != ghostpriv.DefaultVerifier() {
				t.Fatalf("active verifier %T, want the default", ghostpriv.ActiveVerifier())
			}
			part.run(t, s)
		})
		if !ok {
			return
		}
	}

	if out != "" {
		if err := os.WriteFile(out, proofs.request(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote the request of %d proofs to %s; now run ghostverifier/examples/guardfixture.rs", len(proofs.jobs), out)
	}
	proofs.done(t, raw)
	t.Logf("the Guard lifecycle ran on the linked verifier with %d real proofs", len(proofs.jobs))
}
