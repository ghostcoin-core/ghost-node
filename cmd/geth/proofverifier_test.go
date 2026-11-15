// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"os"
	"testing"

	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/internal/cmdtest"
	"github.com/ethereum/go-ethereum/internal/reexec"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// stubVerifier stands in for the proof verifier in a test binary built
// without it, so the geth it runs passes the startup check for a public
// network. It rejects every reveal, as the build's own default does; no test
// here sends one.
type stubVerifier struct{}

func (stubVerifier) VerifyReveal(*ghostpriv.VerifyInputs, []byte) error {
	return ghostpriv.ErrNoVerifier
}

// A test binary without the proof verifier runs every geth with
// stubVerifier, except one run as "geth-test-no-verifier", which keeps the
// build's default and so is what a shipped build without the verifier is.
func init() {
	if !ghostpriv.CanVerifyProofs() {
		ghostpriv.SetVerifier(stubVerifier{})
	}
	reexec.Register("geth-test-no-verifier", func() {
		ghostpriv.SetVerifier(nil)
		args := append([]string{"geth"}, os.Args[1:]...)
		if err := app.Run(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	})
}

// runGethNoVerifier runs geth as a build without the proof verifier, on a
// new data directory.
func runGethNoVerifier(t *testing.T, args ...string) *testgeth {
	g := &testgeth{Datadir: t.TempDir()}
	g.TestCmd = cmdtest.NewTestCmd(t, g)
	g.Run("geth-test-no-verifier", append([]string{"--datadir", g.Datadir}, args...)...)
	return g
}

// TestNoVerifierRefusesPublicTestNet checks that a node built without the
// proof verifier, which would reject every block holding a reveal, refuses
// to start on the public test network, the network it runs with no flags,
// instead of forking off it.
func TestNoVerifierRefusesPublicTestNet(t *testing.T) {
	ghostpriv.SetVerifier(nil)
	linked := ghostpriv.CanVerifyProofs()
	ghostpriv.SetVerifier(stubVerifier{})
	if linked {
		t.Skip("this build links the proof verifier")
	}
	g := runGethNoVerifier(t, append([]string{"--maxpeers", "0", "--nodiscover", "--ipcdisable"}, localNetFlags...)...)
	g.ExpectRegexp(fmt.Sprintf(`Fatal: Failed to register the Ethereum service: this node was built without the reveal proof verifier.*\(chain ID %d\)\n`, ghost.TestNetChainID))
	g.ExpectExit()
	if g.ExitStatus() == 0 {
		t.Error("geth without the proof verifier exited 0 on the public test network")
	}
}

// TestNoVerifierRunsDevMode checks that developer mode still runs on a
// node built without the proof verifier.
func TestNoVerifierRunsDevMode(t *testing.T) {
	g := runGethNoVerifier(t, "--dev", "--port", "0", "--authrpc.port", "0", "--maxpeers", "0", "--nodiscover",
		"--nat", "none", "--ipcdisable", "--exec", "eth.chainId()", "console")
	g.KillTimeout = 3 * time.Minute
	g.Expect(fmt.Sprintf("%q\n", hexutil.EncodeUint64(ghost.DeveloperChainID)))
	g.ExpectExit()
}
