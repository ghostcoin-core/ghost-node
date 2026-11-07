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

package ghostscale_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghostscale"
	"github.com/ethereum/go-ethereum/core/types"
)

// envInt reads a positive count from the environment, or def.
func envInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		t.Fatalf("%s=%q is not a positive count", name, v)
	}
	return n
}

func stubConfig(t *testing.T, n, runs int) ghostscale.Config {
	t.Cleanup(ghostpriv.SetVerifier(ghostprivtest.Verifier{}))
	return ghostscale.Config{
		Reveals:         n,
		Public:          n,
		Runs:            runs,
		Dir:             t.TempDir(),
		BundleProof:     ghostprivtest.BundleProof,
		PublicRootProof: ghostprivtest.PublicRootProof,
	}
}

// TestScaleBlock builds and imports, timed, a block of GHOST_SCALE_BENCH_TXS
// reveals and as many public transactions (3,500 each by default, 50 in
// short mode), GHOST_SCALE_BENCH_RUNS times (5 by default), and checks the
// record: measured, without root proof verification, the machine named, the
// execution time against the 3,000 ms budget of spec 07, section 4, and the
// disk growth a day. With GHOST_SCALE_BENCH_OUT set it writes the record and
// its README into that folder (docs/scale for the committed run).
func TestScaleBlock(t *testing.T) {
	def := ghostscale.FullCount
	if testing.Short() {
		def = 50
	}
	n := envInt(t, "GHOST_SCALE_BENCH_TXS", def)
	runs := envInt(t, "GHOST_SCALE_BENCH_RUNS", 5)
	res, err := ghostscale.Run(stubConfig(t, n, runs))
	if err != nil {
		t.Fatal(err)
	}

	bundles := (n + ghostpriv.BundleMaxReveals - 1) / ghostpriv.BundleMaxReveals
	switch {
	case res.Label != "measured" || res.Scope != "block execution without root proof verification":
		t.Fatalf("label %q, scope %q", res.Label, res.Scope)
	case res.Block.Reveals != n || res.Block.PublicTransactions != n:
		t.Fatalf("block of %d reveals and %d public transactions, want %d", res.Block.Reveals, res.Block.PublicTransactions, n)
	case res.Block.Bundles != bundles || res.Block.Transactions != bundles+1+n:
		t.Fatalf("%d bundles and %d transactions, want %d and %d", res.Block.Bundles, res.Block.Transactions, bundles, bundles+1+n)
	case res.Block.GasUsed < uint64(n)*ghostpriv.GasPriv:
		t.Fatalf("gas used %d, below the reveals' %d", res.Block.GasUsed, uint64(n)*ghostpriv.GasPriv)
	case res.Machine.Hostname == "" || res.Machine.CPU == "" || res.Machine.Cores < 1 || res.Machine.Arch == "" || res.Machine.GoVersion == "" || res.Machine.Date == "":
		t.Fatalf("machine not named: %+v", res.Machine)
	case res.Runs != runs || len(res.Execution.Each) != runs:
		t.Fatalf("%d runs, %d times, want %d", res.Runs, len(res.Execution.Each), runs)
	case res.Execution.Median <= 0 || res.Execution.Slowest < res.Execution.Median:
		t.Fatalf("median %v ms, slowest %v ms", res.Execution.Median, res.Execution.Slowest)
	case res.Budget.Ms != 3000 || res.Budget.Source != "spec 07, section 4":
		t.Fatalf("budget %d ms of %q", res.Budget.Ms, res.Budget.Source)
	case res.Disk.BytesPerBlock <= 0 || res.Disk.BlocksPerDay != 2880 || res.Disk.BytesPerDay != res.Disk.BytesPerBlock*2880:
		t.Fatalf("disk %+v", res.Disk)
	}
	if want := 100 * res.Execution.Median / 3000; res.Budget.MedianSharePercent < want-0.1 || res.Budget.MedianSharePercent > want+0.1 {
		t.Fatalf("median share %v%%, want %v%%", res.Budget.MedianSharePercent, want)
	}
	t.Logf("%d reveals and %d public transactions, %d bytes: median %.1f ms, slowest %.1f ms of the %d ms budget (%.1f%%), %d bytes a block, %.2f GB a day, on %s (%s, %d cores)",
		n, n, res.Block.Bytes, res.Execution.Median, res.Execution.Slowest, res.Budget.Ms, res.Budget.MedianSharePercent,
		res.Disk.BytesPerBlock, res.Disk.GBPerDay, res.Machine.Hostname, res.Machine.CPU, res.Machine.Cores)

	if out := os.Getenv("GHOST_SCALE_BENCH_OUT"); out != "" {
		if err := res.WriteFiles(out); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s and README.md to %s", ghostscale.FileName(n), out)
	}
}

// TestScaleBlockRecordWording checks what the record and its README say: the
// measured scope, no root proof time, and no claim that the budget is met.
func TestScaleBlockRecordWording(t *testing.T) {
	res, err := ghostscale.Run(stubConfig(t, 3, 1))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := res.WriteFiles(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ghostscale.FileName(3)))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"label", "scope", "machine", "block", "execution_ms", "budget", "disk"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("record has no %q", k)
		}
	}
	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{string(raw), string(readme)} {
		lower := strings.ToLower(text)
		if !strings.Contains(lower, "block execution without root proof verification") {
			t.Error("the record does not say it is block execution without root proof verification")
		}
		if !strings.Contains(lower, "does not show") {
			t.Error("the record does not say the share does not show the budget is met")
		}
		for _, claim := range []string{"meets the budget", "within the budget", "budget met", "root proof time:", "root_proof_ms", "verification_ms"} {
			if strings.Contains(lower, claim) {
				t.Errorf("the record says %q", claim)
			}
		}
	}
	if !strings.Contains(string(readme), "Measured: block execution without root proof verification") {
		t.Error("the README does not open with what was measured")
	}
}

// TestScaleBlockChecksHeaderMMR checks that the timed import checks the
// header MMR root: the block with its root changed is refused before any of
// it is written, and a block whose stub root proof is refused fails too, so
// the root proofs are on the timed path.
func TestScaleBlockChecksHeaderMMR(t *testing.T) {
	cfg := stubConfig(t, 3, 1)
	b, err := ghostscale.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Execute(filepath.Join(cfg.Dir, "good"), b.Block()); err != nil {
		t.Fatalf("the benchmark block: %v", err)
	}

	header := types.CopyHeader(b.Block().Header())
	wrong := *header.HeaderMmrRoot
	wrong[0] ^= 1
	header.HeaderMmrRoot = &wrong
	bad := b.Block().WithSeal(header)
	if _, err := b.Execute(filepath.Join(cfg.Dir, "wrong mmr"), bad); !errors.Is(err, randomx.ErrHeaderMmrRoot) {
		t.Fatalf("block with a wrong header MMR root: %v, want %v", err, randomx.ErrHeaderMmrRoot)
	}
	header.HeaderMmrRoot = nil
	if _, err := b.Execute(filepath.Join(cfg.Dir, "no mmr"), b.Block().WithSeal(header)); err == nil {
		t.Fatal("block without a header MMR root imported")
	}

	// The same block under a verifier that refuses every bundle root.
	restore := ghostpriv.SetVerifier(refuseBundles{})
	defer restore()
	if _, err := b.Execute(filepath.Join(cfg.Dir, "refused root"), b.Block()); !errors.Is(err, ghostpriv.ErrBundleProof) {
		t.Fatalf("block whose bundle roots are refused: %v, want %v", err, ghostpriv.ErrBundleProof)
	}
}

// refuseBundles is the stub verifier refusing every bundle root.
type refuseBundles struct{ ghostprivtest.Verifier }

func (refuseBundles) VerifyBundle(*ghostpriv.BundleInputs, []byte) error {
	return errors.New("refused")
}
