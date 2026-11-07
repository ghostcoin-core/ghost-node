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

package ghostscale

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
)

// Result is the record of a benchmark run.
type Result struct {
	Label   string    `json:"label"` // Label
	Scope   string    `json:"scope"` // Scope
	Machine Machine   `json:"machine"`
	Block   BlockInfo `json:"block"`
	Method  []string  `json:"method"`

	Runs      int         `json:"runs"`
	Execution ExecutionMs `json:"execution_ms"`
	Budget    Budget      `json:"budget"`
	Disk      Disk        `json:"disk"`
	Notes     []string    `json:"notes"`
}

// BlockInfo describes the benchmark block.
type BlockInfo struct {
	Reveals            int    `json:"reveals"`
	PublicTransactions int    `json:"public_transactions"`
	Bundles            int    `json:"bundles"`
	PublicRoots        int    `json:"public_roots"`
	Transactions       int    `json:"transactions"`
	GasUsed            uint64 `json:"gas_used"`
	Bytes              uint64 `json:"bytes"`
	RootProofFields    int    `json:"root_proof_fields"`
	RootProofBytes     int    `json:"root_proof_field_bytes"`
}

// ExecutionMs are the times of the timed imports, in milliseconds.
type ExecutionMs struct {
	Median  float64   `json:"median"`
	Slowest float64   `json:"slowest"`
	Each    []float64 `json:"each_run"`
}

// Budget is the time budget the execution is set against.
type Budget struct {
	Ms                  int     `json:"ms"`
	Source              string  `json:"source"`
	MedianSharePercent  float64 `json:"median_share_percent"`
	SlowestSharePercent float64 `json:"slowest_share_percent"`
	Covers              string  `json:"covers"`
}

// Disk is the disk growth of the block.
type Disk struct {
	BytesPerBlock int64   `json:"bytes_per_block"`
	BlocksPerDay  int     `json:"blocks_per_day"`
	BytesPerDay   int64   `json:"bytes_per_day"`
	GBPerDay      float64 `json:"gb_per_day"`
	Measured      string  `json:"measured"`

	// The root proof fields are zeros past the stub proof's 32 bytes, which
	// the database compresses away; a real root proof does not compress.
	// RootProofGBPerDay is what the fields add a day uncompressed: computed
	// from their size, not measured.
	RootProofGBPerDay float64 `json:"root_proof_fields_gb_per_day_not_measured"`
}

// Run builds the benchmark and imports its block cfg.Runs times, each into a
// fresh database, and returns the result on this machine.
func Run(cfg Config) (*Result, error) {
	if cfg.Runs < 1 {
		return nil, fmt.Errorf("ghostscale: %d runs", cfg.Runs)
	}
	b, err := Build(cfg)
	if err != nil {
		return nil, err
	}
	var (
		times  []time.Duration
		growth []int64
	)
	for k := range cfg.Runs {
		m, err := b.Execute(filepath.Join(cfg.Dir, fmt.Sprintf("run-%d", k)), b.block)
		if err != nil {
			return nil, fmt.Errorf("ghostscale: run %d: %w", k, err)
		}
		times = append(times, m.Elapsed)
		growth = append(growth, m.DiskAfter-m.DiskBefore)
	}
	return b.result(time.Now(), times, growth), nil
}

func ms(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/100) / 10 }

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// result is the record of the runs' times and disk growths.
func (b *Bench) result(now time.Time, times []time.Duration, growth []int64) *Result {
	each := make([]float64, len(times))
	for i, t := range times {
		each[i] = ms(t)
	}
	sorted := slices.Clone(times)
	slices.Sort(sorted)
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	slowest := sorted[len(sorted)-1]
	g := slices.Clone(growth)
	slices.Sort(g)
	perBlock := g[len(g)/2]

	fields := b.bundles + 1
	proofBytes := fields * ghostpriv.ProofSize
	r := &Result{
		Label:   Label,
		Scope:   Scope,
		Machine: ThisMachine(now),
		Block: BlockInfo{
			Reveals:            b.cfg.Reveals,
			PublicTransactions: b.cfg.Public,
			Bundles:            b.bundles,
			PublicRoots:        1,
			Transactions:       len(b.block.Transactions()),
			GasUsed:            b.block.GasUsed(),
			Bytes:              b.block.Size(),
			RootProofFields:    fields,
			RootProofBytes:     proofBytes,
		},
		Method: []string{
			"The block is built once with the chain maker on a genesis that funds the public senders, records their key identities and seeds the hidden set; the reveals spend the genesis coin root.",
			"Each run opens a fresh pebble database holding only that genesis and times core.BlockChain.InsertChain of the block: the header checks of the benchmark engine (parent link, gas used, header MMR root), the body checks, the state processor running the bundles, the public root and the binding transactions with their coin tree appends and spent markers, the receipt, bloom, tree root and state root checks, the state commit and the block, receipt and header MMR writes.",
			"The state cache writes every block's state trie to the database (hash scheme, no dirty trie cache, no snapshot); no transaction index is kept.",
			"After each run the import is checked: every reveal applied, every public transaction successful, the hidden set's total out, every public recipient paid, the gas used, and the block's header MMR state stored with the header's root.",
		},
		Runs: len(times),
		Execution: ExecutionMs{
			Median:  ms(median),
			Slowest: ms(slowest),
			Each:    each,
		},
		Budget: Budget{
			Ms:                  BudgetMs,
			Source:              BudgetSource,
			MedianSharePercent:  round(100*float64(median)/float64(BudgetMs*time.Millisecond), 1),
			SlowestSharePercent: round(100*float64(slowest)/float64(BudgetMs*time.Millisecond), 1),
			Covers:              "the budget is for verifying the block, root proofs included; this share is that of block execution without root proof verification only, so it does not show that the budget is met",
		},
		Disk: Disk{
			BytesPerBlock:     perBlock,
			BlocksPerDay:      BlocksPerDay,
			BytesPerDay:       perBlock * BlocksPerDay,
			GBPerDay:          round(float64(perBlock*BlocksPerDay)/1e9, 2),
			Measured:          "growth of the database's table files, after compaction, from the genesis to the imported block; median of the runs",
			RootProofGBPerDay: round(float64(int64(proofBytes)*BlocksPerDay)/1e9, 2),
		},
		Notes: []string{
			"The root proofs of the bundles and the public root are checked by the stub verifier of the tests, which compares one hash: no root proof is verified here and no root proof time is given. The real root proof verifier waits for the stage 2 prover.",
			"The block's gas limit is above the consensus maximum of 30,000,000, which holds a bundle of at most one reveal, so the benchmark engine does not check it; nor the difficulty, the timestamp or the RandomX seal, which take the same time for any block.",
			"Disk growth counts the stub root proof fields, zeros past 32 bytes, as the database compresses them; real root proofs do not compress, and their fields would add up to root_proof_fields_gb_per_day_not_measured a day.",
		},
	}
	return r
}

// FileName is the name of the result file of a block of n reveals.
func FileName(n int) string { return fmt.Sprintf("block-%d.json", n) }

// WriteFiles writes the result as FileName(reveals) and a README.md beside
// it into dir.
func (r *Result) WriteFiles(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	enc, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	name := FileName(r.Block.Reveals)
	if err := os.WriteFile(filepath.Join(dir, name), append(enc, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(r.readme(name)), 0o644)
}

// readme is the README of the result file name.
func (r *Result) readme(name string) string {
	var b strings.Builder
	m := r.Machine
	fmt.Fprintf(&b, "# Scale benchmark: one block of %s reveals and %s public transactions\n\n", thousands(int64(r.Block.Reveals)), thousands(int64(r.Block.PublicTransactions)))
	fmt.Fprintf(&b, "Measured: %s. The record is [`%s`](%s), written by `TestScaleBlock` in `core/ghostscale` when `GHOST_SCALE_BENCH_OUT` names this folder. `GHOST_SCALE_BENCH_TXS` sets the number of reveals and of public transactions (3,500 by default) and `GHOST_SCALE_BENCH_RUNS` the number of timed imports (5 by default).\n\n", r.Scope, name, name)

	fmt.Fprintf(&b, "Machine: `%s`, %s, %d cores, %s/%s", m.Hostname, m.CPU, m.Cores, m.OS, m.Arch)
	if m.MemoryBytes > 0 {
		fmt.Fprintf(&b, ", %.1f GiB of memory", float64(m.MemoryBytes)/(1<<30))
	}
	fmt.Fprintf(&b, ", %s, %s.\n\n", m.GoVersion, m.Date)

	bundles := "bundles"
	if r.Block.Bundles == 1 {
		bundles = "bundle"
	}
	fmt.Fprintf(&b, "The block holds %d %s of reveals, one public root and %s binding transactions: %s transactions, %s gas, %s bytes.\n\n",
		r.Block.Bundles, bundles, thousands(int64(r.Block.PublicTransactions)), thousands(int64(r.Block.Transactions)), thousands(int64(r.Block.GasUsed)), thousands(int64(r.Block.Bytes)))

	b.WriteString("| Measure | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Block execution, median of %d runs | %.1f ms |\n", r.Runs, r.Execution.Median)
	fmt.Fprintf(&b, "| Block execution, slowest run | %.1f ms |\n", r.Execution.Slowest)
	fmt.Fprintf(&b, "| Budget of %s | %s ms |\n", r.Budget.Source, thousands(int64(r.Budget.Ms)))
	fmt.Fprintf(&b, "| Share of the budget, median / slowest | %.1f%% / %.1f%% |\n", r.Budget.MedianSharePercent, r.Budget.SlowestSharePercent)
	fmt.Fprintf(&b, "| Database growth for the block | %s bytes |\n", thousands(r.Disk.BytesPerBlock))
	fmt.Fprintf(&b, "| Disk growth a day, %s blocks | %.2f GB |\n\n", thousands(int64(r.Disk.BlocksPerDay)), r.Disk.GBPerDay)

	fmt.Fprintf(&b, "What the time covers: %s\n\n", strings.Join(r.Method[1:3], " "))
	fmt.Fprintf(&b, "What it does not cover: root proof verification. %s The budget is for verifying the block with its root proofs, so the share above is that of execution alone and does not show the budget is met. See [root verification time](../private-transactions.md#root-verification-time).\n\n", r.Notes[0])
	fmt.Fprintf(&b, "%s\n\n", r.Notes[1])
	fmt.Fprintf(&b, "Disk growth is the %s. It counts the %d stub root proof fields, zeros past 32 bytes, as the database compresses them. Real root proofs do not compress: their fields, %s bytes a block, would add up to %.2f GB a day (computed from their size, not measured).\n",
		r.Disk.Measured, r.Block.RootProofFields, thousands(int64(r.Block.RootProofBytes)), r.Disk.RootProofGBPerDay)
	return b.String()
}

// thousands formats n with commas between groups of three digits.
func thousands(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []byte
	for i := range len(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
