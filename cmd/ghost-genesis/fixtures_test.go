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
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The fixture generator. It mines Bitcoin headers at the easiest bits, so a
// nonce takes about two tries, and builds the header files of the fixtures
// in testdata. They are not Bitcoin's chain: the tests read them as a test
// chain whose checkpoint is their first header and whose proof-of-work limit
// is the target of those bits, defined here and nowhere in the command. The
// files are pinned: the tests compare the generator's output with them and,
// on a difference, print the generator's output, which
// is the content to write to rebuild a fixture. Every test derives from the
// stored file, not from the generator.
//
// T_L of the fixtures is an arbitrary test value. Main-branch block i has the
// time fixtureTL - 15*fixtureSpacing + i*fixtureSpacing, so its median time
// past is the time of block i-5 and block 20 is the first at or above T_L.
const (
	fixtureBits    = 0x207fffff
	fixtureVersion = 0x20000000
	fixtureTL      = 1_800_000_000
	fixtureSpacing = 600

	// fixtureMainLen is the length of the main branch: blocks 0 to 25, so
	// block 20 has exactly Confirmations.
	fixtureMainLen = 26

	// The reorg branch leaves the main branch after block fixtureForkAt and
	// runs to block fixtureReorgTip, with blocks fixtureReorgSpacing apart
	// from the fork, so its block 25 is the first at or above T_L.
	fixtureForkAt       = 10
	fixtureReorgTip     = 30
	fixtureReorgSpacing = 300
)

// fixtureHeader is a mined header with its hash.
type fixtureHeader struct {
	raw  [BitcoinHeaderSize]byte
	hash [32]byte
}

// fixturePowLimit is the easy proof-of-work limit of the fixtures' test
// chain, the target of fixtureBits. It exists only in the tests: the command
// reads Bitcoin mainnet alone.
func fixturePowLimit(t *testing.T) *big.Int {
	t.Helper()
	limit, err := compactTarget(fixtureBits)
	if err != nil {
		t.Fatal(err)
	}
	return limit
}

// fixtureChain is the test chain whose checkpoint is the fixture header
// first, at the given height, with the easy proof-of-work limit.
func fixtureChain(t *testing.T, first fixtureHeader, height int) chain {
	t.Helper()
	h, err := decodeBitcoinHeader(first.raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return chain{
		checkpointHash:   first.hash,
		checkpointHeight: height,
		checkpointBits:   h.Bits,
		powLimit:         fixturePowLimit(t),
	}
}

// normalChain is the test chain of the fixtures: its checkpoint is
// main-branch block 0, at height 0.
func normalChain(t *testing.T) chain {
	t.Helper()
	return fixtureChain(t, mainBranch(t, 1)[0], 0)
}

// mineFixtureHeader mines a header at fixtureBits on prev with the given
// time, whose merkle root is derived from label so that headers of different
// branches differ.
func mineFixtureHeader(t *testing.T, prev [32]byte, label string, time uint32) fixtureHeader {
	t.Helper()
	return mineHeader(t, prev, label, time, fixtureBits)
}

// mineHeader mines a header with the given time and bits on prev.
func mineHeader(t *testing.T, prev [32]byte, label string, time, bits uint32) fixtureHeader {
	t.Helper()
	merkle := doubleSHA256([]byte("ghost-genesis fixture merkle root " + label))
	limit := fixturePowLimit(t)
	for nonce := uint32(0); nonce < 1<<20; nonce++ {
		raw := encodeBitcoinHeader(fixtureVersion, prev, merkle, time, bits, nonce)
		h, err := decodeBitcoinHeader(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.checkProofOfWork(limit); err == nil {
			return fixtureHeader{raw: raw, hash: h.Hash()}
		}
	}
	t.Fatalf("no nonce for fixture header %s", label)
	return fixtureHeader{}
}

// fixtureAnchorParent is the previous-block hash of a fixture's first header,
// which the rule does not check.
func fixtureAnchorParent() [32]byte {
	return doubleSHA256([]byte("ghost-genesis fixture anchor parent"))
}

func mainTime(i int) uint32 {
	return uint32(fixtureTL - 15*fixtureSpacing + i*fixtureSpacing)
}

func reorgTime(i int) uint32 {
	return mainTime(fixtureForkAt) + uint32((i-fixtureForkAt)*fixtureReorgSpacing)
}

// mainBranch mines main-branch blocks 0 to n-1.
func mainBranch(t *testing.T, n int) []fixtureHeader {
	t.Helper()
	var out []fixtureHeader
	prev := fixtureAnchorParent()
	for i := 0; i < n; i++ {
		h := mineFixtureHeader(t, prev, "main "+strconv.Itoa(i), mainTime(i))
		out = append(out, h)
		prev = h.hash
	}
	return out
}

// reorgBranch mines the reorg branch on main-branch block fixtureForkAt, up
// to block tip.
func reorgBranch(t *testing.T, main []fixtureHeader, tip int) []fixtureHeader {
	t.Helper()
	var out []fixtureHeader
	prev := main[fixtureForkAt].hash
	for i := fixtureForkAt + 1; i <= tip; i++ {
		h := mineFixtureHeader(t, prev, "reorg "+strconv.Itoa(i), reorgTime(i))
		out = append(out, h)
		prev = h.hash
	}
	return out
}

// fixture is a header file of the tests.
type fixture struct {
	name    string
	headers []fixtureHeader
}

// fixtures builds every fixture: the normal case, the case one block short
// of the confirmations, and the reorg case, whose heavier branch leaves the
// main branch before its selected block.
func fixtures(t *testing.T) map[string]fixture {
	t.Helper()
	main := mainBranch(t, fixtureMainLen)
	reorg := reorgBranch(t, main, fixtureReorgTip)
	all := []fixture{
		{name: "normal", headers: main},
		{name: "too_few_confirmations", headers: main[:fixtureMainLen-1]},
		{name: "reorg", headers: append(append([]fixtureHeader{}, main...), reorg...)},
	}
	out := make(map[string]fixture)
	for _, f := range all {
		out[f.name] = f
	}
	return out
}

// headerFileHex is the stored form of a header file: one header in hex per
// line.
func headerFileHex(headers []fixtureHeader) string {
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(hex.EncodeToString(h.raw[:]))
		b.WriteByte('\n')
	}
	return b.String()
}

func rawHeaders(headers []fixtureHeader) []byte {
	var out []byte
	for _, h := range headers {
		out = append(out, h.raw[:]...)
	}
	return out
}

// rebuildEnv names the environment variable that, set to 1, makes the tests
// rewrite every pinned file in testdata from the generator and the command
// instead of comparing: GHOST_GENESIS_REBUILD=1 go test ./cmd/ghost-genesis.
const rebuildEnv = "GHOST_GENESIS_REBUILD"

// requirePinned fails unless testdata/name holds want, printing want so the
// file can be rebuilt.
func requirePinned(t *testing.T, name, want string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv(rebuildEnv) == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("testdata/%s: %v; its content should be:\n%s", name, err, want)
		return
	}
	if string(have) != want {
		t.Errorf("testdata/%s differs from what it pins; its content should be:\n%s", name, want)
	}
}

// loadFixture reads the stored header file of a fixture, checks that the
// generator still builds it, and writes it as raw headers to a temporary
// file, whose path it returns with the raw bytes.
func loadFixture(t *testing.T, name string) (string, []byte) {
	t.Helper()
	f, ok := fixtures(t)[name]
	if !ok {
		t.Fatalf("no fixture %s", name)
	}
	requirePinned(t, name+".headers.hex", headerFileHex(f.headers))
	stored, err := os.ReadFile(filepath.Join("testdata", name+".headers.hex"))
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, line := range strings.Fields(string(stored)) {
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != BitcoinHeaderSize {
			t.Fatalf("testdata/%s.headers.hex: bad line %q", name, line)
		}
		raw = append(raw, b...)
	}
	path := filepath.Join(t.TempDir(), name+".headers")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, raw
}
