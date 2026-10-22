// Copyright 2026 The go-ethereum Authors
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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/core/types"
)

// ethkeyResult runs ethkey to completion and returns its stdout and exit
// status.
func ethkeyResult(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := runEthkey(t, args...)
	out := cmd.Output()
	cmd.WaitExit()
	return string(out), cmd.ExitStatus()
}

// ethkeyJSON runs ethkey with --json, expects it to succeed and decodes its
// output into v.
func ethkeyJSON(t *testing.T, v interface{}, args ...string) {
	t.Helper()
	// Flags go before the positional arguments, so --json follows the command.
	out, status := ethkeyResult(t, append([]string{args[0], "--json"}, args[1:]...)...)
	if status != 0 {
		t.Fatalf("ethkey %v: exit status %d, output %s", args, status, out)
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("ethkey %v: output %q is not JSON: %v", args, out, err)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestGenerateInspectMLDSA44 checks that ethkey generate writes an ML-DSA-44
// key file (from a given seed or a random one) and shows its scheme, public
// key and address, that inspect shows the same of the file, that
// changepassword re-encrypts it, and that a secp256k1 key file and the removed
// message signing commands are refused.
func TestGenerateInspectMLDSA44(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var (
		passFile    = filepath.Join(dir, "password")
		newPassFile = filepath.Join(dir, "newpassword")
		seedFile    = filepath.Join(dir, "seed")
		keyFile     = filepath.Join(dir, "key.json")
		randomFile  = filepath.Join(dir, "random.json")
	)
	writeTestFile(t, passFile, "foobar\n")
	writeTestFile(t, newPassFile, "foobar2\n")
	seed := bytes.Repeat([]byte{0x5a}, mldsa44.SeedSize)
	writeTestFile(t, seedFile, hex.EncodeToString(seed)+"\n")

	// The expected key, derived without the keystore.
	var s [mldsa44.SeedSize]byte
	copy(s[:], seed)
	pub, _ := mldsa44.NewKeyFromSeed(&s)
	wantPub := hex.EncodeToString(pub.Bytes())
	wantAddr := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes()).Hex()

	type output struct {
		Address   string
		Scheme    uint16
		PublicKey string
		Seed      string
	}
	check := func(what string, have output, wantSeed string) {
		t.Helper()
		if have.Address != wantAddr || have.Scheme != types.GhostSchemeMLDSA44 || have.PublicKey != wantPub || have.Seed != wantSeed {
			t.Fatalf("%s: address %s, scheme %d, public key of %d hex digits, seed %q; want %s, %d, the %d hex digits of the key and %q",
				what, have.Address, have.Scheme, len(have.PublicKey), have.Seed, wantAddr, types.GhostSchemeMLDSA44, len(wantPub), wantSeed)
		}
	}

	// Generate from the seed.
	var gen output
	ethkeyJSON(t, &gen, "generate", "--lightkdf", "--passwordfile", passFile, "--seed", seedFile, keyFile)
	check("generate", gen, "")

	keyjson, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Address string  `json:"address"`
		Scheme  *uint16 `json:"scheme"`
	}
	if err := json.Unmarshal(keyjson, &file); err != nil {
		t.Fatal(err)
	}
	if file.Scheme == nil || *file.Scheme != 1 || "0x"+file.Address != strings.ToLower(wantAddr) {
		t.Fatalf("key file scheme %v, address %s; want 1 and %s", file.Scheme, file.Address, wantAddr)
	}

	// The text output names the scheme.
	text, status := ethkeyResult(t, "inspect", "--passwordfile", passFile, keyFile)
	if status != 0 || !strings.Contains(text, wantAddr) || !strings.Contains(text, "ML-DSA-44") || !strings.Contains(text, wantPub) {
		t.Fatalf("inspect: exit status %d, output %s", status, text)
	}

	// Inspect, with and without the seed.
	var insp output
	ethkeyJSON(t, &insp, "inspect", "--passwordfile", passFile, keyFile)
	check("inspect", insp, "")
	var private output
	ethkeyJSON(t, &private, "inspect", "--passwordfile", passFile, "--private", keyFile)
	check("inspect --private", private, hex.EncodeToString(seed))

	// A wrong password is refused.
	if out, status := ethkeyResult(t, "inspect", "--passwordfile", newPassFile, keyFile); status == 0 {
		t.Fatalf("inspect with a wrong password succeeded: %s", out)
	}

	// Change the password.
	if out, status := ethkeyResult(t, "changepassword", "--lightkdf", "--passwordfile", passFile, "--newpasswordfile", newPassFile, keyFile); status != 0 {
		t.Fatalf("changepassword: exit status %d, output %s", status, out)
	}
	var changed output
	ethkeyJSON(t, &changed, "inspect", "--passwordfile", newPassFile, keyFile)
	check("inspect after changepassword", changed, "")
	if out, status := ethkeyResult(t, "inspect", "--passwordfile", passFile, keyFile); status == 0 {
		t.Fatalf("inspect with the old password succeeded: %s", out)
	}

	// Generate a random key.
	var random output
	ethkeyJSON(t, &random, "generate", "--lightkdf", "--passwordfile", passFile, randomFile)
	if random.Scheme != types.GhostSchemeMLDSA44 || random.Address == wantAddr || len(random.PublicKey) != len(wantPub) {
		t.Fatalf("random key: address %s, scheme %d, public key of %d hex digits", random.Address, random.Scheme, len(random.PublicKey))
	}
	randomPub, err := hex.DecodeString(random.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if addr := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, randomPub).Hex(); addr != random.Address {
		t.Fatalf("random key address %s, want the address %s of its public key", random.Address, addr)
	}
	var randomInsp output
	ethkeyJSON(t, &randomInsp, "inspect", "--passwordfile", passFile, randomFile)
	if randomInsp.Address != random.Address || randomInsp.PublicKey != random.PublicKey || randomInsp.Scheme != random.Scheme {
		t.Fatalf("inspect of the random key: %+v, want %+v", randomInsp, random)
	}

	// A seed that is not 32 bytes is refused.
	shortSeed := filepath.Join(dir, "short-seed")
	writeTestFile(t, shortSeed, "0123456789abcdef")
	if out, status := ethkeyResult(t, "generate", "--lightkdf", "--passwordfile", passFile, "--seed", shortSeed, filepath.Join(dir, "short.json")); status == 0 {
		t.Fatalf("generate with a short seed succeeded: %s", out)
	}

	// A secp256k1 key file is refused.
	ecdsaFile := filepath.Join(dir, "ecdsa.json")
	ecdsaJSON, err := os.ReadFile(filepath.Join("..", "..", "accounts", "keystore", "testdata", "ecdsa-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, ecdsaFile, string(ecdsaJSON))
	if out, status := ethkeyResult(t, "inspect", "--passwordfile", passFile, ecdsaFile); status == 0 || !strings.Contains(out, "scheme") {
		t.Fatalf("inspect of a secp256k1 key file: exit status %d, output %s", status, out)
	}
	if out, status := ethkeyResult(t, "changepassword", "--lightkdf", "--passwordfile", passFile, "--newpasswordfile", newPassFile, ecdsaFile); status == 0 {
		t.Fatalf("changepassword of a secp256k1 key file succeeded: %s", out)
	}

	// The message signing commands are gone.
	for _, command := range []string{"signmessage", "verifymessage"} {
		if out, status := ethkeyResult(t, command, keyFile, "message"); status == 0 {
			t.Fatalf("ethkey %s succeeded: %s", command, out)
		}
	}
}
