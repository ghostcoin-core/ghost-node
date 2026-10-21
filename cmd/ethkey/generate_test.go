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
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestGenerateInspectMLDSA44 checks that ethkey generates the keyfile of an
// ML-DSA-44 seed, whose address is derived from the scheme and the public
// key, and that inspect reads it back.
func TestGenerateInspectMLDSA44(t *testing.T) {
	t.Parallel()
	tmpdir := t.TempDir()

	seed := bytes.Repeat([]byte{0x3c}, keystore.SeedSize)
	var s [keystore.SeedSize]byte
	copy(s[:], seed)
	pub, _ := mldsa44.NewKeyFromSeed(&s)
	address := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes())

	seedfile := filepath.Join(tmpdir, "seed")
	if err := os.WriteFile(seedfile, []byte(hex.EncodeToString(seed)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	passfile := filepath.Join(tmpdir, "password")
	if err := os.WriteFile(passfile, []byte("foobar"), 0600); err != nil {
		t.Fatal(err)
	}
	keyfile := filepath.Join(tmpdir, "the-keyfile")

	generate := runEthkey(t, "generate", "--lightkdf", "--passwordfile", passfile, "--seed", seedfile, keyfile)
	generate.Expect("Address: " + address.Hex() + "\n")
	generate.ExpectExit()

	keyjson, err := os.ReadFile(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keystore.DecryptKey(keyjson, "foobar")
	if err != nil {
		t.Fatal(err)
	}
	if key.Address != address || !bytes.Equal(key.Seed[:], seed) {
		t.Fatalf("keyfile holds the key of address %x, want %x", key.Address, address)
	}

	inspect := runEthkey(t, "inspect", "--passwordfile", passfile, keyfile)
	inspect.Expect(`
Address:        ` + address.Hex() + `
Scheme:         0x0001
Public key:     ` + hex.EncodeToString(pub.Bytes()) + `
`)
	inspect.ExpectExit()
}
