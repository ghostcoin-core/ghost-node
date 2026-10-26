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

// ghost-verify checks the ed25519 signature of a release archive for
// install.sh, which carries no other way to verify one: a stock Mac has no
// OpenSSL 3.
//
//	ghost-verify <public-key-file> <archive> <sig-file>
//
// The public key file is the PEM "PUBLIC KEY" block pinned in install.sh, and
// the signature file the raw 64-byte ed25519 signature of the archive's exact
// bytes. It exits 0 only when the signature is valid, 1 when it is not, and 2
// when it cannot check.
//
// The release builds it statically, with the standard library only.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// spkiPrefix is the DER of an ed25519 SubjectPublicKeyInfo up to the key's
// 32 bytes (RFC 8410).
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// errBadSignature means the signature is well-formed but does not match.
var errBadSignature = errors.New("the signature does not match the key")

// parseKey returns the ed25519 key of a PEM "PUBLIC KEY" block holding
// nothing else.
func parseKey(keyFile []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(keyFile)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the key file is not one PEM PUBLIC KEY block")
	}
	der := block.Bytes
	if len(der) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, spkiPrefix) {
		return nil, errors.New("the key file does not hold an ed25519 public key")
	}
	return ed25519.PublicKey(der[len(spkiPrefix):]), nil
}

// verify checks that sig is the signature of archive by the key in keyFile.
func verify(keyFile, archive, sig []byte) error {
	key, err := parseKey(keyFile)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("the signature is %d bytes, not a %d-byte ed25519 signature", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, archive, sig) {
		return errBadSignature
	}
	return nil
}

func run(args []string) int {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: ghost-verify <public-key-file> <archive> <sig-file>")
		return 2
	}
	var files [3][]byte
	for i, name := range args {
		blob, err := os.ReadFile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghost-verify: %v\n", err)
			return 2
		}
		files[i] = blob
	}
	if err := verify(files[0], files[1], files[2]); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-verify: %v\n", err)
		if errors.Is(err, errBadSignature) {
			return 1
		}
		return 2
	}
	fmt.Println("ghost-verify: the signature is valid")
	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}
