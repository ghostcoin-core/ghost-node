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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func keyPEM(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// The tests are named for install.sh, the one user of the checker, so that
// its tests run them.

func TestInstallScriptVerifierChecksSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	archive := []byte("release archive bytes")
	sig := ed25519.Sign(priv, archive)
	key := keyPEM(t, pub)

	if err := verify(key, archive, sig); err != nil {
		t.Fatalf("a valid signature was refused: %v", err)
	}
	tampered := append([]byte(nil), archive...)
	tampered[0] ^= 1
	for name, err := range map[string]error{
		"tampered archive":  verify(key, tampered, sig),
		"longer archive":    verify(key, append(append([]byte(nil), archive...), 0), sig),
		"other key":         verify(keyPEM(t, otherPub), archive, sig),
		"short signature":   verify(key, archive, sig[:63]),
		"long signature":    verify(key, archive, append(append([]byte(nil), sig...), 0)),
		"not an ed25519key": verify(keyPEM(t, &ec.PublicKey), archive, sig),
		"not PEM":           verify([]byte("not a key\n"), archive, sig),
		"two keys":          verify(append(append([]byte(nil), key...), key...), archive, sig),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := verify(key, tampered, sig); !errors.Is(err, errBadSignature) {
		t.Errorf("a tampered archive gave %v, not %v", err, errBadSignature)
	}
}

func TestInstallScriptVerifierExitCodes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, blob []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, blob, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	archive := []byte("release archive bytes")
	key := write("key.pub", keyPEM(t, pub))
	good := write("archive", archive)
	bad := write("tampered", []byte("release archive bytez"))
	sig := write("archive.sig", ed25519.Sign(priv, archive))

	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{key, good, sig}, 0},
		{[]string{key, bad, sig}, 1},
		{[]string{key, good, filepath.Join(dir, "missing")}, 2},
		{[]string{key, good}, 2},
		{[]string{good, good, sig}, 2},
	} {
		if got := run(tc.args); got != tc.want {
			t.Errorf("run(%q) = %d, want %d", tc.args, got, tc.want)
		}
	}
}
