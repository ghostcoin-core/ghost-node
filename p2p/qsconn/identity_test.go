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

package qsconn

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestNodeID(t *testing.T) {
	k := newTestIdentity(t)
	if len(k.PublicKey()) != PublicKeySize {
		t.Fatalf("public key has %d bytes", len(k.PublicKey()))
	}
	// K: one length byte, the ASCII tag, the scheme as two bytes, the key.
	h := sha3.NewLegacyKeccak256()
	h.Write(append([]byte{16}, "ghost/node-id/v1"...))
	h.Write([]byte{0x00, 0x01})
	h.Write(k.PublicKey())
	if id, want := k.ID(), h.Sum(nil); !bytes.Equal(id[:], want) {
		t.Fatalf("node ID %x, want %x", id, want)
	}
	if NodeIDOf(2, k.PublicKey()) == k.ID() {
		t.Fatal("the node ID does not cover the scheme")
	}
	if newTestIdentity(t).ID() == k.ID() {
		t.Fatal("two generated identities share a node ID")
	}
}

func TestIdentitySaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodekey")
	k := newTestIdentity(t)
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID() != k.ID() || !bytes.Equal(loaded.PublicKey(), k.PublicKey()) {
		t.Fatal("loaded identity differs")
	}
	sig, err := loaded.sign([]byte("message"), HandshakeContext)
	if err != nil || len(sig) != SignatureSize {
		t.Fatalf("sign: %v", err)
	}

	// Saving over an existing, too open file leaves it readable by its owner only.
	other := filepath.Join(dir, "open")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := k.Save(other); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(other); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityLoadRefused(t *testing.T) {
	dir := t.TempDir()
	k := newTestIdentity(t)
	good := []byte(hex.EncodeToString(k.priv.Bytes()))
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := map[string]string{
		"newline":   write("newline", append(bytes.Clone(good), '\n'), 0o600),
		"short":     write("short", good[:len(good)-2], 0o600),
		"not hex":   write("nothex", append(bytes.Clone(good[:len(good)-2]), 'z', 'z'), 0o600),
		"empty":     write("empty", nil, 0o600),
		"directory": dir,
		"missing":   filepath.Join(dir, "missing"),
	}
	if runtime.GOOS != "windows" {
		cases["group readable"] = write("group", good, 0o640)
		cases["world readable"] = write("world", good, 0o604)
	}
	for name, path := range cases {
		if _, err := LoadIdentity(path); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadIdentity(write("good", good, 0o600)); err != nil {
		t.Fatalf("good file: %v", err)
	}
}
