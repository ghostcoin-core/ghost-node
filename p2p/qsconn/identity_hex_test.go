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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseIdentityHex checks that the text of a saved identity file parses
// to the same identity, and that anything else is refused.
func TestParseIdentityHex(t *testing.T) {
	key, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nodekey")
	if err := key.Save(path); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIdentityHex(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != key.ID() || !bytes.Equal(got.PublicKey(), key.PublicKey()) {
		t.Fatal("parsed identity differs from the saved one")
	}

	s := string(text)
	for name, bad := range map[string]string{
		"empty":         "",
		"line ending":   s + "\n",
		"0x prefix":     "0x" + s[2:],
		"short":         s[:len(s)-2],
		"not hex":       "zz" + s[2:],
		"secp256k1 key": strings.Repeat("ab", 32),
	} {
		if _, err := ParseIdentityHex(bad); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
