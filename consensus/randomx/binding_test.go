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

package randomx

import (
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestHashVectors checks the vendored library with Ghost's salt against the
// value measured with the C++ reference and the pure-Go library in the
// RandomX survey, in the portable interpreter with software AES and in the
// mode the engine uses (JIT and hardware AES where available).
func TestHashVectors(t *testing.T) {
	const (
		key   = "test key 000"
		input = "Ghost survey test input"
		want  = "253de6bf1004419ac11fdb08b5a8efd7fa0269d82ea8bb39db173ba43d6cf8ee"
	)
	flags := detectFlags()
	cache, err := newRxCache(flags, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.free()

	modes := []struct {
		name  string
		flags rxFlags
	}{
		{"interpreter, software AES", interpreterFlags},
		{"engine flags", flags},
	}
	t.Logf("engine flags: %#x", uint64(flags))
	for _, mode := range modes {
		vm, err := newRxVM(mode.flags, cache)
		if err != nil {
			t.Fatalf("%s: %v", mode.name, err)
		}
		out := vm.hash([]byte(input))
		vm.free()
		if got := hex.EncodeToString(out[:]); got != want {
			t.Errorf("%s: hash %s, want %s", mode.name, got, want)
		}
	}
}

// TestSaltMatchesVendoredHeader keeps the Go salt constant equal to the
// salt the C library is built with, and to the recorded patch.
func TestSaltMatchesVendoredHeader(t *testing.T) {
	if Salt != "Ghost-RandomX"+"\x01" || len(Salt) != 14 {
		t.Fatalf("Salt is %q, want \"Ghost-RandomX\" followed by byte 0x01", Salt)
	}
	line := regexp.MustCompile(`(?m)^#define RANDOMX_ARGON_SALT\s+"((?:[^"\\]|\\.)*)"\s*$`)

	header, err := os.ReadFile("librandomx/src/configuration.h")
	if err != nil {
		t.Fatal(err)
	}
	m := line.FindAllSubmatch(header, -1)
	if len(m) != 1 {
		t.Fatalf("found %d RANDOMX_ARGON_SALT definitions in configuration.h, want 1", len(m))
	}
	salt, err := strconv.Unquote(`"` + string(m[0][1]) + `"`)
	if err != nil {
		t.Fatalf("cannot read the C salt %q: %v", m[0][1], err)
	}
	if salt != Salt {
		t.Fatalf("configuration.h salt %q, Go constant %q", salt, Salt)
	}

	patch, err := os.ReadFile("librandomx/ghost-salt.patch")
	if err != nil {
		t.Fatal(err)
	}
	var added, removed []string
	for _, l := range strings.Split(string(patch), "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			added = append(added, l[1:])
		case strings.HasPrefix(l, "-"):
			removed = append(removed, l[1:])
		}
	}
	if len(added) != 1 || len(removed) != 1 {
		t.Fatalf("patch changes %d lines for %d, want one line", len(removed), len(added))
	}
	if !strings.Contains(string(header), added[0]+"\n") {
		t.Errorf("patched line %q is not in configuration.h", added[0])
	}
	if !strings.Contains(removed[0], `"RandomX\x03"`) {
		t.Errorf("patch does not replace the upstream salt: %q", removed[0])
	}
}
