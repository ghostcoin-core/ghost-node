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

package node

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Tests that the quantum-safe identity is created on first start, stored in
// the data directory readable by its owner only, and loaded afterwards.
func TestNodeIdentityPersistence(t *testing.T) {
	dir := t.TempDir()
	config := &Config{Name: "unit-test", DataDir: dir}
	first, err := config.NodeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "unit-test", datadirIdentity)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("identity file not created: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("identity file mode %04o, want 0600", info.Mode().Perm())
	}
	second, err := config.NodeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatal("identity changed between starts")
	}

	// The node's p2p server uses it.
	node, err := New(&Config{Name: "unit-test", DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if node.server.Config.Identity == nil || node.server.Config.Identity.ID() != first.ID() {
		t.Fatal("node does not use the stored identity")
	}
	if enode.ID(first.ID()) == (enode.ID{}) {
		t.Fatal("empty node ID")
	}
}

// Tests that a stored identity file that cannot be loaded stops the node
// and is left as it is.
func TestNodeIdentityRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unit-test", datadirIdentity)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(&Config{Name: "unit-test", DataDir: dir}); err == nil {
		t.Fatal("node started with an unreadable identity file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "not a key" {
		t.Fatal("identity file was replaced")
	}

	// Without a data directory the identity is ephemeral.
	config := &Config{Name: "unit-test"}
	a, err := config.NodeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.NodeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() == b.ID() {
		t.Fatal("ephemeral identities are equal")
	}
}
