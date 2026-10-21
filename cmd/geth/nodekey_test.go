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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/qsconn"
)

// nodeInfoScript prints the node ID, the node part of the enode URL and the
// public key that admin_nodeInfo reports, as one string.
const nodeInfoScript = `admin.nodeInfo.id + "|" + admin.nodeInfo.enode.split("@")[0] + "|" + admin.nodeInfo.publicKey`

// TestNodeKeyFlagNamesQuantumSafeIdentity starts geth with --nodekey naming an
// identity file written by qsconn.Identity.Save, and with --nodekeyhex holding
// that file's text, and checks that admin_nodeInfo reports that identity's
// node ID, URL and public key. An identity that cannot be loaded stops geth.
func TestNodeKeyFlagNamesQuantumSafeIdentity(t *testing.T) {
	key, err := qsconn.GenerateIdentity()
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
	id := key.ID().String()
	want := `"` + id + "|enode://" + id + "|" + hex.EncodeToString(key.PublicKey()) + `"` + "\n"

	for _, flag := range [][]string{
		{"--nodekey", path},
		{"--nodekeyhex", string(text)},
	} {
		t.Run(flag[0], func(t *testing.T) {
			args := append(flag, "--ipcdisable", "--exec", nodeInfoScript, "console")
			geth := runMinimalGeth(t, args...)
			geth.KillTimeout = time.Minute
			geth.Expect(want)
			geth.ExpectExit()
		})
	}

	// The node does not fall back to another identity.
	bad := filepath.Join(t.TempDir(), "nodekey")
	if err := os.WriteFile(bad, []byte("not an identity"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range [][]string{
		{"--nodekey", bad},
		{"--nodekeyhex", "not an identity"},
		{"--nodekeyhex", "1f" + string(text)},
	} {
		t.Run(flag[0]+"-refused", func(t *testing.T) {
			args := append(flag, "--ipcdisable", "--exec", nodeInfoScript, "console")
			geth := runMinimalGeth(t, args...)
			geth.KillTimeout = time.Minute
			geth.ExpectRegexp(`Fatal: Option "` + flag[0][2:] + `": [^\n]+\n`)
			geth.ExpectExit()
			if status := geth.ExitStatus(); status == 0 {
				t.Errorf("geth with %s %q exited with status 0", flag[0], flag[1])
			}
		})
	}
}
