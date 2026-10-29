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

//go:build linux

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The tests of the port the installed node listens for peers on: geth's
// default 30303 unless GHOST_P2P_PORT names another, kept across re-runs.

const p2pPortRefusal = "GHOST_P2P_PORT must be the port the node listens for peers on, a whole number from 1 to 65535"

// TestInstallScriptP2PPort installs a node with GHOST_P2P_PORT: the node runs
// with --port and that number, which a re-run without it keeps. Installed
// without it, the node runs with no --port, on geth's default; and a
// malformed number is refused with nothing installed.
func TestInstallScriptP2PPort(t *testing.T) {
	verifier := builtVerifier(t)
	key := newSigner(t)
	script := writeScript(t, key, sha256Hex(verifier))

	t.Run("set", func(t *testing.T) {
		release, _ := internalNetRelease(t)
		blob := release.tarGz(t)
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		holdDefaultP2PPort(t)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 2})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		base := filepath.Join(env.home, ".ghost-node")
		port := strconv.Itoa(env.p2pPort)
		check := func(t *testing.T) {
			t.Helper()
			execStart := fmt.Sprintf("ExecStart=%q --config %q --mine --miner.threads 1 --port %s\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"), port)
			if unit := nodeUnit(t, env); !strings.Contains(unit, execStart) {
				t.Fatalf("the unit does not run the node on port %s:\n%s", port, unit)
			}
			args := procArgs(t, env.servicePID(t))
			found := false
			for i, a := range args {
				if a == "--port" && i+1 < len(args) && args[i+1] == port {
					found = true
				}
			}
			if !found {
				t.Fatalf("the node runs as %q, not with --port %s", args, port)
			}
			if kept := strings.TrimSpace(readFile(t, filepath.Join(base, "p2p-port"))); kept != port {
				t.Fatalf("the installer kept port %q, not %s", kept, port)
			}
		}
		if _, err := env.run(t, script, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		check(t)
		// A re-run without the setting keeps the port.
		if _, err := env.run(t, script, rs, true, "GHOST_P2P_PORT="); err != nil {
			t.Fatalf("the re-run failed: %v", err)
		}
		check(t)
	})

	t.Run("default", func(t *testing.T) {
		// The stand-in geth listens for no peers, so 30303 need not be free.
		blob := nodeRelease(t).tarGz(t)
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 2})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		base := filepath.Join(env.home, ".ghost-node")
		if _, err := runMineTo(t, env, script, rs, "GHOST_P2P_PORT="); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		execStart := fmt.Sprintf("ExecStart=%q --config %q --mine --miner.threads 1\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
		if unit := nodeUnit(t, env); !strings.Contains(unit, execStart) {
			t.Fatalf("the unit does not run the node on geth's default port:\n%s", unit)
		}
		if pid := env.servicePID(t); hasArg(t, pid, "--port") {
			t.Fatalf("the node runs as %q, with a --port", procArgs(t, pid))
		}
		if _, err := os.Stat(filepath.Join(base, "p2p-port")); !os.IsNotExist(err) {
			t.Fatalf("the installer kept a port with no GHOST_P2P_PORT: %v", err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "ran")
		blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		for _, value := range []string{
			"0", "00", "030303", "-1", "+2", "1.5", "2 ", " 2", "2\n3", "65536", "100000", "port", "0x76", "$(touch " + marker + ")",
		} {
			t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
				env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 2})
				out, err := env.run(t, script, rs, true, "GHOST_P2P_PORT="+value)
				checkRefused(t, env, out, err, p2pPortRefusal+", not '"+value+"'; refusing to install. Nothing was installed.", marker)
			})
		}
		if served := rs.servedFiles(); len(served) != 0 {
			t.Fatalf("a refused GHOST_P2P_PORT downloaded %v", served)
		}
	})
}
