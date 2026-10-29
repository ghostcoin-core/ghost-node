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

package install

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The test binary copied into a release archive as geth is the recording
// geth of TestInstallScriptWritesNoPrivateChain: run under the name geth, it
// acts as one instead of running tests.
func init() {
	if filepath.Base(os.Args[0]) == "geth" {
		os.Exit(recordingGeth(os.Args[1:]))
	}
}

// recordingGeth appends its arguments, one JSON array a line, to
// $STUB_DIR/geth.calls, and answers the way geth does: version runs, account
// new makes a key and prints its address, init succeeds, and anything else
// is the node, which opens the IPC endpoint in the config's DataDir and runs
// until it is stopped. It opens no network port at all.
func recordingGeth(args []string) int {
	if dir := os.Getenv("STUB_DIR"); dir != "" {
		line, _ := json.Marshal(args)
		f, err := os.OpenFile(filepath.Join(dir, "geth.calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			fmt.Fprintf(f, "%s\n", line)
			f.Close()
		}
	}
	has := func(word string) bool {
		for _, a := range args {
			if a == word {
				return true
			}
		}
		return false
	}
	value := func(flag string) string {
		for i, a := range args {
			if a == flag && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	switch {
	case len(args) > 0 && args[0] == "version":
		fmt.Println("Geth\nVersion: 0.0.0-recording")
		return 0
	case has("account") && has("new"):
		if err := os.MkdirAll(filepath.Join(value("--datadir"), "keystore"), 0700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("Public address of the key:   0x00000000000000000000000000000000000000c0")
		return 0
	case has("init"):
		return 0
	}
	dataDir, err := configDataDir(value("--config"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ipc := filepath.Join(dataDir, "geth.ipc")
	os.Remove(ipc)
	l, err := net.Listen("unix", ipc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	l.Close()
	return 0
}

// configDataDir reads DataDir from the config file at path.
func configDataDir(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "DataDir = "); ok {
			return strconv.Unquote(rest)
		}
	}
	return "", fmt.Errorf("the config %s has no DataDir", path)
}

// gethCalls returns the argument lists the recording geth was run with.
func gethCalls(t *testing.T, env *installEnv) [][]string {
	t.Helper()
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(env.readStub(t, "geth.calls")), "\n") {
		if line == "" {
			continue
		}
		var args []string
		if err := json.Unmarshal([]byte(line), &args); err != nil {
			t.Fatalf("geth.calls line %q: %v", line, err)
		}
		calls = append(calls, args)
	}
	return calls
}

// The geth flags that would take a node off the public test network, or cut
// it off from its peers.
var privateChainFlags = []string{
	"--bootnodes", "--networkid", "--nodiscover", "--maxpeers", "--dev", "--netrestrict",
	"--internalnet", "--ghost.internalnet",
}

// The config keys and sections that would do the same.
var privateChainConfig = []string{
	"[Node.P2P]", "BootstrapNodes", "StaticNodes", "TrustedNodes", "NoDiscovery", "MaxPeers",
	"NetworkId", "Genesis", "NetRestrict",
}

// The data directory files geth reads peers or a chain from.
var privateChainFiles = []string{"static-nodes.json", "trusted-nodes.json", "genesis.json"}

// checkNoPrivateChain checks that geth was never run to initialise a chain,
// that the node was run without a flag that sets its network or peers, and
// that the installed config and data directory set neither.
func checkNoPrivateChain(t *testing.T, env *installEnv) {
	t.Helper()
	calls := gethCalls(t, env)
	ran := false
	for _, args := range calls {
		joined := strings.Join(args, " ")
		for _, a := range args {
			if a == "init" {
				t.Fatalf("the installer initialised a chain: geth %s", joined)
			}
		}
		if len(args) < 2 || args[0] != "--config" {
			continue
		}
		ran = true
		for _, a := range args {
			name, _, _ := strings.Cut(a, "=")
			for _, flag := range privateChainFlags {
				if name == flag {
					t.Fatalf("the node runs with %s: geth %s", flag, joined)
				}
			}
		}
	}
	if !ran {
		t.Fatalf("the node never ran; geth was run as %v", calls)
	}
	config := readConfig(t, env)
	for _, key := range privateChainConfig {
		if strings.Contains(config, key) {
			t.Fatalf("the config sets %s:\n%s", key, config)
		}
	}
	base := filepath.Join(env.home, ".ghost-node")
	filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		for _, name := range privateChainFiles {
			if d.Name() == name {
				t.Errorf("the installer left %s", path)
			}
		}
		return nil
	})
}

// TestInstallScriptWritesNoPrivateChain installs a release with the public
// test network built in, as published releases are, with a geth that records
// how it is run. The installer must not initialise a chain of its own, run
// the node with a flag that sets its network or its peers, or write a config
// or data file that does: the node joins the public test network through the
// boot nodes built into it, as a node without peers otherwise mines a fork of
// its own. The script's text must not hold such an override either.
func TestInstallScriptWritesNoPrivateChain(t *testing.T) {
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{
		"--bootnodes", "--networkid", "--nodiscover", "--maxpeers", "--netrestrict",
		"[Node.P2P]", "BootstrapNodes", "StaticNodes", "TrustedNodes", "NoDiscovery", "NetworkId",
		"static-nodes.json", "trusted-nodes.json",
	} {
		if strings.Contains(string(script), word) {
			t.Fatalf("install.sh holds %q", word)
		}
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := archive{"geth": bin}.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	path := writeScript(t, key, sha256Hex(verifier))

	t.Run("systemd", func(t *testing.T) {
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 2})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		if _, err := env.run(t, path, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		checkNoPrivateChain(t, env)
		unit := nodeUnit(t, env)
		for _, word := range strings.Fields(unit) {
			name, _, _ := strings.Cut(strings.Trim(word, `"'`), "=")
			for _, flag := range privateChainFlags {
				if name == flag {
					t.Fatalf("the node's unit runs it with %s:\n%s", flag, unit)
				}
			}
		}
	})

	t.Run("no systemd user services", func(t *testing.T) {
		env := newInstallEnv(t, envOptions{systemctl: stubNoSystemd})
		stopNodeAtCleanup(t, filepath.Join(env.home, ".ghost-node", "node.pid"))
		if _, err := env.run(t, path, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		checkNoPrivateChain(t, env)
	})
}
