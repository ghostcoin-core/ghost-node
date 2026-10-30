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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests of the public test network faucet in faucet/: its own Node tests,
// and faucet/install-faucet.sh run with HOME in a temporary directory and
// systemctl, sudo, tailscale and node as stubs that record their calls in
// $STUB_DIR/calls.

const (
	stubFaucetSystemctl = `#!/bin/sh
echo "systemctl $*" >>"$STUB_DIR/calls"
case "$*" in
"--user daemon-reload" | \
	"--user enable --now ghost-faucet-signer.service" | "--user enable --now ghost-faucet.service" | \
	"--user restart ghost-faucet-signer.service" | "--user restart ghost-faucet.service")
	exit 0
	;;
esac
echo "unexpected systemctl call: $*" >&2
exit 1
`
	// stubFaucetTailscale publishes with funnel as root only, unless
	// $STUB_DIR/funnel-refused is there.
	stubFaucetTailscale = `#!/bin/sh
echo "tailscale $*" >>"$STUB_DIR/calls"
case "$1" in
funnel)
	[ -n "$SUDO_USER" ] || { echo "tailscale funnel: needs root" >&2; exit 1; }
	[ ! -f "$STUB_DIR/funnel-refused" ] || exit 1
	exit 0
	;;
esac
echo "unexpected tailscale call: $*" >&2
exit 1
`
	stubFaucetNode = `#!/bin/sh
echo "node $*" >>"$STUB_DIR/calls"
exit 1
`
	// The node's password file, which the install must leave alone and never
	// print.
	faucetFakePassword = "synthetic test password for only the faucet"
)

// The files install-faucet.sh copies into ~/.ghost-faucet, as they are.
var faucetFiles = []string{"faucet.js", "signer.sh", "signer.toml"}

type faucetEnv struct {
	home, stubs string
}

// newFaucetEnv is a Linux computer with a Ghost node installed in
// ~/.ghost-node, a systemd user session, sudo, Tailscale logged in with Funnel
// allowed, and Node.js, and a PATH of stock tools besides.
func newFaucetEnv(t *testing.T) *faucetEnv {
	t.Helper()
	root := t.TempDir()
	env := &faucetEnv{home: filepath.Join(root, "h"), stubs: filepath.Join(root, "s")}
	nodeDir := filepath.Join(env.home, ".ghost-node")
	for _, dir := range []string{env.stubs, filepath.Join(nodeDir, "bin"), filepath.Join(nodeDir, "data", "keystore")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range append([]string{"uname"}, stockTools...) {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("the faucet install tests need %s: %v", tool, err)
		}
		if err := os.Symlink(path, filepath.Join(env.stubs, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, script := range map[string]string{
		"systemctl": stubFaucetSystemctl,
		"sudo":      stubSudo,
		"tailscale": stubFaucetTailscale,
		"node":      stubFaucetNode,
	} {
		env.write(t, filepath.Join(env.stubs, name), script, 0700)
	}
	env.write(t, filepath.Join(nodeDir, "config.toml"), "[Eth]\nNetworkId = 6777972\n\n[Eth.Miner]\nEtherbase = \"0x"+strings.Repeat("ab", 20)+"\"\n", 0600)
	env.write(t, filepath.Join(nodeDir, "bin", "geth"), "#!/bin/sh\nexit 1\n", 0700)
	env.write(t, filepath.Join(nodeDir, "password"), faucetFakePassword+"\n", 0600)
	env.write(t, filepath.Join(nodeDir, "data", "keystore", "UTC--example"), `{"note":"`+faucetFakePassword+`"}`, 0600)
	return env
}

func (env *faucetEnv) write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// run runs install-faucet.sh from this checkout, as the one install command
// does, and returns what it printed.
func (env *faucetEnv) run(t *testing.T, extraEnv ...string) (string, error) {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("faucet", "install-faucet.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(env.stubs, "sh"), script)
	cmd.Dir = env.home
	cmd.Env = append([]string{"HOME=" + env.home, "PATH=" + env.stubs, "STUB_DIR=" + env.stubs}, extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (env *faucetEnv) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(env.stubs, "calls"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func (env *faucetEnv) unitDir() string {
	return filepath.Join(env.home, ".config", "systemd", "user")
}

// checkFaucetInstalled checks that the faucet's files are in ~/.ghost-faucet
// as they are in the checkout and nothing else is, that both units are
// written and point there with the faucet on port, that both are enabled and
// started after a daemon-reload, and that the faucet is published at
// /ghost-faucet on port with Funnel as root, after the units started.
func checkFaucetInstalled(t *testing.T, env *faucetEnv, out, port string) {
	t.Helper()
	faucetDir := filepath.Join(env.home, ".ghost-faucet")
	for _, name := range faucetFiles {
		if readFile(t, filepath.Join(faucetDir, name)) != readFile(t, filepath.Join("faucet", name)) {
			t.Fatalf("~/.ghost-faucet/%s is not the checkout's", name)
		}
	}
	if info, err := os.Stat(filepath.Join(faucetDir, "signer.sh")); err != nil || info.Mode().Perm()&0100 == 0 {
		t.Fatalf("~/.ghost-faucet/signer.sh is not executable: %v", err)
	}
	if left := entries(t, faucetDir); strings.Join(left, " ") != "faucet.js signer.sh signer.toml" {
		t.Fatalf("~/.ghost-faucet holds %v, not just the faucet's code and config", left)
	}

	signerUnit := readFile(t, filepath.Join(env.unitDir(), "ghost-faucet-signer.service"))
	if signerUnit != readFile(t, filepath.Join("faucet", "ghost-faucet-signer.service")) {
		t.Fatalf("the signer unit is not the checkout's:\n%s", signerUnit)
	}
	if !strings.Contains(signerUnit, "\nExecStart=/bin/sh %h/.ghost-faucet/signer.sh\n") {
		t.Fatalf("the signer unit does not run ~/.ghost-faucet/signer.sh:\n%s", signerUnit)
	}
	unit := readFile(t, filepath.Join(env.unitDir(), "ghost-faucet.service"))
	for _, want := range []string{
		"\nWorkingDirectory=%h/.ghost-faucet\n",
		"\nExecStart=" + filepath.Join(env.stubs, "node") + " %h/.ghost-faucet/faucet.js\n",
		"\nEnvironment=FAUCET_PORT=" + port + "\n",
		"\nWants=ghost-faucet-signer.service\n",
		"\nWantedBy=default.target\n",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("the faucet unit has no line %q:\n%s", strings.TrimSpace(want), unit)
		}
	}
	if strings.Count(unit, "FAUCET_PORT") != 1 {
		t.Fatalf("the faucet unit names FAUCET_PORT more than once:\n%s", unit)
	}

	calls := env.calls(t)
	index := func(want string) int {
		for i, line := range calls {
			if line == want {
				return i
			}
		}
		t.Fatalf("no call %q; the calls were:\n%s", want, strings.Join(calls, "\n"))
		return -1
	}
	funnel := "tailscale funnel --bg --set-path /ghost-faucet http://127.0.0.1:" + port
	reload := index("systemctl --user daemon-reload")
	signer := index("systemctl --user enable --now ghost-faucet-signer.service")
	faucet := index("systemctl --user enable --now ghost-faucet.service")
	published := index("sudo " + funnel)
	index(funnel)
	if !(reload < signer && reload < faucet && signer < published && faucet < published) {
		t.Fatalf("the install steps ran out of order:\n%s", strings.Join(calls, "\n"))
	}
	for _, line := range calls {
		if strings.HasPrefix(line, "tailscale") && line != funnel {
			t.Fatalf("the install called %q", line)
		}
	}
	if !strings.Contains(out, "/ghost-faucet") {
		t.Fatalf("the install did not say where the faucet is published:\n%s", out)
	}
	checkKeysUntouched(t, env, out)
}

// checkKeysUntouched checks that the node's password and keystore are as they
// were, were not printed, and were copied nowhere.
func checkKeysUntouched(t *testing.T, env *faucetEnv, out string) {
	t.Helper()
	nodeDir := filepath.Join(env.home, ".ghost-node")
	if readFile(t, filepath.Join(nodeDir, "password")) != faucetFakePassword+"\n" {
		t.Fatal("the install changed the node's password file")
	}
	if left := entries(t, filepath.Join(nodeDir, "data", "keystore")); strings.Join(left, " ") != "UTC--example" {
		t.Fatalf("the node's keystore holds %v", left)
	}
	if strings.Contains(out, faucetFakePassword) {
		t.Fatal("the install printed the node's password")
	}
	err := filepath.WalkDir(env.home, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(path, nodeDir+string(filepath.Separator)) {
			return err
		}
		if strings.Contains(readFile(t, path), faucetFakePassword) {
			t.Errorf("%s holds the node's password", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// checkFaucetRefused checks that the install failed saying want, and left
// nothing behind and called nothing.
func checkFaucetRefused(t *testing.T, env *faucetEnv, out string, err error, want string) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("install-faucet.sh did not fail: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) || !strings.Contains(out, "Nothing was installed.") {
		t.Fatalf("install-faucet.sh did not say %q and that nothing was installed:\n%s", want, out)
	}
	for _, path := range []string{filepath.Join(env.home, ".ghost-faucet"), env.unitDir()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused install left %s", path)
		}
	}
	if calls := env.calls(t); len(calls) != 0 {
		t.Fatalf("a refused install made calls:\n%s", strings.Join(calls, "\n"))
	}
	checkKeysUntouched(t, env, out)
}

// TestFaucetNodeTests runs the faucet's own tests: the minute for each address, a
// failed transfer, the test network check and bad addresses. Without Node.js
// it fails rather than skips, so CI always runs them.
func TestFaucetNodeTests(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("the faucet tests need Node.js (node) on the PATH: %v", err)
	}
	cmd := exec.Command(node, "--test", "faucet/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --test faucet/ failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "checkTestNetwork accepts the public test network only") {
		t.Fatalf("node --test faucet/ did not run the faucet's tests:\n%s", out)
	}
}

// TestFaucetInstall installs the faucet on a computer with a node: its files,
// both units, both started, and the Funnel path /ghost-faucet on port 8548. A
// re-run is safe and changes nothing.
func TestFaucetInstall(t *testing.T) {
	env := newFaucetEnv(t)
	out, err := env.run(t)
	if err != nil {
		t.Fatalf("install-faucet.sh failed: %v\n%s", err, out)
	}
	checkFaucetInstalled(t, env, out, "8548")

	t.Run("re-run", func(t *testing.T) {
		unit := readFile(t, filepath.Join(env.unitDir(), "ghost-faucet.service"))
		if err := os.Remove(filepath.Join(env.stubs, "calls")); err != nil {
			t.Fatal(err)
		}
		out, err := env.run(t)
		if err != nil {
			t.Fatalf("the re-run failed: %v\n%s", err, out)
		}
		checkFaucetInstalled(t, env, out, "8548")
		if after := readFile(t, filepath.Join(env.unitDir(), "ghost-faucet.service")); after != unit {
			t.Fatalf("the re-run changed the faucet unit:\n%s", after)
		}
		// The running units restart on the files just copied.
		calls := strings.Join(env.calls(t), "\n")
		for _, unit := range []string{"ghost-faucet-signer.service", "ghost-faucet.service"} {
			if !strings.Contains(calls, "systemctl --user restart "+unit) {
				t.Fatalf("the re-run did not restart %s:\n%s", unit, calls)
			}
		}
	})
}

// TestFaucetInstallPort runs the faucet on FAUCET_PORT and publishes that
// port; a FAUCET_PORT that is not a port is refused.
func TestFaucetInstallPort(t *testing.T) {
	env := newFaucetEnv(t)
	out, err := env.run(t, "FAUCET_PORT=9123")
	if err != nil {
		t.Fatalf("install-faucet.sh failed: %v\n%s", err, out)
	}
	checkFaucetInstalled(t, env, out, "9123")

	for _, port := range []string{"84x8", "0", "70000", "8548 --other"} {
		t.Run(port, func(t *testing.T) {
			env := newFaucetEnv(t)
			out, err := env.run(t, "FAUCET_PORT="+port)
			checkFaucetRefused(t, env, out, err, "FAUCET_PORT must be a port number")
		})
	}
}

// TestFaucetInstallNeedsNode refuses, with nothing installed, on a computer
// without the node's config or its geth.
func TestFaucetInstallNeedsNode(t *testing.T) {
	for _, missing := range []string{"config.toml", filepath.Join("bin", "geth")} {
		t.Run(missing, func(t *testing.T) {
			env := newFaucetEnv(t)
			path := filepath.Join(env.home, ".ghost-node", missing)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			out, err := env.run(t)
			checkFaucetRefused(t, env, out, err, "no Ghost node here: "+path+" is missing")
		})
	}
}

// TestFaucetInstallFunnelRefused fails with a clear message when Funnel does
// not publish the faucet, and a re-run once it does completes the install.
func TestFaucetInstallFunnelRefused(t *testing.T) {
	env := newFaucetEnv(t)
	env.write(t, filepath.Join(env.stubs, "funnel-refused"), "", 0600)
	out, err := env.run(t)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !strings.Contains(out, "/ghost-faucet http://127.0.0.1:8548' failed") || !strings.Contains(out, "Running this again is safe.") {
		t.Fatalf("install-faucet.sh did not fail at the Funnel step, saying so: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(env.stubs, "funnel-refused")); err != nil {
		t.Fatal(err)
	}
	out, err = env.run(t)
	if err != nil {
		t.Fatalf("the re-run failed: %v\n%s", err, out)
	}
	checkFaucetInstalled(t, env, out, "8548")
}
