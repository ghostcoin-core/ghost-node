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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/params/ghost"
)

// The tests of install.sh --public, which publishes the installed node as a
// public node for the Ghost Wallet at https://<its Tailscale name>/ghost-rpc
// with Tailscale Funnel. tailscale, sudo, loginctl, systemctl and Tailscale's
// install script are stubs that record their calls in $STUB_DIR/calls.

const (
	// stubSudo runs its command as sudo would, with SUDO_USER set, which the
	// stubs below take as running as root.
	stubSudo = `#!/bin/sh
echo "sudo $*" >>"$STUB_DIR/calls"
SUDO_USER=$(id -un) exec "$@"
`
	// stubPublicLoginctl turns lingering on, the file $STUB_DIR/linger, and
	// tells whether it is on. With $STUB_DIR/linger-needs-root only root may
	// turn it on, and with $STUB_DIR/linger-refused nobody may.
	stubPublicLoginctl = `#!/bin/sh
echo "loginctl $*" >>"$STUB_DIR/calls"
case "$1" in
show-user)
	[ "$*" = "show-user $(id -un) --property=Linger --value" ] || exit 1
	if [ -f "$STUB_DIR/linger" ]; then echo yes; else echo no; fi
	exit 0
	;;
enable-linger)
	[ ! -f "$STUB_DIR/linger-refused" ] || exit 1
	[ ! -f "$STUB_DIR/linger-needs-root" ] || [ -n "$SUDO_USER" ] || exit 1
	touch "$STUB_DIR/linger"
	exit 0
	;;
esac
exit 1
`
	// stubTailscale is logged in while $STUB_DIR/tailscale-name holds this
	// computer's DNSName; up, as root, logs it in with the name in
	// $STUB_DIR/tailscale-login-name, when there is one. funnel succeeds as
	// root only.
	stubTailscale = `#!/bin/sh
echo "tailscale $*" >>"$STUB_DIR/calls"
case "$1" in
status)
	[ "$*" = "status --self --json" ] || exit 1
	state=NeedsLogin
	name=
	if [ -f "$STUB_DIR/tailscale-name" ]; then
		state=Running
		name=$(cat "$STUB_DIR/tailscale-name")
	fi
	printf '{\n  "Version": "1.80.0",\n  "BackendState": "%s",\n  "TailscaleIPs": ["100.64.0.1"],\n' "$state"
	printf '  "Peer": {\n    "nodekey:1": {\n      "HostName": "other",\n      "DNSName": "other.tail1234.ts.net.",\n      "CapMap": {}\n    }\n  },\n'
	printf '  "Self": {\n    "ID": "n1",\n    "HostName": "box",\n    "DNSName": "%s",\n    "TailscaleIPs": ["100.64.0.1"],\n    "CapMap": {"funnel": null}\n  }\n}\n' "$name"
	exit 0
	;;
up)
	[ -n "$SUDO_USER" ] || { echo "tailscale up: needs root" >&2; exit 1; }
	echo "To authenticate, visit: https://login.tailscale.com/a/example"
	[ ! -f "$STUB_DIR/tailscale-login-name" ] || cp "$STUB_DIR/tailscale-login-name" "$STUB_DIR/tailscale-name"
	exit 0
	;;
funnel)
	[ -n "$SUDO_USER" ] || { echo "tailscale funnel: needs root" >&2; exit 1; }
	exit 0
	;;
esac
echo "unexpected tailscale call: $*" >&2
exit 1
`
	// fakeTailscaleInstaller stands in for Tailscale's install script: it
	// puts the tailscale stub on the PATH.
	fakeTailscaleInstaller = `#!/bin/sh
echo "tailscale-install.sh $*" >>"$STUB_DIR/calls"
cp "$STUB_DIR/tailscale.stub" "$STUB_DIR/tailscale"
chmod 700 "$STUB_DIR/tailscale"
`
	publicName  = "box.tail1234.ts.net"
	publicName2 = "node2.tail1234.ts.net"
	loginStep   = "This is the one step the installer cannot do for you: Tailscale prints a login link below; open it in a browser, sign in to your own free Tailscale account, and allow Funnel when it asks."
	rerunLine   = "run the line again, which is safe: curl -fsSL https://get.ghostcoin.com | sh -s -- --public"
)

// publicEnv is a Linux computer with a systemd user session, sudo, and
// Tailscale logged in as publicName, unless the test changes that.
func publicEnv(t *testing.T) *installEnv {
	t.Helper()
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 2})
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	for name, script := range map[string]string{
		"sudo":           stubSudo,
		"loginctl":       stubPublicLoginctl,
		"tailscale":      stubTailscale,
		"tailscale.stub": stubTailscale,
	} {
		writeStub(t, env, name, script)
	}
	writeStub(t, env, "tailscale-name", publicName+".\n")
	return env
}

func writeStub(t *testing.T, env *installEnv, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(env.stubs, name), []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
}

// publicRelease serves a release whose geth is the stand-in node, and
// Tailscale's stand-in install script next to it. It returns the release
// server and the installer.
func publicRelease(t *testing.T, release archive) (*releaseServer, string) {
	t.Helper()
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	rs.setFile("tailscale-install.sh", []byte(fakeTailscaleInstaller))
	script := writeScript(t, key, sha256Hex(verifier))
	serveInstaller(t, rs, key, script)
	return rs, script
}

// runPublic runs the one line with --public, mining to a wallet address.
func runPublic(t *testing.T, env *installEnv, script string, rs *releaseServer, extraEnv ...string) (string, error) {
	t.Helper()
	extraEnv = append([]string{
		"GHOST_MINE_TO=" + mineToWallet,
		"GHOST_TAILSCALE_INSTALL_URL=" + rs.URL + "/latest/download/tailscale-install.sh",
	}, extraEnv...)
	return env.runArgs(t, script, []string{"--public"}, rs, true, extraEnv...)
}

func callLines(t *testing.T, env *installEnv) []string {
	t.Helper()
	return strings.Split(strings.TrimRight(env.calls(t), "\n"), "\n")
}

func countLines(lines []string, want string) int {
	n := 0
	for _, line := range lines {
		if line == want {
			n++
		}
	}
	return n
}

func funnelCall(env *installEnv) string {
	return fmt.Sprintf("tailscale funnel --bg --set-path /ghost-rpc http://127.0.0.1:%d", env.httpPort)
}

func vhostLine(name string) string {
	return fmt.Sprintf("HTTPVirtualHosts = [\"localhost\", %q]", name)
}

// checkPublicConfig checks that the config names name once in its
// HTTPVirtualHosts line, right after the HTTPModules line, and still opens
// the HTTP RPC on 127.0.0.1 only with only the eth, net and web3 modules.
func checkPublicConfig(t *testing.T, env *installEnv, name string) {
	t.Helper()
	config := readConfig(t, env)
	lines := strings.Split(config, "\n")
	if n := countLines(lines, vhostLine(name)); n != 1 {
		t.Fatalf("the config has %d lines %q, not one:\n%s", n, vhostLine(name), config)
	}
	if n := strings.Count(config, "HTTPVirtualHosts"); n != 1 {
		t.Fatalf("the config names HTTPVirtualHosts %d times:\n%s", n, config)
	}
	for i, line := range lines {
		if line == vhostLine(name) && (i == 0 || lines[i-1] != `HTTPModules = ["eth", "net", "web3"]`) {
			t.Fatalf("the HTTPVirtualHosts line does not follow the HTTPModules line:\n%s", config)
		}
	}
	if countLines(lines, `HTTPHost = "127.0.0.1"`) != 1 || strings.Count(config, "HTTPHost") != 1 {
		t.Fatalf("the config does not keep the HTTP RPC on 127.0.0.1 only:\n%s", config)
	}
	if countLines(lines, `HTTPModules = ["eth", "net", "web3"]`) != 1 || strings.Count(config, "HTTPModules") != 1 {
		t.Fatalf("the config's modules are not exactly eth, net and web3:\n%s", config)
	}
	if countLines(lines, fmt.Sprintf("HTTPPort = %d", env.httpPort)) != 1 {
		t.Fatalf("the config's HTTP port is not %d:\n%s", env.httpPort, config)
	}
}

// checkPublished checks that the installer published the node's HTTP RPC at
// /ghost-rpc with Tailscale Funnel as root, and never with tailscale serve,
// and printed its public address.
func checkPublished(t *testing.T, env *installEnv, out, name string) {
	t.Helper()
	lines := callLines(t, env)
	if countLines(lines, "sudo "+funnelCall(env)) == 0 || countLines(lines, funnelCall(env)) == 0 {
		t.Fatalf("no call %q through sudo; the calls were:\n%s", funnelCall(env), env.calls(t))
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "tailscale funnel") && line != funnelCall(env) {
			t.Fatalf("the installer called %q; the calls were:\n%s", line, env.calls(t))
		}
		if strings.HasPrefix(line, "tailscale serve") {
			t.Fatalf("the installer called %q, which turns Funnel off", line)
		}
	}
	if want := "ghost-node: the node's public address for the Ghost Wallet: https://" + name + "/ghost-rpc\n"; !strings.HasSuffix(out, want) {
		t.Fatalf("the installer did not end by printing %q", want)
	}
}

// checkPublicFailed checks that the installer failed at the public step step,
// saying why and how to re-run it, with the node installed and running and
// nothing published.
func checkPublicFailed(t *testing.T, env *installEnv, out string, err error, step, why string) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("install.sh --public did not fail: %v", err)
	}
	want := "making the node public failed at the step '" + step + "': " + why
	if !strings.Contains(out, want) || !strings.Contains(out, "The node itself stays installed and running.") || !strings.Contains(out, rerunLine) {
		t.Fatalf("install.sh --public did not say %q, that the node runs, and how to re-run", want)
	}
	if !strings.Contains(out, "ghost-node: the node is installed in ") {
		t.Fatal("the plain install did not complete before the public steps")
	}
	if pid := env.servicePID(t); !running(pid) {
		t.Fatalf("the node (process %d) is not running", pid)
	}
	if calls := env.calls(t); strings.Contains(calls, "tailscale funnel") {
		t.Fatalf("a failed public step still published the node:\n%s", calls)
	}
	if strings.Contains(out, "/ghost-rpc\n") && strings.Contains(out, "public address for the Ghost Wallet") {
		t.Fatal("a failed public step printed a public address")
	}
}

// TestInstallScriptPublic installs with --public on a computer logged in to
// Tailscale: the config gets the public name once, the node restarts with it,
// only the RPC is published at /ghost-rpc, and the address is printed. A
// re-run changes nothing, a re-run after the name changed updates the line,
// and an update keeps the node public.
func TestInstallScriptPublic(t *testing.T) {
	rs, script := publicRelease(t, nodeRelease(t))
	env := publicEnv(t)
	const restart = "systemctl --user restart ghost-node.service"

	out, err := runPublic(t, env, script, rs)
	if err != nil {
		t.Fatalf("install.sh --public failed: %v", err)
	}
	checkPublicConfig(t, env, publicName)
	checkPublished(t, env, out, publicName)
	lines := callLines(t, env)
	if n := countLines(lines, restart); n != 2 {
		t.Fatalf("the node was restarted %d times, not once for the install and once for its public name:\n%s", n, env.calls(t))
	}
	// The restart for the public name comes before the Funnel.
	last := -1
	for i, line := range lines {
		if line == restart {
			last = i
		}
	}
	for i, line := range lines {
		if line == funnelCall(env) && i < last {
			t.Fatalf("the node was published before it restarted with its public name:\n%s", env.calls(t))
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "tailscale up") || strings.HasPrefix(line, "tailscale-install.sh") || strings.HasPrefix(line, "sudo loginctl") {
			t.Fatalf("on a computer logged in to Tailscale with lingering allowed the installer called %q", line)
		}
	}
	if strings.Contains(out, loginStep) {
		t.Fatal("the installer asked for a Tailscale login on a computer logged in")
	}
	if pid := env.servicePID(t); !running(pid) {
		t.Fatal("the node is not running")
	}

	t.Run("re-run", func(t *testing.T) {
		before := readConfig(t, env)
		restarts := countLines(callLines(t, env), restart)
		out, err := runPublic(t, env, script, rs)
		if err != nil {
			t.Fatalf("the re-run failed: %v", err)
		}
		if after := readConfig(t, env); after != before {
			t.Fatalf("the re-run changed the config:\n%s", after)
		}
		if n := countLines(callLines(t, env), restart); n != restarts+1 {
			t.Fatalf("the re-run restarted the node %d times, not once for the install", n-restarts)
		}
		checkPublished(t, env, out, publicName)
	})

	t.Run("name changed", func(t *testing.T) {
		writeStub(t, env, "tailscale-name", publicName2+".\n")
		out, err := runPublic(t, env, script, rs)
		if err != nil {
			t.Fatalf("the re-run failed: %v", err)
		}
		checkPublicConfig(t, env, publicName2)
		if config := readConfig(t, env); strings.Contains(config, publicName) {
			t.Fatalf("the config still names %s:\n%s", publicName, config)
		}
		checkPublished(t, env, out, publicName2)
	})

	t.Run("update", func(t *testing.T) {
		before := readConfig(t, env)
		calls := env.calls(t)
		out, err := env.update(t, rs)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		if after := readConfig(t, env); after != before {
			t.Fatalf("the update changed the config of a public node:\n%s", after)
		}
		if added := strings.TrimPrefix(env.calls(t), calls); strings.Contains(added, "tailscale") || strings.Contains(added, "sudo") {
			t.Fatalf("the update called Tailscale or sudo:\n%s", added)
		}
		if strings.Contains(out, "public") {
			t.Fatal("the update ran the public steps")
		}
	})
}

// TestInstallScriptPublicInstallsTailscaleAndLogsIn runs --public on a
// computer without Tailscale where only root may turn lingering on: the
// installer turns it on with sudo, installs Tailscale with its install
// script, says plainly that the login is the volunteer's one step, and logs
// in with sudo tailscale up.
func TestInstallScriptPublicInstallsTailscaleAndLogsIn(t *testing.T) {
	rs, script := publicRelease(t, nodeRelease(t))
	env := publicEnv(t)
	for _, name := range []string{"tailscale", "tailscale-name"} {
		if err := os.Remove(filepath.Join(env.stubs, name)); err != nil {
			t.Fatal(err)
		}
	}
	writeStub(t, env, "tailscale-login-name", publicName+".\n")
	writeStub(t, env, "linger-needs-root", "")

	out, err := runPublic(t, env, script, rs)
	if err != nil {
		t.Fatalf("install.sh --public failed: %v", err)
	}
	checkPublicConfig(t, env, publicName)
	checkPublished(t, env, out, publicName)
	user, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := callLines(t, env)
	index := func(want string) int {
		for i, line := range lines {
			if line == want {
				return i
			}
		}
		t.Fatalf("no call %q; the calls were:\n%s", want, env.calls(t))
		return -1
	}
	linger := index("sudo loginctl enable-linger " + strings.TrimSpace(string(user)))
	install := index("tailscale-install.sh ")
	up := index("sudo tailscale up")
	funnel := index("sudo " + funnelCall(env))
	if !(linger < install && install < up && up < funnel) {
		t.Fatalf("the public steps ran out of order:\n%s", env.calls(t))
	}
	step := strings.Index(out, loginStep)
	if step < 0 {
		t.Fatalf("the installer did not say %q", loginStep)
	}
	if link := strings.Index(out, "https://login.tailscale.com/a/example"); link < step {
		t.Fatal("the installer did not say what the volunteer must do before tailscale up printed its link")
	}
}

// TestInstallScriptPublicLingerRefused stops with a clear message when
// lingering cannot be turned on, even with sudo, rather than print an address
// that goes away at the next reboot.
func TestInstallScriptPublicLingerRefused(t *testing.T) {
	rs, script := publicRelease(t, nodeRelease(t))
	env := publicEnv(t)
	writeStub(t, env, "linger-refused", "")
	out, err := runPublic(t, env, script, rs)
	checkPublicFailed(t, env, out, err, "keep running", "'sudo loginctl enable-linger ")
	if strings.Contains(readConfig(t, env), "HTTPVirtualHosts") {
		t.Fatal("a failed public step changed the config")
	}
}

// TestInstallScriptPublicNotLoggedIn stops when Tailscale is still not logged
// in after tailscale up.
func TestInstallScriptPublicNotLoggedIn(t *testing.T) {
	rs, script := publicRelease(t, nodeRelease(t))
	env := publicEnv(t)
	if err := os.Remove(filepath.Join(env.stubs, "tailscale-name")); err != nil {
		t.Fatal(err)
	}
	out, err := runPublic(t, env, script, rs)
	checkPublicFailed(t, env, out, err, "log in to Tailscale", "Tailscale is not logged in")
	if !strings.Contains(out, loginStep) {
		t.Fatalf("the installer did not say %q", loginStep)
	}
	if strings.Contains(readConfig(t, env), "HTTPVirtualHosts") {
		t.Fatal("a failed public step changed the config")
	}
}

// TestInstallScriptPublicRefusesOtherModules does not publish a node whose
// config offers more than the eth, net and web3 modules.
func TestInstallScriptPublicRefusesOtherModules(t *testing.T) {
	rs, script := publicRelease(t, nodeRelease(t))
	env := publicEnv(t)
	if _, err := runMineTo(t, env, script, rs); err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	path := filepath.Join(env.home, ".ghost-node", "config.toml")
	config := readConfig(t, env)
	edited := strings.Replace(config, `HTTPModules = ["eth", "net", "web3"]`, `HTTPModules = ["eth", "net", "web3", "rpc"]`, 1)
	if edited == config {
		t.Fatalf("the config has no HTTPModules line to edit:\n%s", config)
	}
	if err := os.WriteFile(path, []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runPublic(t, env, script, rs)
	checkPublicFailed(t, env, out, err, "set the public name", "the config "+path+" must have one HTTPModules line")
	if readConfig(t, env) != edited {
		t.Fatal("a refused public step changed the config")
	}
}

// TestInstallScriptPublicDarwin refuses --public on a Mac before anything is
// downloaded or installed.
func TestInstallScriptPublicDarwin(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	env := newInstallEnv(t, envOptions{darwin: true, cpus: 2})
	writeStub(t, env, "tailscale", stubTailscale)
	writeStub(t, env, "sudo", stubSudo)
	out, err := runPublic(t, env, script, rs)
	checkRefused(t, env, out, err, "public nodes (--public) are Linux-only for now; on this Mac run the plain install line, without --public; refusing to install. Nothing was installed.", marker)
	if served := rs.servedFiles(); len(served) != 0 {
		t.Fatalf("a refused --public downloaded %v", served)
	}
}

// TestInstallScriptPublicPlainUnchanged installs without --public on a
// computer with Tailscale logged in: no Tailscale or sudo call, no public
// name in the config, and nothing said about a public node. Any argument but
// --update or --public alone is refused.
func TestInstallScriptPublicPlainUnchanged(t *testing.T) {
	rs, script := publicRelease(t, nodeRelease(t))
	env := publicEnv(t)
	out, err := runMineTo(t, env, script, rs)
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	if calls := env.calls(t); strings.Contains(calls, "tailscale") || strings.Contains(calls, "sudo") {
		t.Fatalf("the plain install called Tailscale or sudo:\n%s", calls)
	}
	config := readConfig(t, env)
	if strings.Contains(config, "HTTPVirtualHosts") || !strings.Contains(config, "HTTPModules = [\"eth\", \"net\", \"web3\"]\nHTTPCors") {
		t.Fatalf("the plain install's config changed:\n%s", config)
	}
	if strings.Contains(out, "public") || strings.Contains(out, "ghost-rpc") {
		t.Fatal("the plain install spoke of a public node")
	}

	for _, args := range [][]string{{"--public", "--update"}, {"--update", "--public"}, {"--public", "--public"}, {"--publish"}, {"public"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			env := publicEnv(t)
			out, err := env.runArgs(t, script, args, rs, true)
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !strings.Contains(out, "usage: install.sh [--update | --public]") {
				t.Fatalf("install.sh %v did not stop with its usage: %v", args, err)
			}
			if left := entries(t, env.home); len(left) != 0 {
				t.Fatalf("install.sh %v left %v in the home", args, left)
			}
			if calls := env.calls(t); calls != "" {
				t.Fatalf("install.sh %v made calls:\n%s", args, calls)
			}
		})
	}
}

// TestInstallScriptPublicRealNode installs the node built from this checkout
// with --public, and checks that its HTTP RPC answers eth_chainId with the
// test network's chain ID to a request for the public name, as Tailscale
// Funnel passes them on, and still refuses other names.
func TestInstallScriptPublicRealNode(t *testing.T) {
	release, _ := internalNetRelease(t)
	rs, script := publicRelease(t, release)
	holdDefaultP2PPort(t)
	env := publicEnv(t)
	out, err := env.runArgs(t, script, []string{"--public"}, rs, true)
	if err != nil {
		t.Fatalf("install.sh --public failed: %v", err)
	}
	checkPublicConfig(t, env, publicName)
	checkPublished(t, env, out, publicName)
	call := func(host string) (int, string) {
		t.Helper()
		req, err := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/", env.httpPort), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("the node's HTTP RPC: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if status, body := call(publicName); status != http.StatusOK || !strings.Contains(body, fmt.Sprintf(`"result":"%#x"`, ghost.InternalNetChainID)) {
		t.Fatalf("eth_chainId for %s gave %d %s", publicName, status, body)
	}
	if status, body := call("other.example"); status != http.StatusForbidden {
		t.Fatalf("eth_chainId for another name gave %d %s, not 403", status, body)
	}
}
