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
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests of the Ghost Node Dashboard the installer ships with the node:
// ghost-dash from the release archive, its key, its open script and its
// service, its port, GHOST_NO_DASHBOARD, and the mining-paused file its pause
// control writes.

// fakeDashSource is a stand-in for ghost-dash. Like the real one it takes
// --node-dir and --port, serves on 127.0.0.1 at the port, and its /open link
// with the key of <node-dir>/dashboard-key answers 303 and sets the session
// cookie ghost_dash, while a wrong key gets 401; "open" prints the link. Each
// run appends its arguments to $STUB_DIR/dash.calls.
//
// Run as geth, it is a stand-in for the node, so that these tests need not
// wait for a real node: "version" succeeds, and with --config it opens the
// IPC endpoint of the config's DataDir, which the installer waits for, and
// answers every call on the config's HTTPPort with its Etherbase, as
// eth_coinbase does.
const fakeDashSource = `package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func node() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "version" {
		fmt.Println("Geth stand-in")
		return
	}
	var config string
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			config = args[i+1]
		}
	}
	blob, err := os.ReadFile(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	setting := func(name string) string {
		m := regexp.MustCompile("(?m)^" + name + " = \"?([^\"\n]*)\"?$").FindSubmatch(blob)
		if m == nil {
			fmt.Fprintln(os.Stderr, "the config has no", name)
			os.Exit(1)
		}
		return string(m[1])
	}
	dataDir, port, etherbase := setting("DataDir"), setting("HTTPPort"), setting("Etherbase")
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":%q}", etherbase)
	}))
	ipc := filepath.Join(dataDir, "geth.ipc")
	os.MkdirAll(dataDir, 0700)
	os.Remove(ipc)
	u, err := net.Listen("unix", ipc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for {
		c, err := u.Accept()
		if err != nil {
			os.Exit(1)
		}
		c.Close()
	}
}

func main() {
	if filepath.Base(os.Args[0]) == "geth" {
		node()
		return
	}
	args := os.Args[1:]
	open := len(args) > 0 && args[0] == "open"
	if open {
		args = args[1:]
	}
	fs := flag.NewFlagSet("ghost-dash", flag.ExitOnError)
	nodeDir := fs.String("node-dir", "", "")
	port := fs.Int("port", 8580, "")
	fs.Parse(args)
	if f, err := os.OpenFile(filepath.Join(os.Getenv("STUB_DIR"), "dash.calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
		f.Close()
	}
	blob, err := os.ReadFile(filepath.Join(*nodeDir, "dashboard-key"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key := strings.TrimSpace(string(blob))
	if open {
		fmt.Printf("http://127.0.0.1:%d/open?key=%s\n", *port, key)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != key {
			http.Error(w, "Open the dashboard from its link", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "ghost_dash", Value: "session", Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Open the dashboard from its link", http.StatusUnauthorized)
	})
	err = http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", *port), mux)
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
`

var (
	fakeDashOnce sync.Once
	fakeDashBin  []byte
	fakeDashErr  error
)

// builtFakeDash builds the stand-in ghost-dash once for all tests.
func builtFakeDash(t *testing.T) []byte {
	t.Helper()
	fakeDashOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ghost-fake-dash")
		if err != nil {
			fakeDashErr = err
			return
		}
		defer os.RemoveAll(dir)
		files := map[string]string{"go.mod": "module fakedash\n\ngo 1.21\n", "main.go": fakeDashSource}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
				fakeDashErr = err
				return
			}
		}
		goTool, err := exec.LookPath("go")
		if err != nil {
			goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
		}
		out := filepath.Join(dir, "ghost-dash")
		cmd := exec.Command(goTool, "build", "-o", out, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-modcacherw")
		if blob, err := cmd.CombinedOutput(); err != nil {
			fakeDashErr = fmt.Errorf("building the stand-in ghost-dash: %v\n%s", err, blob)
			return
		}
		fakeDashBin, fakeDashErr = os.ReadFile(out)
	})
	if fakeDashErr != nil {
		t.Fatal(fakeDashErr)
	}
	return fakeDashBin
}

// dashRelease is a release whose geth and ghost-dash are the stand-ins. It
// returns the archive and the ghost-dash.
func dashRelease(t *testing.T) (archive, []byte) {
	t.Helper()
	dash := builtFakeDash(t)
	return archive{"geth": dash, "ghost-dash": dash}, dash
}

// nodeRelease is a release whose geth is the stand-in, without a ghost-dash.
func nodeRelease(t *testing.T) archive {
	t.Helper()
	return archive{"geth": builtFakeDash(t)}
}

// runMineTo runs the installer as env.run does, mining to a wallet address:
// the stand-in geth makes no mining key.
func runMineTo(t *testing.T, env *installEnv, script string, rs *releaseServer, extraEnv ...string) (string, error) {
	t.Helper()
	return env.run(t, script, rs, true, append([]string{"GHOST_MINE_TO=" + mineToWallet}, extraEnv...)...)
}

// stubOpener puts a stub browser opener, open on a Mac or xdg-open on Linux,
// on the PATH of env. It records the links it is given in $STUB_DIR/opened.
func stubOpener(t *testing.T, env *installEnv, name string) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\necho \"%s $*\" >>\"$STUB_DIR/opened\"\n", name)
	if err := os.WriteFile(filepath.Join(env.stubs, name), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

// opened returns the links the stub opener was given, waiting a little for
// an opener the installer started in the background.
func opened(t *testing.T, env *installEnv, want int) []string {
	t.Helper()
	var lines []string
	for i := 0; i < 50; i++ {
		lines = nil
		if text := strings.TrimSpace(env.readStub(t, "opened")); text != "" {
			lines = strings.Split(text, "\n")
		}
		if len(lines) >= want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return lines
}

// stopDashAtCleanup stops, when the test ends, the dashboards the stub
// service managers or the installer started.
func stopDashAtCleanup(t *testing.T, env *installEnv) {
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "dash.pid"))
	stopNodeAtCleanup(t, filepath.Join(env.home, ".ghost-node", "dashboard.pid"))
}

var dashKeyFile = regexp.MustCompile(`^[0-9a-f]{64}\n$`)

// dashKey returns the installed dashboard key, checking its file.
func dashKey(t *testing.T, env *installEnv) string {
	t.Helper()
	path := filepath.Join(env.home, ".ghost-node", "dashboard-key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("there is no dashboard key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("the dashboard key has mode %v, not 0600", info.Mode().Perm())
	}
	blob := readFile(t, path)
	if !dashKeyFile.MatchString(blob) {
		t.Fatalf("the dashboard key file holds %q, not 32 bytes in hex", blob)
	}
	return strings.TrimSpace(blob)
}

func dashLink(env *installEnv, key string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/open?key=%s", env.dashPort, key)
}

// procArgs returns the arguments of the running process pid.
func procArgs(t *testing.T, pid int) []string {
	t.Helper()
	blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		t.Fatalf("process %d does not run: %v", pid, err)
	}
	return strings.Split(strings.TrimRight(string(blob), "\x00"), "\x00")
}

func pidIn(t *testing.T, path string) int {
	t.Helper()
	pid, err := strconv.Atoi(strings.TrimSpace(readFile(t, path)))
	if err != nil {
		t.Fatalf("%s holds no process ID: %v", path, err)
	}
	return pid
}

// dashPID returns the process ID of the running dashboard: the one the stub
// service manager started, or the one the installer started itself.
func dashPID(t *testing.T, env *installEnv) int {
	t.Helper()
	path := filepath.Join(env.stubs, "dash.pid")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(env.home, ".ghost-node", "dashboard.pid")
	}
	return pidIn(t, path)
}

// signIn opens the dashboard's link and returns the status and whether the
// dashboard set its session cookie.
func signIn(t *testing.T, link string) (int, bool) {
	t.Helper()
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		if resp, err = client.Get(link); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the dashboard does not answer: %v", err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "ghost_dash" {
			return resp.StatusCode, true
		}
	}
	return resp.StatusCode, false
}

// checkDashboardInstalled checks the installed dashboard: ghost-dash is the
// release's dash, its key and open script are there, its service runs it with
// --node-dir and --port, it runs and signs in with its key, and the closing
// lines printed its link. It returns the key.
func checkDashboardInstalled(t *testing.T, env *installEnv, dash []byte, out string) string {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	bin := filepath.Join(base, "bin", "ghost-dash")
	if fileHash(t, bin) != sha256.Sum256(dash) {
		t.Fatal("the installed ghost-dash is not the release's")
	}
	if info, err := os.Stat(bin); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("the installed ghost-dash is not executable (%v)", err)
	}
	key := dashKey(t, env)
	link := dashLink(env, key)
	if !strings.Contains(out, "this link opens it signed in: "+link+"\n") {
		t.Fatalf("the installer did not print the dashboard's link %s", link)
	}

	script := filepath.Join(base, "dashboard")
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("there is no dashboard script: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("the dashboard script has mode %v", info.Mode().Perm())
	}
	if want := fmt.Sprintf("exec '%s' open --node-dir '%s' --port %d \"$@\"\n", bin, base, env.dashPort); !strings.Contains(readFile(t, script), want) {
		t.Fatalf("the dashboard script does not run %q:\n%s", want, readFile(t, script))
	}
	if !strings.Contains(out, "open it again with: "+script+"\n") {
		t.Fatal("the installer did not say how to open the dashboard again")
	}
	cmd := exec.Command(script)
	cmd.Env = []string{"PATH=" + env.stubs, "STUB_DIR=" + env.stubs}
	if printed, err := cmd.Output(); err != nil || strings.TrimSpace(string(printed)) != link {
		t.Fatalf("the dashboard script printed %q (%v), not the link", printed, err)
	}

	pid := dashPID(t, env)
	if !running(pid) {
		t.Fatalf("the dashboard, process %d, does not run", pid)
	}
	args := procArgs(t, pid)
	if want := []string{bin, "--node-dir", base, "--port", strconv.Itoa(env.dashPort)}; strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("the dashboard runs as %q, not %q", args, want)
	}
	if status, cookie := signIn(t, link); status != http.StatusSeeOther || !cookie {
		t.Fatalf("the dashboard's link answered %d (cookie %v), not a sign-in", status, cookie)
	}
	if status, cookie := signIn(t, dashLink(env, strings.Repeat("0", 64))); status == http.StatusSeeOther || cookie {
		t.Fatal("the dashboard signs in with a key other than the installed one")
	}
	return key
}

// TestDashboardInstalled installs a release that holds ghost-dash: on Linux
// as a systemd user service with a desktop session, where the installer opens
// the link with xdg-open, and without one, where it only prints it; without
// systemd user services, where it runs it itself; and on a Mac as a launchd
// agent, where it opens the link with open.
func TestDashboardInstalled(t *testing.T) {
	t.Parallel()
	release, dash := dashRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	script := writeScript(t, key, sha256Hex(verifier))
	blob := release.tarGz(t)
	unitDir := func(env *installEnv) string { return filepath.Join(env.home, ".config", "systemd", "user") }

	t.Run("systemd", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		stubOpener(t, env, "xdg-open")
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		stopDashAtCleanup(t, env)
		out, err := runMineTo(t, env, script, rs, "DISPLAY=:0")
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		installed := checkDashboardInstalled(t, env, dash, out)
		base := filepath.Join(env.home, ".ghost-node")
		unit := readFile(t, filepath.Join(unitDir(env), "ghost-dashboard.service"))
		execStart := fmt.Sprintf("ExecStart=%q --node-dir %q --port %d\n", filepath.Join(base, "bin", "ghost-dash"), base, env.dashPort)
		if !strings.Contains(unit, execStart) || !strings.Contains(unit, "WantedBy=default.target") {
			t.Fatalf("the dashboard's unit does not run it at login:\n%s", unit)
		}
		calls := env.calls(t)
		for _, want := range []string{"systemctl --user enable ghost-dashboard.service\n", "systemctl --user restart ghost-dashboard.service\n"} {
			if !strings.Contains(calls, want) {
				t.Fatalf("no call %q; the calls were:\n%s", want, calls)
			}
		}
		if got := opened(t, env, 1); len(got) != 1 || got[0] != "xdg-open "+dashLink(env, installed) {
			t.Fatalf("the installer opened %q, not the dashboard's link once with xdg-open", got)
		}
		if !strings.Contains(out, "opened the dashboard in the browser") {
			t.Fatal("the installer did not say it opened the dashboard")
		}
	})

	t.Run("systemd without a desktop session", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		stubOpener(t, env, "xdg-open")
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		stopDashAtCleanup(t, env)
		out, err := runMineTo(t, env, script, rs)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		checkDashboardInstalled(t, env, dash, out)
		time.Sleep(time.Second)
		if got := opened(t, env, 0); len(got) != 0 {
			t.Fatalf("without a desktop session the installer opened %q", got)
		}
		if !strings.Contains(out, "there is no desktop session here, so the browser was not opened") {
			t.Fatal("the installer did not say why it did not open the dashboard")
		}
	})

	t.Run("no systemd user services", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubNoSystemd})
		stopNodeAtCleanup(t, filepath.Join(env.home, ".ghost-node", "node.pid"))
		stopDashAtCleanup(t, env)
		out, err := runMineTo(t, env, script, rs)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		checkDashboardInstalled(t, env, dash, out)
	})

	t.Run("darwin", func(t *testing.T) {
		rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{darwin: true, stockMac: true})
		stubOpener(t, env, "open")
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		stopDashAtCleanup(t, env)
		out, err := runMineTo(t, env, script, rs)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		installed := checkDashboardInstalled(t, env, dash, out)
		base := filepath.Join(env.home, ".ghost-node")
		agents := filepath.Join(env.home, "Library", "LaunchAgents")
		plist := readFile(t, filepath.Join(agents, "com.ghostcoin.dashboard.plist"))
		args := fmt.Sprintf("<array>\n\t\t<string>%s</string>\n\t\t<string>--node-dir</string>\n\t\t<string>%s</string>\n"+
			"\t\t<string>--port</string>\n\t\t<string>%d</string>\n\t</array>", filepath.Join(base, "bin", "ghost-dash"), base, env.dashPort)
		for _, want := range []string{"<string>com.ghostcoin.dashboard</string>", args, "<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<true/>"} {
			if !strings.Contains(plist, want) {
				t.Fatalf("the dashboard's plist has no %q:\n%s", want, plist)
			}
		}
		checkEnabledBeforeBootstrap(t, env.calls(t), fmt.Sprintf("gui/%d", os.Getuid()), agents, "com.ghostcoin.dashboard")
		if got := opened(t, env, 1); len(got) != 1 || got[0] != "open "+dashLink(env, installed) {
			t.Fatalf("the installer opened %q, not the dashboard's link once with open", got)
		}
	})
}

// TestDashboardKeptAcrossReRunAndUpdate installs the dashboard, runs the
// installer again while the dashboard runs on its port, and then updates to a
// release with another ghost-dash: the key and the port are kept, the link is
// printed but not opened again, and the update replaces ghost-dash and
// restarts the dashboard, not the node.
func TestDashboardKeptAcrossReRunAndUpdate(t *testing.T) {
	t.Parallel()
	release, dash := dashRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	stubOpener(t, env, "xdg-open")
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	stopDashAtCleanup(t, env)

	out, err := runMineTo(t, env, script, rs, "DISPLAY=:0")
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	first := checkDashboardInstalled(t, env, dash, out)
	if got := opened(t, env, 1); len(got) != 1 {
		t.Fatalf("the first install opened %q", got)
	}

	// A re-run, without GHOST_DASH_PORT: the running dashboard holds the
	// port it was installed with, which the re-run keeps.
	oldPID := dashPID(t, env)
	out, err = runMineTo(t, env, script, rs, "DISPLAY=:0", "GHOST_DASH_PORT=")
	if err != nil {
		t.Fatalf("the re-run of install.sh failed: %v", err)
	}
	if again := checkDashboardInstalled(t, env, dash, out); again != first {
		t.Fatal("the re-run changed the dashboard key")
	}
	if newPID := dashPID(t, env); newPID == oldPID || running(oldPID) {
		t.Fatal("the re-run did not restart the dashboard")
	}
	time.Sleep(time.Second)
	if got := opened(t, env, 2); len(got) != 1 {
		t.Fatalf("the re-run opened the dashboard again: %q", got)
	}

	// An update to a release whose geth is the same and whose ghost-dash is
	// not.
	serveInstaller(t, rs, key, script)
	newDash := append(append([]byte(nil), dash...), []byte("\nghost-dash test release 2\n")...)
	newRelease := archive{"ghost-dash": newDash}
	for name, content := range release {
		if name != "ghost-dash" {
			newRelease[name] = content
		}
	}
	newBlob := newRelease.tarGz(t)
	rs.setRelease(newBlob, key.sign(newBlob))
	const restart = "systemctl --user restart ghost-node.service\n"
	nodePID, restarts := env.servicePID(t), strings.Count(env.calls(t), restart)
	oldPID = dashPID(t, env)
	out, err = env.update(t, rs, "GHOST_DASH_PORT=")
	if err != nil {
		t.Fatalf("the update failed: %v", err)
	}
	if !strings.Contains(out, "the node is up to date") || !strings.Contains(out, "updated the dashboard to the latest release and restarted it") {
		t.Fatal("the update did not say it updated the dashboard and left the node as it was")
	}
	if again := checkDashboardInstalled(t, env, newDash, out); again != first {
		t.Fatal("the update changed the dashboard key")
	}
	if newPID := dashPID(t, env); newPID == oldPID || running(oldPID) {
		t.Fatal("the update did not restart the dashboard")
	}
	if strings.Count(env.calls(t), restart) != restarts || env.servicePID(t) != nodePID || !running(nodePID) {
		t.Fatal("an update of the dashboard alone restarted the node")
	}
	time.Sleep(time.Second)
	if got := opened(t, env, 2); len(got) != 1 {
		t.Fatalf("the update opened the dashboard again: %q", got)
	}
}

// TestDashboardSkipped installs with GHOST_NO_DASHBOARD=1: no ghost-dash, key,
// script, service or link, and the dashboard's port is not checked. A re-run
// without it installs the dashboard; a re-run with it again takes it out and
// keeps its key.
func TestDashboardSkipped(t *testing.T) {
	t.Parallel()
	release, dash := dashRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	script := writeScript(t, key, sha256Hex(verifier))
	base := func(env *installEnv) string { return filepath.Join(env.home, ".ghost-node") }
	unit := func(env *installEnv) string {
		return filepath.Join(env.home, ".config", "systemd", "user", "ghost-dashboard.service")
	}
	checkNoDashboard := func(t *testing.T, env *installEnv, out string) {
		t.Helper()
		for _, path := range []string{filepath.Join(base(env), "bin", "ghost-dash"), filepath.Join(base(env), "dashboard"), unit(env)} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("with GHOST_NO_DASHBOARD=1 there is %s (%v)", path, err)
			}
		}
		if strings.Contains(out, "/open?key=") {
			t.Fatal("with GHOST_NO_DASHBOARD=1 the installer printed a dashboard link")
		}
		if got := opened(t, env, 0); len(got) != 0 {
			t.Fatalf("with GHOST_NO_DASHBOARD=1 the installer opened %q", got)
		}
	}

	t.Run("install and re-runs", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		stubOpener(t, env, "xdg-open")
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		stopDashAtCleanup(t, env)
		out, err := runMineTo(t, env, script, rs, "DISPLAY=:0", "GHOST_NO_DASHBOARD=1")
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		if !strings.Contains(out, "mining to: "+mineToWallet+"\n") {
			t.Fatal("the installer did not install the node")
		}
		checkNoDashboard(t, env, out)
		if _, err := os.Stat(filepath.Join(base(env), "dashboard-key")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("with GHOST_NO_DASHBOARD=1 there is a dashboard key (%v)", err)
		}
		if calls := env.calls(t); strings.Contains(calls, "dashboard") {
			t.Fatalf("with GHOST_NO_DASHBOARD=1 the installer called the service manager for the dashboard:\n%s", calls)
		}
		if env.readStub(t, "dash.calls") != "" {
			t.Fatal("with GHOST_NO_DASHBOARD=1 the installer ran ghost-dash")
		}
		if !strings.Contains(out, "the dashboard is left out, as GHOST_NO_DASHBOARD=1 asks") {
			t.Fatal("the installer did not say it left the dashboard out")
		}

		// A re-run without it is the dashboard's first install.
		out, err = runMineTo(t, env, script, rs, "DISPLAY=:0")
		if err != nil {
			t.Fatalf("the re-run of install.sh failed: %v", err)
		}
		kept := checkDashboardInstalled(t, env, dash, out)
		if got := opened(t, env, 1); len(got) != 1 {
			t.Fatalf("the dashboard's first install opened %q", got)
		}
		pid := dashPID(t, env)

		// A re-run with it takes the dashboard out.
		if err := os.Remove(filepath.Join(env.stubs, "opened")); err != nil {
			t.Fatal(err)
		}
		out, err = runMineTo(t, env, script, rs, "DISPLAY=:0", "GHOST_NO_DASHBOARD=1")
		if err != nil {
			t.Fatalf("the re-run of install.sh failed: %v", err)
		}
		checkNoDashboard(t, env, out)
		if !strings.Contains(env.calls(t), "systemctl --user disable --now ghost-dashboard.service\n") {
			t.Fatal("the re-run with GHOST_NO_DASHBOARD=1 did not disable the dashboard's service")
		}
		for i := 0; i < 50 && running(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if running(pid) {
			t.Fatal("the re-run with GHOST_NO_DASHBOARD=1 left the dashboard running")
		}
		if got := dashKey(t, env); got != kept {
			t.Fatal("taking the dashboard out did not keep its key")
		}
	})

	t.Run("port held", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		holdPort(t, env.dashPort)
		out, err := runMineTo(t, env, script, rs, "GHOST_NO_DASHBOARD=1")
		if err != nil {
			t.Fatalf("with GHOST_NO_DASHBOARD=1 a program on the dashboard's port stopped the install: %v", err)
		}
		checkNoDashboard(t, env, out)
	})
}

func dashPortInUse(port int) string {
	return fmt.Sprintf("port %d on this computer is already in use by another program; stop it, or install with GHOST_DASH_PORT=<free port>; refusing to install. Nothing was installed.", port)
}

// TestDashboardPortInUse installs, on Linux and on a Mac, while another
// program listens on the dashboard's port, with the dashboard's port set to
// the node's HTTP RPC port, and with a GHOST_DASH_PORT that is no port: the
// installer must refuse before it downloads or writes anything.
func TestDashboardPortInUse(t *testing.T) {
	t.Parallel()
	verifier := builtVerifier(t)
	key := newSigner(t)
	script := writeScript(t, key, sha256Hex(verifier))
	for _, tc := range []struct {
		name string
		opts envOptions
	}{
		{"linux", envOptions{systemctl: stubSystemctl}},
		{"darwin", envOptions{darwin: true, stockMac: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ran")
			blob := archive{"geth": fakeGeth(marker), "ghost-dash": fakeGeth(marker)}.tarGz(t)
			rs := serveRelease(t, tc.name, blob, key.sign(blob), verifier)

			env := newInstallEnv(t, tc.opts)
			holdPort(t, env.dashPort)
			out, err := env.run(t, script, rs, true, "GHOST_MINE_TO="+mineToWallet)
			checkRefused(t, env, out, err, dashPortInUse(env.dashPort), marker)

			env = newInstallEnv(t, tc.opts)
			out, err = env.run(t, script, rs, true, "GHOST_MINE_TO="+mineToWallet, "GHOST_DASH_PORT="+strconv.Itoa(env.httpPort))
			checkRefused(t, env, out, err, fmt.Sprintf("the dashboard's port %d is the node's HTTP RPC port", env.httpPort), marker)

			for _, value := range []string{"80a", "0", "65536", "123456", "-1"} {
				env = newInstallEnv(t, tc.opts)
				out, err = env.run(t, script, rs, true, "GHOST_MINE_TO="+mineToWallet, "GHOST_DASH_PORT="+value)
				checkRefused(t, env, out, err, "GHOST_DASH_PORT must be a port number, not '"+value+"'; refusing to install.", marker)
			}
			if served := rs.servedFiles(); len(served) != 0 {
				t.Fatalf("an install refused for the dashboard's port downloaded %v", served)
			}
		})
	}
}

// hasArg reports whether the running process pid has the argument arg.
func hasArg(t *testing.T, pid int, arg string) bool {
	t.Helper()
	for _, a := range procArgs(t, pid) {
		if a == arg {
			return true
		}
	}
	return false
}

// TestMiningPausedFile pauses mining with ~/.ghost-node/mining-paused, as the
// dashboard's pause control does: an update rewrites the node's unit without
// --mine and restarts the node so, a re-run keeps it so, and once the file is
// gone an update starts the node mining again. On a Mac and without systemd
// user services, an install with the file there starts the node without
// --mine.
func TestMiningPausedFile(t *testing.T) {
	t.Parallel()
	release := nodeRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	script := writeScript(t, key, sha256Hex(verifier))

	t.Run("systemd", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		base := filepath.Join(env.home, ".ghost-node")
		paused := filepath.Join(base, "mining-paused")
		const restart = "systemctl --user restart ghost-node.service\n"
		mining := fmt.Sprintf("ExecStart=%q --config %q --mine --miner.threads 1\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
		notMining := fmt.Sprintf("ExecStart=%q --config %q --miner.threads 1\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
		checkMining := func(t *testing.T, want bool, out string) {
			t.Helper()
			unit := nodeUnit(t, env)
			execStart := notMining
			if want {
				execStart = mining
			}
			if !strings.Contains(unit, execStart) {
				t.Fatalf("the node's unit does not run %q:\n%s", execStart, unit)
			}
			pid := env.servicePID(t)
			if got := hasArg(t, pid, "--mine"); got != want {
				t.Fatalf("the node runs with --mine %v, not %v: %q", got, want, procArgs(t, pid))
			}
			if got := strings.Contains(out, "mining is paused: "+paused+" is there"); got != !want {
				t.Fatalf("the installer said mining is paused %v, not %v", got, !want)
			}
		}

		out, err := runMineTo(t, env, script, rs)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		checkMining(t, true, out)

		// The dashboard pauses mining; an update restarts the node without
		// --mine.
		if err := os.WriteFile(paused, nil, 0600); err != nil {
			t.Fatal(err)
		}
		serveInstaller(t, rs, key, script)
		oldPID, restarts := env.servicePID(t), strings.Count(env.calls(t), restart)
		out, err = env.update(t, rs)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		checkRestarted(t, env, oldPID, restarts, restart)
		checkMining(t, false, out)

		// An update with nothing new leaves the paused node alone.
		oldPID, restarts = env.servicePID(t), strings.Count(env.calls(t), restart)
		out, err = env.update(t, rs)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		if strings.Count(env.calls(t), restart) != restarts || env.servicePID(t) != oldPID {
			t.Fatal("an update with nothing new restarted the paused node")
		}
		checkMining(t, false, out)

		// A re-run keeps the pause.
		out, err = runMineTo(t, env, script, rs)
		if err != nil {
			t.Fatalf("the re-run of install.sh failed: %v", err)
		}
		checkMining(t, false, out)
		if !strings.Contains(out, "running and syncing\n") {
			t.Fatal("the re-run said a paused node mines")
		}

		// Mining resumed: an update starts the node mining again.
		if err := os.Remove(paused); err != nil {
			t.Fatal(err)
		}
		oldPID, restarts = env.servicePID(t), strings.Count(env.calls(t), restart)
		out, err = env.update(t, rs)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		checkRestarted(t, env, oldPID, restarts, restart)
		checkMining(t, true, out)
	})

	t.Run("darwin", func(t *testing.T) {
		rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{darwin: true, stockMac: true})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		base := filepath.Join(env.home, ".ghost-node")
		if err := os.MkdirAll(base, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "mining-paused"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runMineTo(t, env, script, rs); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		plist := readFile(t, filepath.Join(env.home, "Library", "LaunchAgents", "com.ghostcoin.node.plist"))
		args := fmt.Sprintf("<array>\n\t\t<string>%s</string>\n\t\t<string>--config</string>\n\t\t<string>%s</string>\n"+
			"\t\t<string>--miner.threads</string>\n\t\t<string>1</string>\n\t</array>",
			filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
		if !strings.Contains(plist, args) {
			t.Fatalf("the agent's plist does not run the node without --mine:\n%s", plist)
		}
		if pid := env.servicePID(t); hasArg(t, pid, "--mine") {
			t.Fatalf("the paused node runs with --mine: %q", procArgs(t, pid))
		}
	})

	t.Run("no systemd user services", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubNoSystemd})
		base := filepath.Join(env.home, ".ghost-node")
		stopNodeAtCleanup(t, filepath.Join(base, "node.pid"))
		if err := os.MkdirAll(base, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "mining-paused"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runMineTo(t, env, script, rs); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		pid := pidIn(t, filepath.Join(base, "node.pid"))
		args := procArgs(t, pid)
		if hasArg(t, pid, "--mine") || !hasArg(t, pid, "--miner.threads") {
			t.Fatalf("the paused node runs as %q, not without --mine", args)
		}
	})
}
