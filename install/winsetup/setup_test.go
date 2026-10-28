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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/internal/winsvc"
)

// The tests run ghost-setup's logic against a local TLS release server signed
// with a test key, with a fake Run key, fake processes and a fake geth. The
// fake geth.exe is a file whose content says how it behaves: "geth" runs,
// "crashing geth" starts and exits at once, "broken geth" does not run at
// all.

const testAddress = "0x1111222233334444555566667777888899990000"

type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{pub, priv}
}

// tarEntry is one member of a test release archive.
type tarEntry struct {
	name     string
	body     string
	typeflag byte
}

func tarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typeflag
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: typ, ModTime: time.Unix(1790000000, 0)}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if typ == tar.TypeSymlink {
			hdr.Linkname = e.body
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gethArchive is a release archive holding a geth.exe with the content body.
func gethArchive(t *testing.T, body string) []byte {
	return tarGz(t, tarEntry{name: gethExeName, body: body})
}

// releaseServer serves release files over TLS and counts the requests.
type releaseServer struct {
	*httptest.Server
	mu       sync.Mutex
	files    map[string][]byte
	requests int
	caFile   string
}

func newReleaseServer(t *testing.T) *releaseServer {
	t.Helper()
	rs := &releaseServer{files: make(map[string][]byte)}
	rs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		rs.requests++
		blob, ok := rs.files[strings.TrimPrefix(r.URL.Path, "/download/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(blob)
	}))
	t.Cleanup(rs.Close)
	rs.caFile = filepath.Join(t.TempDir(), "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rs.Certificate().Raw})
	if err := os.WriteFile(rs.caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	return rs
}

func (rs *releaseServer) url() string { return rs.URL + "/download" }

// publish serves archive as the windows-amd64 release, signed by s.
func (rs *releaseServer) publish(s *signer, archive []byte) {
	rs.publishSigned(archive, ed25519.Sign(s.priv, archive))
}

func (rs *releaseServer) publishSigned(archive, sig []byte) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.files["ghost-node-windows-amd64.tar.gz"] = archive
	rs.files["ghost-node-windows-amd64.tar.gz.sig"] = sig
}

func (rs *releaseServer) count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.requests
}

// fakeRunKey is the current user's Run key.
type fakeRunKey struct {
	mu     sync.Mutex
	values map[string]string
}

func (k *fakeRunKey) Get(name string) (string, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.values[name]
	return v, ok, nil
}

func (k *fakeRunKey) Set(name, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.values[name] = value
	return nil
}

func (k *fakeRunKey) Delete(name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.values, name)
	return nil
}

// fakeUserEnv is the current user's environment.
type fakeUserEnv struct {
	mu     sync.Mutex
	values map[string]string
}

func (u *fakeUserEnv) Get(name string) (string, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	v, ok := u.values[name]
	return v, ok, nil
}

func (u *fakeUserEnv) Set(name, value string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.values[name] = value
	return nil
}

func (u *fakeUserEnv) copy() map[string]string {
	u.mu.Lock()
	defer u.mu.Unlock()
	c := make(map[string]string)
	for k, v := range u.values {
		c[k] = v
	}
	return c
}

// fakeProc is a process the fake processes started.
type fakeProc struct {
	exe     string
	args    []string
	content string // of exe when it started
	threads string // GETH_MINER_THREADS of its environment, "" if none
	alive   bool
}

type fakeProcesses struct {
	mu    sync.Mutex
	procs map[int]*fakeProc
	next  int
	// environ is the environment of the process that starts the node, which
	// the node inherits.
	environ map[string]string
}

// setenv sets a variable of the starting process's environment.
func (p *fakeProcesses) setenv(key, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.environ[key] = value
	return nil
}

// setEnviron makes environ the starting process's environment.
func (p *fakeProcesses) setEnviron(environ map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.environ = environ
}

func (p *fakeProcesses) Start(exe string, args []string, logPath string) (int, error) {
	content, err := os.ReadFile(exe)
	if err != nil {
		return 0, err
	}
	if string(content) == "broken geth" {
		return 0, errors.New("not a valid application for this OS platform")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	p.procs[p.next] = &fakeProc{exe: exe, args: args, content: string(content), threads: p.environ[minerThreadsVar], alive: string(content) != "crashing geth"}
	return p.next, nil
}

func (p *fakeProcesses) Running(pid int, exe string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	proc, ok := p.procs[pid]
	return ok && proc.alive && proc.exe == exe, nil
}

func (p *fakeProcesses) Interrupt(pid int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if proc, ok := p.procs[pid]; ok {
		proc.alive = false
	}
	return nil
}

// running returns the running processes.
func (p *fakeProcesses) running() []*fakeProc {
	p.mu.Lock()
	defer p.mu.Unlock()
	var live []*fakeProc
	for _, proc := range p.procs {
		if proc.alive {
			live = append(live, proc)
		}
	}
	return live
}

func (p *fakeProcesses) started() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.procs)
}

// fakeGeth runs geth commands the way geth.exe answers them.
func fakeGeth(t *testing.T, accounts *int) func(string, ...string) ([]byte, error) {
	return func(exe string, args ...string) ([]byte, error) {
		content, err := os.ReadFile(exe)
		if err != nil {
			return nil, err
		}
		if string(content) == "broken geth" {
			return []byte("this app can't run on your PC"), errors.New("exit status 1")
		}
		switch {
		case len(args) == 1 && args[0] == "version":
			return []byte("Geth\nVersion: 1.0.0-test\n"), nil
		case len(args) == 6 && args[0] == "--datadir" && args[2] == "account" && args[3] == "new" && args[4] == "--password":
			if _, err := os.Stat(args[5]); err != nil {
				return nil, fmt.Errorf("no password file: %v", err)
			}
			*accounts++
			return []byte("Your new key was generated\n\nPublic address of the key:   " + testAddress + "\nPath of the secret key file: x\n"), nil
		case len(args) == 4 && args[0] == "--datadir" && args[2] == "init":
			return []byte("Successfully wrote genesis state\n"), nil
		}
		t.Errorf("unexpected geth command: %q", args)
		return nil, errors.New("unexpected command")
	}
}

// env is one user's Windows computer.
type env struct {
	t        *testing.T
	profile  string
	home     string
	selfExe  string
	runKey   *fakeRunKey
	procs    *fakeProcesses
	userEnv  *fakeUserEnv
	cpus     int
	accounts int
	now      time.Time
	vars     map[string]string
	key      ed25519.PublicKey
}

func newEnv(t *testing.T, rs *releaseServer, key ed25519.PublicKey) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t:       t,
		profile: filepath.Join(root, "profile"),
		selfExe: filepath.Join(root, "download", setupExeName),
		runKey:  &fakeRunKey{values: make(map[string]string)},
		procs:   &fakeProcesses{procs: make(map[int]*fakeProc), environ: make(map[string]string)},
		userEnv: &fakeUserEnv{values: make(map[string]string)},
		cpus:    8,
		now:     time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC),
		key:     key,
	}
	e.home = filepath.Join(e.profile, homeDirName)
	e.vars = map[string]string{
		"USERPROFILE":           e.profile,
		"GHOST_RELEASE_URL":     rs.url(),
		"GHOST_INSTALL_CA_FILE": rs.caFile,
	}
	for _, dir := range []string{e.profile, filepath.Dir(e.selfExe), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(e.selfExe, []byte("ghost-setup"), 0o700); err != nil {
		t.Fatal(err)
	}
	return e
}

// run runs ghost-setup with args and returns its output.
func (e *env) run(args ...string) (string, error) {
	e.t.Helper()
	m, err := parseArgs(args)
	if err != nil {
		e.t.Fatal(err)
	}
	var out bytes.Buffer
	s, err := newSetup(func(name string) string { return e.vars[name] }, e.selfExe, &out)
	if err != nil {
		return out.String(), err
	}
	s.key = e.key
	s.arch = "amd64"
	s.workRoot = filepath.Join(filepath.Dir(e.selfExe), "..", "tmp")
	s.runKey, s.procs = e.runKey, e.procs
	s.userEnv, s.cpus = e.userEnv, e.cpus
	// ghost-setup runs with the user's environment, as at login.
	e.procs.setEnviron(e.userEnv.copy())
	s.setenv = e.procs.setenv
	s.runGeth = fakeGeth(e.t, &e.accounts)
	s.now = func() time.Time { return e.now }
	s.sleep = func(time.Duration) {}
	err = s.run(m)
	return out.String(), err
}

func (e *env) gethPath() string { return filepath.Join(e.home, "bin", gethExeName) }

func (e *env) installedGeth() string {
	e.t.Helper()
	blob, err := os.ReadFile(e.gethPath())
	if err != nil {
		e.t.Fatal(err)
	}
	return string(blob)
}

// nodeService is the service the node must be installed as.
func (e *env) nodeService() *winsvc.Service {
	return &winsvc.Service{Exe: e.gethPath(), Home: e.home, RunKey: e.runKey, Processes: e.procs}
}

// requireNothingInstalled fails unless the computer is as it was.
func (e *env) requireNothingInstalled() {
	e.t.Helper()
	if _, err := os.Stat(e.home); !errors.Is(err, fs.ErrNotExist) {
		e.t.Errorf("%s exists after a refused install (%v)", e.home, err)
	}
	if len(e.runKey.values) != 0 {
		e.t.Errorf("the Run key was changed: %v", e.runKey.values)
	}
	if n := e.procs.started(); n != 0 {
		e.t.Errorf("%d processes were started", n)
	}
	if vars := e.userEnv.copy(); len(vars) != 0 {
		e.t.Errorf("the user's environment was changed: %v", vars)
	}
	e.requireNoTempLeft()
}

// requireMinesOn fails unless the running node mines on threads cores, and the
// user's environment keeps that number for the node started at login.
func (e *env) requireMinesOn(threads string) {
	e.t.Helper()
	live := e.procs.running()
	if len(live) != 1 {
		e.t.Fatalf("%d nodes are running, not 1", len(live))
	}
	if live[0].threads != threads {
		e.t.Errorf("the node runs with %s=%q, not %q", minerThreadsVar, live[0].threads, threads)
	}
	if got, _, _ := e.userEnv.Get(minerThreadsVar); got != threads {
		e.t.Errorf("the user's environment holds %s=%q, not %q", minerThreadsVar, got, threads)
	}
}

func (e *env) requireNoTempLeft() {
	e.t.Helper()
	left, err := os.ReadDir(filepath.Join(filepath.Dir(filepath.Dir(e.selfExe)), "tmp"))
	if err != nil {
		e.t.Fatal(err)
	}
	if len(left) != 0 {
		e.t.Errorf("temporary files were left: %v", left)
	}
}

// requireRunning fails unless exactly one node runs, the installed geth.exe
// with content, with its config and mining on.
func (e *env) requireRunning(content string) {
	e.t.Helper()
	live := e.procs.running()
	if len(live) != 1 {
		e.t.Fatalf("%d nodes are running, not 1", len(live))
	}
	p := live[0]
	if p.exe != e.gethPath() || p.content != content {
		e.t.Errorf("the running node is %s holding %q, not %s holding %q", p.exe, p.content, e.gethPath(), content)
	}
	want := []string{"--config", filepath.Join(e.home, "config.toml"), "--mine"}
	if strings.Join(p.args, "|") != strings.Join(want, "|") {
		e.t.Errorf("the node runs with %q, not %q", p.args, want)
	}
	st, err := e.nodeService().Status()
	if err != nil {
		e.t.Fatal(err)
	}
	if !st.Running {
		e.t.Error("the node service reports the node is not running")
	}
}

func TestWinSetupCleanInstall(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	rs.publish(s, gethArchive(t, "geth"))
	e := newEnv(t, rs, s.pub)

	out, err := e.run()
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	if got := e.installedGeth(); got != "geth" {
		t.Errorf("the installed geth.exe holds %q", got)
	}
	setupCopy, err := os.ReadFile(filepath.Join(e.home, setupExeName))
	if err != nil || string(setupCopy) != "ghost-setup" {
		t.Errorf("ghost-setup.exe was not copied into the home directory: %q, %v", setupCopy, err)
	}

	// The config: a new mining address, mining to it, RPC on this computer
	// only, open to the web apps.
	if e.accounts != 1 {
		t.Errorf("%d mining keys were made, not 1", e.accounts)
	}
	config, err := os.ReadFile(filepath.Join(e.home, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[Eth.Miner]\nEtherbase = \"" + testAddress + "\"\n",
		"[Node]\n",
		"DataDir = \"" + filepath.Join(e.home, "data") + "\"\n",
		"HTTPHost = \"127.0.0.1\"\n",
		"HTTPPort = 8545\n",
		"HTTPModules = [\"eth\", \"net\", \"web3\"]\n",
		"HTTPCors = [\"https://ghost-webapp-alpha.vercel.app\", \"https://ghost-wallet-nine.vercel.app\"]\n",
	} {
		if !strings.Contains(string(config), want) {
			t.Errorf("the config lacks %q:\n%s", want, config)
		}
	}
	if pw, err := os.ReadFile(filepath.Join(e.home, "password")); err != nil || len(strings.TrimSpace(string(pw))) != 64 {
		t.Errorf("the mining key's password file is not a 64-character password: %v", err)
	}

	// The service: installed in the Run key and running.
	svc := e.nodeService()
	if got := e.runKey.values[winsvc.RunValueName]; got != svc.RunCommand() {
		t.Errorf("the Run key starts %q at login, not %q", got, svc.RunCommand())
	}
	st, err := svc.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Current {
		t.Error("the node service is not installed")
	}
	e.requireRunning("geth")

	// The daily update.
	wantUpdate := winsvc.JoinCommandLine(filepath.Join(e.home, setupExeName), "--update", "--daily")
	if got := e.runKey.values[updateValueName]; got != wantUpdate {
		t.Errorf("the Run key runs %q for updates, not %q", got, wantUpdate)
	}
	if len(e.runKey.values) != 2 {
		t.Errorf("the Run key holds %d values, not the node and the update: %v", len(e.runKey.values), e.runKey.values)
	}

	for _, want := range []string{
		"the release signature is valid",
		"your mining address: " + testAddress,
		"check its status with: " + winsvc.JoinCommandLine(e.gethPath(), "service", "status", "--home", e.home),
		"signed updates are checked daily at login",
		"mining on 4 of the 8 logical CPU cores of this computer; to change that, run the install line again with GHOST_MINE_THREADS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	e.requireMinesOn("4")
	e.requireNoTempLeft()

	// Run again, it keeps the config and the mining address and runs one node.
	out, err = e.run()
	if err != nil {
		t.Fatalf("second install failed: %v\n%s", err, out)
	}
	if e.accounts != 1 {
		t.Errorf("a second install made another mining key")
	}
	if !strings.Contains(out, "your mining address: "+testAddress) {
		t.Errorf("the second install does not print the kept address:\n%s", out)
	}
	e.requireRunning("geth")
}

func TestWinSetupGenesisAndPort(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	rs.publish(s, tarGz(t, tarEntry{name: "./" + gethExeName, body: "geth"}, tarEntry{name: "genesis.json", body: "{}"}))
	e := newEnv(t, rs, s.pub)
	e.vars["GHOST_HTTP_PORT"] = "8645"
	e.vars["GHOST_NO_UPDATE"] = "1"

	out, err := e.run()
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	config, _ := os.ReadFile(filepath.Join(e.home, "config.toml"))
	if !strings.Contains(string(config), "HTTPPort = 8645\n") {
		t.Errorf("GHOST_HTTP_PORT did not move the RPC port:\n%s", config)
	}
	if _, ok := e.runKey.values[updateValueName]; ok {
		t.Error("GHOST_NO_UPDATE=1 still scheduled the daily update")
	}
	if !strings.Contains(out, "automatic updates are off") {
		t.Errorf("the output does not say updates are off:\n%s", out)
	}
	e.requireRunning("geth")
}

func TestWinSetupRefusesTamperedArchive(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	good := gethArchive(t, "geth")
	tampered := append([]byte{}, good...)
	tampered[len(tampered)/2] ^= 0x01
	traversal := tarGz(t, tarEntry{name: "../evil.exe", body: "evil"}, tarEntry{name: gethExeName, body: "geth"})

	tests := []struct {
		name    string
		archive []byte
		sig     []byte
		envURL  string
		want    string
	}{
		{"tampered archive", tampered, ed25519.Sign(s.priv, good), "", "does not match the release key"},
		{"another key's signature", good, ed25519.Sign(other.priv, good), "", "does not match the release key"},
		{"short signature", good, ed25519.Sign(s.priv, good)[:63], "", "not a 64-byte ed25519 signature"},
		{"no signature", good, nil, "", "404"},
		{"plain http", good, ed25519.Sign(s.priv, good), "http://127.0.0.1:1/download", "must be an https URL"},
		{"member outside the directory", traversal, ed25519.Sign(s.priv, traversal), "", "unexpected entry"},
		{"no geth.exe", tarGz(t, tarEntry{name: "geth", body: "geth"}), nil, "", "holds no geth.exe"},
		{"link", tarGz(t, tarEntry{name: gethExeName, body: "C:/Windows/System32/cmd.exe", typeflag: tar.TypeSymlink}), nil, "", "unexpected entry"},
		{"geth.exe does not run", gethArchive(t, "broken geth"), nil, "", "does not run on this computer"},
		{"not a tar.gz", []byte("not an archive"), nil, "", "cannot be read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := newReleaseServer(t)
			sig := tt.sig
			if sig == nil && tt.name != "no signature" {
				sig = ed25519.Sign(s.priv, tt.archive)
			}
			rs.publishSigned(tt.archive, sig)
			if tt.name == "no signature" {
				delete(rs.files, "ghost-node-windows-amd64.tar.gz.sig")
			}
			e := newEnv(t, rs, s.pub)
			if tt.envURL != "" {
				e.vars["GHOST_RELEASE_URL"] = tt.envURL
			}
			out, err := e.run()
			if err == nil {
				t.Fatalf("the install was not refused:\n%s", out)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("the refusal %q does not say %q", err, tt.want)
			}
			if tt.envURL == "" && !strings.Contains(err.Error(), "refusing to install. Nothing was installed") {
				t.Errorf("the refusal %q does not say nothing was installed", err)
			}
			e.requireNothingInstalled()
		})
	}
}

func TestWinSetupRefusesUntrustedServer(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	rs.publish(s, gethArchive(t, "geth"))
	e := newEnv(t, rs, s.pub)
	delete(e.vars, "GHOST_INSTALL_CA_FILE")
	_, err := e.run()
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a server with an untrusted certificate was not refused: %v", err)
	}
	e.requireNothingInstalled()
}

// installed returns a computer with the node installed from rs.
func installed(t *testing.T, rs *releaseServer, s *signer) *env {
	t.Helper()
	rs.publish(s, gethArchive(t, "geth"))
	e := newEnv(t, rs, s.pub)
	if out, err := e.run(); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	return e
}

func TestWinSetupUpdate(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	e := installed(t, rs, s)
	config, _ := os.ReadFile(filepath.Join(e.home, "config.toml"))
	firstPID := e.procs.running()[0]

	// The same release: nothing to do, the node keeps running.
	out, err := e.run("--update")
	if err != nil || !strings.Contains(out, "the node is up to date") {
		t.Fatalf("an update to the same release: %v\n%s", err, out)
	}
	if live := e.procs.running(); len(live) != 1 || live[0] != firstPID {
		t.Error("an update to the same release restarted the node")
	}

	rs.publish(s, gethArchive(t, "geth v2"))
	out, err = e.run("--update")
	if err != nil {
		t.Fatalf("update failed: %v\n%s", err, out)
	}
	if got := e.installedGeth(); got != "geth v2" {
		t.Errorf("the installed geth.exe holds %q after the update", got)
	}
	e.requireRunning("geth v2")
	if _, err := os.Stat(e.gethPath() + ".previous"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the previous geth.exe was kept after the node restarted: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(e.home, "config.toml"))
	if !bytes.Equal(config, after) || e.accounts != 1 {
		t.Error("the update changed the config or the mining key")
	}
	if !strings.Contains(out, "updated the node to the latest release") {
		t.Errorf("the output does not say the node was updated:\n%s", out)
	}
	e.requireNoTempLeft()
}

func TestWinSetupRefusesTamperedUpdate(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	e := installed(t, rs, s)
	running := e.procs.running()[0]
	runKey := fmt.Sprint(e.runKey.values)

	good := gethArchive(t, "geth v2")
	tampered := gethArchive(t, "evil geth")
	rs.publishSigned(tampered, ed25519.Sign(s.priv, good))
	out, err := e.run("--update")
	if err == nil {
		t.Fatalf("a tampered update was applied:\n%s", out)
	}
	if !strings.Contains(err.Error(), "does not match the release key") || !strings.Contains(err.Error(), "Nothing was changed, and the running node was left alone") {
		t.Errorf("the refusal does not say why and that nothing changed: %v", err)
	}
	if got := e.installedGeth(); got != "geth" {
		t.Errorf("a refused update changed geth.exe to %q", got)
	}
	if live := e.procs.running(); len(live) != 1 || live[0] != running {
		t.Error("a refused update stopped or restarted the node")
	}
	if fmt.Sprint(e.runKey.values) != runKey {
		t.Error("a refused update changed the Run key")
	}
	e.requireNoTempLeft()
}

func TestWinSetupUpdateRollsBack(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	e := installed(t, rs, s)

	rs.publish(s, gethArchive(t, "crashing geth"))
	_, err := e.run("--update")
	if err == nil || !strings.Contains(err.Error(), "previous geth.exe was put back and restarted") {
		t.Fatalf("an update that does not start was not rolled back: %v", err)
	}
	if got := e.installedGeth(); got != "geth" {
		t.Errorf("geth.exe holds %q after the rollback", got)
	}
	if _, err := os.Stat(e.gethPath() + ".previous"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the previous geth.exe is still beside it: %v", err)
	}
	e.requireRunning("geth")
}

func TestWinSetupDailyUpdateChecksOnceADay(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	e := installed(t, rs, s)
	rs.publish(s, gethArchive(t, "geth v2"))

	before := rs.count()
	if out, err := e.run("--update", "--daily"); err != nil {
		t.Fatalf("daily update failed: %v\n%s", err, out)
	}
	if rs.count() == before || e.installedGeth() != "geth v2" {
		t.Fatal("the first daily update did not update")
	}

	rs.publish(s, gethArchive(t, "geth v3"))
	e.now = e.now.Add(23 * time.Hour)
	before = rs.count()
	if out, err := e.run("--update", "--daily"); err != nil {
		t.Fatalf("daily update failed: %v\n%s", err, out)
	}
	if rs.count() != before || e.installedGeth() != "geth v2" {
		t.Error("the daily update checked again within a day")
	}

	e.now = e.now.Add(2 * time.Hour)
	if out, err := e.run("--update", "--daily"); err != nil {
		t.Fatalf("daily update failed: %v\n%s", err, out)
	}
	if e.installedGeth() != "geth v3" {
		t.Error("the daily update did not check again after a day")
	}
	e.requireRunning("geth v3")
}

func TestWinSetupUpdateNeedsInstall(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	rs.publish(s, gethArchive(t, "geth"))
	e := newEnv(t, rs, s.pub)
	_, err := e.run("--update")
	if err == nil || !strings.Contains(err.Error(), "no Ghost node installed") {
		t.Fatalf("an update with nothing installed: %v", err)
	}
	if rs.count() != 0 {
		t.Error("an update with nothing installed downloaded the release")
	}
	e.requireNothingInstalled()
}

func TestWinSetupMemberNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"geth.exe":        true,
		"./geth.exe":      true,
		"dir/file":        true,
		"../geth.exe":     false,
		"a/../../b":       false,
		"/geth.exe":       false,
		`..\geth.exe`:     false,
		"C:geth.exe":      false,
		"geth.exe:stream": false,
		"geth.exe.":       false,
		"geth.exe ":       false,
		"":                false,
	} {
		if _, got := memberName(name); got != ok {
			t.Errorf("memberName(%q) accepted %v, want %v", name, got, ok)
		}
	}
}

func TestWinSetupArgs(t *testing.T) {
	for _, args := range [][]string{{"--daily"}, {"--update", "--now"}, {"install"}} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%q) accepted", args)
		}
	}
}

// TestWinSetupReleaseKeyPinned checks the pinned key is the release key in
// install/release-key.pub, so the two cannot drift apart.
func TestWinSetupReleaseKeyPinned(t *testing.T) {
	pub, err := os.ReadFile(filepath.Join("..", "release-key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseKey([]byte(releaseKey))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Error("the key pinned in setup.go is not install/release-key.pub")
	}
}

// login starts the node as the Run key does at login: a new process with the
// user's environment runs geth service start.
func (e *env) login() {
	e.t.Helper()
	if _, err := e.nodeService().Stop(); err != nil {
		e.t.Fatal(err)
	}
	e.procs.setEnviron(e.userEnv.copy())
	if _, _, err := e.nodeService().Start(); err != nil {
		e.t.Fatal(err)
	}
}

// TestWinSetupMinerThreadsDefault installs on computers with various numbers
// of logical cores: the node mines on half of them, rounded down and at least
// one, now and after every login.
func TestWinSetupMinerThreadsDefault(t *testing.T) {
	for cpus, want := range map[int]string{1: "1", 2: "1", 7: "3", 18: "9"} {
		t.Run(fmt.Sprint(cpus), func(t *testing.T) {
			rs := newReleaseServer(t)
			s := newSigner(t)
			rs.publish(s, gethArchive(t, "geth"))
			e := newEnv(t, rs, s.pub)
			e.cpus = cpus
			out, err := e.run()
			if err != nil {
				t.Fatalf("install failed: %v\n%s", err, out)
			}
			e.requireRunning("geth")
			e.requireMinesOn(want)
			if summary := fmt.Sprintf("mining on %s of the %d logical CPU cores", want, cpus); !strings.Contains(out, summary) {
				t.Errorf("the output lacks %q:\n%s", summary, out)
			}
			e.login()
			e.requireMinesOn(want)
		})
	}
}

// TestWinSetupMinerThreadsSetting installs with GHOST_MINE_THREADS: the node
// mines on that many cores. A re-run or an update without it keeps the
// number; with another, the node restarts on it.
func TestWinSetupMinerThreadsSetting(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	rs.publish(s, gethArchive(t, "geth"))
	e := newEnv(t, rs, s.pub)
	e.vars["GHOST_MINE_THREADS"] = "6"
	if out, err := e.run(); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	e.requireMinesOn("6")

	delete(e.vars, "GHOST_MINE_THREADS")
	if out, err := e.run(); err != nil {
		t.Fatalf("second install failed: %v\n%s", err, out)
	}
	e.requireMinesOn("6")

	// An update with nothing new keeps the number and the running node.
	e.login()
	running := e.procs.running()[0]
	out, err := e.run("--update")
	if err != nil || !strings.Contains(out, "the node is up to date") || !strings.Contains(out, "mining on 6 of the 8") {
		t.Fatalf("an update to the same release: %v\n%s", err, out)
	}
	if live := e.procs.running(); len(live) != 1 || live[0] != running {
		t.Error("an update keeping the number of cores restarted the node")
	}

	// An update with another number restarts the node on it.
	e.vars["GHOST_MINE_THREADS"] = "2"
	out, err = e.run("--update")
	if err != nil {
		t.Fatalf("update failed: %v\n%s", err, out)
	}
	if live := e.procs.running(); len(live) != 1 || live[0] == running {
		t.Error("an update with another number of cores did not restart the node")
	}
	e.requireRunning("geth")
	e.requireMinesOn("2")
	if !strings.Contains(out, "restarted the node to mine on 2 of the 8") {
		t.Errorf("the update does not say it restarted the node on 2 cores:\n%s", out)
	}

	// A new release is installed with the number kept.
	delete(e.vars, "GHOST_MINE_THREADS")
	rs.publish(s, gethArchive(t, "geth v2"))
	if out, err := e.run("--update"); err != nil {
		t.Fatalf("update failed: %v\n%s", err, out)
	}
	e.requireRunning("geth v2")
	e.requireMinesOn("2")
	e.login()
	e.requireMinesOn("2")
}

// TestWinSetupMinerThreadsOldInstall updates a node installed before
// ghost-setup set the number of cores, which mines on all of them: the update
// restarts it on half, though the release is the same.
func TestWinSetupMinerThreadsOldInstall(t *testing.T) {
	rs := newReleaseServer(t)
	s := newSigner(t)
	e := installed(t, rs, s)
	// As before: nothing in the user's environment, the node started without.
	delete(e.userEnv.values, minerThreadsVar)
	e.login()
	e.requireRunning("geth")
	old := e.procs.running()[0]
	if old.threads != "" {
		t.Fatalf("the old node runs with %s=%q", minerThreadsVar, old.threads)
	}

	e.cpus = 18
	out, err := e.run("--update", "--daily")
	if err != nil {
		t.Fatalf("daily update failed: %v\n%s", err, out)
	}
	if live := e.procs.running(); len(live) != 1 || live[0] == old {
		t.Fatal("the update did not restart the node")
	}
	e.requireRunning("geth")
	e.requireMinesOn("9")
	if !strings.Contains(out, "the node is up to date") || !strings.Contains(out, "restarted the node to mine on 9 of the 18") {
		t.Errorf("the update does not say it restarted the node on 9 cores:\n%s", out)
	}
	e.login()
	e.requireMinesOn("9")
}

// TestWinSetupMinerThreadsRefusesMalformed runs ghost-setup with
// GHOST_MINE_THREADS set to what is not a number of cores: it refuses before
// it downloads anything.
func TestWinSetupMinerThreadsRefusesMalformed(t *testing.T) {
	for _, value := range []string{"0", "00", "02", "-1", "+2", "1.5", "2 ", " 2", "10000", "two", "0x4"} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			rs := newReleaseServer(t)
			s := newSigner(t)
			rs.publish(s, gethArchive(t, "geth"))
			e := newEnv(t, rs, s.pub)
			e.vars["GHOST_MINE_THREADS"] = value
			_, err := e.run()
			want := "GHOST_MINE_THREADS must be the number of CPU cores to mine on, a whole number from 1 to 9999, not '" + value + "'"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("GHOST_MINE_THREADS=%q was not refused saying %q: %v", value, want, err)
			}
			if rs.count() != 0 {
				t.Error("a refused GHOST_MINE_THREADS downloaded the release")
			}
			e.requireNothingInstalled()
		})
	}
}
