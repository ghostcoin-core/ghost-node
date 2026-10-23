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

// Package install tests install.sh, the one-line installer of the node. The
// tests run the script with sh against a local TLS release server, with HOME
// in a temporary directory and a test release key pinned in a copy of the
// script.
package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	keyBegin = "-----BEGIN PUBLIC KEY-----\n"
	keyEnd   = "-----END PUBLIC KEY-----\n"
)

// asset is the name of this computer's release archive.
var asset = fmt.Sprintf("ghost-node-linux-%s.tar.gz", runtime.GOARCH)

var (
	gethOnce sync.Once
	gethDir  string
	gethPath string
	gethErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if gethDir != "" {
		os.RemoveAll(gethDir)
	}
	os.Exit(code)
}

// builtGeth builds the node once for all tests and returns its path.
func builtGeth(t *testing.T) string {
	t.Helper()
	gethOnce.Do(func() {
		gethDir, gethErr = os.MkdirTemp("", "ghost-install-geth")
		if gethErr != nil {
			return
		}
		goTool, err := exec.LookPath("go")
		if err != nil {
			goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
		}
		gethPath = filepath.Join(gethDir, "geth")
		out, err := exec.Command(goTool, "build", "-o", gethPath, "github.com/ethereum/go-ethereum/cmd/geth").CombinedOutput()
		if err != nil {
			gethErr = fmt.Errorf("building geth: %v\n%s", err, out)
		}
	})
	if gethErr != nil {
		t.Fatal(gethErr)
	}
	return gethPath
}

// requireOpenSSL fails the test unless an OpenSSL 3 is on the PATH, as the
// script needs.
func requireOpenSSL(t *testing.T) {
	t.Helper()
	out, err := exec.Command("openssl", "version").Output()
	if err != nil || !regexp.MustCompile(`^OpenSSL [3-9]\.`).Match(out) {
		t.Fatalf("the installer tests need OpenSSL 3 or later as openssl; have %q (%v)", out, err)
	}
}

// signer is an ed25519 test release key, made for one test.
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

func (s *signer) sign(archive []byte) []byte {
	return ed25519.Sign(s.priv, archive)
}

func (s *signer) pem(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(s.pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// pinnedKey returns the key block pinned in the script and where it starts.
func pinnedKey(t *testing.T, script string) (string, int) {
	t.Helper()
	if strings.Count(script, keyBegin) != 1 || strings.Count(script, keyEnd) != 1 {
		t.Fatal("install.sh does not pin exactly one public key")
	}
	start := strings.Index(script, keyBegin)
	end := strings.Index(script, keyEnd) + len(keyEnd)
	if end < start {
		t.Fatal("install.sh's pinned key ends before it begins")
	}
	return script[start:end], start
}

// writeScript writes a copy of install.sh pinning the key of s and returns its
// path.
func writeScript(t *testing.T, s *signer) string {
	t.Helper()
	blob, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(blob)
	block, start := pinnedKey(t, script)
	script = script[:start] + s.pem(t) + script[start+len(block):]
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// archive is the content of a release archive: file names and contents, all
// written executable.
type archive map[string][]byte

func (a archive) tarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range a {
		hdr := &tar.Header{Name: name, Mode: 0755, Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: time.Unix(1790000000, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
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

// releaseServer serves one release over TLS the way GitHub does: the latest
// download URL redirects to the release's own.
type releaseServer struct {
	*httptest.Server
	caFile string

	mu     sync.Mutex
	served []string
}

func serveRelease(t *testing.T, archive, sig []byte) *releaseServer {
	t.Helper()
	files := map[string][]byte{asset: archive, asset + ".sig": sig}
	rs := &releaseServer{}
	rs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/latest/download/"); ok {
			http.Redirect(w, r, "/download/v0.0.0-test/"+name, http.StatusFound)
			return
		}
		name, ok := strings.CutPrefix(r.URL.Path, "/download/v0.0.0-test/")
		content, found := files[name]
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
		rs.mu.Lock()
		rs.served = append(rs.served, name)
		rs.mu.Unlock()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Write(content)
	}))
	t.Cleanup(rs.Close)
	rs.caFile = filepath.Join(t.TempDir(), "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rs.Certificate().Raw})
	if err := os.WriteFile(rs.caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	return rs
}

func (rs *releaseServer) servedFiles() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]string(nil), rs.served...)
}

// The stub service managers. Each records its calls in $STUB_DIR/calls. The
// systemd stub stands in for a user session's systemd: it starts the unit's
// ExecStart line as the unit would, and records the process ID.
const (
	stubSystemctl = `#!/bin/sh
echo "systemctl $*" >>"$STUB_DIR/calls"
case "$*" in
"--user show-environment" | "--user daemon-reload" | "--user enable ghost-node.service")
	exit 0
	;;
"--user restart ghost-node.service")
	line=$(sed -n 's/^ExecStart=//p' "$HOME/.config/systemd/user/ghost-node.service")
	eval "set -- $line"
	nohup "$@" >"$STUB_DIR/service.log" 2>&1 </dev/null &
	echo "$!" >"$STUB_DIR/service.pid"
	exit 0
	;;
esac
echo "unexpected systemctl call: $*" >&2
exit 1
`
	stubNoSystemd = `#!/bin/sh
echo "systemctl $*" >>"$STUB_DIR/calls"
echo "Failed to connect to bus: No medium found" >&2
exit 1
`
	stubLoginctl = `#!/bin/sh
echo "loginctl $*" >>"$STUB_DIR/calls"
exit 0
`
)

// installEnv is the computer the script runs on: an empty home, an empty
// temporary directory, and stub service managers ahead of the PATH.
type installEnv struct {
	home, tmp, stubs string
}

func newInstallEnv(t *testing.T, systemctl string) *installEnv {
	t.Helper()
	// Short paths: the node's IPC socket lives in the home, and socket paths
	// are limited to about a hundred bytes.
	root, err := os.MkdirTemp("", "gi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	env := &installEnv{home: filepath.Join(root, "h"), tmp: filepath.Join(root, "t"), stubs: filepath.Join(root, "s")}
	for _, dir := range []string{env.home, env.tmp, env.stubs} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, script := range map[string]string{"systemctl": systemctl, "loginctl": stubLoginctl} {
		if err := os.WriteFile(filepath.Join(env.stubs, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

// run runs the script against the release server and returns its output.
func (env *installEnv) run(t *testing.T, script string, rs *releaseServer, trustServer bool) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", script)
	cmd.Env = []string{
		"HOME=" + env.home,
		"TMPDIR=" + env.tmp,
		"PATH=" + env.stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_DIR=" + env.stubs,
		"GHOST_RELEASE_URL=" + rs.URL + "/latest/download",
	}
	if trustServer {
		cmd.Env = append(cmd.Env, "GHOST_INSTALL_CA_FILE="+rs.caFile)
	}
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	t.Logf("install.sh output:\n%s", out)
	return string(out), err
}

func (env *installEnv) calls(t *testing.T) string {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(env.stubs, "calls"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(blob)
}

// stopNodeAtCleanup stops, when the test ends, the node whose process ID the
// file pidFile holds by then.
func stopNodeAtCleanup(t *testing.T, pidFile string) {
	t.Cleanup(func() {
		blob, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(blob)))
		if err != nil || pid <= 0 {
			return
		}
		syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 300 && syscall.Kill(pid, 0) == nil; i++ {
			time.Sleep(100 * time.Millisecond)
		}
		syscall.Kill(pid, syscall.SIGKILL)
	})
}

// entries returns the names in dir.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(blob)
}

// internalNetRelease is a release of the node built from this checkout, for
// the internal test network.
func internalNetRelease(t *testing.T) (archive, string) {
	t.Helper()
	geth := builtGeth(t)
	bin, err := os.ReadFile(geth)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := json.Marshal(ghost.InternalNetGenesis())
	if err != nil {
		t.Fatal(err)
	}
	return archive{"geth": bin, "genesis.json": genesis}, geth
}

var etherbaseLine = regexp.MustCompile(`(?m)^Etherbase = "(0x[0-9a-fA-F]{40})"$`)

// checkInstalledAndMining checks the installed files, then waits for the
// running node to mine a block of the internal network to the address of its
// config.
func checkInstalledAndMining(t *testing.T, env *installEnv, geth string) {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	if fileHash(t, filepath.Join(base, "bin", "geth")) != fileHash(t, geth) {
		t.Fatal("the installed geth is not the released one")
	}
	config, err := os.ReadFile(filepath.Join(base, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	m := etherbaseLine.FindSubmatch(config)
	if m == nil {
		t.Fatalf("the config has no mining address:\n%s", config)
	}
	address := common.HexToAddress(string(m[1]))
	if !strings.Contains(string(config), fmt.Sprintf("DataDir = %q", filepath.Join(base, "data"))) {
		t.Fatalf("the config does not name the data directory:\n%s", config)
	}
	keys := entries(t, filepath.Join(base, "data", "keystore"))
	if len(keys) != 1 || !strings.HasSuffix(keys[0], strings.ToLower(address.Hex()[2:])) {
		t.Fatalf("the keystore holds %v, not the one key of the mining address %s", keys, address.Hex())
	}
	info, err := os.Stat(filepath.Join(base, "password"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || info.Size() == 0 {
		t.Fatalf("the key's password file has mode %v and %d bytes", info.Mode().Perm(), info.Size())
	}
	if left := entries(t, env.tmp); len(left) != 0 {
		t.Fatalf("the installer left %v in the temporary directory", left)
	}

	client, err := rpc.Dial(filepath.Join(base, "data", "geth.ipc"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var chainID hexutil.Big
	if err := client.Call(&chainID, "eth_chainId"); err != nil {
		t.Fatal(err)
	}
	if chainID.ToInt().Uint64() != ghost.InternalNetChainID {
		t.Fatalf("the node runs chain %v, not the internal network %d", chainID.ToInt(), ghost.InternalNetChainID)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var head hexutil.Uint64
		if err := client.Call(&head, "eth_blockNumber"); err != nil {
			t.Fatal(err)
		}
		if head > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the node mined no block in 3 minutes")
		}
		time.Sleep(200 * time.Millisecond)
	}
	var block struct {
		Miner common.Address `json:"miner"`
	}
	if err := client.Call(&block, "eth_getBlockByNumber", "0x1", false); err != nil {
		t.Fatal(err)
	}
	if block.Miner != address {
		t.Fatalf("block 1 was mined to %s, not to the config's address %s", block.Miner.Hex(), address.Hex())
	}
}

// TestInstallScriptInstallsAndStarts installs a release for the internal
// network from a local release server, and checks that the installed node
// runs and mines to the generated address: once as a systemd user service (a
// stub that runs the unit's command), and once on a computer without systemd
// user services, where the script starts the node itself.
func TestInstallScriptInstallsAndStarts(t *testing.T) {
	requireOpenSSL(t)
	release, geth := internalNetRelease(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, blob, key.sign(blob))
	script := writeScript(t, key)

	t.Run("systemd", func(t *testing.T) {
		env := newInstallEnv(t, stubSystemctl)
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		if _, err := env.run(t, script, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		unit, err := os.ReadFile(filepath.Join(env.home, ".config", "systemd", "user", "ghost-node.service"))
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(env.home, ".ghost-node")
		execStart := fmt.Sprintf("ExecStart=%q --config %q --mine\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
		if !strings.Contains(string(unit), execStart) || !strings.Contains(string(unit), "WantedBy=default.target") {
			t.Fatalf("the unit does not run the node mining at login:\n%s", unit)
		}
		calls := env.calls(t)
		for _, want := range []string{"systemctl --user enable ghost-node.service\n", "systemctl --user restart ghost-node.service\n", "loginctl enable-linger"} {
			if !strings.Contains(calls, want) {
				t.Fatalf("no call %q; the calls were:\n%s", want, calls)
			}
		}
		checkInstalledAndMining(t, env, geth)
	})

	t.Run("no systemd user services", func(t *testing.T) {
		env := newInstallEnv(t, stubNoSystemd)
		stopNodeAtCleanup(t, filepath.Join(env.home, ".ghost-node", "node.pid"))
		if _, err := env.run(t, script, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		if calls := env.calls(t); strings.Contains(calls, "loginctl") || strings.Contains(calls, "restart") {
			t.Fatalf("the script used systemd without a user session:\n%s", calls)
		}
		checkInstalledAndMining(t, env, geth)
	})
}

// fakeGeth is a geth that, run at all, leaves the file marker.
func fakeGeth(marker string) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\necho ran >%q\n", marker))
}

// checkRefused checks that the script failed with the message want and left
// nothing behind: nothing in the home or the temporary directory, no service
// call, and the archive's geth never run.
func checkRefused(t *testing.T, env *installEnv, out string, err error, want, marker string) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("install.sh did not fail: %v", err)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("install.sh did not say %q", want)
	}
	if left := entries(t, env.home); len(left) != 0 {
		t.Fatalf("a refused install left %v in the home", left)
	}
	if left := entries(t, env.tmp); len(left) != 0 {
		t.Fatalf("a refused install left %v in the temporary directory", left)
	}
	if calls := env.calls(t); calls != "" {
		t.Fatalf("a refused install called the service manager:\n%s", calls)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused install ran the archive's geth (%v)", err)
	}
}

const refusedSignature = "does not match the release key; refusing to install. Nothing was installed."

// TestInstallScriptRefusesTamperedArchive serves an archive other than the
// one the release key signed, with the signature of the signed one.
func TestInstallScriptRefusesTamperedArchive(t *testing.T) {
	requireOpenSSL(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	signed := archive{"geth": []byte("#!/bin/sh\nexit 0\n")}.tarGz(t)
	tampered := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, tampered, key.sign(signed))
	env := newInstallEnv(t, stubSystemctl)

	out, err := env.run(t, writeScript(t, key), rs, true)
	checkRefused(t, env, out, err, refusedSignature, marker)
	if served := rs.servedFiles(); len(served) != 2 {
		t.Fatalf("the script downloaded %v, not the archive and its signature", served)
	}
}

// TestInstallScriptRefusesWrongSignature serves an archive signed by a key
// other than the pinned one.
func TestInstallScriptRefusesWrongSignature(t *testing.T) {
	requireOpenSSL(t)
	pinned, other := newSigner(t), newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	env := newInstallEnv(t, stubSystemctl)
	script := writeScript(t, pinned)

	t.Run("signed by another key", func(t *testing.T) {
		rs := serveRelease(t, blob, other.sign(blob))
		out, err := env.run(t, script, rs, true)
		checkRefused(t, env, out, err, refusedSignature, marker)
	})
	t.Run("not a signature", func(t *testing.T) {
		rs := serveRelease(t, blob, []byte("not a signature\n"))
		out, err := env.run(t, script, rs, true)
		checkRefused(t, env, out, err, "is not a 64-byte ed25519 signature; refusing to install.", marker)
	})
}

// TestInstallScriptRefusesUntrustedServer runs the script against a release
// server whose certificate it has no reason to trust: it must not download.
func TestInstallScriptRefusesUntrustedServer(t *testing.T) {
	requireOpenSSL(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, blob, key.sign(blob))
	env := newInstallEnv(t, stubSystemctl)

	out, err := env.run(t, writeScript(t, key), rs, false)
	checkRefused(t, env, out, err, "could not download", marker)
	if served := rs.servedFiles(); len(served) != 0 {
		t.Fatalf("the script downloaded %v from an untrusted server", served)
	}
}

// TestInstallScriptPinsTheKeyFile checks that install.sh pins the key of the
// .pub file next to it, an ed25519 public key, so that the key is swapped in
// that file and the same lines of the script.
func TestInstallScriptPinsTheKeyFile(t *testing.T) {
	files, err := filepath.Glob("*.pub")
	if err != nil || len(files) != 1 {
		t.Fatalf("want one .pub key file next to install.sh, have %v (%v)", files, err)
	}
	keyFile, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	pinned, _ := pinnedKey(t, string(script))
	if pinned != string(keyFile) {
		t.Fatalf("install.sh pins\n%s\nbut %s holds\n%s", pinned, files[0], keyFile)
	}
	block, _ := pem.Decode(keyFile)
	if block == nil {
		t.Fatalf("%s is not PEM", files[0])
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("%s holds a %T, not an ed25519 key", files[0], pub)
	}
}
