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
// in a temporary directory, a PATH holding only the stock tools a Mac or a
// Linux computer has, and a copy of the script that pins a test release key
// and the hash of a ghost-verify the test builds. macOS is a stub uname and
// launchctl on this Linux computer.
package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
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
	"sync/atomic"
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

// The web app origins the node's HTTP RPC must allow.
var webOrigins = []string{"https://ghost-webapp-alpha.vercel.app", "https://ghost-wallet-nine.vercel.app"}

// assetName and verifierName are the release's archive and checker for os on
// this computer's processor.
func assetName(os string) string    { return fmt.Sprintf("ghost-node-%s-%s.tar.gz", os, runtime.GOARCH) }
func verifierName(os string) string { return fmt.Sprintf("ghost-verify-%s-%s", os, runtime.GOARCH) }

var (
	buildOnce   sync.Once
	buildDir    string
	gethPath    string
	verifierBin []byte
	buildErr    error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// build builds the node and the static ghost-verify once for all tests.
func build(t *testing.T) {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "ghost-install-build")
		if buildErr != nil {
			return
		}
		goTool, err := exec.LookPath("go")
		if err != nil {
			goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
		}
		gethPath = filepath.Join(buildDir, "geth")
		out, err := exec.Command(goTool, "build", "-o", gethPath, "github.com/ethereum/go-ethereum/cmd/geth").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("building geth: %v\n%s", err, out)
			return
		}
		verifierPath := filepath.Join(buildDir, "ghost-verify")
		cmd := exec.Command(goTool, "build", "-trimpath", "-o", verifierPath, "github.com/ethereum/go-ethereum/install/verify")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building ghost-verify: %v\n%s", err, out)
			return
		}
		verifierBin, buildErr = os.ReadFile(verifierPath)
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

func builtGeth(t *testing.T) string {
	build(t)
	return gethPath
}

func builtVerifier(t *testing.T) []byte {
	build(t)
	return verifierBin
}

func sha256Hex(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
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

// hashLine matches a line of the script's table of ghost-verify hashes.
var hashLine = regexp.MustCompile(`(?m)^(linux|darwin)-(amd64|arm64) ([0-9a-f]{64})$`)

// pinnedHashes returns the script's table of ghost-verify hashes.
func pinnedHashes(t *testing.T, script string) map[string]string {
	t.Helper()
	table := make(map[string]string)
	for _, m := range hashLine.FindAllStringSubmatch(script, -1) {
		table[m[1]+"-"+m[2]] = m[3]
	}
	if len(table) != 4 {
		t.Fatalf("install.sh pins %d ghost-verify hashes, not one for each of linux and darwin on amd64 and arm64", len(table))
	}
	return table
}

// writeScript writes a copy of install.sh pinning the key of s and, unless
// verifierHash is empty, verifierHash as the hash of every platform's
// ghost-verify. It returns the copy's path.
func writeScript(t *testing.T, s *signer, verifierHash string) string {
	t.Helper()
	blob, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(blob)
	block, start := pinnedKey(t, script)
	script = script[:start] + s.pem(t) + script[start+len(block):]
	pinnedHashes(t, script)
	if verifierHash != "" {
		script = hashLine.ReplaceAllString(script, "${1}-${2} "+verifierHash)
	}
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

// firstTag is the tag of the release a release server serves first.
const firstTag = "v0.0.0-test"

// releaseServer serves releases over TLS the way GitHub does: each release's
// files under its own download URL, and the latest download URL redirecting
// to the latest release's. Its files can be swapped, and a newer release
// published.
type releaseServer struct {
	*httptest.Server
	caFile string
	os     string

	mu       sync.Mutex
	latest   string
	releases map[string]map[string][]byte
	served   []string // the names of the files served
	paths    []string // the tag and name of the files served
}

// serveRelease serves the archive for os, its signature, and as the release's
// ghost-verify for os the checker verifier.
func serveRelease(t *testing.T, os_ string, archive, sig, verifier []byte) *releaseServer {
	t.Helper()
	rs := &releaseServer{os: os_, latest: firstTag, releases: map[string]map[string][]byte{firstTag: {}}}
	rs.setRelease(archive, sig)
	rs.setVerifier(verifier)
	rs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/latest/download/"); ok {
			rs.mu.Lock()
			tag := rs.latest
			rs.mu.Unlock()
			http.Redirect(w, r, "/download/"+tag+"/"+name, http.StatusFound)
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/download/")
		tag, name, cut := strings.Cut(rest, "/")
		ok = ok && cut
		rs.mu.Lock()
		content, found := rs.releases[tag][name]
		if ok && found {
			rs.served = append(rs.served, name)
			rs.paths = append(rs.paths, tag+"/"+name)
		}
		rs.mu.Unlock()
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
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

// setFile serves content as the latest release's file name, or with nil
// content stops serving it.
func (rs *releaseServer) setFile(name string, content []byte) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if content == nil {
		delete(rs.releases[rs.latest], name)
		return
	}
	rs.releases[rs.latest][name] = content
}

func (rs *releaseServer) setRelease(archive, sig []byte) {
	rs.setFile(assetName(rs.os), archive)
	rs.setFile(assetName(rs.os)+".sig", sig)
}

func (rs *releaseServer) setVerifier(verifier []byte) {
	rs.setFile(verifierName(rs.os), verifier)
}

// setInstaller serves script as the latest release's install.sh, and sig as
// its signature.
func (rs *releaseServer) setInstaller(script, sig []byte) {
	rs.setFile("install.sh", script)
	rs.setFile("install.sh.sig", sig)
}

// publish publishes a new, empty release tag and makes it the latest.
func (rs *releaseServer) publish(tag string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.releases[tag] = make(map[string][]byte)
	rs.latest = tag
}

// downloadURL is the download URL of the release tag.
func (rs *releaseServer) downloadURL(tag string) string {
	return rs.URL + "/download/" + tag
}

func (rs *releaseServer) servedFiles() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]string(nil), rs.served...)
}

func (rs *releaseServer) servedPaths() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]string(nil), rs.paths...)
}

// checkServedUpdate checks that the files served since the first skip were
// those of an update: the checker of the release tag the updater pins, the
// newest release's install.sh and its signature, then the newest release's
// checker, archive and signature.
func checkServedUpdate(t *testing.T, rs *releaseServer, skip int, pinned, newest string) {
	t.Helper()
	served := rs.servedPaths()[skip:]
	want := []string{
		pinned + "/" + verifierName(rs.os),
		newest + "/install.sh",
		newest + "/install.sh.sig",
		newest + "/" + verifierName(rs.os),
		newest + "/" + assetName(rs.os),
		newest + "/" + assetName(rs.os) + ".sig",
	}
	if strings.Join(served, " ") != strings.Join(want, " ") {
		t.Fatalf("the update downloaded %v, not %v", served, want)
	}
}

// serveInstaller serves the script at path, signed by key, as the latest
// release's install.sh.
func serveInstaller(t *testing.T, rs *releaseServer, key *signer, path string) {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rs.setInstaller(blob, key.sign(blob))
}

// pinRelease makes the script at path download from url by default instead
// of the latest release, as the release does to the copy it publishes.
func pinRelease(t *testing.T, path, url string) {
	t.Helper()
	editScript(t, path, func(s string) string {
		line := "release_url=${GHOST_RELEASE_URL:-" + latestURL + "}\n"
		if strings.Count(s, line) != 1 {
			t.Fatalf("install.sh has no line %q", line)
		}
		return strings.Replace(s, line, "release_url=${GHOST_RELEASE_URL:-"+url+"}\n", 1)
	})
}

// checkServedRelease checks that the files served since the first skip were
// the checker, the archive and its signature, in that order.
func checkServedRelease(t *testing.T, rs *releaseServer, skip int) {
	t.Helper()
	served := rs.servedFiles()[skip:]
	want := []string{verifierName(rs.os), assetName(rs.os), assetName(rs.os) + ".sig"}
	if strings.Join(served, " ") != strings.Join(want, " ") {
		t.Fatalf("the script downloaded %v, not %v", served, want)
	}
}

// The stub service managers. Each records its calls in $STUB_DIR/calls. The
// systemd stub stands in for a user session's systemd, and the launchd stub
// for a Mac's launchd: each starts the node's command as the service would,
// stopping the one it started before, and records the process ID.
const stubStopNode = `
stop_node() {
	[ -f "$STUB_DIR/service.pid" ] || return 0
	pid=$(cat "$STUB_DIR/service.pid")
	rm -f "$STUB_DIR/service.pid"
	kill "$pid" 2>/dev/null || return 0
	i=0
	while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 300 ]; do
		case "$(ps -o stat= -p "$pid" 2>/dev/null)" in
		Z*) break ;;
		esac
		sleep 0.1
		i=$((i + 1))
	done
}
`

const (
	stubSystemctl = `#!/bin/sh
echo "systemctl $*" >>"$STUB_DIR/calls"
` + stubStopNode + `
case "$*" in
"--user show-environment" | "--user daemon-reload" | "--user enable ghost-node.service" | \
	"--user enable --now ghost-node-update.timer" | "--user disable --now ghost-node-update.timer")
	exit 0
	;;
"--user restart ghost-node.service")
	stop_node
	line=$(sed -n 's/^ExecStart=//p' "$HOME/.config/systemd/user/ghost-node.service")
	eval "set -- $line"
	nohup "$@" >>"$STUB_DIR/service.log" 2>&1 </dev/null &
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
	stubLaunchctl = `#!/bin/sh
echo "launchctl $*" >>"$STUB_DIR/calls"
` + stubStopNode + `
node="gui/$(id -u)/com.ghostcoin.node"
start_node() {
	plist=$1
	set --
	for arg in $(sed -n '/<key>ProgramArguments<\/key>/,/<\/array>/s/.*<string>\(.*\)<\/string>.*/\1/p' "$plist"); do
		set -- "$@" "$arg"
	done
	nohup "$@" >>"$STUB_DIR/service.log" 2>&1 </dev/null &
	echo "$!" >"$STUB_DIR/service.pid"
}
# Like launchd, the stub refuses to bootstrap an agent that is disabled: one
# with a file disabled.<label> in STUB_DIR. enable clears it, unless the file
# enable-refused is there too.
refuse_disabled() {
	[ -f "$STUB_DIR/disabled.$1" ] || return 0
	echo "Bootstrap failed: 5: Input/output error" >&2
	exit 5
}
case "$1 $2" in
"bootout $node")
	stop_node
	exit 0
	;;
"bootout $node.update")
	exit 0
	;;
"enable $node" | "enable $node.update")
	[ -f "$STUB_DIR/enable-refused" ] || rm -f "$STUB_DIR/disabled.${2##*/}"
	exit 0
	;;
"print-disabled gui/$(id -u)")
	echo "disabled services = {"
	for f in "$STUB_DIR"/disabled.*; do
		[ -f "$f" ] && printf '\t"%s" => disabled\n' "${f##*/disabled.}"
	done
	echo "}"
	exit 0
	;;
"bootstrap gui/$(id -u)")
	case "$3" in
	*/Library/LaunchAgents/com.ghostcoin.node.plist)
		refuse_disabled com.ghostcoin.node
		start_node "$3"
		exit 0
		;;
	*/Library/LaunchAgents/com.ghostcoin.node.update.plist)
		refuse_disabled com.ghostcoin.node.update
		exit 0
		;;
	esac
	;;
"kickstart -k")
	if [ "$3" = "$node" ]; then
		stop_node
		start_node "$HOME/Library/LaunchAgents/com.ghostcoin.node.plist"
		exit 0
	fi
	;;
esac
echo "unexpected launchctl call: $*" >&2
exit 1
`
	// stubShasum is the shasum of a Mac, for SHA-256 only.
	stubShasum = `#!/bin/sh
echo "shasum $*" >>"$STUB_DIR/shasum.calls"
[ "$1" = -a ] && [ "$2" = 256 ] || {
	echo "stub shasum: only -a 256" >&2
	exit 1
}
shift 2
exec %q "$@"
`
	// stubLibreSSL is the openssl of a Mac, a LibreSSL that cannot verify
	// an ed25519 signature: it does nothing but say what it is.
	stubLibreSSL = `#!/bin/sh
echo "openssl $*" >>"$STUB_DIR/openssl.calls"
if [ "$1" = version ]; then
	echo "LibreSSL 3.3.6"
	exit 0
fi
echo "stub LibreSSL: $1 is not supported" >&2
exit 1
`
	stubUnameDarwin = `#!/bin/sh
case "$1" in
-m) echo %s ;;
*) echo Darwin ;;
esac
`
)

// The stock tools the script and the stubs may use. A Mac has them all, with
// shasum in place of sha256sum.
var stockTools = []string{
	"sh", "cat", "cp", "mv", "rm", "mkdir", "chmod", "sed", "tr", "head", "tail", "wc", "mktemp",
	"grep", "od", "tar", "gzip", "curl", "id", "ps", "sleep", "nohup", "basename", "touch", "find", "kill",
}

// envOptions describes the computer the script runs on.
type envOptions struct {
	systemctl string // the systemctl stub, or none
	darwin    bool   // a Mac: uname says Darwin, and launchctl is a stub
	stockMac  bool   // a Mac's tools: shasum, no sha256sum, and a LibreSSL openssl
	// cpus, when not 0, is the number of logical cores the computer has: a
	// stub getconf says so on Linux, a stub sysctl on a Mac. Without, the
	// installer finds no tool that tells.
	cpus int
}

// The stub tools that tell the number of logical cores, as Linux's getconf
// and a Mac's sysctl do.
const (
	stubGetconf = `#!/bin/sh
echo "getconf $*" >>"$STUB_DIR/cpus.calls"
[ "$*" = _NPROCESSORS_ONLN ] || exit 1
echo %d
`
	stubSysctl = `#!/bin/sh
echo "sysctl $*" >>"$STUB_DIR/cpus.calls"
[ "$*" = "-n hw.logicalcpu" ] || exit 1
echo %d
`
)

// installEnv is the computer the script runs on: an empty home, an empty
// temporary directory, a PATH of stock tools and stub service managers, and
// a free port for the node's HTTP RPC.
type installEnv struct {
	home, tmp, stubs string
	httpPort         int
}

func newInstallEnv(t *testing.T, opts envOptions) *installEnv {
	t.Helper()
	// Short paths: the node's IPC socket lives in the home, and socket paths
	// are limited to about a hundred bytes.
	root, err := os.MkdirTemp("", "gi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	env := &installEnv{home: filepath.Join(root, "h"), tmp: filepath.Join(root, "t"), stubs: filepath.Join(root, "s"), httpPort: freePort(t)}
	for _, dir := range []string{env.home, env.tmp, env.stubs} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	tools := append([]string(nil), stockTools...)
	stubs := make(map[string]string)
	if opts.systemctl != "" {
		stubs["systemctl"] = opts.systemctl
		stubs["loginctl"] = stubLoginctl
	}
	if opts.darwin {
		machine := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
		stubs["uname"] = fmt.Sprintf(stubUnameDarwin, machine)
		stubs["launchctl"] = stubLaunchctl
		if opts.cpus != 0 {
			stubs["sysctl"] = fmt.Sprintf(stubSysctl, opts.cpus)
		}
	} else {
		tools = append(tools, "uname")
		if opts.cpus != 0 {
			stubs["getconf"] = fmt.Sprintf(stubGetconf, opts.cpus)
		}
	}
	if opts.stockMac {
		sha256sum, err := exec.LookPath("sha256sum")
		if err != nil {
			t.Fatal(err)
		}
		stubs["shasum"] = fmt.Sprintf(stubShasum, sha256sum)
		stubs["openssl"] = stubLibreSSL
	} else {
		tools = append(tools, "sha256sum")
	}
	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("the installer tests need %s: %v", tool, err)
		}
		if err := os.Symlink(path, filepath.Join(env.stubs, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, script := range stubs {
		if err := os.WriteFile(filepath.Join(env.stubs, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// runScript runs the script at path against the release server and returns
// its output.
func (env *installEnv) runScript(t *testing.T, path string, rs *releaseServer, trustServer bool, extraEnv ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", path)
	cmd.Env = []string{
		"HOME=" + env.home,
		"TMPDIR=" + env.tmp,
		"PATH=" + env.stubs,
		"STUB_DIR=" + env.stubs,
		"GHOST_RELEASE_URL=" + rs.URL + "/latest/download",
		"GHOST_LATEST_URL=" + rs.URL + "/latest/download",
		"GHOST_HTTP_PORT=" + strconv.Itoa(env.httpPort),
	}
	if trustServer {
		cmd.Env = append(cmd.Env, "GHOST_INSTALL_CA_FILE="+rs.caFile)
	}
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	t.Logf("%s output:\n%s", filepath.Base(path), out)
	return string(out), err
}

// run runs the installer.
func (env *installEnv) run(t *testing.T, script string, rs *releaseServer, trustServer bool, extraEnv ...string) (string, error) {
	t.Helper()
	return env.runScript(t, script, rs, trustServer, extraEnv...)
}

// update runs the update script the installer installed. An empty
// GHOST_RELEASE_URL= in extraEnv leaves the script its pinned release.
func (env *installEnv) update(t *testing.T, rs *releaseServer, extraEnv ...string) (string, error) {
	t.Helper()
	return env.runScript(t, filepath.Join(env.home, ".ghost-node", "update"), rs, true, extraEnv...)
}

func (env *installEnv) readStub(t *testing.T, name string) string {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(env.stubs, name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(blob)
}

func (env *installEnv) calls(t *testing.T) string {
	t.Helper()
	return env.readStub(t, "calls")
}

// servicePID returns the process ID of the node the stub service manager
// started last.
func (env *installEnv) servicePID(t *testing.T) int {
	t.Helper()
	pid, err := strconv.Atoi(strings.TrimSpace(env.readStub(t, "service.pid")))
	if err != nil {
		t.Fatalf("the service manager started no node: %v", err)
	}
	return pid
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
		for i := 0; i < 300 && running(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		syscall.Kill(pid, syscall.SIGKILL)
	})
}

// running reports whether the process pid runs, a zombie not counting.
func running(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(stat, ')')
	return i >= 0 && i+2 < len(stat) && stat[i+2] != 'Z'
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
// the internal test network: an archive that still holds a genesis.json, so
// the node mines alone.
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

// configAddress returns the mining address of the installed config.
func configAddress(t *testing.T, env *installEnv) common.Address {
	t.Helper()
	config, err := os.ReadFile(filepath.Join(env.home, ".ghost-node", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	m := etherbaseLine.FindSubmatch(config)
	if m == nil {
		t.Fatalf("the config has no mining address:\n%s", config)
	}
	return common.HexToAddress(string(m[1]))
}

// checkInstalledAndMining checks the installed files, then waits for the
// running node to mine a block of the internal network to the address of its
// config, and checks that the web apps, and only they, can reach its HTTP
// RPC.
func checkInstalledAndMining(t *testing.T, env *installEnv, geth string, out string) {
	t.Helper()
	checkInstalledAndMiningTo(t, env, geth, out, "")
}

// checkInstalledAndMiningTo checks as checkInstalledAndMining does. With
// mineTo, a wallet address given as GHOST_MINE_TO, the config must name it as
// Etherbase, exactly as given, and no mining key or password must have been
// made; without, the config must name a newly made key.
func checkInstalledAndMiningTo(t *testing.T, env *installEnv, geth string, out string, mineTo string) {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	if fileHash(t, filepath.Join(base, "bin", "geth")) != fileHash(t, geth) {
		t.Fatal("the installed geth is not the released one")
	}
	config, err := os.ReadFile(filepath.Join(base, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	address := configAddress(t, env)
	for _, want := range []string{
		fmt.Sprintf("DataDir = %q\n", filepath.Join(base, "data")),
		"HTTPHost = \"127.0.0.1\"\n",
		fmt.Sprintf("HTTPPort = %d\n", env.httpPort),
		"HTTPModules = [\"eth\", \"net\", \"web3\"]\n",
		fmt.Sprintf("HTTPCors = [%q, %q]\n", webOrigins[0], webOrigins[1]),
	} {
		if !strings.Contains(string(config), want) {
			t.Fatalf("the config has no line %q:\n%s", want, config)
		}
	}
	printed := address.Hex()
	if mineTo != "" {
		printed = mineTo
		if !strings.Contains(string(config), "\nEtherbase = \""+mineTo+"\"\n") {
			t.Fatalf("the config does not mine to GHOST_MINE_TO's %s:\n%s", mineTo, config)
		}
		checkNoMiningKey(t, env)
	} else {
		keys := entries(t, filepath.Join(base, "data", "keystore"))
		if len(keys) != 1 || !strings.HasSuffix(keys[0], strings.ToLower(address.Hex()[2:])) {
			t.Fatalf("the keystore holds %v, not the one key of the mining address %s", keys, address.Hex())
		}
		info, err := os.Stat(filepath.Join(base, "password"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 || info.Size() != 65 {
			t.Fatalf("the key's password file has mode %v and %d bytes", info.Mode().Perm(), info.Size())
		}
	}
	updater, err := os.Stat(filepath.Join(base, "update"))
	if err != nil {
		t.Fatal(err)
	}
	if updater.Mode().Perm() != 0700 {
		t.Fatalf("the update script has mode %v", updater.Mode().Perm())
	}
	if left := entries(t, env.tmp); len(left) != 0 {
		t.Fatalf("the installer left %v in the temporary directory", left)
	}
	if !strings.Contains(out, "mining to: "+printed+"\n") || !strings.Contains(out, "check its status with: ") {
		t.Fatal("the installer did not print the mining address and how to check on the node")
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

	for _, origin := range webOrigins {
		allowed, body := httpCall(t, env.httpPort, origin)
		if allowed != origin {
			t.Fatalf("the HTTP RPC allows the origin %q, not the web app's %q", allowed, origin)
		}
		if want := fmt.Sprintf(`"result":"%#x"`, ghost.InternalNetChainID); !strings.Contains(body, want) {
			t.Fatalf("eth_chainId over HTTP gave %s", body)
		}
	}
	if allowed, _ := httpCall(t, env.httpPort, "https://example.com"); allowed != "" {
		t.Fatalf("the HTTP RPC allows the origin https://example.com (%q)", allowed)
	}
}

// httpCall calls eth_chainId on the node's HTTP RPC from a page of origin and
// returns the origin the node allows and the body.
func httpCall(t *testing.T, port int, origin string) (string, string) {
	t.Helper()
	req, err := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d", port), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the node's HTTP RPC: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Header.Get("Access-Control-Allow-Origin"), string(body)
}

// TestInstallScriptInstallsAndStarts installs a release for the internal
// network from a local release server, and checks that the installed node
// runs and mines to the generated address: once as a systemd user service (a
// stub that runs the unit's command) with its daily update timer, once
// without the timer, and once on a computer without systemd user services,
// where the script starts the node itself.
func TestInstallScriptInstallsAndStarts(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	unitDir := func(env *installEnv) string { return filepath.Join(env.home, ".config", "systemd", "user") }

	t.Run("systemd", func(t *testing.T) {
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 6})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		out, err := env.run(t, script, rs, true)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		unit, err := os.ReadFile(filepath.Join(unitDir(env), "ghost-node.service"))
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(env.home, ".ghost-node")
		execStart := fmt.Sprintf("ExecStart=%q --config %q --mine --miner.threads 3\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
		if !strings.Contains(string(unit), execStart) || !strings.Contains(string(unit), "WantedBy=default.target") {
			t.Fatalf("the unit does not run the node mining at login:\n%s", unit)
		}
		updateUnit, err := os.ReadFile(filepath.Join(unitDir(env), "ghost-node-update.service"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(updateUnit), fmt.Sprintf("ExecStart=%q\n", filepath.Join(base, "update"))) {
			t.Fatalf("the update unit does not run the update script:\n%s", updateUnit)
		}
		timer, err := os.ReadFile(filepath.Join(unitDir(env), "ghost-node-update.timer"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(timer), "OnCalendar=daily\n") || !strings.Contains(string(timer), "WantedBy=timers.target") {
			t.Fatalf("the update timer does not run daily:\n%s", timer)
		}
		calls := env.calls(t)
		for _, want := range []string{"systemctl --user enable ghost-node.service\n", "systemctl --user restart ghost-node.service\n", "systemctl --user enable --now ghost-node-update.timer\n", "loginctl enable-linger"} {
			if !strings.Contains(calls, want) {
				t.Fatalf("no call %q; the calls were:\n%s", want, calls)
			}
		}
		checkServedRelease(t, rs, len(rs.servedFiles())-3)
		checkInstalledAndMining(t, env, geth, out)
	})

	t.Run("systemd without updates", func(t *testing.T) {
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		out, err := env.run(t, script, rs, true, "GHOST_NO_UPDATE=1")
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		if names := entries(t, unitDir(env)); len(names) != 1 || names[0] != "ghost-node.service" {
			t.Fatalf("with GHOST_NO_UPDATE=1 the units are %v", names)
		}
		if calls := env.calls(t); strings.Contains(calls, "timer") {
			t.Fatalf("with GHOST_NO_UPDATE=1 the script enabled a timer:\n%s", calls)
		}
		if _, err := os.Stat(filepath.Join(env.home, ".ghost-node", "update")); err != nil {
			t.Fatalf("with GHOST_NO_UPDATE=1 there is no update script to run by hand: %v", err)
		}
		if !strings.Contains(out, "automatic updates are off") {
			t.Fatal("the script did not say that automatic updates are off")
		}
	})

	t.Run("no systemd user services", func(t *testing.T) {
		env := newInstallEnv(t, envOptions{systemctl: stubNoSystemd})
		stopNodeAtCleanup(t, filepath.Join(env.home, ".ghost-node", "node.pid"))
		out, err := env.run(t, script, rs, true)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		if calls := env.calls(t); strings.Contains(calls, "loginctl") || strings.Contains(calls, "restart") {
			t.Fatalf("the script used systemd without a user session:\n%s", calls)
		}
		checkInstalledAndMining(t, env, geth, out)
	})
}

// fakeGeth is a geth that, run at all, leaves the file marker.
func fakeGeth(marker string) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\necho ran >%q\n", marker))
}

// fakeVerifier is a ghost-verify that accepts everything and leaves the file
// marker.
func fakeVerifier(marker string) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\necho ran >%q\nexit 0\n", marker))
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
	verifier := builtVerifier(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	signed := archive{"geth": []byte("#!/bin/sh\nexit 0\n")}.tarGz(t)
	tampered := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, "linux", tampered, key.sign(signed), verifier)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})

	out, err := env.run(t, writeScript(t, key, sha256Hex(verifier)), rs, true)
	checkRefused(t, env, out, err, refusedSignature, marker)
	checkServedRelease(t, rs, 0)
}

// TestInstallScriptRefusesWrongSignature serves an archive signed by a key
// other than the pinned one.
func TestInstallScriptRefusesWrongSignature(t *testing.T) {
	verifier := builtVerifier(t)
	pinned, other := newSigner(t), newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	script := writeScript(t, pinned, sha256Hex(verifier))

	t.Run("signed by another key", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, other.sign(blob), verifier)
		out, err := env.run(t, script, rs, true)
		checkRefused(t, env, out, err, refusedSignature, marker)
	})
	t.Run("not a signature", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, []byte("not a signature\n"), verifier)
		out, err := env.run(t, script, rs, true)
		checkRefused(t, env, out, err, "is not a 64-byte ed25519 signature; refusing to install.", marker)
	})
}

// TestInstallScriptRefusesUntrustedServer runs the script against a release
// server whose certificate it has no reason to trust: it must not download.
func TestInstallScriptRefusesUntrustedServer(t *testing.T) {
	verifier := builtVerifier(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})

	out, err := env.run(t, writeScript(t, key, sha256Hex(verifier)), rs, false)
	checkRefused(t, env, out, err, "could not download", marker)
	if served := rs.servedFiles(); len(served) != 0 {
		t.Fatalf("the script downloaded %v from an untrusted server", served)
	}
}

// TestInstallScriptRefusesUnpinnedVerifier serves a ghost-verify that accepts
// any archive: the script must not run it unless its hash is the pinned one,
// and with the placeholder hashes of install.sh as it is, it installs nothing.
func TestInstallScriptRefusesUnpinnedVerifier(t *testing.T) {
	verifier := builtVerifier(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	verifierMarker := filepath.Join(t.TempDir(), "verifier-ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)

	t.Run("another hash pinned", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, newSigner(t).sign(blob), fakeVerifier(verifierMarker))
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		out, err := env.run(t, writeScript(t, key, sha256Hex(verifier)), rs, true)
		checkRefused(t, env, out, err, fmt.Sprintf("not the %s pinned in this installer; refusing to install. Nothing was installed.", sha256Hex(verifier)), marker)
		if _, err := os.Stat(verifierMarker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the script ran an unpinned ghost-verify (%v)", err)
		}
		if served := rs.servedFiles(); len(served) != 1 || served[0] != verifierName("linux") {
			t.Fatalf("the script downloaded %v after refusing the checker", served)
		}
	})

	t.Run("placeholder", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		out, err := env.run(t, writeScript(t, key, ""), rs, true)
		checkRefused(t, env, out, err, "has no hash of "+verifierName("linux")+" pinned yet", marker)
		if served := rs.servedFiles(); len(served) != 0 {
			t.Fatalf("the script downloaded %v with no checker pinned", served)
		}
	})
}

// TestInstallScriptPinsTheKeyFile checks that install.sh pins the key of the
// .pub file next to it, an ed25519 public key, so that the key is swapped in
// that file and the same lines of the script; and that its ghost-verify
// hashes are the all-zero placeholder until the release fills them in.
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
	for platform, hash := range pinnedHashes(t, string(script)) {
		if hash != strings.Repeat("0", 64) {
			t.Errorf("install.sh pins %s for ghost-verify-%s before the release has built one", hash, platform)
		}
	}
	if !strings.Contains(string(script), "http_port=${GHOST_HTTP_PORT:-8545}") {
		t.Error("the node's HTTP RPC is not on port 8545 by default, where the web apps look for it")
	}
}

// baseFiles returns the hashes of the installed files, all but the chain and
// the logs, which the running node changes.
func baseFiles(t *testing.T, env *installEnv) map[string][32]byte {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	files := make(map[string][32]byte)
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(base, path)
		if d.IsDir() {
			if rel == filepath.Join("data", "geth") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && !strings.HasSuffix(rel, ".log") {
			files[rel] = fileHash(t, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func sameFiles(a, b map[string][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, hash := range a {
		if b[name] != hash {
			return false
		}
	}
	return true
}

// installRunning installs release with the stub service manager of env and
// waits for the node to run.
func installRunning(t *testing.T, env *installEnv, script string, rs *releaseServer, geth string) {
	t.Helper()
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	out, err := env.run(t, script, rs, true)
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	checkInstalledAndMining(t, env, geth, out)
}

// checkUpdateApplied serves a new release signed by key, a geth that is the
// one of gethBin with bytes appended and the installer script, runs the update
// script, and checks the update as checkUpdatedTo does. restart is the service
// manager's restart call.
func checkUpdateApplied(t *testing.T, env *installEnv, rs *releaseServer, key *signer, script string, gethBin []byte, restart string) {
	t.Helper()
	newGeth := append(append([]byte(nil), gethBin...), []byte("\nghost test release 2\n")...)
	newArchive := archive{"geth": newGeth}.tarGz(t)
	rs.setRelease(newArchive, key.sign(newArchive))
	serveInstaller(t, rs, key, script)
	checkUpdatedTo(t, env, rs, newGeth, firstTag, firstTag, restart)
}

// checkUpdatedTo runs the update script with extraEnv, a release with the geth
// newGeth being the newest, and checks that it downloaded the files of an
// update from the release tag pinned and the newest release tag newest, that
// the node runs the new geth with the old config, keys, update script and
// chain, and that a second update finds nothing to do. restart is the service
// manager's restart call.
func checkUpdatedTo(t *testing.T, env *installEnv, rs *releaseServer, newGeth []byte, pinned, newest, restart string, extraEnv ...string) {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	installed := filepath.Join(base, "bin", "geth")
	address := configAddress(t, env)
	before := baseFiles(t, env)
	oldPID := env.servicePID(t)
	restarts := strings.Count(env.calls(t), restart)
	served := len(rs.servedPaths())

	out, err := env.update(t, rs, extraEnv...)
	if err != nil {
		t.Fatalf("the update failed: %v", err)
	}
	if !strings.Contains(out, "the newest release's install.sh is signed by the release key") {
		t.Fatal("the update did not say it checked the newest release's install.sh")
	}
	if !strings.Contains(out, "updated the node to the latest release and restarted it") {
		t.Fatal("the update did not say it updated the node")
	}
	checkServedUpdate(t, rs, served, pinned, newest)
	if fileHash(t, installed) != sha256.Sum256(newGeth) {
		t.Fatal("the installed geth is not the new release's")
	}
	after := baseFiles(t, env)
	delete(before, filepath.Join("bin", "geth"))
	delete(after, filepath.Join("bin", "geth"))
	if !sameFiles(before, after) {
		t.Fatalf("the update changed more than geth: had %v, has %v", before, after)
	}
	if configAddress(t, env) != address {
		t.Fatal("the update changed the mining address")
	}
	if left := entries(t, env.tmp); len(left) != 0 {
		t.Fatalf("the update left %v in the temporary directory", left)
	}
	if got := strings.Count(env.calls(t), restart); got != restarts+1 {
		t.Fatalf("the update restarted the node %d times:\n%s", got-restarts, env.calls(t))
	}
	newPID := env.servicePID(t)
	if newPID == oldPID || running(oldPID) || !running(newPID) {
		t.Fatalf("the node was not restarted: process %d (running %v) became %d (running %v)", oldPID, running(oldPID), newPID, running(newPID))
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", newPID)); err != nil || exe != installed {
		t.Fatalf("the restarted node runs %q (%v), not %s", exe, err, installed)
	}
	client, err := rpc.Dial(filepath.Join(base, "data", "geth.ipc"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var head hexutil.Uint64
	if err := client.Call(&head, "eth_blockNumber"); err != nil {
		t.Fatal(err)
	}
	if head == 0 {
		t.Fatal("the updated node lost its chain")
	}

	out, err = env.update(t, rs, extraEnv...)
	if err != nil {
		t.Fatalf("the second update failed: %v", err)
	}
	if !strings.Contains(out, "the node is up to date") {
		t.Fatal("the second update did not find the node up to date")
	}
	if got := strings.Count(env.calls(t), restart); got != restarts+1 || env.servicePID(t) != newPID {
		t.Fatal("an update with nothing new restarted the node")
	}
}

// TestInstallScriptAppliesUpdate installs a release, then serves a newer one
// and runs the installed update script, as its daily timer would.
func TestInstallScriptAppliesUpdate(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	script := writeScript(t, key, sha256Hex(verifier))
	installRunning(t, env, script, rs, geth)

	checkUpdateApplied(t, env, rs, key, script, release["geth"], "systemctl --user restart ghost-node.service\n")
}

// installPinned installs, from rs, the script at path pinned to the release
// tag, and waits for the node to run.
func installPinned(t *testing.T, env *installEnv, rs *releaseServer, path, tag, geth string) {
	t.Helper()
	pinRelease(t, path, rs.downloadURL(tag))
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	out, err := env.run(t, path, rs, true, "GHOST_RELEASE_URL=")
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	checkInstalledAndMining(t, env, geth, out)
	if served := rs.servedPaths(); len(served) == 0 || !strings.HasPrefix(served[0], tag+"/") {
		t.Fatalf("the install downloaded %v, not from its release %s", served, tag)
	}
}

// publishNewer publishes the release tag as the newest: its install.sh, signed
// by key, pins the release tag and the hash of a ghost-verify of its own, the
// built one with bytes appended. The release serves archive and sig, and
// checker as its ghost-verify, or with checker nil the pinned one.
func publishNewer(t *testing.T, rs *releaseServer, key *signer, tag string, archive, sig, checker []byte) {
	t.Helper()
	pinned := append(append([]byte(nil), builtVerifier(t)...), []byte("\nghost-verify of "+tag+"\n")...)
	script := writeScript(t, key, sha256Hex(pinned))
	pinRelease(t, script, rs.downloadURL(tag))
	rs.publish(tag)
	serveInstaller(t, rs, key, script)
	rs.setRelease(archive, sig)
	if checker == nil {
		checker = pinned
	}
	rs.setVerifier(checker)
}

// TestInstallScriptUpdatesToNewerRelease installs a release whose installer
// pins it, as a published install.sh does, then publishes a newer release,
// whose installer pins it and another ghost-verify, and runs the installed
// update script, as its daily timer would: the node moves to the newer
// release and keeps its config and mining address.
func TestInstallScriptUpdatesToNewerRelease(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	installPinned(t, env, rs, script, firstTag, geth)
	serveInstaller(t, rs, key, script)
	updater, err := os.ReadFile(filepath.Join(env.home, ".ghost-node", "update"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updater), "release_url=${GHOST_RELEASE_URL:-"+rs.downloadURL(firstTag)+"}\n") {
		t.Fatal("the installed update script is not pinned to the release it was installed from")
	}

	const newer = "v0.0.1-test"
	newGeth := append(append([]byte(nil), release["geth"]...), []byte("\nghost test release 2\n")...)
	newArchive := archive{"geth": newGeth}.tarGz(t)
	publishNewer(t, rs, key, newer, newArchive, key.sign(newArchive), nil)
	checkUpdatedTo(t, env, rs, newGeth, firstTag, newer, "systemctl --user restart ghost-node.service\n", "GHOST_RELEASE_URL=")
}

// untrustedServer serves a release's install.sh over TLS with a certificate of
// its own, which no CA file of the tests trusts, and counts the files it
// serves. httptest's TLS servers all share one certificate.
type untrustedServer struct {
	*httptest.Server
	served atomic.Int32
}

// serveUntrusted serves the script at path, signed by key, as the latest
// release's install.sh of an untrusted server.
func serveUntrusted(t *testing.T, key *signer, path string) *untrustedServer {
	t.Helper()
	script, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"install.sh": script, "install.sh.sig": key.sign(script)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "untrusted release server"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	us := &untrustedServer{}
	us.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, ok := files[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		us.served.Add(1)
		w.Write(content)
	}))
	us.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}
	us.StartTLS()
	t.Cleanup(us.Close)
	return us
}

// nodeState is what a refused update must leave as it was: the installed
// files, the service manager's calls and the running node.
type nodeState struct {
	files map[string][32]byte
	calls string
	pid   int
}

func snapshot(t *testing.T, env *installEnv) nodeState {
	t.Helper()
	return nodeState{files: baseFiles(t, env), calls: env.calls(t), pid: env.servicePID(t)}
}

// checkUpdateRefused checks that the update failed saying want and that
// nothing was changed, nothing was left in the temporary directory and none
// of the files markers was made.
func checkUpdateRefused(t *testing.T, env *installEnv, state nodeState, out string, err error, want string, markers ...string) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the update did not fail: %v", err)
	}
	if !strings.Contains(out, want) || !strings.Contains(out, "refusing to update. Nothing was changed, and the running node was left alone.") {
		t.Fatalf("the update did not say %q and that nothing was changed", want)
	}
	if after := baseFiles(t, env); !sameFiles(state.files, after) {
		t.Fatalf("a refused update changed the installed files: had %v, has %v", state.files, after)
	}
	if got := env.calls(t); got != state.calls {
		t.Fatalf("a refused update called the service manager:\n%s", strings.TrimPrefix(got, state.calls))
	}
	if env.servicePID(t) != state.pid || !running(state.pid) {
		t.Fatal("a refused update did not leave the running node alone")
	}
	if left := entries(t, env.tmp); len(left) != 0 {
		t.Fatalf("a refused update left %v in the temporary directory", left)
	}
	for _, m := range markers {
		if _, err := os.Stat(m); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused update ran %s (%v)", m, err)
		}
	}
}

// TestInstallScriptRefusesUntrustedNewerRelease installs a release, then
// publishes newer releases that must not be installed: an install.sh that the
// release key did not sign, or that cannot be fetched, or a signed one whose
// release fails its own checks. Each refused update changes nothing, leaves
// the running node alone and runs nothing it downloaded.
func TestInstallScriptRefusesUntrustedNewerRelease(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key, other := newSigner(t), newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	installPinned(t, env, rs, script, firstTag, geth)
	state := snapshot(t, env)

	marker := filepath.Join(t.TempDir(), "ran")
	verifierMarker := filepath.Join(t.TempDir(), "verifier-ran")
	// evil is an install.sh that, run at all, leaves the marker.
	evil := []byte(fmt.Sprintf("#!/bin/sh\necho ran >%q\n", marker))
	signed := archive{"geth": append(append([]byte(nil), release["geth"]...), "\nsigned\n"...)}.tarGz(t)
	tampered := archive{"geth": fakeGeth(marker)}.tarGz(t)
	untrusted := serveUntrusted(t, key, script)

	for i, tc := range []struct {
		name     string
		newer    func() // edits the newest release after publishNewer, unless nil
		archive  []byte
		sig      []byte
		checker  []byte
		env      []string
		want     string
		releases bool // whether the newest release's own checks refused it
	}{
		{
			name:  "install.sh signed by another key",
			newer: func() { rs.setInstaller(evil, other.sign(evil)) },
			want:  "the signature of install.sh does not match the release key",
		},
		{
			name:  "tampered install.sh",
			newer: func() { rs.setFile("install.sh", evil) },
			want:  "the signature of install.sh does not match the release key",
		},
		{
			name:  "install.sh not a signature",
			newer: func() { rs.setFile("install.sh.sig", []byte("not a signature\n")) },
			want:  "the signature of install.sh is not a 64-byte ed25519 signature",
		},
		{
			name:  "no install.sh signature",
			newer: func() { rs.setFile("install.sh.sig", nil) },
			want:  "could not download " + rs.URL + "/latest/download/install.sh.sig",
		},
		{
			name:  "no install.sh",
			newer: func() { rs.setFile("install.sh", nil) },
			want:  "could not download " + rs.URL + "/latest/download/install.sh",
		},
		{
			name: "untrusted server",
			env:  []string{"GHOST_LATEST_URL=" + untrusted.URL + "/latest/download"},
			want: "could not download " + untrusted.URL + "/latest/download/install.sh",
		},
		{
			name: "not https",
			env:  []string{"GHOST_LATEST_URL=http://" + untrusted.Listener.Addr().String() + "/latest/download"},
			want: "GHOST_LATEST_URL must be an https URL",
		},
		{
			name:     "newer release's checker not pinned",
			archive:  tampered,
			sig:      key.sign(signed),
			checker:  fakeVerifier(verifierMarker),
			want:     "pinned in this installer",
			releases: true,
		},
		{
			name:     "newer release signed by another key",
			archive:  signed,
			sig:      other.sign(signed),
			want:     "the signature of " + assetName("linux") + " does not match the release key",
			releases: true,
		},
		{
			name:     "newer release tampered",
			archive:  tampered,
			sig:      key.sign(signed),
			want:     "the signature of " + assetName("linux") + " does not match the release key",
			releases: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag := fmt.Sprintf("v0.1.%d-test", i)
			newArchive, newSig := tc.archive, tc.sig
			if newArchive == nil {
				newArchive, newSig = signed, key.sign(signed)
			}
			publishNewer(t, rs, key, tag, newArchive, newSig, tc.checker)
			if tc.newer != nil {
				tc.newer()
			}
			served := len(rs.servedPaths())
			out, err := env.update(t, rs, append([]string{"GHOST_RELEASE_URL="}, tc.env...)...)
			checkUpdateRefused(t, env, state, out, err, tc.want, marker, verifierMarker)
			for _, path := range rs.servedPaths()[served:] {
				if !tc.releases && path != firstTag+"/"+verifierName("linux") && !strings.HasPrefix(path, tag+"/install.sh") {
					t.Fatalf("the update downloaded %s though the newest install.sh was refused", path)
				}
			}
			if n := untrusted.served.Load(); n != 0 {
				t.Fatalf("the update downloaded %d files from an untrusted server", n)
			}
		})
	}
}

// TestInstallScriptRefusesTamperedUpdate installs a release, then serves
// updates that must not be installed, and checks that each refused update
// changes nothing and leaves the running node alone.
func TestInstallScriptRefusesTamperedUpdate(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	script := writeScript(t, key, sha256Hex(verifier))
	installRunning(t, env, script, rs, geth)
	serveInstaller(t, rs, key, script)

	state := snapshot(t, env)
	marker := filepath.Join(t.TempDir(), "ran")
	verifierMarker := filepath.Join(t.TempDir(), "verifier-ran")
	signed := archive{"geth": append(append([]byte(nil), release["geth"]...), "\nsigned\n"...)}.tarGz(t)
	tampered := archive{"geth": fakeGeth(marker)}.tarGz(t)

	checkUnchanged := func(t *testing.T, out string, err error, want string) {
		t.Helper()
		checkUpdateRefused(t, env, state, out, err, want, marker, verifierMarker)
	}

	t.Run("tampered archive", func(t *testing.T) {
		rs.setRelease(tampered, key.sign(signed))
		out, err := env.update(t, rs)
		checkUnchanged(t, out, err, "does not match the release key")
	})
	t.Run("signed by another key", func(t *testing.T) {
		rs.setRelease(signed, newSigner(t).sign(signed))
		out, err := env.update(t, rs)
		checkUnchanged(t, out, err, "does not match the release key")
	})
	t.Run("unpinned checker", func(t *testing.T) {
		rs.setRelease(tampered, key.sign(signed))
		rs.setVerifier(fakeVerifier(verifierMarker))
		defer rs.setVerifier(verifier)
		out, err := env.update(t, rs)
		checkUnchanged(t, out, err, "pinned in this installer")
	})
}

// checkStockMac checks that the computer of env has no sha256sum and no
// OpenSSL that verifies ed25519, only a Mac's LibreSSL.
func checkStockMac(t *testing.T, env *installEnv) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(env.stubs, "sha256sum")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a stock Mac has no sha256sum")
	}
	cmd := exec.Command(filepath.Join(env.stubs, "openssl"), "version")
	cmd.Env = []string{"PATH=" + env.stubs, "STUB_DIR=" + t.TempDir()}
	if out, err := cmd.Output(); err != nil || !strings.HasPrefix(string(out), "LibreSSL ") {
		t.Fatalf("the stock Mac's openssl says %q (%v)", out, err)
	}
	// The PATH is the stubs directory alone.
	for _, name := range entries(t, env.stubs) {
		if strings.HasPrefix(name, "openssl") && name != "openssl" {
			t.Fatalf("the stock Mac has another OpenSSL, %s", name)
		}
	}
}

// checkNoOpenSSL checks that the script never ran openssl and hashed with
// shasum.
func checkNoOpenSSL(t *testing.T, env *installEnv) {
	t.Helper()
	if calls := env.readStub(t, "openssl.calls"); calls != "" {
		t.Fatalf("the script ran openssl:\n%s", calls)
	}
	if calls := env.readStub(t, "shasum.calls"); !strings.Contains(calls, "shasum -a 256 ") {
		t.Fatalf("the script did not hash with shasum -a 256:\n%s", calls)
	}
}

// TestInstallScriptWithoutOpenSSL3 runs the script on a computer with a stock
// Mac's tools, shasum and a LibreSSL that cannot verify ed25519, and nothing
// else: it refuses a tampered archive and installs a signed one.
func TestInstallScriptWithoutOpenSSL3(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	script := writeScript(t, key, sha256Hex(verifier))

	t.Run("tampered archive", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "ran")
		signed := archive{"geth": []byte("#!/bin/sh\nexit 0\n")}.tarGz(t)
		rs := serveRelease(t, "linux", archive{"geth": fakeGeth(marker)}.tarGz(t), key.sign(signed), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, stockMac: true})
		checkStockMac(t, env)
		out, err := env.run(t, script, rs, true)
		checkRefused(t, env, out, err, refusedSignature, marker)
		checkNoOpenSSL(t, env)
	})

	t.Run("signed archive", func(t *testing.T) {
		blob := release.tarGz(t)
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, stockMac: true})
		checkStockMac(t, env)
		installRunning(t, env, script, rs, geth)
		checkNoOpenSSL(t, env)
	})
}

// TestInstallScriptDarwin installs on a Mac, a stub uname and launchctl on
// this computer with a stock Mac's tools: the darwin release, a launchd agent
// that runs the node mining at login and another that runs the update daily,
// and then an update.
func TestInstallScriptDarwin(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{darwin: true, stockMac: true, cpus: 18})
	checkStockMac(t, env)
	script := writeScript(t, key, sha256Hex(verifier))
	installRunning(t, env, script, rs, geth)
	checkServedRelease(t, rs, 0)
	checkNoOpenSSL(t, env)

	base := filepath.Join(env.home, ".ghost-node")
	agents := filepath.Join(env.home, "Library", "LaunchAgents")
	plist, err := os.ReadFile(filepath.Join(agents, "com.ghostcoin.node.plist"))
	if err != nil {
		t.Fatal(err)
	}
	args := fmt.Sprintf("<array>\n\t\t<string>%s</string>\n\t\t<string>--config</string>\n\t\t<string>%s</string>\n\t\t<string>--mine</string>\n"+
		"\t\t<string>--miner.threads</string>\n\t\t<string>9</string>\n\t</array>",
		filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"))
	for _, want := range []string{"<string>com.ghostcoin.node</string>", args, "<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<true/>"} {
		if !strings.Contains(string(plist), want) {
			t.Fatalf("the agent's plist has no %q:\n%s", want, plist)
		}
	}
	updatePlist, err := os.ReadFile(filepath.Join(agents, "com.ghostcoin.node.update.plist"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>com.ghostcoin.node.update</string>", fmt.Sprintf("<string>%s</string>", filepath.Join(base, "update")), "<key>StartInterval</key>\n\t<integer>86400</integer>"} {
		if !strings.Contains(string(updatePlist), want) {
			t.Fatalf("the update agent's plist has no %q:\n%s", want, updatePlist)
		}
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	calls := env.calls(t)
	for _, want := range []string{
		fmt.Sprintf("launchctl bootstrap %s %s\n", domain, filepath.Join(agents, "com.ghostcoin.node.plist")),
		fmt.Sprintf("launchctl bootstrap %s %s\n", domain, filepath.Join(agents, "com.ghostcoin.node.update.plist")),
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("no call %q; the calls were:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "systemctl") {
		t.Fatalf("the script used systemd on a Mac:\n%s", calls)
	}

	checkUpdateApplied(t, env, rs, key, script, release["geth"], fmt.Sprintf("launchctl kickstart -k %s/com.ghostcoin.node\n", domain))
	checkNoOpenSSL(t, env)
}

// The wallet addresses the GHOST_MINE_TO tests mine to, as a tester's pop-up
// wallet gives them: no key of theirs is on the computer.
var (
	mineToWallet  = "0x" + strings.Repeat("aB", 20)
	mineToWallet2 = "0x" + strings.Repeat("12", 20)
	mineToWallet3 = "0x" + strings.Repeat("Cd", 20)
)

const mineToRefusal = "GHOST_MINE_TO must be a wallet address, 0x followed by exactly 40 hex characters"

// checkNoMiningKey checks that the installer made no mining key and no
// password file.
func checkNoMiningKey(t *testing.T, env *installEnv) {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	if keys, err := os.ReadDir(filepath.Join(base, "data", "keystore")); err == nil && len(keys) != 0 {
		t.Fatalf("with GHOST_MINE_TO the keystore holds %d keys", len(keys))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "password")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("with GHOST_MINE_TO there is a mining key password file (%v)", err)
	}
}

// readConfig returns the installed config.
func readConfig(t *testing.T, env *installEnv) string {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(env.home, ".ghost-node", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

// checkRestarted checks that the node of the process oldPID was restarted
// once, by the service manager's call restart, which had been made restarts
// times before.
func checkRestarted(t *testing.T, env *installEnv, oldPID, restarts int, restart string) {
	t.Helper()
	if got := strings.Count(env.calls(t), restart); got != restarts+1 {
		t.Fatalf("the node was restarted %d times, not once:\n%s", got-restarts, env.calls(t))
	}
	newPID := env.servicePID(t)
	if newPID == oldPID || running(oldPID) || !running(newPID) {
		t.Fatalf("the node was not restarted: process %d (running %v) became %d (running %v)", oldPID, running(oldPID), newPID, running(newPID))
	}
}

// waitMinedTo waits for the running node's latest block to be mined to
// address.
func waitMinedTo(t *testing.T, env *installEnv, address common.Address) {
	t.Helper()
	client, err := rpc.Dial(filepath.Join(env.home, ".ghost-node", "data", "geth.ipc"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var block struct {
			Number hexutil.Uint64 `json:"number"`
			Miner  common.Address `json:"miner"`
		}
		if err := client.Call(&block, "eth_getBlockByNumber", "latest", false); err != nil {
			t.Fatal(err)
		}
		if block.Number > 0 && block.Miner == address {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the node mined no block to %s in 3 minutes; block %d went to %s", address.Hex(), block.Number, block.Miner.Hex())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestInstallScriptMineTo installs with GHOST_MINE_TO set to a wallet
// address: the node mines straight to it, and no mining key or password is
// made. A re-run with another address rewrites Etherbase, keeping the rest of
// the config, and restarts the node mining to it; a re-run without keeps the
// config as it is. An update with an address does the same; one without, or
// with a malformed address, changes nothing.
func TestInstallScriptMineTo(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	const restart = "systemctl --user restart ghost-node.service\n"

	out, err := env.run(t, script, rs, true, "GHOST_MINE_TO="+mineToWallet)
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	checkInstalledAndMiningTo(t, env, geth, out, mineToWallet)
	first := readConfig(t, env)

	// A re-run with another address.
	oldPID, restarts := env.servicePID(t), strings.Count(env.calls(t), restart)
	out, err = env.run(t, script, rs, true, "GHOST_MINE_TO="+mineToWallet2)
	if err != nil {
		t.Fatalf("the re-run of install.sh failed: %v", err)
	}
	second := readConfig(t, env)
	if want := strings.Replace(first, mineToWallet, mineToWallet2, 1); second != want {
		t.Fatalf("the re-run with GHOST_MINE_TO=%s did not rewrite only Etherbase; the config went from\n%s\nto\n%s", mineToWallet2, first, second)
	}
	checkRestarted(t, env, oldPID, restarts, restart)
	checkNoMiningKey(t, env)
	if !strings.Contains(out, "mining to: "+mineToWallet2+"\n") {
		t.Fatal("the re-run did not print the address it mines to")
	}
	waitMinedTo(t, env, common.HexToAddress(mineToWallet2))

	// A re-run without GHOST_MINE_TO keeps the config.
	out, err = env.run(t, script, rs, true)
	if err != nil {
		t.Fatalf("the re-run of install.sh failed: %v", err)
	}
	if got := readConfig(t, env); got != second {
		t.Fatalf("the re-run without GHOST_MINE_TO changed the config from\n%s\nto\n%s", second, got)
	}
	checkNoMiningKey(t, env)
	if !strings.Contains(out, "keeping the existing config") || !strings.Contains(out, "mining to: "+mineToWallet2+"\n") {
		t.Fatal("the re-run without GHOST_MINE_TO did not keep the config and say what it mines to")
	}

	// An update with another address.
	serveInstaller(t, rs, key, script)
	oldPID, restarts = env.servicePID(t), strings.Count(env.calls(t), restart)
	out, err = env.update(t, rs, "GHOST_MINE_TO="+mineToWallet3)
	if err != nil {
		t.Fatalf("the update failed: %v", err)
	}
	third := readConfig(t, env)
	if want := strings.Replace(second, mineToWallet2, mineToWallet3, 1); third != want {
		t.Fatalf("the update with GHOST_MINE_TO=%s did not rewrite only Etherbase; the config went from\n%s\nto\n%s", mineToWallet3, second, third)
	}
	checkRestarted(t, env, oldPID, restarts, restart)
	checkNoMiningKey(t, env)
	if !strings.Contains(out, "the node is up to date") || !strings.Contains(out, "mining to: "+mineToWallet3+"\n") {
		t.Fatal("the update did not say the node is up to date and what it mines to")
	}
	waitMinedTo(t, env, common.HexToAddress(mineToWallet3))

	// An update without GHOST_MINE_TO, or with the address already mined to,
	// changes nothing and leaves the node running.
	for _, extra := range [][]string{nil, {"GHOST_MINE_TO=" + mineToWallet3}} {
		pid, restarts := env.servicePID(t), strings.Count(env.calls(t), restart)
		out, err = env.update(t, rs, extra...)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		if got := readConfig(t, env); got != third {
			t.Fatalf("the update with %q changed the config from\n%s\nto\n%s", extra, third, got)
		}
		if strings.Count(env.calls(t), restart) != restarts || env.servicePID(t) != pid || !running(pid) {
			t.Fatalf("the update with %q restarted the node", extra)
		}
		if !strings.Contains(out, "mining to: "+mineToWallet3+"\n") {
			t.Fatalf("the update with %q did not say what the node mines to", extra)
		}
	}

	// An update with a malformed address is refused.
	state := snapshot(t, env)
	out, err = env.update(t, rs, "GHOST_MINE_TO=0x1234")
	checkUpdateRefused(t, env, state, out, err, mineToRefusal)
}

// TestInstallScriptMineToRefusesMalformed sets GHOST_MINE_TO to what is not
// 0x followed by exactly 40 hex characters: the installer refuses it before it
// downloads anything, and installs nothing. The release it would install is
// one whose geth leaves a marker when run.
func TestInstallScriptMineToRefusesMalformed(t *testing.T) {
	verifier := builtVerifier(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	hex40 := strings.Repeat("aB", 20)

	for _, value := range []string{
		"0x" + hex40[:39],
		"0x" + hex40 + "a",
		hex40,
		"0X" + hex40,
		"0x" + hex40[:39] + "g",
		"0x",
		" 0x" + hex40,
		"0x" + hex40 + "\n",
		"0x" + hex40 + " 0x" + hex40,
		"0x$(touch " + marker + ")",
		"wallet",
	} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
			out, err := env.run(t, script, rs, true, "GHOST_MINE_TO="+value)
			checkRefused(t, env, out, err, mineToRefusal+", not '"+value+"'; refusing to install. Nothing was installed.", marker)
		})
	}
	if served := rs.servedFiles(); len(served) != 0 {
		t.Fatalf("a refused GHOST_MINE_TO downloaded %v", served)
	}
}

// TestInstallScriptMineToUnset installs without GHOST_MINE_TO, as before it
// existed: the node mines to a newly made key, whose password is kept, and
// the installer says it mines to it.
func TestInstallScriptMineToUnset(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	out, err := env.run(t, writeScript(t, key, sha256Hex(verifier)), rs, true)
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	checkInstalledAndMining(t, env, geth, out)
	if config := readConfig(t, env); !strings.Contains(config, "whose key is in the keystore of DataDir") {
		t.Fatalf("the config does not say where the mining key is:\n%s", config)
	}
}

// disableAgent marks the launchd agent label disabled in the stub launchd, as
// launchctl disable leaves it on a Mac.
func (env *installEnv) disableAgent(t *testing.T, label string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(env.stubs, "disabled."+label), nil, 0600); err != nil {
		t.Fatal(err)
	}
}

// checkEnabledBeforeBootstrap checks that every bootstrap of the agent label
// in calls follows a launchctl enable of it.
func checkEnabledBeforeBootstrap(t *testing.T, calls, domain, agents, label string) {
	t.Helper()
	enable := fmt.Sprintf("launchctl enable %s/%s\n", domain, label)
	bootstrap := fmt.Sprintf("launchctl bootstrap %s %s\n", domain, filepath.Join(agents, label+".plist"))
	b := strings.Index(calls, bootstrap)
	if b < 0 {
		t.Fatalf("no call %q; the calls were:\n%s", bootstrap, calls)
	}
	if e := strings.Index(calls, enable); e < 0 || e > b {
		t.Fatalf("the agent %s was not enabled before it was bootstrapped; the calls were:\n%s", label, calls)
	}
}

// TestInstallScriptLaunchdEnablesDisabledAgents installs on a Mac where both
// launchd agents were disabled before, as stopping the node leaves them: the
// stub launchd refuses to bootstrap a disabled agent, so the installer must
// enable each one before it bootstraps it.
func TestInstallScriptLaunchdEnablesDisabledAgents(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{darwin: true, stockMac: true})
	env.disableAgent(t, "com.ghostcoin.node")
	env.disableAgent(t, "com.ghostcoin.node.update")
	installRunning(t, env, writeScript(t, key, sha256Hex(verifier)), rs, geth)

	domain := fmt.Sprintf("gui/%d", os.Getuid())
	agents := filepath.Join(env.home, "Library", "LaunchAgents")
	calls := env.calls(t)
	checkEnabledBeforeBootstrap(t, calls, domain, agents, "com.ghostcoin.node")
	checkEnabledBeforeBootstrap(t, calls, domain, agents, "com.ghostcoin.node.update")
	for _, label := range []string{"com.ghostcoin.node", "com.ghostcoin.node.update"} {
		if _, err := os.Stat(filepath.Join(env.stubs, "disabled."+label)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the agent %s is still disabled (%v)", label, err)
		}
	}
}

// TestInstallScriptLaunchdBootstrapFailsSaysWhy installs on a Mac whose
// launchd keeps the node's agent disabled however it is enabled: the
// installer must stop saying launchd's error, what launchd lists for the
// agent, and what to do.
func TestInstallScriptLaunchdBootstrapFailsSaysWhy(t *testing.T) {
	verifier := builtVerifier(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{darwin: true, stockMac: true})
	env.disableAgent(t, "com.ghostcoin.node")
	if err := os.WriteFile(filepath.Join(env.stubs, "enable-refused"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, writeScript(t, key, sha256Hex(verifier)), rs, true, "GHOST_MINE_TO="+mineToWallet)
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("install.sh did not fail: %v", err)
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	for _, want := range []string{
		"could not start the launchd agent com.ghostcoin.node: Bootstrap failed: 5: Input/output error",
		`launchd lists it as: "com.ghostcoin.node" => disabled.`,
		fmt.Sprintf("Run 'launchctl enable %s/com.ghostcoin.node', then run this installer again.", domain),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("install.sh did not say %q", want)
		}
	}
	calls := env.calls(t)
	checkEnabledBeforeBootstrap(t, calls, domain, filepath.Join(env.home, "Library", "LaunchAgents"), "com.ghostcoin.node")
	if !strings.Contains(calls, "launchctl print-disabled "+domain+"\n") {
		t.Fatalf("install.sh did not ask launchd what it disabled; the calls were:\n%s", calls)
	}
}

// holdPort makes another program, a JSON-RPC server that is not the node,
// listen on 127.0.0.1:port until the test ends. It answers eth_coinbase with
// an address no installed config names.
func holdPort(t *testing.T, port int) {
	t.Helper()
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%q}`, "0x"+strings.Repeat("99", 20))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
}

func portInUse(port int) string {
	return fmt.Sprintf("port %d on this computer is already in use by another program; stop it, or install with GHOST_HTTP_PORT=<free port>", port)
}

// TestInstallScriptPortInUse installs, on Linux and on a Mac, while another
// program listens on the node's HTTP RPC port: the installer must refuse
// before it downloads or writes anything.
func TestInstallScriptPortInUse(t *testing.T) {
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
			blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
			rs := serveRelease(t, tc.name, blob, key.sign(blob), verifier)
			env := newInstallEnv(t, tc.opts)
			holdPort(t, env.httpPort)

			out, err := env.run(t, script, rs, true, "GHOST_MINE_TO="+mineToWallet)
			checkRefused(t, env, out, err, portInUse(env.httpPort)+"; refusing to install. Nothing was installed.", marker)
			if served := rs.servedFiles(); len(served) != 0 {
				t.Fatalf("an install refused for a busy port downloaded %v", served)
			}
		})
	}
}

// TestInstallScriptUpdatePortHeldByOwnNode installs a node and updates it
// while it runs and holds its HTTP RPC port, which must not stop the update.
// Then, with the node stopped and another program on the port, an update must
// refuse and change nothing.
func TestInstallScriptUpdatePortHeldByOwnNode(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
	script := writeScript(t, key, sha256Hex(verifier))
	installRunning(t, env, script, rs, geth)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.httpPort))
	if err != nil {
		t.Fatalf("the installed node does not hold its HTTP RPC port: %v", err)
	}
	conn.Close()
	checkUpdateApplied(t, env, rs, key, script, release["geth"], "systemctl --user restart ghost-node.service\n")

	pid := env.servicePID(t)
	syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 600 && running(pid); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if running(pid) {
		t.Fatal("the node did not stop")
	}
	holdPort(t, env.httpPort)
	before := baseFiles(t, env)
	calls := env.calls(t)
	served := len(rs.servedPaths())

	out, err := env.update(t, rs)
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the update did not fail: %v", err)
	}
	if want := portInUse(env.httpPort) + "; refusing to update. Nothing was changed"; !strings.Contains(out, want) {
		t.Fatalf("the update did not say %q", want)
	}
	if !sameFiles(before, baseFiles(t, env)) {
		t.Fatal("an update refused for a busy port changed the installed files")
	}
	if env.calls(t) != calls {
		t.Fatal("an update refused for a busy port called the service manager")
	}
	if got := rs.servedPaths(); len(got) != served {
		t.Fatalf("an update refused for a busy port downloaded %v", got[served:])
	}
	if left := entries(t, env.tmp); len(left) != 0 {
		t.Fatalf("the update left %v in the temporary directory", left)
	}
}
