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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/internal/winsvc"
)

// releaseKey is the release key. This is a test key whose private half nobody
// holds, so until the real key replaces it ghost-setup accepts no release.
// The same key is install/release-key.pub; a test keeps the two equal.
const releaseKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAaXYrmAQBL2GOex7Gk5uAi/2q/0DxRZwTbYyVPGQVHfE=
-----END PUBLIC KEY-----
`

const (
	// defaultReleaseURL is where the latest release is downloaded from. The
	// install.ps1 and install.cmd scripts name the same.
	defaultReleaseURL = "https://github.com/ghostcoin-core/ghost-node/releases/latest/download"

	// updateValueName is the Run key value that runs the daily update.
	updateValueName = "GhostNodeUpdate"

	homeDirName    = ".ghost-node"
	gethExeName    = "geth.exe"
	setupExeName   = "ghost-setup.exe"
	defaultPort    = 8545
	userAgent      = "ghost-node-installer"
	maxRedirects   = 8
	maxArchiveSize = 1 << 30 // a release archive is well under this
	maxUnpacked    = 4 << 30

	// updateInterval is how often the login-time update checks at most.
	updateInterval = 24 * time.Hour

	// startCheck is how long after starting the node it must still run to
	// count as started.
	startCheck = 5 * time.Second

	installLine = "irm https://get.ghostcoin.com/win | iex"
)

// webOrigins are the Ghost web apps the node's HTTP RPC allows.
var webOrigins = []string{"https://ghost-webapp-alpha.vercel.app", "https://ghost-wallet-nine.vercel.app"}

// mode is what ghost-setup was asked to do.
type mode int

const (
	modeInstall mode = iota
	// --update
	modeUpdate
	// --update --daily: at most once a day, from the Run key
	modeDailyUpdate
)

func parseArgs(args []string) (mode, error) {
	switch strings.Join(args, " ") {
	case "":
		return modeInstall, nil
	case "--update":
		return modeUpdate, nil
	case "--update --daily":
		return modeDailyUpdate, nil
	}
	return 0, errors.New("usage: ghost-setup.exe [--update [--daily]]")
}

// setup installs and updates the node of one user.
type setup struct {
	releaseURL string // https, with no trailing slash
	client     *http.Client
	key        ed25519.PublicKey
	arch       string // amd64 or arm64
	home       string // %USERPROFILE%\.ghost-node
	self       string // this ghost-setup.exe, copied into home
	workRoot   string // where temporary directories are made; "" is the system's
	httpPort   int
	autoUpdate bool

	runKey winsvc.RunKey
	procs  winsvc.Processes

	// runGeth runs the geth executable exe with args to completion and
	// returns its output.
	runGeth func(exe string, args ...string) ([]byte, error)
	now     func() time.Time
	sleep   func(time.Duration)
	out     io.Writer
}

// newSetup returns the setup that getenv's environment asks for, with the
// pinned release key. Its Run key and processes are left for the caller.
func newSetup(getenv func(string) string, self string, out io.Writer) (*setup, error) {
	key, err := parseKey([]byte(releaseKey))
	if err != nil {
		return nil, fmt.Errorf("the pinned release key: %w", err)
	}
	profile := getenv("USERPROFILE")
	if profile == "" || !filepath.IsAbs(profile) {
		return nil, errors.New("USERPROFILE is not set to a directory, so there is nowhere to install the node")
	}
	releaseURL := strings.TrimRight(getenv("GHOST_RELEASE_URL"), "/")
	if releaseURL == "" {
		releaseURL = defaultReleaseURL
	}
	if u, err := url.Parse(releaseURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("GHOST_RELEASE_URL must be an https URL, not %s", releaseURL)
	}
	port := defaultPort
	if p := getenv("GHOST_HTTP_PORT"); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port <= 0 || port > 65535 || strings.HasPrefix(p, "0") {
			return nil, fmt.Errorf("GHOST_HTTP_PORT is not a port number: %s", p)
		}
	}
	client, err := newClient(getenv("GHOST_INSTALL_CA_FILE"))
	if err != nil {
		return nil, err
	}
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("there is no Ghost node release for %s processors; releases are for amd64 and arm64", arch)
	}
	return &setup{
		releaseURL: releaseURL,
		client:     client,
		key:        key,
		arch:       arch,
		home:       filepath.Join(profile, homeDirName),
		self:       self,
		httpPort:   port,
		autoUpdate: getenv("GHOST_NO_UPDATE") != "1",
		runGeth:    runCommand,
		now:        time.Now,
		sleep:      time.Sleep,
		out:        out,
	}, nil
}

// newClient returns the https client of the downloads. With a CA file it
// trusts only the certificates in it, as curl --cacert does.
func newClient(caFile string) (*http.Client, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		blob, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("GHOST_INSTALL_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(blob) {
			return nil, fmt.Errorf("GHOST_INSTALL_CA_FILE %s holds no PEM certificate", caFile)
		}
		tlsConf.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tlsConf,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("more than %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("will not follow a redirect to %s, which is not an https URL", req.URL)
			}
			return nil
		},
	}, nil
}

func runCommand(exe string, args ...string) ([]byte, error) {
	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	return cmd.CombinedOutput()
}

// spkiPrefix is the DER of an ed25519 SubjectPublicKeyInfo up to the key's
// 32 bytes (RFC 8410).
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// parseKey returns the ed25519 key of a PEM "PUBLIC KEY" block holding
// nothing else.
func parseKey(keyFile []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(keyFile)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not one PEM PUBLIC KEY block")
	}
	der := block.Bytes
	if len(der) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, spkiPrefix) {
		return nil, errors.New("not an ed25519 public key")
	}
	return ed25519.PublicKey(der[len(spkiPrefix):]), nil
}

func (s *setup) say(format string, args ...any) {
	fmt.Fprintf(s.out, "ghost-node: "+format+"\n", args...)
}

func (s *setup) binDir() string     { return filepath.Join(s.home, "bin") }
func (s *setup) gethPath() string   { return filepath.Join(s.binDir(), gethExeName) }
func (s *setup) setupPath() string  { return filepath.Join(s.home, setupExeName) }
func (s *setup) dataDir() string    { return filepath.Join(s.home, "data") }
func (s *setup) password() string   { return filepath.Join(s.home, "password") }
func (s *setup) stampPath() string  { return filepath.Join(s.home, "update.checked") }
func (s *setup) assetName() string  { return "ghost-node-windows-" + s.arch + ".tar.gz" }
func (s *setup) configPath() string { return s.service().ConfigPath() }

// updateCmd is the command line of the daily update in the Run key.
func (s *setup) updateCmd() string {
	return winsvc.JoinCommandLine(s.setupPath(), "--update", "--daily")
}

// service is the node's per-user service.
func (s *setup) service() *winsvc.Service {
	return &winsvc.Service{Exe: s.gethPath(), Home: s.home, RunKey: s.runKey, Processes: s.procs, Sleep: s.sleep}
}

func (s *setup) run(m mode) error {
	if s.runKey == nil || s.procs == nil || s.runGeth == nil {
		return errors.New("the setup has no Run key, process or geth access")
	}
	if m == modeInstall {
		return s.install()
	}
	return s.update(m == modeDailyUpdate)
}

// release is a verified and unpacked release.
type release struct {
	geth    string // its geth.exe
	genesis string // its genesis.json, "" if it has the network built in
	sum     [32]byte
}

// fetchRelease downloads the release archive and its signature into work,
// checks the signature, and only then unpacks the archive. Every error means
// nothing was unpacked outside work.
func (s *setup) fetchRelease(work string) (*release, error) {
	asset := s.assetName()
	s.say("downloading %s", asset)
	archive, err := s.download(s.releaseURL+"/"+asset, maxArchiveSize)
	if err != nil {
		return nil, err
	}
	sig, err := s.download(s.releaseURL+"/"+asset+".sig", ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("the signature of %s is not a %d-byte ed25519 signature", asset, ed25519.SignatureSize)
	}
	if len(s.key) != ed25519.PublicKeySize || !ed25519.Verify(s.key, archive, sig) {
		return nil, fmt.Errorf("the signature of %s does not match the release key", asset)
	}
	s.say("the release signature is valid")

	dir := filepath.Join(work, "release")
	if err := unpack(archive, dir); err != nil {
		return nil, fmt.Errorf("the release archive %s: %w", asset, err)
	}
	rel := &release{geth: filepath.Join(dir, gethExeName)}
	if fi, err := os.Lstat(rel.geth); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("the release archive %s holds no %s", asset, gethExeName)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "genesis.json")); err == nil && fi.Mode().IsRegular() {
		rel.genesis = filepath.Join(dir, "genesis.json")
	}
	if rel.sum, err = fileSum(rel.geth); err != nil {
		return nil, err
	}
	if out, err := s.runGeth(rel.geth, "version"); err != nil {
		return nil, fmt.Errorf("the downloaded %s does not run on this computer: %v %s", gethExeName, err, lastLines(out))
	}
	return rel, nil
}

// download returns the body of the https URL u, refusing one over limit
// bytes.
func (s *setup) download(u string, limit int64) ([]byte, error) {
	if parsed, err := url.Parse(u); err != nil || parsed.Scheme != "https" {
		return nil, fmt.Errorf("will not download %s, which is not an https URL", u)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not download %s: %v", u, err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not download %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not download %s: the server answered %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("could not download %s: %v", u, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("could not download %s: it is larger than %d bytes", u, limit)
	}
	return body, nil
}

// unpack unpacks the .tar.gz blob into the new directory dir. It takes only
// regular files and directories with plain relative names.
func unpack(blob []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return errors.New("it cannot be read")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("it cannot be read")
		}
		name, ok := memberName(hdr.Name)
		if !ok {
			return fmt.Errorf("it holds an unexpected entry: %q", hdr.Name)
		}
		if name == "." {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			total += hdr.Size
			if hdr.Size < 0 || total > maxUnpacked {
				return errors.New("it unpacks to more than is plausible")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
			if err != nil {
				return fmt.Errorf("it cannot be unpacked: %v", err)
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("it cannot be unpacked: %v", err)
			}
		default:
			return fmt.Errorf("it holds an unexpected entry: %q is not a file or a directory", hdr.Name)
		}
	}
	// Reading to the end checks the gzip checksum.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return errors.New("it cannot be read")
	}
	return nil
}

// memberName returns the archive member name as a clean relative path, and
// false for one that could land outside the directory it is unpacked in or
// that Windows would read another way.
func memberName(name string) (string, bool) {
	if name == "" || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return "", false
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." || strings.HasSuffix(part, ".") && part != "." || strings.HasSuffix(part, " ") {
			return "", false
		}
	}
	return clean, true
}

// workDir makes the temporary directory of one run.
func (s *setup) workDir() (string, error) {
	work, err := os.MkdirTemp(s.workRoot, "ghost-setup-")
	if err != nil {
		return "", fmt.Errorf("could not make a temporary directory: %w", err)
	}
	return work, nil
}

func (s *setup) install() error {
	work, err := s.workDir()
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	rel, err := s.fetchRelease(work)
	if err != nil {
		return fmt.Errorf("%v; refusing to install. Nothing was installed", err)
	}

	for _, dir := range []string{s.binDir(), s.dataDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("could not make %s: %w", dir, err)
		}
	}
	svc := s.service()
	// A node installed before runs the geth.exe about to be replaced.
	if pid, err := svc.Stop(); err != nil {
		return fmt.Errorf("could not stop the installed node to replace it: %w", err)
	} else if pid != 0 {
		s.say("stopped the installed node to replace it")
	}
	if err := installFile(rel.geth, s.gethPath()); err != nil {
		return fmt.Errorf("could not install %s: %w", gethExeName, err)
	}
	if err := installFile(s.self, s.setupPath()); err != nil {
		return fmt.Errorf("could not install %s: %w", setupExeName, err)
	}
	address, err := s.configure()
	if err != nil {
		return err
	}
	if err := s.initialise(rel); err != nil {
		return err
	}
	if _, err := svc.Install(); err != nil {
		return fmt.Errorf("could not make the node start at login: %w", err)
	}
	if _, err := s.startNode(svc); err != nil {
		return err
	}
	if s.autoUpdate {
		if err := s.runKey.Set(updateValueName, s.updateCmd()); err != nil {
			return fmt.Errorf("could not schedule the daily update in the Run key: %w", err)
		}
	} else if err := s.runKey.Delete(updateValueName); err != nil {
		return fmt.Errorf("could not remove the daily update from the Run key: %w", err)
	}

	status := winsvc.JoinCommandLine(s.gethPath(), "service", "status", "--home", s.home)
	stop := winsvc.JoinCommandLine(s.gethPath(), "service", "stop", "--home", s.home)
	s.say("the node is installed in %s, running, syncing and mining", s.home)
	s.say("your mining address: %s", address)
	s.say("check its status with: %s", status)
	s.say("follow its log with: Get-Content -Wait %s", winsvc.QuoteArg(svc.LogPath()))
	s.say("the Ghost web apps reach it at http://127.0.0.1:%d", s.httpPort)
	update := winsvc.JoinCommandLine(s.setupPath(), "--update")
	if s.autoUpdate {
		s.say("signed updates are checked daily at login; to update now run: %s", update)
	} else {
		s.say("automatic updates are off; to update run: %s", update)
	}
	s.say("stop it with: %s", stop)
	return nil
}

// startNode starts the node service and checks the node is still running a
// moment later.
func (s *setup) startNode(svc *winsvc.Service) (int, error) {
	pid, _, err := svc.Start()
	if err != nil {
		return 0, fmt.Errorf("could not start the node: %w", err)
	}
	s.sleep(startCheck)
	running, err := s.procs.Running(pid, svc.Exe)
	if err != nil {
		return 0, fmt.Errorf("could not check the node started: %w", err)
	}
	if !running {
		return 0, fmt.Errorf("the node did not start; see its log, %s", svc.LogPath())
	}
	return pid, nil
}

var (
	createdAddress = regexp.MustCompile(`(?m)^Public address of the key:\s*(0x[0-9a-fA-F]{40})\s*$`)
	configAddress  = regexp.MustCompile(`(?m)^Etherbase = "(0x[0-9a-fA-F]{40})"\r?$`)
)

// configure writes the config with a new mining address, unless there is
// one, and returns the mining address.
func (s *setup) configure() (string, error) {
	config := s.configPath()
	if blob, err := os.ReadFile(config); err == nil {
		s.say("keeping the existing config %s", config)
		if m := configAddress.FindSubmatch(blob); m != nil {
			return string(m[1]), nil
		}
		return "(the existing config names none)", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("could not read the config: %w", err)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("could not make a password for the mining key: %w", err)
	}
	if err := os.WriteFile(s.password(), []byte(hex.EncodeToString(secret[:])+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("could not write the password of the mining key: %w", err)
	}
	out, err := s.runGeth(s.gethPath(), "--datadir", s.dataDir(), "account", "new", "--password", s.password())
	if err != nil {
		return "", fmt.Errorf("could not create the mining key: %v %s", err, lastLines(out))
	}
	m := createdAddress.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("could not read the new mining address from: %s", lastLines(out))
	}
	address := string(m[1])

	var b strings.Builder
	fmt.Fprintf(&b, "# The Ghost node's config, written by ghost-setup. The node mines to Etherbase,\n")
	fmt.Fprintf(&b, "# whose key is in the keystore of DataDir, locked with the password in\n")
	fmt.Fprintf(&b, "# %s. Its HTTP RPC listens on this computer only,\n# for the Ghost web apps.\n\n", s.password())
	fmt.Fprintf(&b, "[Eth.Miner]\nEtherbase = %q\n\n", address)
	dataDir, err := tomlString(s.dataDir())
	if err != nil {
		return "", err
	}
	origins := make([]string, len(webOrigins))
	for i, o := range webOrigins {
		origins[i] = strconv.Quote(o)
	}
	fmt.Fprintf(&b, "[Node]\nDataDir = %s\nHTTPHost = \"127.0.0.1\"\nHTTPPort = %d\n", dataDir, s.httpPort)
	fmt.Fprintf(&b, "HTTPModules = [\"eth\", \"net\", \"web3\"]\nHTTPCors = [%s]\n", strings.Join(origins, ", "))
	if err := writeFileAtomic(config, []byte(b.String())); err != nil {
		return "", fmt.Errorf("could not write the config: %w", err)
	}
	return address, nil
}

// initialise writes the genesis of the release's network into a new data
// directory. A release with the network built in has no genesis.json.
func (s *setup) initialise(rel *release) error {
	if rel.genesis == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(s.dataDir(), "geth", "chaindata")); err == nil {
		return nil
	}
	if out, err := s.runGeth(s.gethPath(), "--datadir", s.dataDir(), "init", rel.genesis); err != nil {
		return fmt.Errorf("could not initialise the chain: %v %s", err, lastLines(out))
	}
	return nil
}

// update installs the latest release over the installed node and restarts
// it, keeping the previous geth.exe until the new one runs. daily makes it
// check at most once a day.
func (s *setup) update(daily bool) error {
	if !isFile(s.gethPath()) || !isFile(s.configPath()) {
		return fmt.Errorf("there is no Ghost node installed in %s to update; install one with: %s", s.home, installLine)
	}
	if daily {
		if s.checkedRecently() {
			return nil
		}
		// A check that fails is not retried until tomorrow either.
		if err := writeFileAtomic(s.stampPath(), []byte(s.now().UTC().Format(time.RFC3339)+"\n")); err != nil {
			return fmt.Errorf("could not record the update check: %w", err)
		}
	}
	work, err := s.workDir()
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	rel, err := s.fetchRelease(work)
	if err != nil {
		return fmt.Errorf("%v; refusing to update. Nothing was changed, and the running node was left alone", err)
	}
	have, err := fileSum(s.gethPath())
	if err != nil {
		return err
	}
	if have == rel.sum {
		s.say("the node is up to date")
		return nil
	}

	svc := s.service()
	if _, err := svc.Stop(); err != nil {
		return fmt.Errorf("could not stop the node to update it: %w; nothing was changed", err)
	}
	geth, previous := s.gethPath(), s.gethPath()+".previous"
	if err := copyFile(geth, previous); err != nil {
		os.Remove(previous)
		s.startNode(svc)
		return fmt.Errorf("could not keep the previous %s: %w; nothing was changed", gethExeName, err)
	}
	if err := installFile(rel.geth, geth); err != nil {
		os.Remove(previous)
		s.startNode(svc)
		return fmt.Errorf("could not install the new %s: %w; nothing was changed", gethExeName, err)
	}
	_, startErr := s.startNode(svc)
	if startErr == nil {
		os.Remove(previous)
		s.say("updated the node to the latest release and restarted it")
		return nil
	}
	svc.Stop()
	if err := os.Rename(previous, geth); err != nil {
		return fmt.Errorf("the updated node did not start (%v), and the previous %s could not be put back: %v; it is %s", startErr, gethExeName, err, previous)
	}
	if _, err := s.startNode(svc); err != nil {
		return fmt.Errorf("the updated node did not start (%v), so the previous %s was put back, but it did not start either: %v", startErr, gethExeName, err)
	}
	return fmt.Errorf("the updated node did not start (%v), so the previous %s was put back and restarted", startErr, gethExeName)
}

// checkedRecently reports whether the daily update checked less than a day
// ago.
func (s *setup) checkedRecently() bool {
	blob, err := os.ReadFile(s.stampPath())
	if err != nil {
		return false
	}
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(blob)))
	if err != nil {
		return false
	}
	since := s.now().Sub(last)
	return since >= 0 && since < updateInterval
}

// tomlString returns s as a TOML basic string.
func tomlString(s string) (string, error) {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("the path %q holds a control character", s)
		}
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`, nil
}

func isFile(name string) bool {
	fi, err := os.Stat(name)
	return err == nil && fi.Mode().IsRegular()
}

func fileSum(name string) ([32]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// installFile copies src over dst through a new file renamed into place. A
// src that is dst already is left as it is.
func installFile(src, dst string) error {
	if a, err := os.Stat(src); err == nil {
		if b, err := os.Stat(dst); err == nil && os.SameFile(a, b) {
			return nil
		}
	}
	tmp := dst + ".new"
	if err := copyFile(src, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if serr := out.Sync(); err == nil {
		err = serr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

func writeFileAtomic(name string, data []byte) error {
	tmp := name + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// lastLines returns the last lines of a command's output, for an error.
func lastLines(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return strings.TrimSpace(strings.Join(lines, " "))
}
