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
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The platforms whose ghost-verify the release publishes and install.sh pins.
var verifierPlatforms = []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}

// runPin runs pin-verifier-hashes.sh on the script with the release folder
// dir, and checks that it leaves nothing in its temporary directory.
func runPin(t *testing.T, script, dir string) (string, error) {
	return runPinEnv(t, script, dir, nil)
}

// runPinEnv is runPin with the variables env added to an environment that
// holds none of the GITHUB_ variables of the computer running the tests.
func runPinEnv(t *testing.T, script, dir string, env []string) (string, error) {
	t.Helper()
	tmp := t.TempDir()
	cmd := exec.Command("/bin/sh", "pin-verifier-hashes.sh", script, dir)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GITHUB_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "TMPDIR="+tmp)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	t.Logf("pin-verifier-hashes.sh output:\n%s", out)
	if left := entries(t, tmp); len(left) != 0 {
		t.Fatalf("pin-verifier-hashes.sh left %v in the temporary directory", left)
	}
	return string(out), err
}

// releaseDir writes a release folder holding a ghost-verify-<os>-<arch> for
// each platform, files[platform] or, where files has none, a stand-in with
// content of its own. It returns the folder and the files' contents.
func releaseDir(t *testing.T, files map[string][]byte) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	content := make(map[string][]byte)
	for _, platform := range verifierPlatforms {
		blob, ok := files[platform]
		if !ok {
			blob = []byte("stand-in ghost-verify for " + platform + "\n")
		}
		content[platform] = blob
		if err := os.WriteFile(filepath.Join(dir, "ghost-verify-"+platform), blob, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, content
}

// editScript rewrites the script at path with edit.
func editScript(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(edit(string(blob))), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestPinVerifierHashesInstalls pins the hashes of a release folder's
// ghost-verify files in install.sh, as the release does before it signs the
// script, and checks that each line pins its own file, that nothing else of
// the script changes, and that the pinned script installs from that release on
// Linux and on a Mac instead of refusing at the placeholder.
func TestPinVerifierHashesInstalls(t *testing.T) {
	release, geth := internalNetRelease(t)
	verifier := builtVerifier(t)
	// The darwin checker served on this Linux computer is the same program
	// with bytes appended, which it ignores, so that the two hashes differ.
	darwinVerifier := append(append([]byte(nil), verifier...), []byte("\nthe darwin build\n")...)
	dir, content := releaseDir(t, map[string][]byte{
		"linux-" + runtime.GOARCH:  verifier,
		"darwin-" + runtime.GOARCH: darwinVerifier,
	})
	key := newSigner(t)
	script := writeScript(t, key, "")
	before, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runPin(t, script, dir); err != nil {
		t.Fatalf("pin-verifier-hashes.sh failed: %v", err)
	}
	after, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	pinned := pinnedHashes(t, string(after))
	for _, platform := range verifierPlatforms {
		if want := sha256Hex(content[platform]); pinned[platform] != want {
			t.Errorf("install.sh pins %s for ghost-verify-%s, not its SHA-256 %s", pinned[platform], platform, want)
		}
	}
	oldLines, newLines := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	if len(oldLines) != len(newLines) {
		t.Fatalf("pinning changed install.sh from %d lines to %d", len(oldLines), len(newLines))
	}
	changed := 0
	for i := range oldLines {
		if oldLines[i] == newLines[i] {
			continue
		}
		changed++
		if !hashLine.MatchString(newLines[i]) || strings.Fields(oldLines[i])[0] != strings.Fields(newLines[i])[0] {
			t.Errorf("pinning changed line %d of install.sh from %q to %q", i+1, oldLines[i], newLines[i])
		}
	}
	if changed != len(verifierPlatforms) {
		t.Fatalf("pinning changed %d lines of install.sh, not one for each of the %d checkers", changed, len(verifierPlatforms))
	}
	if strings.Count(string(after), strings.Repeat("0", 64)) != 1 {
		t.Fatal("the pinned install.sh still holds the placeholder outside placeholder_hash")
	}

	blob := release.tarGz(t)
	t.Run("linux", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl})
		installRunning(t, env, script, rs, geth)
		checkServedRelease(t, rs, 0)
	})
	t.Run("darwin", func(t *testing.T) {
		rs := serveRelease(t, "darwin", blob, key.sign(blob), darwinVerifier)
		env := newInstallEnv(t, envOptions{darwin: true, stockMac: true})
		installRunning(t, env, script, rs, geth)
		checkServedRelease(t, rs, 0)
	})
	t.Run("another platform's checker", func(t *testing.T) {
		// The linux checker served as the darwin one is refused: each line
		// pins its own file.
		marker := filepath.Join(t.TempDir(), "ran")
		other := archive{"geth": fakeGeth(marker)}.tarGz(t)
		rs := serveRelease(t, "darwin", other, key.sign(other), verifier)
		env := newInstallEnv(t, envOptions{darwin: true, stockMac: true})
		out, err := env.run(t, script, rs, true)
		checkRefused(t, env, out, err, "not the "+sha256Hex(darwinVerifier)+" pinned in this installer", marker)
	})
}

// TestPinVerifierHashesRefuses checks that pin-verifier-hashes.sh fails, and
// leaves the script as it was, for a release folder or a script it cannot
// fully pin: the release must not sign an install.sh that refuses everyone.
func TestPinVerifierHashesRefuses(t *testing.T) {
	zero := strings.Repeat("0", 64)
	for _, tc := range []struct {
		name   string
		folder func(t *testing.T, dir string)
		script func(string) string
		want   string
	}{
		{
			name:   "a checker missing",
			folder: func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, "ghost-verify-darwin-arm64")) },
			want:   "there is no ghost-verify-darwin-arm64 in",
		},
		{
			name: "an empty checker",
			folder: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "ghost-verify-linux-amd64"), nil, 0755); err != nil {
					t.Fatal(err)
				}
			},
			want: "there is no ghost-verify-linux-amd64 in",
		},
		{
			name:   "a placeholder line missing",
			script: func(s string) string { return strings.Replace(s, "linux-arm64 "+zero+"\n", "", 1) },
			want:   "has 0 placeholder lines for ghost-verify-linux-arm64, not one",
		},
		{
			name: "a placeholder line twice",
			script: func(s string) string {
				line := "darwin-amd64 " + zero + "\n"
				return strings.Replace(s, line, line+line, 1)
			},
			want: "has 2 placeholder lines for ghost-verify-darwin-amd64, not one",
		},
		{
			name: "a placeholder left over",
			script: func(s string) string {
				line := "darwin-arm64 " + zero + "\n"
				return strings.Replace(s, line, line+"freebsd-amd64 "+zero+"\n", 1)
			},
			want: "still pins the placeholder for: freebsd-amd64",
		},
		{
			name: "already pinned",
			script: func(s string) string {
				return hashLine.ReplaceAllString(s, "${1}-${2} "+strings.Repeat("ab", 32))
			},
			want: "has 0 placeholder lines for ghost-verify-linux-amd64, not one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := releaseDir(t, nil)
			if tc.folder != nil {
				tc.folder(t, dir)
			}
			script := writeScript(t, newSigner(t), "")
			if tc.script != nil {
				editScript(t, script, tc.script)
			}
			before, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			out, err := runPin(t, script, dir)
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("pin-verifier-hashes.sh did not fail: %v", err)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("pin-verifier-hashes.sh did not say %q", tc.want)
			}
			after, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("a refused pinning changed the script")
			}
		})
	}
}

const (
	latestURL = "https://github.com/ghostcoin-core/ghost-node/releases/latest/download"
	// The commit and run a release in GitHub Actions is built from, and the
	// download URL of the release the publish step makes of them.
	testRunNumber = "21"
	testSHA       = "478f05260a1bc2d3e4f5a6b7c8d9e0f1a2b3c4d5"
	taggedURL     = "https://github.com/ghostcoin-core/ghost-node/releases/download/build-21-478f05260a1b"
)

// The installers the release publishes, as they are in dist.
var installerNames = []string{"install.sh", "install.ps1", "install.cmd"}

// actionsEnv is the environment GitHub Actions gives the release's steps.
var actionsEnv = []string{"GITHUB_ACTIONS=true", "GITHUB_RUN_NUMBER=" + testRunNumber, "GITHUB_SHA=" + testSHA}

// distDir writes a release folder like the release's dist when it pins the
// hashes: the ghost-verify files and copies of the repository's installers,
// each passed through edit[name] where it has one. It returns the folder and
// the installers' contents.
func distDir(t *testing.T, edit map[string]func(string) string) (string, map[string]string) {
	t.Helper()
	dir, _ := releaseDir(t, nil)
	content := make(map[string]string)
	for _, name := range installerNames {
		blob, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(blob)
		if strings.Count(text, latestURL) != 1 {
			t.Fatalf("the repository's %s does not hold %s once", name, latestURL)
		}
		if e := edit[name]; e != nil {
			text = e(text)
		}
		content[name] = text
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, content
}

// readInstallers returns the contents of the installers in dir.
func readInstallers(t *testing.T, dir string) map[string]string {
	t.Helper()
	content := make(map[string]string)
	for _, name := range installerNames {
		blob, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		content[name] = string(blob)
	}
	return content
}

// TestPinReleaseURLRewrite checks that in GitHub Actions the release pins the
// installers it publishes to its own release, the one whose ghost-verify
// hashes install.sh pins, and changes nothing else in them.
func TestPinReleaseURLRewrite(t *testing.T) {
	dir, before := distDir(t, nil)
	out, err := runPinEnv(t, filepath.Join(dir, "install.sh"), dir, actionsEnv)
	if err != nil {
		t.Fatalf("pin-verifier-hashes.sh failed: %v", err)
	}
	if !strings.Contains(out, "pinned the release URL "+taggedURL) {
		t.Errorf("pin-verifier-hashes.sh did not say it pinned %s", taggedURL)
	}
	after := readInstallers(t, dir)
	for _, name := range installerNames {
		if n := strings.Count(after[name], taggedURL); n != 1 {
			t.Errorf("%s holds %s %d times, not once", name, taggedURL, n)
		}
		if strings.Contains(after[name], latestURL) || strings.Contains(after[name], "releases/latest") {
			t.Errorf("%s still downloads from the latest release", name)
		}
		// Apart from the URL, and install.sh's hashes, nothing changes.
		restored := strings.Replace(after[name], taggedURL, latestURL, 1)
		if name == "install.sh" {
			restored = hashLine.ReplaceAllString(restored, "${1}-${2} "+strings.Repeat("0", 64))
		}
		if restored != before[name] {
			t.Errorf("pinning changed %s beyond its release URL", name)
		}
	}
	// The override still comes first.
	if !strings.Contains(after["install.sh"], "release_url=${GHOST_RELEASE_URL:-"+taggedURL+"}\n") {
		t.Error("the pinned install.sh does not keep GHOST_RELEASE_URL as an override of the release URL")
	}
	if !strings.Contains(after["install.ps1"], "$ReleaseUrl = '"+taggedURL+"'") {
		t.Error("the pinned install.ps1 does not default $ReleaseUrl to the release URL")
	}
	if !strings.Contains(after["install.cmd"], `set "RELEASE_URL=`+taggedURL+`"`) {
		t.Error("the pinned install.cmd does not default RELEASE_URL to the release URL")
	}
	pinned := pinnedHashes(t, after["install.sh"])
	for _, platform := range verifierPlatforms {
		if pinned[platform] == strings.Repeat("0", 64) {
			t.Errorf("install.sh still pins the placeholder for ghost-verify-%s", platform)
		}
	}
}

// TestPinReleaseURLNoRewriteOutsideActions checks that outside GitHub Actions
// the installers keep downloading from the latest release.
func TestPinReleaseURLNoRewriteOutsideActions(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{name: "no GITHUB_ACTIONS"},
		{name: "GITHUB_ACTIONS not true", env: []string{"GITHUB_ACTIONS=false", "GITHUB_RUN_NUMBER=" + testRunNumber, "GITHUB_SHA=" + testSHA}},
		{name: "only the run and commit", env: []string{"GITHUB_RUN_NUMBER=" + testRunNumber, "GITHUB_SHA=" + testSHA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, before := distDir(t, nil)
			if _, err := runPinEnv(t, filepath.Join(dir, "install.sh"), dir, tc.env); err != nil {
				t.Fatalf("pin-verifier-hashes.sh failed: %v", err)
			}
			after := readInstallers(t, dir)
			for _, name := range installerNames {
				if strings.Count(after[name], latestURL) != 1 || strings.Contains(after[name], "releases/download/") {
					t.Errorf("%s does not download from the latest release any more", name)
				}
			}
			for _, name := range []string{"install.ps1", "install.cmd"} {
				if after[name] != before[name] {
					t.Errorf("pinning changed %s", name)
				}
			}
			restored := hashLine.ReplaceAllString(after["install.sh"], "${1}-${2} "+strings.Repeat("0", 64))
			if restored != before["install.sh"] {
				t.Error("pinning changed install.sh beyond its hashes")
			}
		})
	}
}

// TestPinReleaseURLRefuses checks that in GitHub Actions the pinning fails,
// and changes none of the installers, when it cannot tell the release's tag
// or cannot pin the URL in every installer: the release must not publish
// installers that download different releases.
func TestPinReleaseURLRefuses(t *testing.T) {
	without := func(drop string) []string {
		var env []string
		for _, kv := range actionsEnv {
			if !strings.HasPrefix(kv, drop+"=") {
				env = append(env, kv)
			}
		}
		return env
	}
	with := func(kv string) []string {
		return append(append([]string(nil), actionsEnv...), kv)
	}
	twice := func(s string) string { return strings.Replace(s, latestURL, latestURL+"\n"+latestURL, 1) }
	gone := func(s string) string {
		return strings.Replace(s, latestURL, "https://github.com/ghostcoin-core/ghost-node/releases/download/build-1-000000000000", 1)
	}
	for _, tc := range []struct {
		name string
		env  []string
		edit map[string]func(string) string
		want string
	}{
		{name: "no run number", env: without("GITHUB_RUN_NUMBER"), want: "GITHUB_RUN_NUMBER is not a positive integer"},
		{name: "an empty run number", env: with("GITHUB_RUN_NUMBER="), want: "GITHUB_RUN_NUMBER is not a positive integer"},
		{name: "a run number of zero", env: with("GITHUB_RUN_NUMBER=0"), want: "GITHUB_RUN_NUMBER is not a positive integer"},
		{name: "a run number not a number", env: with("GITHUB_RUN_NUMBER=21a"), want: "GITHUB_RUN_NUMBER is not a positive integer"},
		{name: "a negative run number", env: with("GITHUB_RUN_NUMBER=-21"), want: "GITHUB_RUN_NUMBER is not a positive integer"},
		{name: "no sha", env: without("GITHUB_SHA"), want: "GITHUB_SHA is not a hex commit hash"},
		{name: "a sha not hex", env: with("GITHUB_SHA=478f0526zz1bc2d3e4f5a6b7c8d9e0f1a2b3c4d5"), want: "GITHUB_SHA is not a hex commit hash"},
		{name: "a sha with a slash", env: with("GITHUB_SHA=478f05260a1b/c2d3e4f5"), want: "GITHUB_SHA is not a hex commit hash"},
		{name: "a short sha", env: with("GITHUB_SHA=478f05260a1"), want: "GITHUB_SHA is shorter than 12 characters"},
		{
			name: "install.sh without the URL",
			env:  actionsEnv,
			edit: map[string]func(string) string{"install.sh": gone},
			want: "install.sh holds the default release URL " + latestURL + " 0 times, not once",
		},
		{
			name: "install.ps1 without the URL",
			env:  actionsEnv,
			edit: map[string]func(string) string{"install.ps1": gone},
			want: "install.ps1 holds the default release URL " + latestURL + " 0 times, not once",
		},
		{
			name: "install.cmd with the URL twice",
			env:  actionsEnv,
			edit: map[string]func(string) string{"install.cmd": twice},
			want: "install.cmd holds the default release URL " + latestURL + " 2 times, not once",
		},
		{
			name: "install.sh with the URL twice on one line",
			env:  actionsEnv,
			edit: map[string]func(string) string{"install.sh": func(s string) string {
				return strings.Replace(s, latestURL, latestURL+" "+latestURL, 1)
			}},
			want: "install.sh holds the default release URL " + latestURL + " 2 times, not once",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, before := distDir(t, tc.edit)
			out, err := runPinEnv(t, filepath.Join(dir, "install.sh"), dir, tc.env)
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("pin-verifier-hashes.sh did not fail: %v", err)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("pin-verifier-hashes.sh did not say %q", tc.want)
			}
			after := readInstallers(t, dir)
			for _, name := range installerNames {
				if after[name] != before[name] {
					t.Errorf("a refused pinning changed %s", name)
				}
			}
		})
	}
	t.Run("an installer missing", func(t *testing.T) {
		dir, before := distDir(t, nil)
		if err := os.Remove(filepath.Join(dir, "install.cmd")); err != nil {
			t.Fatal(err)
		}
		out, err := runPinEnv(t, filepath.Join(dir, "install.sh"), dir, actionsEnv)
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("pin-verifier-hashes.sh did not fail: %v", err)
		}
		if !strings.Contains(out, "there is no install.cmd in") {
			t.Fatal("pin-verifier-hashes.sh did not say install.cmd is missing")
		}
		for _, name := range []string{"install.sh", "install.ps1"} {
			blob, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if string(blob) != before[name] {
				t.Errorf("a refused pinning changed %s", name)
			}
		}
	})
}
