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
	t.Helper()
	tmp := t.TempDir()
	cmd := exec.Command("/bin/sh", "pin-verifier-hashes.sh", script, dir)
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
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
