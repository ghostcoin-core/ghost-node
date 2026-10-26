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
	"os"
	"regexp"
	"strings"
	"testing"
)

// windowsScript is what TestWindowsInstallerScripts looks for in one of the
// two Windows installer scripts. Each literal must be a whole line of the
// script's code, or a part of one.
type windowsScript struct {
	file      string
	isComment func(line string) bool

	hashes     *regexp.Regexp // the pinned SHA-256 of each ghost-setup, by arch
	releaseURL *regexp.Regexp // the default release URL
	httpsCheck string         // refuses a GHOST_RELEASE_URL that is not https
	name       string         // the name of the setup executable
	nameCheck  string         // refuses the placeholder hash
	download   string         // downloads the setup executable
	hashFile   string         // hashes it
	compare    string         // compares the hash with the pinned one
	refuse     string         // stops, on a mismatch
	runLine    string         // runs it: the one line that does
}

var windowsScripts = []windowsScript{
	{
		file:       "install.ps1",
		isComment:  func(line string) bool { return strings.HasPrefix(line, "#") },
		hashes:     regexp.MustCompile(`(?m)^(amd64|arm64) = '([0-9a-f]{64})'$`),
		releaseURL: regexp.MustCompile(`(?m)^\$ReleaseUrl = '(https://[^']+)'$`),
		httpsCheck: `if (-not $ReleaseUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {`,
		name:       `$Name = "ghost-setup-windows-$Arch.exe"`,
		nameCheck:  `if ($Pinned -eq $Placeholder) {`,
		download:   `& curl.exe @CurlArgs "$ReleaseUrl/$Name"`,
		hashFile:   `$Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Setup).Hash.ToLowerInvariant()`,
		compare:    `if ($Hash -ne $Pinned) {`,
		refuse:     `throw `,
		runLine:    `& $Setup`,
	},
	{
		file: "install.cmd",
		isComment: func(line string) bool {
			lower := strings.ToLower(line)
			return lower == "rem" || strings.HasPrefix(lower, "rem ") || strings.HasPrefix(line, "::")
		},
		hashes:     regexp.MustCompile(`(?m)^set "SETUP_SHA256_(amd64|arm64)=([0-9a-f]{64})"$`),
		releaseURL: regexp.MustCompile(`(?m)^set "RELEASE_URL=(https://[^"]+)"$`),
		httpsCheck: `if /i not "%RELEASE_URL:~0,8%"=="https://" (`,
		name:       `set "NAME=ghost-setup-windows-%ARCH%.exe"`,
		nameCheck:  `if "%PINNED%"=="%PLACEHOLDER%" (`,
		download:   `--output "%SETUP%" "%RELEASE_URL%/%NAME%"`,
		hashFile:   `('certutil -hashfile "%SETUP%" SHA256')`,
		compare:    `if /i not "%HASH%"=="%PINNED%" (`,
		refuse:     `exit /b 1`,
		runLine:    `"%SETUP%"`,
	},
}

// code returns the script's lines that are not comments or blank, trimmed.
func (ws windowsScript) code(t *testing.T) []string {
	t.Helper()
	blob, err := os.ReadFile(ws.file)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(blob), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !ws.isComment(line) {
			lines = append(lines, line)
		}
	}
	return lines
}

// find returns the index of the only code line that contains s.
func find(t *testing.T, file string, code []string, s string) int {
	t.Helper()
	at := -1
	for i, line := range code {
		if strings.Contains(line, s) {
			if at >= 0 {
				t.Errorf("%s: more than one line holds %q", file, s)
			}
			at = i
		}
	}
	if at < 0 {
		t.Errorf("%s: no line holds %q", file, s)
	}
	return at
}

func TestWindowsInstallerScripts(t *testing.T) {
	setupSource, err := os.ReadFile("winsetup/setup.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`defaultReleaseURL = "([^"]+)"`).FindSubmatch(setupSource)
	if m == nil {
		t.Fatal("winsetup/setup.go names no defaultReleaseURL")
	}
	setupURL := string(m[1])

	var hashes []map[string]string
	for _, ws := range windowsScripts {
		code := ws.code(t)
		text := strings.Join(code, "\n")

		// It pins a SHA-256 for each processor.
		pinned := make(map[string]string)
		for _, m := range ws.hashes.FindAllStringSubmatch(text, -1) {
			pinned[m[1]] = m[2]
		}
		if len(pinned) != 2 {
			t.Errorf("%s pins %d ghost-setup hashes, not one for each of amd64 and arm64", ws.file, len(pinned))
		}
		hashes = append(hashes, pinned)

		// It names the release URL ghost-setup does, and the setup executable.
		urls := ws.releaseURL.FindAllStringSubmatch(text, -1)
		if len(urls) != 1 || urls[0][1] != setupURL {
			t.Errorf("%s does not name the release URL %s as its default: %q", ws.file, setupURL, urls)
		}
		find(t, ws.file, code, ws.httpsCheck)
		find(t, ws.file, code, ws.name)
		find(t, ws.file, code, "refusing to install. Nothing was installed.")

		// It checks the hash before it runs the executable, and refuses on a
		// mismatch.
		order := []string{ws.httpsCheck, ws.nameCheck, ws.download, ws.hashFile, ws.compare}
		at := make([]int, len(order), len(order)+1)
		for i, s := range order {
			at[i] = find(t, ws.file, code, s)
		}
		run := -1
		for i, line := range code {
			if line == ws.runLine {
				if run >= 0 {
					t.Errorf("%s runs ghost-setup twice", ws.file)
				}
				run = i
			}
		}
		if run < 0 {
			t.Errorf("%s has no line %q that runs ghost-setup", ws.file, ws.runLine)
		}
		order, at = append(order, ws.runLine), append(at, run)
		for i := 1; i < len(order); i++ {
			if at[i] <= at[i-1] {
				t.Errorf("%s: %q does not come after %q", ws.file, order[i], order[i-1])
			}
		}
		// The placeholder and the hash checks stop in their block, saying
		// nothing was installed.
		for _, check := range []int{at[1], at[4]} {
			if check < 0 {
				continue
			}
			end := check + 1
			for end < len(code) && code[end] != "}" && code[end] != ")" {
				end++
			}
			block := strings.Join(code[check+1 : end], "\n")
			if !strings.Contains(block, ws.refuse) || !strings.Contains(block, "%REFUSAL%") && !strings.Contains(block, "$Refusal") || strings.Contains(block, ws.runLine) {
				t.Errorf("%s: the check %q does not refuse to install:\n%s", ws.file, code[check], block)
			}
		}

		// Nothing else runs a program, and nothing elevates or leaves https.
		lower := strings.ToLower(text)
		for _, banned := range []string{
			"runas", "-verb", "hklm", "hkey_local_machine", "local_machine", "start-process", "invoke-expression",
			"iex", "invoke-item", "reg add", "reg.exe", "schtasks", "sc create", "sc.exe", "http://", "-k ", "--insecure",
		} {
			if strings.Contains(lower, banned) {
				t.Errorf("%s holds %q", ws.file, banned)
			}
		}
	}
	if len(hashes) == 2 && (hashes[0]["amd64"] != hashes[1]["amd64"] || hashes[0]["arm64"] != hashes[1]["arm64"]) {
		t.Errorf("install.ps1 and install.cmd pin different ghost-setup hashes: %v and %v", hashes[0], hashes[1])
	}

	// The PowerShell script is one script block, so a download cut short runs
	// nothing.
	ps1 := windowsScripts[0].code(t)
	if len(ps1) < 2 || ps1[0] != "& {" || ps1[len(ps1)-1] != "}" {
		t.Error("install.ps1 is not one script block run at its last line")
	}

	// The README gives both lines, and they fetch these scripts' names.
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"irm https://get.ghostcoin.com/win | iex",
		`curl -fsSL https://get.ghostcoin.com/win.cmd -o "%TEMP%\ghost-install.cmd" && "%TEMP%\ghost-install.cmd" && del "%TEMP%\ghost-install.cmd"`,
	} {
		if !strings.Contains(string(readme), line) {
			t.Errorf("README.md does not give the line %s", line)
		}
	}
}
