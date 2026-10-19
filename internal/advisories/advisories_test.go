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

// Package advisories checks that the security catch-up inventory in
// SECURITY-BACKPORTS.md covers the known advisories and upstream fixes.
package advisories

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const backportsFile = "SECURITY-BACKPORTS.md"

// fixedModules gives, for each module with a fixable advisory, the lowest
// version that fixes all of its advisories. Modules are named by their path
// without the hosting domain; a go.mod requirement matches when its path ends
// in "/" and the name.
var fixedModules = []struct {
	name, fixed, advisories string
}{
	{"gorilla/websocket", "v1.5.3", "GO-2026-6278"},
	{"x/text", "v0.39.0", "GO-2026-5970"},
	{"x/net", "v0.55.0", "GO-2026-5026"},
	{"consensys/gnark-crypto", "v0.18.1", "GO-2025-4087"},
	{"golang-jwt/jwt/v4", "v4.5.2", "GO-2025-3553, GO-2024-3250"},
	{"tidwall/gjson", "v1.9.3", "GO-2022-0957, GO-2021-0265, GO-2021-0059, GO-2021-0054"},
}

// requirements returns the module requirements of the repository's go.mod.
func requirements(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	reqs := make(map[string]string)
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
			continue
		case inBlock && fields[0] == ")":
			inBlock = false
			continue
		case fields[0] == "require" && len(fields) == 2 && fields[1] == "(":
			inBlock = true
			continue
		case fields[0] == "require" && len(fields) == 3:
			fields = fields[1:]
		case !inBlock:
			continue
		}
		if len(fields) == 2 {
			reqs[fields[0]] = fields[1]
		}
	}
	return reqs
}

// parseVersion returns the major, minor and patch numbers of a vX.Y.Z version,
// ignoring any pre-release or build suffix.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// versionBelow reports whether version a is lower than version b.
func versionBelow(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func TestDependencyAdvisoriesFixed(t *testing.T) {
	reqs := requirements(t)
	for _, m := range fixedModules {
		var path, have string
		for p, v := range reqs {
			if strings.HasSuffix(p, "/"+m.name) {
				path, have = p, v
				break
			}
		}
		if path == "" {
			t.Errorf("go.mod does not require %s", m.name)
			continue
		}
		haveV, ok := parseVersion(have)
		if !ok {
			t.Errorf("go.mod requires %s at unparsable version %q", path, have)
			continue
		}
		fixedV, _ := parseVersion(m.fixed)
		if versionBelow(haveV, fixedV) {
			t.Errorf("go.mod requires %s %s, below %s which fixes %s", path, have, m.fixed, m.advisories)
		}
	}
}

// repoRoot is the repository root, relative to this package's directory.
var repoRoot = filepath.Join("..", "..")

// dependencyAdvisories are the Go module advisories govulncheck v1.1.4
// reported as reachable at the fork point.
var dependencyAdvisories = []string{
	"GO-2026-6278",
	"GO-2026-5970",
	"GO-2026-5932",
	"GO-2026-5026",
	"GO-2025-4087",
	"GO-2025-3553",
	"GO-2024-3250",
	"GO-2022-0957",
	"GO-2021-0265",
	"GO-2021-0059",
	"GO-2021-0054",
}

// coreGethItems are the rows of the fork-point comparison in
// docs/decisions/0001-fork-point.md and the two v1.13.0 hardening commits.
var coreGethItems = []string{
	"CVE-2026-26313",
	"CVE-2026-26314",
	"CVE-2026-26315",
	"CVE-2026-22862",
	"CVE-2025-24883",
	"CVE-2026-22868",
	"GHSA-mh3m-8c74-74xh",
	"#33803",
	"#30029",
	"2048",
	"delayed decoding",
	"034051590",
	"cb07055da",
}

// inventoryRows returns the table rows under the inventory heading.
func inventoryRows(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, backportsFile))
	if err != nil {
		t.Fatalf("reading %s: %v", backportsFile, err)
	}
	var (
		rows   []string
		inside bool
	)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "## ") {
			inside = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Inventory since go-ethereum 1.13.15"
			continue
		}
		if inside && strings.HasPrefix(strings.TrimSpace(line), "|") {
			rows = append(rows, line)
		}
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no inventory rows", backportsFile)
	}
	return rows
}

// rowStatus returns the Status cell of a five-column inventory row.
func rowStatus(row string) (string, bool) {
	row = strings.TrimSpace(row)
	row = strings.TrimSuffix(strings.TrimPrefix(row, "|"), "|")
	cells := strings.Split(row, "|")
	if len(cells) != 5 {
		return "", false
	}
	return strings.TrimSpace(cells[3]), true
}

func TestInventoryCoversEveryAdvisory(t *testing.T) {
	rows := inventoryRows(t)
	statuses := map[string]bool{"applied": true, "not applicable": true, "open": true}

	var want []string
	want = append(want, dependencyAdvisories...)
	want = append(want, coreGethItems...)
	for _, id := range want {
		found := false
		for _, row := range rows {
			if !strings.Contains(strings.ToLower(row), strings.ToLower(id)) {
				continue
			}
			status, ok := rowStatus(row)
			if !ok || !statuses[status] {
				continue
			}
			found = true
			break
		}
		if !found {
			t.Errorf("%s has no inventory row with a valid status for %q", backportsFile, id)
		}
	}
}
