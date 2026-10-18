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

// Package securitydocs checks the repository's security documents: the
// security policy, the emergency release procedure and the backport log.
package securitydocs

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	policyFile    = "SECURITY.md"
	emergencyFile = "docs/emergency-release.md"
	backportsFile = "SECURITY-BACKPORTS.md"

	logHeader = "| Logged | Source | Item | Status | Evidence |"
)

// repoRoot is the repository root, relative to this package's directory.
var repoRoot = filepath.Join("..", "..")

func readDoc(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

var linkRE = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// localLinks returns the targets of the document's Markdown links that point
// into the repository, without any #fragment.
func localLinks(doc string) []string {
	var links []string
	for _, m := range linkRE.FindAllStringSubmatch(doc, -1) {
		target := m[1]
		if strings.Contains(target, ":") || strings.HasPrefix(target, "#") {
			continue
		}
		if i := strings.IndexByte(target, '#'); i >= 0 {
			target = target[:i]
		}
		links = append(links, target)
	}
	return links
}

// checkLinks reports every local link in the document whose target does not
// exist, and returns the links resolved to repository-relative paths.
func checkLinks(t *testing.T, name, doc string) map[string]bool {
	t.Helper()
	resolved := make(map[string]bool)
	for _, link := range localLinks(doc) {
		rel := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(name), filepath.FromSlash(link))))
		resolved[rel] = true
		if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s links to %s, which does not exist: %v", name, link, err)
		}
	}
	return resolved
}

// headings returns the document's level-two headings in order.
func headings(doc string) []string {
	var hs []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "## ") {
			hs = append(hs, strings.TrimSpace(strings.TrimPrefix(line, "## ")))
		}
	}
	return hs
}

// section returns the text under the level-two heading, up to the next one.
func section(doc, heading string) (string, bool) {
	lines := strings.Split(doc, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "## "+heading {
			continue
		}
		var body []string
		for _, l := range lines[i+1:] {
			if strings.HasPrefix(l, "## ") {
				break
			}
			body = append(body, l)
		}
		return strings.Join(body, "\n"), true
	}
	return "", false
}

func normalizeRow(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	cells := strings.Split(line, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

var separatorRE = regexp.MustCompile(`^\|(\s*:?-+:?\s*\|)+$`)

// logRows returns the rows of every table in the document whose header is the
// backport log header. It fails the test on a log table without a separator.
func logRows(t *testing.T, doc string) [][]string {
	t.Helper()
	var rows [][]string
	lines := strings.Split(doc, "\n")
	for i := 0; i < len(lines); i++ {
		if normalizeRow(lines[i]) != logHeader {
			continue
		}
		if i+1 >= len(lines) || !separatorRE.MatchString(strings.TrimSpace(lines[i+1])) {
			t.Errorf("log table at line %d has no separator row", i+1)
			continue
		}
		for i += 2; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|"); i++ {
			rows = append(rows, splitRow(lines[i]))
		}
	}
	return rows
}

func TestSecurityPolicy(t *testing.T) {
	doc := readDoc(t, policyFile)
	for _, want := range []string{
		"hello@ghostcoin.com",
		"until a dedicated security address exists",
		"**Primary maintainer:** GhostcoinHQ",
		"**Backup maintainer:** to be named by the founder",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s does not contain %q", policyFile, want)
		}
	}
	hs := headings(doc)
	for _, want := range []string{"Maintainers", "What this policy covers"} {
		if !slices.Contains(hs, want) {
			t.Errorf("%s has no %q section", policyFile, want)
		}
	}
	links := checkLinks(t, policyFile, doc)
	for _, want := range []string{emergencyFile, backportsFile} {
		if !links[want] {
			t.Errorf("%s does not link to %s", policyFile, want)
		}
	}
}

func TestEmergencyReleaseProcedure(t *testing.T) {
	doc := readDoc(t, emergencyFile)
	hs := headings(doc)
	for _, want := range []string{
		"Who builds",
		"Who signs",
		"How operators are told",
		"Release signing is not chain authority",
	} {
		if !slices.Contains(hs, want) {
			t.Errorf("%s has no %q heading", emergencyFile, want)
		}
	}
	body, _ := section(doc, "Release signing is not chain authority")
	if !strings.Contains(body, "Release signing is not chain authority.") {
		t.Errorf("%s does not state the sentence %q", emergencyFile, "Release signing is not chain authority.")
	}
	checkLinks(t, emergencyFile, doc)
}

func TestBackportsLog(t *testing.T) {
	doc := readDoc(t, backportsFile)
	lines := strings.Split(doc, "\n")
	if !slices.Contains(lines, "**Owner:** GhostcoinHQ (primary maintainer)") {
		t.Errorf("%s has no owner line", backportsFile)
	}
	want := []string{"Routine", "Status values", "Inventory since go-ethereum 1.13.15", "Log"}
	if hs := headings(doc); !slices.Equal(hs, want) {
		t.Errorf("%s sections are %q, want %q", backportsFile, hs, want)
	}
	routine, _ := section(doc, "Routine")
	if !strings.Contains(routine, "7 days") {
		t.Errorf("%s routine does not say %q", backportsFile, "7 days")
	}
	checkLinks(t, backportsFile, doc)

	rows := logRows(t, doc)
	if len(rows) == 0 {
		t.Fatalf("%s has no logged rows", backportsFile)
	}
	statuses := map[string]bool{"applied": true, "not applicable": true, "open": true}
	for i, row := range rows {
		if len(row) != 5 {
			t.Errorf("log row %d has %d cells, want 5: %q", i+1, len(row), row)
			continue
		}
		if row[0] == "" || row[2] == "" {
			t.Errorf("log row %d has an empty Logged or Item cell", i+1)
		}
		if row[1] == "" {
			t.Errorf("log row %d has no Source", i+1)
		}
		if !statuses[row[3]] {
			t.Errorf("log row %d has status %q, want applied, not applicable or open", i+1, row[3])
		}
		if row[4] == "" {
			t.Errorf("log row %d has no Evidence", i+1)
		}
	}
}

var placeholderRE = regexp.MustCompile(`(?i)\b(todo|tbd|fixme|xxx|lorem|ipsum)\b`)

func TestNoPlaceholderText(t *testing.T) {
	for _, name := range []string{policyFile, emergencyFile, backportsFile} {
		for i, line := range strings.Split(readDoc(t, name), "\n") {
			if m := placeholderRE.FindString(line); m != "" {
				t.Errorf("%s:%d contains placeholder text %q", name, i+1, m)
			}
		}
	}
}
