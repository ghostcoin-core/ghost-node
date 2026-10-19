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

package securitydocs

import (
	"regexp"
	"strings"
	"testing"
)

// noUpstreamFixPrefix starts the Evidence of the only kind of row that may
// stay open: an advisory for which upstream has published no fix.
const noUpstreamFixPrefix = "no upstream fix:"

// advisoryRE matches an advisory identifier: a GitHub security advisory, a
// CVE or a Go vulnerability database entry.
var advisoryRE = regexp.MustCompile(`\b(GHSA(-[23456789cfghjmpqrvwx]{4}){3}|CVE-\d{4}-\d{4,}|GO-\d{4}-\d{4,})\b`)

// openRowProblem returns why a five-cell log row may not be open, or "" if
// the row is not open or is an advisory with no upstream fix.
func openRowProblem(row []string) string {
	if row[3] != "open" {
		return ""
	}
	evidence := row[4]
	if !strings.HasPrefix(evidence, noUpstreamFixPrefix) {
		return "an open row must be an advisory with no upstream fix, its Evidence starting with " + `"` + noUpstreamFixPrefix + `"`
	}
	if !advisoryRE.MatchString(strings.TrimPrefix(evidence, noUpstreamFixPrefix)) {
		return "the Evidence of an open row does not name the advisory (GHSA, CVE or GO identifier)"
	}
	return ""
}

// TestNoOpenItemsRemain checks the end condition of the security catch-up:
// every logged upstream fix is applied or not applicable, and a row stays
// open only for an advisory upstream has not fixed.
func TestNoOpenItemsRemain(t *testing.T) {
	rows := logRows(t, readDoc(t, backportsFile))
	if len(rows) == 0 {
		t.Fatalf("%s has no logged rows", backportsFile)
	}
	for i, row := range rows {
		if len(row) != 5 {
			t.Errorf("log row %d has %d cells, want 5: %q", i+1, len(row), row)
			continue
		}
		if problem := openRowProblem(row); problem != "" {
			t.Errorf("log row %d (%s) is open: %s", i+1, row[2], problem)
		}
	}
}

// TestOpenRowProblem checks the rule TestNoOpenItemsRemain applies to each row.
func TestOpenRowProblem(t *testing.T) {
	row := func(status, evidence string) []string {
		return []string{"2026-10-18", "example source", "example item", status, evidence}
	}
	tests := []struct {
		name string
		row  []string
		ok   bool
	}{
		{"applied", row("applied", "`b42b8c437`"), true},
		{"not applicable", row("not applicable", "the code is removed"), true},
		{"open without upstream fix", row("open", "no upstream fix: GHSA-4xc9-8hmq-j652 has no patched release"), true},
		{"open CVE", row("open", "no upstream fix: CVE-2026-22868, no patched release"), true},
		{"open Go advisory", row("open", "no upstream fix: GO-2026-5932, unsafe by design"), true},
		{"open pending backport", row("open", "not yet checked against this code"), false},
		{"open prefix not first", row("open", "pending; no upstream fix: CVE-2026-22868"), false},
		{"open without advisory", row("open", "no upstream fix: none published yet"), false},
	}
	for _, test := range tests {
		problem := openRowProblem(test.row)
		if ok := problem == ""; ok != test.ok {
			t.Errorf("%s: accepted %v, want %v (problem %q)", test.name, ok, test.ok, problem)
		}
	}
}
