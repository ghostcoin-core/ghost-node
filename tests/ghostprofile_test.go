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

package tests

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestProfileForksHaveFixtureConfigs reads the execution fixtures table of
// the published Ghost EVM profile and checks that every fixture fork it names
// is a configuration the fixture runner has, that the configuration switches
// on every EIP the row names, and that the CI job the table names runs the
// state and blockchain fixtures.
func TestProfileForksHaveFixtureConfigs(t *testing.T) {
	const (
		doc     = "../docs/ghost-evm-profile.md"
		section = "## Execution fixtures"
		header  = "| Profile fork | Fixture fork name | Run by |"
	)
	blob, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("the published profile is missing: %v", err)
	}
	lines := strings.Split(string(blob), "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == section {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: no %q section", doc, section)
	}
	var rows [][]string
	for i := start; i < len(lines) && !strings.HasPrefix(lines[i], "## "); i++ {
		if strings.TrimSpace(lines[i]) != header {
			continue
		}
		for _, line := range lines[i+2:] {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "|") {
				break
			}
			cells := strings.Split(strings.Trim(line, "|"), "|")
			for j, c := range cells {
				cells[j] = strings.TrimSpace(strings.ReplaceAll(c, "`", ""))
			}
			if len(cells) != 3 {
				t.Fatalf("%s: row %q has %d cells, want 3", doc, line, len(cells))
			}
			rows = append(rows, cells)
		}
		break
	}
	if len(rows) == 0 {
		t.Fatalf("%s: no rows in a table with the header %s", doc, header)
	}

	eip := regexp.MustCompile(`EIP-(\d+)`)
	for _, row := range rows {
		profile, name, runBy := row[0], row[1], row[2]
		config, ok := Forks[name]
		if !ok {
			t.Errorf("%s: fixture fork %q is not in tests.Forks", profile, name)
			continue
		}
		if runBy != "fixtures CI job" {
			t.Errorf("%s: run by %q, want the fixtures CI job", profile, runBy)
		}
		// A row for single EIPs names a fixture fork that switches them on.
		value := reflect.ValueOf(config)
		for _, m := range eip.FindAllStringSubmatch(profile, -1) {
			on := false
			for _, getter := range []string{"GetEIP" + m[1] + "Transition", "GetEIP" + m[1] + "TransitionTime"} {
				method := value.MethodByName(getter)
				if !method.IsValid() {
					continue
				}
				if n, _ := method.Call(nil)[0].Interface().(*uint64); n != nil {
					on = true
				}
			}
			if !on {
				t.Errorf("%s: fixture fork %s does not switch on %s", profile, name, m[0])
			}
		}
	}

	// The fixtures CI job runs the state and blockchain fixtures of ./tests
	// through build/ci-gate.sh.
	checks := []struct {
		file  string
		wants []string
	}{
		{"../.github/workflows/ci.yml", []string{"\n  fixtures:\n", "build/ci-gate.sh fixtures"}},
		{"../build/ci-gate.sh", []string{"-run '^TestState$' ./tests", "-run '^TestBlockchain$' ./tests"}},
	}
	for _, check := range checks {
		data, err := os.ReadFile(check.file)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range check.wants {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s does not contain %q", check.file, want)
			}
		}
	}
}
