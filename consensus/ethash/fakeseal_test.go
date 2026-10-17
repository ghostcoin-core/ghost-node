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

//go:build !ghostrelease

package ethash

import "testing"

// TestTestBuildHasFakeSeals checks that ordinary builds, which the tests use,
// keep the fake modes.
func TestTestBuildHasFakeSeals(t *testing.T) {
	if !FakeSealsAllowed {
		t.Fatal("test build has no fake seals")
	}
	for _, mode := range []Mode{ModeFake, ModePoissonFake, ModeFullFake} {
		if !mode.IsFake() {
			t.Errorf("mode %v does not count as fake", mode)
		}
	}
	for _, mode := range []Mode{ModeNormal, ModeShared, ModeTest} {
		if mode.IsFake() {
			t.Errorf("mode %v counts as fake", mode)
		}
	}
}
