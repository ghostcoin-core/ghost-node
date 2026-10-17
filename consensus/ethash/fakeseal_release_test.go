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

//go:build ghostrelease

package ethash

import (
	"testing"
	"time"
)

// TestReleaseHasNoFakeSeals checks that a release build cannot make an engine
// that skips seal verification, by any constructor or configured mode.
func TestReleaseHasNoFakeSeals(t *testing.T) {
	if FakeSealsAllowed {
		t.Fatal("release build allows fake seals")
	}
	for _, mode := range []Mode{ModeFake, ModePoissonFake, ModeFullFake} {
		if mode.IsFake() {
			t.Errorf("mode %v counts as fake in a release build", mode)
		}
	}
	constructors := map[string]func(){
		"NewFaker":          func() { NewFaker() },
		"NewFakeFailer":     func() { NewFakeFailer(1) },
		"NewFakeDelayer":    func() { NewFakeDelayer(time.Millisecond) },
		"NewPoissonFaker":   func() { NewPoissonFaker() },
		"NewFullFaker":      func() { NewFullFaker() },
		"New(ModeFake)":     func() { New(Config{PowMode: ModeFake}, nil, false) },
		"New(ModeFullFake)": func() { New(Config{PowMode: ModeFullFake}, nil, false) },
		"New(ModePoisson)":  func() { New(Config{PowMode: ModePoissonFake}, nil, false) },
	}
	for name, construct := range constructors {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not refuse to build a fake engine", name)
				}
			}()
			construct()
		}()
	}
}
