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
// that skips seal verification or uses the test mode's tiny dataset, by any
// constructor or configured mode, and that its remote sealer always verifies
// submitted work.
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
		"New(ModeTest)":     func() { New(Config{PowMode: ModeTest}, nil, false) },
		"NewTester":         func() { NewTester(nil, false) },
	}
	sealer := startRemoteSealer(&Ethash{}, nil, true)
	defer stopRemoteSealer(t, sealer)
	if sealer.noverify {
		t.Error("release remote sealer skips verification of submitted work")
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

// TestRemoteSealerExitWithNilLog checks that a remote sealer started on an
// engine without a configured logger shuts down cleanly instead of panicking
// on its way out.
func TestRemoteSealerExitWithNilLog(t *testing.T) {
	sealer := startRemoteSealer(&Ethash{}, nil, true)
	stopRemoteSealer(t, sealer)
}

// stopRemoteSealer asks the sealer's loop to exit and waits for it to finish,
// so that nothing it does on the way out outlives the test.
func stopRemoteSealer(t *testing.T, sealer *remoteSealer) {
	t.Helper()
	close(sealer.requestExit)
	select {
	case <-sealer.exitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("remote sealer did not exit within 5s")
	}
}
