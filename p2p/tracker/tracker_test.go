// Copyright 2026 The go-ethereum Authors
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

package tracker

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p"
)

// TestCleanAfterStop verifies that the clean method does not crash when called
// after Stop. This can happen because clean is scheduled via time.AfterFunc and
// may fire after Stop sets t.expire to nil.
func TestCleanAfterStop(t *testing.T) {
	cap := p2p.Cap{Name: "test", Version: 1}
	timeout := 50 * time.Millisecond
	tr := New(cap, "peer1", timeout)

	// Track a request to start the expiration timer.
	tr.Track(Request{ID: 1, ReqCode: 0x01, RespCode: 0x02, Size: 1})

	// Stop the tracker, then wait for the timer to fire.
	tr.Stop()
	time.Sleep(timeout + 50*time.Millisecond)

	// Also verify that calling clean directly after stop doesn't panic.
	tr.clean()
}

// TestRequestTrackerNoCrash checks that a stopped tracker survives every call
// that can still reach it: the expiration timer firing late, a direct clean, a
// late response and a new request.
func TestRequestTrackerNoCrash(t *testing.T) {
	cap := p2p.Cap{Name: "test", Version: 1}
	timeout := 10 * time.Millisecond
	tr := New(cap, "synthetic-peer", timeout)

	// Track a few requests so the expiration timer is armed and items pending.
	for id := uint64(0); id < 3; id++ {
		if err := tr.Track(Request{ID: id, ReqCode: 0x01, RespCode: 0x02, Size: 1}); err != nil {
			t.Fatalf("failed to track request %d: %v", id, err)
		}
	}
	// Stop once the timer is due, so its clean races with or runs after Stop.
	time.Sleep(timeout)
	tr.Stop()
	time.Sleep(2 * timeout)

	tr.clean()
	if err := tr.Fulfil(Response{ID: 1, MsgCode: 0x02, Size: 1}); err != ErrNoMatchingRequest {
		t.Errorf("response after stop: got %v, want %v", err, ErrNoMatchingRequest)
	}
	if err := tr.Track(Request{ID: 9, ReqCode: 0x01, RespCode: 0x02, Size: 1}); err != ErrStopped {
		t.Errorf("request after stop: got %v, want %v", err, ErrStopped)
	}
	tr.Stop() // stopping twice must not crash either
}

// This checks that metrics gauges for pending requests are be decremented when a
// Tracker is stopped.
func TestMetricsOnStop(t *testing.T) {
	metrics.Enabled = true

	cap := p2p.Cap{Name: "test", Version: 1}
	tr := New(cap, "peer1", time.Minute)

	// Track some requests with different ReqCodes.
	var id uint64
	for i := 0; i < 3; i++ {
		tr.Track(Request{ID: id, ReqCode: 0x01, RespCode: 0x02, Size: 1})
		id++
	}
	for i := 0; i < 5; i++ {
		tr.Track(Request{ID: id, ReqCode: 0x03, RespCode: 0x04, Size: 1})
		id++
	}

	gauge1 := tr.trackedGauge(0x01)
	gauge2 := tr.trackedGauge(0x03)

	if gauge1.Snapshot().Value() != 3 {
		t.Fatalf("gauge1 value mismatch: got %d, want 3", gauge1.Snapshot().Value())
	}
	if gauge2.Snapshot().Value() != 5 {
		t.Fatalf("gauge2 value mismatch: got %d, want 5", gauge2.Snapshot().Value())
	}

	tr.Stop()

	if gauge1.Snapshot().Value() != 0 {
		t.Fatalf("gauge1 value after stop: got %d, want 0", gauge1.Snapshot().Value())
	}
	if gauge2.Snapshot().Value() != 0 {
		t.Fatalf("gauge2 value after stop: got %d, want 0", gauge2.Snapshot().Value())
	}
}
