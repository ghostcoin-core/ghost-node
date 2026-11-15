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

package qsdisc

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
)

func randomID(t testing.TB) enode.ID {
	t.Helper()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestVerifySource(t *testing.T) {
	for _, tt := range []struct{ addr, want string }{
		{"1.2.3.4:30303", "1.2.3.0/24"},
		{"1.2.3.200:1", "1.2.3.0/24"},
		{"[::ffff:1.2.3.4]:30303", "1.2.3.0/24"},
		{"[2001:db8:1:2::1]:30303", "2001:db8:1::/48"},
		{"127.0.0.7:30303", "127.0.0.7/32"},
		{"192.168.1.9:30303", "192.168.1.9/32"},
	} {
		if got := sourceOf(netip.MustParseAddrPort(tt.addr)); got.String() != tt.want {
			t.Errorf("source of %s is %v, want %s", tt.addr, got, tt.want)
		}
	}
}

// TestVerifyStartBudgets checks the budgets of verification starts: one
// source cannot take more than its share, and remote peers together cannot
// take the starts kept for the node's own lookups.
func TestVerifyStartBudgets(t *testing.T) {
	var self enode.ID
	self[0] = 1
	u := newUDP(nil, Config{Self: qsconn.NodeID(self)})
	now := time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()

	charge := func(addr netip.AddrPort, remote bool) error {
		return u.chargeStartLocked(nodeAddr{randomID(t), addr}, sourceOf(addr), remote, now)
	}

	// One address pinging with a fresh ID each time.
	attacker := netip.MustParseAddrPort("1.2.3.4:30303")
	var ok int
	for range 4 * MaxSourceVerifyStarts {
		if err := charge(attacker, true); err == nil {
			ok++
		} else if !errors.Is(err, errSourceStarts) {
			t.Fatalf("start refused with %v, want errSourceStarts", err)
		}
	}
	if ok != MaxSourceVerifyStarts {
		t.Fatalf("one address started %d verifications in a minute, want %d", ok, MaxSourceVerifyStarts)
	}
	// Other endpoints of its /24 share its budget.
	if err := charge(netip.MustParseAddrPort("1.2.3.99:1"), true); !errors.Is(err, errSourceStarts) {
		t.Fatalf("another address of the /24 started with %v", err)
	}

	// Many sources together stop at the remote share.
	remote := ok
	for s := 0; remote < 2*MaxVerifyStarts; s++ {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{20 + byte(s>>8), byte(s), 0, 1}), 30303)
		if err := charge(addr, true); err != nil {
			if !errors.Is(err, errTooManyStarts) {
				t.Fatalf("remote start refused with %v", err)
			}
			break
		}
		remote++
	}
	if remote != MaxRemoteVerifyStarts {
		t.Fatalf("remote peers started %d verifications in a minute, want %d", remote, MaxRemoteVerifyStarts)
	}

	// The node's own lookups still have the rest.
	var own int
	for s := 0; own < 2*MaxVerifyStarts; s++ {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, byte(s >> 8), byte(s), 1}), 30303)
		if err := charge(addr, false); err != nil {
			if !errors.Is(err, errTooManyStarts) {
				t.Fatalf("own start refused with %v", err)
			}
			break
		}
		own++
	}
	if own != MaxVerifyStarts-MaxRemoteVerifyStarts {
		t.Fatalf("own lookups started %d verifications, want the %d kept for them", own, MaxVerifyStarts-MaxRemoteVerifyStarts)
	}

	// A minute later the budgets are free again.
	now = now.Add(VerifyInterval)
	if err := charge(attacker, true); err != nil {
		t.Fatalf("start a minute later refused with %v", err)
	}
	if u.rmtStarts != 1 || len(u.srcStarts) != 1 || u.startList.Len() != 1 {
		t.Fatalf("after a minute %d remote starts, %d sources and %d starts are remembered, want 1 each",
			u.rmtStarts, len(u.srcStarts), u.startList.Len())
	}
}

// TestFailedVerificationExpires checks that a failure is forgotten after
// FailedTime, and that the memory stays within MaxFailed.
func TestFailedVerificationExpires(t *testing.T) {
	var self enode.ID
	self[0] = 1
	u := newUDP(nil, Config{Self: qsconn.NodeID(self)})
	now := time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()

	k := nodeAddr{randomID(t), netip.MustParseAddrPort("1.2.3.4:30303")}
	u.addFailureLocked(k, now)
	if !u.failedLocked(k, now.Add(FailedTime-time.Second)) {
		t.Fatal("failure forgotten before FailedTime")
	}
	if u.failedLocked(k, now.Add(FailedTime)) {
		t.Fatal("failure still remembered after FailedTime")
	}
	if len(u.failed) != 0 || u.failList.Len() != 0 {
		t.Fatalf("%d failures kept after they expired", len(u.failed))
	}
	// Remembered again after it fails again, for FailedTime from then.
	later := now.Add(FailedTime)
	u.addFailureLocked(k, later)
	if !u.failedLocked(k, later.Add(FailedTime-time.Second)) {
		t.Fatal("second failure not remembered")
	}

	for i := range 2 * MaxFailed {
		u.addFailureLocked(nodeAddr{randomID(t), publicAddr(i)}, later)
	}
	if len(u.failed) != MaxFailed || u.failList.Len() != MaxFailed {
		t.Fatalf("%d failures in a memory of %d", len(u.failed), MaxFailed)
	}
}

// stallVerifier never finishes a record fetch until released, as a peer that
// never completes the connection.
type stallVerifier struct {
	release chan struct{}
	started chan netip.AddrPort
}

func (v *stallVerifier) VerifyRecord(id enode.ID, endpoint netip.AddrPort) (*enode.QSRecord, error) {
	v.started <- endpoint
	<-v.release
	return nil, errors.New("connection not completed")
}

// TestVerifySlotsPerSource checks that peers of one source that never
// finish the connection hold at most MaxSourceVerifications of the slots,
// and that a refused or unanswered verification is not charged a start.
func TestVerifySlotsPerSource(t *testing.T) {
	v := &stallVerifier{release: make(chan struct{}), started: make(chan netip.AddrPort, MaxVerifications)}
	conn := listenLoopback(t, 90)
	var self enode.ID
	self[0] = 1
	u, err := Listen(conn, Config{Self: qsconn.NodeID(self), Verifier: v})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	defer close(v.release)

	// Endpoints proven for their IDs, so that no ping is needed.
	prove := func(addr netip.AddrPort) enode.ID {
		id := randomID(t)
		u.mu.Lock()
		ep := u.endpointLocked(addr)
		ep.id, ep.proven = qsconn.NodeID(id), time.Now()
		u.mu.Unlock()
		return id
	}
	stalled := netip.MustParseAddr("1.2.3.4")
	for i := range MaxVerifications {
		addr := netip.AddrPortFrom(stalled, uint16(1000+i))
		_, err := u.verify(prove(addr), addr, false)
		if i < MaxSourceVerifications && err != errStarted {
			t.Fatalf("verification %d of one source: %v, want it started", i, err)
		}
		if i >= MaxSourceVerifications && err != errSourceBusy {
			t.Fatalf("verification %d of one source: %v, want errSourceBusy", i, err)
		}
	}
	for range MaxSourceVerifications {
		<-v.started
	}
	// Another source still gets a slot.
	other := netip.MustParseAddrPort("5.6.7.8:30303")
	if _, err := u.verify(prove(other), other, false); err != errStarted {
		t.Fatalf("verification of another source: %v, want it started", err)
	}
	<-v.started
	u.mu.Lock()
	starts := u.startList.Len()
	u.mu.Unlock()
	if starts != MaxSourceVerifications+1 {
		t.Fatalf("%d starts charged, want %d", starts, MaxSourceVerifications+1)
	}

	// An endpoint that answers the ping with another ID is refused before
	// its record is fetched, and charged no start.
	r := newRawPeer(t, 91)
	done := make(chan error, 1)
	go func() {
		_, err := u.verify(randomID(t), r.addr(), true)
		done <- err
	}()
	for _, p := range r.read(time.Second) {
		if p, ok := p.(*Ping); ok {
			r.send(u.LocalAddr(), &Pong{From: r.id, Token: p.Token})
		}
	}
	if err := <-done; err != errWrongID {
		t.Fatalf("verification answered with another ID: %v, want errWrongID", err)
	}
	u.mu.Lock()
	starts = u.startList.Len()
	u.mu.Unlock()
	if starts != MaxSourceVerifications+1 {
		t.Fatalf("%d starts charged after a refused ping, want %d", starts, MaxSourceVerifications+1)
	}
}

// TestRandomIDPingsKeepLookups checks that one address sending pings with a
// fresh random ID each time, and answering the node's ping back, makes the
// node start at most MaxSourceVerifyStarts verifications for it, and does
// not stop the node's own lookups.
func TestRandomIDPingsKeepLookups(t *testing.T) {
	if testing.Short() {
		t.Skip("sends pings at the source rate for several seconds")
	}
	v := newFakeVerifier()
	t.Cleanup(v.closeNodes)
	a := startNode(t, v, 81, nil)
	x := startNode(t, v, 82, nil, a)
	waitFor(t, "a in x's table", func() bool { return hasNode(x.Nodes(), a.Self()) })

	attacker := newRawPeer(t, 83)
	src := sourceOf(attacker.addr())
	sent := MaxSourceVerifyStarts + 16
	for i := range sent {
		id := qsconn.NodeID(randomID(t))
		attacker.send(x.LocalAddr(), &Ping{From: id, Token: [TokenSize]byte{0xa0, byte(i)}})
		// Answer the ping back with the same ID, as a peer at that
		// endpoint would; pace the pings at the source rate.
		for _, p := range attacker.read(time.Second / SourceRate) {
			if p, ok := p.(*Ping); ok {
				attacker.send(x.LocalAddr(), &Pong{From: id, Token: p.Token})
			}
		}
	}
	waitFor(t, "x to start the attacker's verifications", func() bool {
		x.mu.Lock()
		defer x.mu.Unlock()
		return x.srcStarts[src] >= MaxSourceVerifyStarts/2
	})
	x.mu.Lock()
	got := x.srcStarts[src]
	x.mu.Unlock()
	if got > MaxSourceVerifyStarts {
		t.Fatalf("one address made x start %d verifications in a minute, want at most %d", got, MaxSourceVerifyStarts)
	}

	// A node that joins now is found by x's own lookup.
	n := startNode(t, v, 84, nil, a)
	waitFor(t, "n in a's table", func() bool { return hasNode(a.Nodes(), n.Self()) })
	if !hasNode(x.Lookup(n.Self()), n.Self()) {
		t.Fatal("x's lookup does not find the new node while one address floods it with pings")
	}
}
