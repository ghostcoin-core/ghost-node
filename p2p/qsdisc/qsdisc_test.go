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
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

// fakeVerifier stands for fetching a record over qsconn: it holds the
// encoding each node would serve and passes it through an
// enode.QSRecordCache, which verifies it.
type fakeVerifier struct {
	cache *enode.QSRecordCache

	mu      sync.Mutex
	records map[enode.ID][]byte
	asked   map[enode.ID]int
	nodes   []*UDP // started with this verifier, closed by closeNodes
}

// closeNodes closes every node started with the verifier. Nodes outlive
// the subtest that starts them, so later subtests find them alive.
func (v *fakeVerifier) closeNodes() {
	v.mu.Lock()
	nodes := v.nodes
	v.mu.Unlock()
	for _, n := range nodes {
		n.Close()
	}
}

func newFakeVerifier() *fakeVerifier {
	return &fakeVerifier{
		cache:   enode.NewQSRecordCache(enode.QSRecordCacheSize, enode.QSRecordVerifyRate, nil),
		records: make(map[enode.ID][]byte),
		asked:   make(map[enode.ID]int),
	}
}

func (v *fakeVerifier) serve(id enode.ID, enc []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.records[id] = enc
}

func (v *fakeVerifier) timesAsked(id enode.ID) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.asked[id]
}

func (v *fakeVerifier) VerifyRecord(id enode.ID, endpoint netip.AddrPort) (*enode.QSRecord, error) {
	v.mu.Lock()
	enc := v.records[id]
	v.asked[id]++
	v.mu.Unlock()
	if enc == nil {
		return nil, errors.New("no record at endpoint")
	}
	return v.cache.Add(enc)
}

type testNode struct {
	*UDP
	key *qsconn.Identity
}

// listenLoopback opens a UDP socket on a loopback address of its own, so
// each test node is its own source address.
func listenLoopback(t *testing.T, host byte) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, host)})
	if err != nil {
		t.Fatalf("listen on 127.0.0.%d: %v", host, err)
	}
	return conn
}

func signRecord(t *testing.T, key *qsconn.Identity, ip net.IP, udp uint16) *enode.QSRecord {
	t.Helper()
	rec := &enode.QSRecord{Seq: 1, IP: ip, TCP: udp, UDP: udp}
	if err := rec.Sign(key); err != nil {
		t.Fatal(err)
	}
	return rec
}

// startNode starts a node on 127.0.0.host. serve, when not nil, makes the
// record the verifier serves for it from the node's key and endpoint.
func startNode(t *testing.T, v *fakeVerifier, host byte, serve func(key *qsconn.Identity, addr netip.AddrPort) []byte, boot ...*testNode) *testNode {
	t.Helper()
	return startNodeWithKey(t, v, newKey(t), host, serve, boot...)
}

func newKey(t *testing.T) *qsconn.Identity {
	t.Helper()
	key, err := qsconn.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func startNodeWithKey(t *testing.T, v *fakeVerifier, key *qsconn.Identity, host byte, serve func(key *qsconn.Identity, addr netip.AddrPort) []byte, boot ...*testNode) *testNode {
	t.Helper()
	conn := listenLoopback(t, host)
	addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	if serve == nil {
		serve = func(key *qsconn.Identity, addr netip.AddrPort) []byte {
			return signRecord(t, key, addr.Addr().AsSlice(), addr.Port()).Encode()
		}
	}
	v.serve(enode.ID(key.ID()), serve(key, addr))
	cfg := Config{Self: key.ID(), Verifier: v}
	for _, b := range boot {
		cfg.Bootnodes = append(cfg.Bootnodes, Bootnode{ID: b.Self(), Addr: b.LocalAddr()})
	}
	u, err := Listen(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.nodes = append(v.nodes, u)
	v.mu.Unlock()
	return &testNode{UDP: u, key: key}
}

func hasNode(nodes []Node, id enode.ID) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// rawPeer is a bare UDP socket that speaks the packets by hand.
type rawPeer struct {
	t    *testing.T
	conn *net.UDPConn
	id   qsconn.NodeID
}

func newRawPeer(t *testing.T, host byte) *rawPeer {
	conn := listenLoopback(t, host)
	t.Cleanup(func() { conn.Close() })
	var id qsconn.NodeID
	id[0], id[31] = 0xfe, host
	return &rawPeer{t: t, conn: conn, id: id}
}

func (r *rawPeer) send(to netip.AddrPort, p any) {
	b, err := Encode(p)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.conn.WriteToUDPAddrPort(b, to); err != nil {
		r.t.Fatal(err)
	}
}

// prove pings n, answers its ping back so that n sees the raw peer's
// endpoint proven, and returns the cookie n's pong gave it.
func (r *rawPeer) prove(n *testNode) [CookieSize]byte {
	r.t.Helper()
	r.send(n.LocalAddr(), &Ping{From: r.id, Token: [TokenSize]byte{0xb0, r.id[31]}})
	var proved bool
	var cookie [CookieSize]byte
	for _, p := range r.read(time.Second) {
		switch p := p.(type) {
		case *Ping:
			if enode.ID(p.From) != n.Self() {
				r.t.Fatal("ping back from another ID")
			}
			r.send(n.LocalAddr(), &Pong{From: r.id, Token: p.Token})
			proved = true
		case *Pong:
			cookie = p.Cookie
		}
	}
	if !proved {
		r.t.Fatal("no ping back to an unproven endpoint")
	}
	if cookie == ([CookieSize]byte{}) {
		r.t.Fatal("pong without a cookie")
	}
	waitFor(r.t, "the raw peer's endpoint to be proven", func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.provenLocked(r.addr(), r.id, time.Now())
	})
	return cookie
}

// sendRaw sends a packet of the given type and body as it is, unpadded.
func (r *rawPeer) sendRaw(to netip.AddrPort, typ byte, p any) []byte {
	body, err := rlp.EncodeToBytes(p)
	if err != nil {
		r.t.Fatal(err)
	}
	b := append([]byte{typ}, body...)
	if _, err := r.conn.WriteToUDPAddrPort(b, to); err != nil {
		r.t.Fatal(err)
	}
	return b
}

// readRaw returns the bytes of the packets that arrive within d.
func (r *rawPeer) readRaw(d time.Duration) [][]byte {
	var out [][]byte
	deadline := time.Now().Add(d)
	for {
		buf := make([]byte, 2*MaxPacketSize)
		r.conn.SetReadDeadline(deadline)
		n, _, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return out
		}
		out = append(out, buf[:n])
	}
}

func (r *rawPeer) addr() netip.AddrPort {
	return r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// read returns the packets that arrive within d.
func (r *rawPeer) read(d time.Duration) []any {
	var out []any
	buf := make([]byte, 2*MaxPacketSize)
	deadline := time.Now().Add(d)
	for {
		r.conn.SetReadDeadline(deadline)
		n, _, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return out
		}
		p, err := Decode(buf[:n])
		if err != nil {
			r.t.Fatalf("undecodable packet: %v", err)
		}
		out = append(out, p)
	}
}

func TestQSDiscovery(t *testing.T) {
	v := newFakeVerifier()
	t.Cleanup(v.closeNodes)
	a := startNode(t, v, 11, nil)
	b := startNode(t, v, 12, nil, a)

	t.Run("two-nodes-find-each-other", func(t *testing.T) {
		waitFor(t, "a and b in each other's table", func() bool {
			return hasNode(a.Nodes(), b.Self()) && hasNode(b.Nodes(), a.Self())
		})
		n, _ := a.tab.get(b.Self())
		if n.Addr != b.LocalAddr() || n.Record == nil || n.Record.ID() != b.Self() {
			t.Fatalf("a holds b as %v, want %v with b's record", n.Addr, b.LocalAddr())
		}
	})

	var c *testNode
	t.Run("third-finds-both-through-one", func(t *testing.T) {
		c = startNode(t, v, 13, nil, a)
		waitFor(t, "a and b in c's table", func() bool {
			return hasNode(c.Nodes(), a.Self()) && hasNode(c.Nodes(), b.Self())
		})
		res := c.Lookup(b.Self())
		if len(res) == 0 || res[0].ID != b.Self() {
			t.Fatalf("lookup of b returned %d nodes, closest not b", len(res))
		}
		if !hasNode(res, a.Self()) {
			t.Fatal("lookup of b does not return a")
		}
		if hasNode(res, c.Self()) {
			t.Fatal("lookup returns the node itself")
		}
	})

	t.Run("no-neighbors-to-unproven-endpoint", func(t *testing.T) {
		r := newRawPeer(t, 21)
		r.send(a.LocalAddr(), &Findnode{From: r.id, Target: qsconn.NodeID(b.Self())})
		for _, p := range r.read(time.Second) {
			if _, ok := p.(*Neighbors); ok {
				t.Fatal("neighbors sent to an endpoint that has not proven itself")
			}
		}

		// A ping makes a ping us back; our pong with its token proves us.
		cookie := r.prove(a)
		r.send(a.LocalAddr(), &Findnode{From: r.id, Target: qsconn.NodeID(b.Self()), Cookie: cookie})
		var got *Neighbors
		for _, p := range r.read(time.Second) {
			if n, ok := p.(*Neighbors); ok {
				got = n
			}
		}
		if got == nil || len(got.Nodes) == 0 {
			t.Fatal("no neighbors for a proven endpoint")
		}
		if got.Nodes[0].ID != qsconn.NodeID(b.Self()) || got.Nodes[0].Addr() != b.LocalAddr() {
			t.Fatalf("closest neighbor is %v at %v, want b", got.Nodes[0].ID, got.Nodes[0].Addr())
		}
		// The raw peer serves no record, so it must not have been added.
		waitFor(t, "a to try the raw peer's record", func() bool { return v.timesAsked(enode.ID(r.id)) > 0 })
		if hasNode(a.Nodes(), enode.ID(r.id)) {
			t.Fatal("a node without a record entered the table")
		}
	})

	t.Run("spoofed-findnode-needs-cookie", func(t *testing.T) {
		r := newRawPeer(t, 22)
		cookie := r.prove(a)
		a.mu.Lock()
		proven := a.provenLocked(r.addr(), r.id, time.Now())
		a.mu.Unlock()
		if !proven {
			t.Fatal("raw peer's endpoint not proven at a")
		}
		// Fill a's table so that a full answer is many times a bare
		// findnode; the fillers go again at the end.
		var fillers []enode.ID
		for i := range 12 {
			id := idAtDistance(a.Self(), 256, uint32(0x7000+i))
			a.tab.add(Node{ID: id, Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 2, byte(i + 1)}), 9)}, time.Now())
			fillers = append(fillers, id)
		}
		defer func() {
			for _, id := range fillers {
				a.tab.remove(id)
			}
		}()
		neighbors := func() []*Neighbors {
			var out []*Neighbors
			for _, p := range r.read(500 * time.Millisecond) {
				if n, ok := p.(*Neighbors); ok {
					out = append(out, n)
				}
			}
			return out
		}
		srcIP := r.addr().Addr()
		// A packet charged to the source's bucket moves its last time.
		charged := func() time.Time {
			a.mu.Lock()
			defer a.mu.Unlock()
			tb, ok := a.sources.Peek(srcIP)
			if !ok {
				t.Fatal("no bucket for the raw peer")
			}
			return tb.last
		}

		// Findnodes as an attacker forges them from the proven endpoint:
		// without a cookie, with the cookie of another endpoint, with the
		// endpoint's cookie under another ID, and with an expired cookie.
		now := time.Now()
		other := qsconn.NodeID{0xfd}
		target := qsconn.NodeID(b.Self())
		forged := []*Findnode{
			{From: r.id, Target: target, Token: [TokenSize]byte{0xa1}},
			{From: r.id, Target: target, Token: [TokenSize]byte{0xa2}, Cookie: a.cookieFor(netip.AddrPortFrom(srcIP, r.addr().Port()+1), r.id, now)},
			{From: other, Target: target, Token: [TokenSize]byte{0xa3}, Cookie: cookie},
			{From: r.id, Target: target, Token: [TokenSize]byte{0xa4}, Cookie: a.cookieAt(r.addr(), r.id, cookiePeriod(now)-2)},
		}
		before := charged()
		for i := 0; i < 2*SourceBurst; i++ {
			r.send(a.LocalAddr(), forged[i%len(forged)])
		}
		if got := neighbors(); len(got) != 0 {
			t.Fatalf("a answered %d findnodes forged from a proven endpoint without its cookie", len(got))
		}
		if !charged().Equal(before) {
			t.Fatal("findnodes without the cookie were charged to the source")
		}

		// With the cookie it gets a full answer, charged to the source's
		// one bucket.
		r.send(a.LocalAddr(), &Findnode{From: r.id, Target: target, Token: [TokenSize]byte{0xa5}, Cookie: cookie})
		got := neighbors()
		if len(got) != 1 || got[0].Token != ([TokenSize]byte{0xa5}) {
			t.Fatalf("got %d answers to a findnode with the cookie, want one with its token", len(got))
		}
		full := len(got[0].Nodes)
		if want := min(a.tab.len(), MaxNeighbors); full != want {
			t.Fatalf("padded findnode got %d nodes, want %d", full, want)
		}
		if got[0].Nodes[0].ID != target {
			t.Fatal("closest neighbor is not b")
		}
		if !charged().After(before) {
			t.Fatal("a findnode with the cookie was not charged to the source")
		}

		// A bare, unpadded findnode with the cookie gets an answer of at
		// most MaxAmplification times its size, with fewer nodes.
		req := r.sendRaw(a.LocalAddr(), FindnodePacket, &Findnode{From: r.id, Target: target, Token: [TokenSize]byte{0xa6}, Cookie: cookie})
		raw := r.readRaw(500 * time.Millisecond)
		if len(raw) != 1 {
			t.Fatalf("got %d answers to a bare findnode with the cookie, want one", len(raw))
		}
		if len(raw[0]) > MaxAmplification*len(req) {
			t.Fatalf("answer of %d bytes to a findnode of %d bytes, over %dx", len(raw[0]), len(req), MaxAmplification)
		}
		p, err := Decode(raw[0])
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := p.(*Neighbors); !ok || len(n.Nodes) == 0 || len(n.Nodes) >= full {
			t.Fatalf("bare findnode answered with %T, want neighbors with fewer than %d nodes", p, full)
		}
	})

	t.Run("refused-records-never-enter", func(t *testing.T) {
		// e's record names another UDP port than the one it answers from.
		e := startNode(t, v, 31, func(key *qsconn.Identity, addr netip.AddrPort) []byte {
			return signRecord(t, key, addr.Addr().AsSlice(), addr.Port()+1).Encode()
		}, a)
		// f's record has a broken signature.
		f := startNode(t, v, 32, func(key *qsconn.Identity, addr netip.AddrPort) []byte {
			rec := signRecord(t, key, addr.Addr().AsSlice(), addr.Port())
			rec.Signature[0] ^= 0xff
			return rec.Encode()
		}, a)
		// g's endpoint serves a valid record of another node at g's endpoint.
		g := startNode(t, v, 33, func(_ *qsconn.Identity, addr netip.AddrPort) []byte {
			other, err := qsconn.GenerateIdentity()
			if err != nil {
				t.Fatal(err)
			}
			return signRecord(t, other, addr.Addr().AsSlice(), addr.Port()).Encode()
		}, a)
		bad := []*testNode{e, f, g}
		for _, n := range bad {
			waitFor(t, "a to try the record", func() bool { return v.timesAsked(n.Self()) > 0 })
		}
		waitFor(t, "a to refuse the records", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			for _, n := range bad {
				if _, ok := a.failed[nodeAddr{n.Self(), n.LocalAddr()}]; !ok {
					return false
				}
			}
			return true
		})

		// A rogue node names the refused nodes in its answers.
		rogue := startNode(t, v, 34, nil)
		for _, n := range bad {
			rogue.tab.add(Node{ID: n.Self(), Addr: n.LocalAddr()}, time.Now())
		}
		d := startNode(t, v, 35, nil, rogue, a)
		waitFor(t, "rogue and a in d's table", func() bool {
			return hasNode(d.Nodes(), rogue.Self()) && hasNode(d.Nodes(), a.Self())
		})
		var results [][]Node
		for _, n := range bad {
			results = append(results, d.Lookup(n.Self()), c.Lookup(n.Self()))
		}
		for _, n := range bad {
			for _, tab := range [][]Node{a.Nodes(), c.Nodes(), d.Nodes()} {
				if hasNode(tab, n.Self()) {
					t.Fatalf("refused node %v entered a table", n.LocalAddr())
				}
			}
			for _, res := range results {
				if hasNode(res, n.Self()) {
					t.Fatalf("refused node %v returned by a lookup", n.LocalAddr())
				}
			}
			d.mu.Lock()
			_, tried := d.failed[nodeAddr{n.Self(), n.LocalAddr()}]
			d.mu.Unlock()
			if !tried {
				t.Fatalf("d never verified the node %v the rogue named", n.LocalAddr())
			}
		}
		if !hasNode(d.Lookup(b.Self()), b.Self()) {
			t.Fatal("d does not find the honest node b")
		}
	})

	t.Run("claimed-id-does-not-block-honest-endpoint", func(t *testing.T) {
		key := newKey(t)
		// A peer claims the ID at its own endpoint and fails verification.
		r := newRawPeer(t, 51)
		r.id = key.ID()
		r.send(a.LocalAddr(), &Ping{From: r.id, Token: [TokenSize]byte{5}})
		for _, p := range r.read(time.Second) {
			if p, ok := p.(*Ping); ok {
				r.send(a.LocalAddr(), &Pong{From: r.id, Token: p.Token})
			}
		}
		waitFor(t, "a to refuse the claim", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			_, ok := a.failed[nodeAddr{enode.ID(key.ID()), r.addr()}]
			return ok
		})
		// The honest node is still verified at its own endpoint at once.
		h := startNodeWithKey(t, v, key, 52, nil, a)
		waitFor(t, "a to verify the honest node", func() bool {
			n, ok := a.tab.get(h.Self())
			return ok && n.Addr == h.LocalAddr()
		})
	})

	t.Run("forged-neighbors-ignored", func(t *testing.T) {
		r := newRawPeer(t, 61)
		type answer struct {
			nodes []Neighbor
			err   error
		}
		done := make(chan answer, 1)
		go func() {
			nodes, err := a.findnode(Node{ID: enode.ID(r.id), Addr: r.addr()}, b.Self())
			done <- answer{nodes, err}
		}()
		buf := make([]byte, 2*MaxPacketSize)
		deadline := time.Now().Add(10 * time.Second)
		for answered := false; !answered; {
			r.conn.SetReadDeadline(deadline)
			n, _, err := r.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatalf("no findnode from a: %v", err)
			}
			p, err := Decode(buf[:n])
			if err != nil {
				t.Fatal(err)
			}
			switch p := p.(type) {
			case *Ping:
				// Answer, and ping back so that a sees its endpoint proven.
				r.send(a.LocalAddr(), &Pong{From: r.id, Token: p.Token})
				r.send(a.LocalAddr(), &Ping{From: r.id, Token: [TokenSize]byte{6}})
			case *Findnode:
				// A forged empty answer with a wrong token comes first.
				wrong := p.Token
				wrong[0] ^= 0xff
				r.send(a.LocalAddr(), &Neighbors{From: r.id, Token: wrong})
				r.send(a.LocalAddr(), &Neighbors{From: r.id, Token: p.Token, Nodes: []Neighbor{neighborOf(qsconn.NodeID(b.Self()), b.LocalAddr())}})
				answered = true
			}
		}
		res := <-done
		if res.err != nil {
			t.Fatalf("findnode: %v", res.err)
		}
		if len(res.nodes) != 1 || res.nodes[0].ID != qsconn.NodeID(b.Self()) {
			t.Fatalf("findnode returned %d nodes, want the answer with the request's token", len(res.nodes))
		}
	})

	t.Run("ping-exhaustion-keeps-verified-peers", func(t *testing.T) {
		dead := netip.MustParseAddrPort("127.0.0.99:9")
		noop := func(qsconn.NodeID, bool) {}
		// Remote-triggered pings stop at their share of the pending pings.
		filled := 0
		for a.sendPing(dead, enode.ID{}, true, noop) == nil {
			filled++
		}
		a.mu.Lock()
		remote := a.remotePings
		a.mu.Unlock()
		if filled == 0 || remote != MaxRemotePings {
			t.Fatalf("%d remote pings pending, want %d", remote, MaxRemotePings)
		}
		stale := func() {
			a.tab.mu.Lock()
			defer a.tab.mu.Unlock()
			for _, bk := range a.tab.buckets {
				for _, n := range bk.entries {
					n.checked = time.Time{}
				}
			}
		}
		before := a.tab.len()
		stale()
		if err := a.revalidate(); err != nil {
			t.Fatalf("live check with remote pings at their limit: %v", err)
		}
		// With every ping slot taken, a live check fails locally and
		// evicts nothing.
		for a.sendPing(dead, enode.ID{}, false, noop) == nil {
			filled++
		}
		a.mu.Lock()
		pending := len(a.pings)
		a.mu.Unlock()
		if pending != MaxPendingPings {
			t.Fatalf("%d pings pending after filling %d, want %d", pending, filled, MaxPendingPings)
		}
		stale()
		if err := a.revalidate(); err != errTooManyPings {
			t.Fatalf("live check with no free slot: %v", err)
		}
		if after := a.tab.len(); after != before {
			t.Fatalf("table went from %d to %d nodes on a local failure", before, after)
		}
		waitFor(t, "the pings to time out", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return len(a.pings) == 0
		})
	})

	t.Run("spoofed-flood-keeps-verified-peer", func(t *testing.T) {
		from := b.LocalAddr()
		if _, ok := a.tab.get(b.Self()); !ok {
			t.Fatal("b is not in a's table")
		}
		encode := func(p any) []byte {
			enc, err := Encode(p)
			if err != nil {
				t.Fatal(err)
			}
			return enc
		}
		tokens := func() float64 {
			a.mu.Lock()
			defer a.mu.Unlock()
			if tb, ok := a.sources.Peek(from.Addr()); ok {
				return tb.tokens
			}
			return SourceBurst
		}
		// Packets that do not decode or match nothing we sent, forged from
		// b's address, charge nothing to it.
		start := tokens()
		for i := 0; i < 10*SourceBurst; i++ {
			tok := [TokenSize]byte{0xee, byte(i)}
			a.handlePacket([]byte{0xff, byte(i), 0x01}, from)
			a.handlePacket(make([]byte, MaxPacketSize+1), from)
			a.handlePacket(encode(&Pong{From: qsconn.NodeID(b.Self()), Token: tok}), from)
			a.handlePacket(encode(&Neighbors{From: qsconn.NodeID(b.Self()), Token: tok}), from)
		}
		if got := tokens(); got < start {
			t.Fatalf("undecodable and unmatched packets took %.1f of b's allowance", start-got)
		}

		// Forged pings use up b's open allowance, and keep it used up while a
		// checks b.
		ping := encode(&Ping{From: qsconn.NodeID(b.Self()), Token: [TokenSize]byte{0xef}})
		stop := make(chan struct{})
		flooding := make(chan struct{})
		go func() {
			defer close(flooding)
			for {
				select {
				case <-stop:
					return
				default:
				}
				a.handlePacket(ping, from)
				time.Sleep(time.Millisecond)
			}
		}()
		waitFor(t, "b's open allowance to be spent", func() bool { return tokens() < CookieReserve+1 })
		for i := 0; i < MaxRevalidateFails; i++ {
			a.tab.mu.Lock()
			bk := a.tab.bucket(b.Self())
			bk.entries[indexOf(bk.entries, b.Self())].checked = time.Time{}
			a.tab.mu.Unlock()
			err := a.revalidate()
			if err != nil {
				close(stop)
				<-flooding
				t.Fatalf("live check of b under a forged flood: %v", err)
			}
		}
		close(stop)
		<-flooding
		if _, ok := a.tab.get(b.Self()); !ok {
			t.Fatal("a forged flood from b's address evicted b")
		}

		// A node that misses one live check stays; it is removed only after
		// MaxRevalidateFails checks in a row went unanswered.
		q := newUDP(listenLoopback(t, 71), Config{Self: newKey(t).ID(), Verifier: v})
		q.wg.Add(1)
		go q.readLoop()
		defer q.Close()
		dead := Node{ID: b.Self(), Addr: netip.MustParseAddrPort("127.0.0.98:9")}
		q.tab.add(dead, time.Time{})
		if err := q.revalidate(); err != errTimeout {
			t.Fatalf("live check of a dead node: %v", err)
		}
		if _, ok := q.tab.get(dead.ID); !ok {
			t.Fatal("one unanswered live check evicted the node")
		}
		for i := 1; i < MaxRevalidateFails; i++ {
			if _, ok := q.tab.get(dead.ID); !ok {
				t.Fatalf("node evicted after %d unanswered checks, want %d", i, MaxRevalidateFails)
			}
			q.tab.checkFailed(dead.ID, time.Now())
		}
		if _, ok := q.tab.get(dead.ID); ok {
			t.Fatalf("node kept after %d unanswered checks", MaxRevalidateFails)
		}
	})

	t.Run("spoofed-flood-keeps-peer-live-checks-answered", func(t *testing.T) {
		from := b.LocalAddr()
		waitFor(t, "b to hold a's cookie with a in its table", func() bool {
			_, ok := b.tab.cookie(a.Self(), a.LocalAddr())
			return ok
		})
		encode := func(p any) []byte {
			enc, err := Encode(p)
			if err != nil {
				t.Fatal(err)
			}
			return enc
		}
		tokens := func() float64 {
			a.mu.Lock()
			defer a.mu.Unlock()
			if tb, ok := a.sources.Peek(from.Addr()); ok {
				return min(tb.tokens+time.Since(tb.last).Seconds()*SourceRate, SourceBurst)
			}
			return SourceBurst
		}
		// Pings forged from b's address, without a cookie and with the
		// cookie a gives another endpoint, use up b's open allowance at a
		// and keep it used up while b checks a.
		other := netip.AddrPortFrom(from.Addr(), from.Port()+1)
		forged := [][]byte{
			encode(&Ping{From: qsconn.NodeID(b.Self()), Token: [TokenSize]byte{0xf0}}),
			encode(&Ping{From: qsconn.NodeID(b.Self()), Token: [TokenSize]byte{0xf1}, Cookie: a.cookieFor(other, qsconn.NodeID(b.Self()), time.Now())}),
			encode(&Findnode{From: qsconn.NodeID(b.Self()), Token: [TokenSize]byte{0xf2}}),
		}
		stop := make(chan struct{})
		flooding := make(chan struct{})
		go func() {
			defer close(flooding)
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				a.handlePacket(forged[i%len(forged)], from)
				time.Sleep(time.Millisecond)
			}
		}()
		defer func() {
			close(stop)
			<-flooding
		}()
		waitFor(t, "b's open allowance at a to be spent", func() bool { return tokens() < CookieReserve+1 })
		for i := 0; i < MaxRevalidateFails; i++ {
			b.tab.mu.Lock()
			bk := b.tab.bucket(a.Self())
			bk.entries[indexOf(bk.entries, a.Self())].checked = time.Time{}
			b.tab.mu.Unlock()
			if err := b.revalidate(); err != nil {
				t.Fatalf("b's live check %d of a under a flood forged from b: %v", i+1, err)
			}
			if got := tokens(); got >= CookieReserve+1 {
				t.Fatalf("flood stopped spending b's open allowance (%.1f left)", got)
			}
		}
		if _, ok := b.tab.get(a.Self()); !ok {
			t.Fatal("a flood forged from b's address made b evict a")
		}
	})

	t.Run("proof-churn-restored-by-challenge", func(t *testing.T) {
		r := newRawPeer(t, 81)
		cookie := r.prove(a)
		if !a.tab.add(Node{ID: enode.ID(r.id), Addr: r.addr()}, time.Now()) {
			t.Fatal("raw peer not added to a's table")
		}
		defer a.tab.remove(enode.ID(r.id))
		proven := func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.provenLocked(r.addr(), r.id, time.Now())
		}
		neighbors := func(tok byte) int {
			r.send(a.LocalAddr(), &Findnode{From: r.id, Target: qsconn.NodeID(b.Self()), Token: [TokenSize]byte{tok}, Cookie: cookie})
			n := 0
			for _, p := range r.read(500 * time.Millisecond) {
				if _, ok := p.(*Neighbors); ok {
					n++
				}
			}
			return n
		}
		if !proven() || neighbors(0xd0) != 1 {
			t.Fatal("raw table peer not answered before the churn")
		}

		// Cookie-less pings spoofed from MaxSources new addresses push the
		// peer's proof out of a's endpoints.
		for i := range MaxSources {
			from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 2, byte(i >> 8), byte(i)}), 9)
			var id qsconn.NodeID
			id[0], id[1], id[2] = 0xfc, byte(i>>8), byte(i)
			enc, err := Encode(&Ping{From: id, Token: [TokenSize]byte{0xd1, byte(i)}})
			if err != nil {
				t.Fatal(err)
			}
			a.handlePacket(enc, from)
		}
		if proven() {
			t.Fatal("the churn did not push out the peer's proof")
		}
		if neighbors(0xd2) != 0 {
			t.Fatal("findnode answered to an endpoint whose proof is gone")
		}

		// The peer's ping makes a challenge it, even with every remote ping
		// slot taken by the churn; no findnode is answered before its pong.
		a.mu.Lock()
		remote := a.remotePings
		a.mu.Unlock()
		if remote != MaxRemotePings {
			t.Fatalf("%d remote pings pending after the churn, want all %d", remote, MaxRemotePings)
		}
		r.send(a.LocalAddr(), &Ping{From: r.id, Token: [TokenSize]byte{0xd3}, Cookie: cookie})
		var challenge *Ping
		for _, p := range r.read(500 * time.Millisecond) {
			if p, ok := p.(*Ping); ok {
				challenge = p
			}
		}
		if challenge == nil {
			t.Fatal("no challenge ping to a table peer whose proof is gone")
		}
		if neighbors(0xd4) != 0 {
			t.Fatal("findnode answered before the challenge's pong")
		}
		// A pong with another token proves nothing.
		wrong := challenge.Token
		wrong[0] ^= 0xff
		r.send(a.LocalAddr(), &Pong{From: r.id, Token: wrong})
		time.Sleep(100 * time.Millisecond)
		if proven() {
			t.Fatal("a pong without the challenge's token proved the endpoint")
		}
		r.send(a.LocalAddr(), &Pong{From: r.id, Token: challenge.Token})
		waitFor(t, "the challenge's pong to prove the endpoint", proven)
		if neighbors(0xd5) != 1 {
			t.Fatal("findnode not answered after the challenge's pong")
		}
		waitFor(t, "the churn's pings to time out", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return len(a.pings) == 0
		})
	})

	t.Run("source-over-rate-limit-dropped", func(t *testing.T) {
		// Two ports of one source address, each sending pings without a
		// cookie and then with the cookie a gives its endpoint, all at once.
		peers := []*rawPeer{newRawPeer(t, 41), newRawPeer(t, 41)}
		const sent = 3 * SourceBurst
		for _, r := range peers {
			for i := 0; i < sent; i++ {
				r.send(a.LocalAddr(), &Ping{From: r.id, Token: [TokenSize]byte{0x0e, byte(i)}})
			}
		}
		for _, r := range peers {
			cookie := a.cookieFor(r.addr(), r.id, time.Now())
			for i := 0; i < sent; i++ {
				r.send(a.LocalAddr(), &Ping{From: r.id, Token: [TokenSize]byte{0xc0, byte(i)}, Cookie: cookie})
			}
		}
		var open, withCookie int
		for _, r := range peers {
			for _, p := range r.read(time.Second) {
				if p, ok := p.(*Pong); ok {
					if p.Token[0] == 0xc0 {
						withCookie++
					} else {
						open++
					}
				}
			}
		}
		// The address has one bucket however it mixes ports and cookies;
		// one packet more is refill while the pings were sent.
		if total := open + withCookie; total > SourceBurst+1 {
			t.Fatalf("got %d pongs (%d without a cookie, %d with) for %d pings from one address, want at most the burst of %d",
				total, open, withCookie, 4*sent, SourceBurst)
		}
		if open == 0 || open > SourceBurst-CookieReserve+1 {
			t.Fatalf("got %d pongs for pings without a cookie, want at most %d", open, SourceBurst-CookieReserve)
		}
		// The reserve stays for requests with the cookie.
		if withCookie < CookieReserve {
			t.Fatalf("got %d pongs for pings with the cookie after the open ones, want the reserve of %d", withCookie, CookieReserve)
		}
		// Another source is still answered.
		other := newRawPeer(t, 42)
		other.send(a.LocalAddr(), &Ping{From: other.id, Token: [TokenSize]byte{7}})
		var answered bool
		for _, p := range other.read(time.Second) {
			if _, ok := p.(*Pong); ok {
				answered = true
			}
		}
		if !answered {
			t.Fatal("a source under the limit got no pong")
		}
	})
}

// bootRetryDeadline is how long the bootnode retry tests wait for a node to
// reach a bootnode it missed on its first start. It is under VerifyInterval,
// so only a retry of the bootstrap can get there in time: a ping of the
// bootnode makes the node verify it again no sooner than VerifyInterval
// after the first try.
const bootRetryDeadline = 30 * time.Second

func waitWithin(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// firstBootstrapDone reports whether the bootstrap n ran at start has ended.
func firstBootstrapDone(n *testNode) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return !n.bootDone.IsZero()
}

// TestBootnodeRetry checks that a node whose first bootstrap reached no
// bootnode tries its bootnodes again and gets them into its table, without
// a restart and without anyone adding them by hand.
func TestBootnodeRetry(t *testing.T) {
	v := newFakeVerifier()
	t.Cleanup(v.closeNodes)

	// The bootnode answers pings but its record cannot be fetched at first,
	// as when it is busy. The failed fetch must not be remembered against it.
	t.Run("record-not-served-at-first", func(t *testing.T) {
		t.Parallel()
		b := startNode(t, v, 31, nil)
		v.serve(b.Self(), nil)
		c := startNode(t, v, 32, nil, b)
		waitWithin(t, 15*time.Second, "the first bootstrap", func() bool {
			return v.timesAsked(b.Self()) > 0 && firstBootstrapDone(c)
		})
		if hasNode(c.Nodes(), b.Self()) {
			t.Fatal("bootnode added without a record")
		}
		v.serve(b.Self(), signRecord(t, b.key, b.LocalAddr().Addr().AsSlice(), b.LocalAddr().Port()).Encode())
		waitWithin(t, bootRetryDeadline, "the bootnode in the table once it serves its record", func() bool {
			return hasNode(c.Nodes(), b.Self())
		})
	})

	// The bootnode is not up when the node starts, as when the node starts
	// before its network or the bootnode restarts.
	t.Run("bootnode-not-up-at-first", func(t *testing.T) {
		t.Parallel()
		reserve := listenLoopback(t, 33)
		addr := reserve.LocalAddr().(*net.UDPAddr).AddrPort()
		reserve.Close()
		key := newKey(t)
		v.serve(enode.ID(key.ID()), signRecord(t, key, addr.Addr().AsSlice(), addr.Port()).Encode())

		conn := listenLoopback(t, 34)
		ckey := newKey(t)
		caddr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
		v.serve(enode.ID(ckey.ID()), signRecord(t, ckey, caddr.Addr().AsSlice(), caddr.Port()).Encode())
		cu, err := Listen(conn, Config{Self: ckey.ID(), Verifier: v, Bootnodes: []Bootnode{{ID: enode.ID(key.ID()), Addr: addr}}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cu.Close)
		c := &testNode{UDP: cu, key: ckey}
		waitWithin(t, 15*time.Second, "the first bootstrap", func() bool { return firstBootstrapDone(c) })
		if len(c.Nodes()) != 0 {
			t.Fatal("table not empty with no bootnode up")
		}

		bconn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
		if err != nil {
			t.Fatalf("listen on the bootnode endpoint %v: %v", addr, err)
		}
		bu, err := Listen(bconn, Config{Self: key.ID(), Verifier: v})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(bu.Close)
		waitWithin(t, bootRetryDeadline, "the bootnode in the table once it is up", func() bool {
			return hasNode(c.Nodes(), enode.ID(key.ID()))
		})
	})
}

func TestQSDiscoveryLimitsAreSet(t *testing.T) {
	limits := map[string]int64{
		"MaxPacketSize":      MaxPacketSize,
		"MaxNeighbors":       MaxNeighbors,
		"MaxAmplification":   MaxAmplification,
		"FindnodeSize":       FindnodeSize,
		"NumBuckets":         NumBuckets,
		"BucketSize":         BucketSize,
		"MaxReplacements":    MaxReplacements,
		"BucketIPLimit":      BucketIPLimit,
		"TableIPLimit":       TableIPLimit,
		"ProvenTime":         int64(ProvenTime),
		"PingTimeout":        int64(PingTimeout),
		"MaxPendingPings":    MaxPendingPings,
		"MaxVerifications":   MaxVerifications,
		"VerifyInterval":     int64(VerifyInterval),
		"MaxVerifyStarts":    MaxVerifyStarts,
		"MaxVerifyRetries":   MaxVerifyRetries,
		"MaxRemotePings":     MaxRemotePings,
		"MaxChallengePings":  MaxChallengePings,
		"MaxFailed":          MaxFailed,
		"SourceRate":         SourceRate,
		"SourceBurst":        SourceBurst,
		"CookieReserve":      CookieReserve,
		"MaxSources":         MaxSources,
		"LookupAlpha":        LookupAlpha,
		"LookupTimeout":      int64(LookupTimeout),
		"LookupResults":      LookupResults,
		"RevalidateInterval": int64(RevalidateInterval),
		"MaxRevalidateFails": MaxRevalidateFails,

		"BootnodeRetryInterval": int64(BootnodeRetryInterval),
	}
	if BootnodeRetryInterval+2*PingTimeout > time.Minute/2 {
		t.Errorf("BootnodeRetryInterval %v lets a first start wait too long for its bootnodes", BootnodeRetryInterval)
	}
	for name, v := range limits {
		if v <= 0 {
			t.Errorf("%s is %d, want it set", name, v)
		}
	}
	if CookieReserve >= SourceBurst {
		t.Errorf("CookieReserve %d leaves no requests without the cookie", CookieReserve)
	}
	if MaxRemotePings+MaxChallengePings >= MaxPendingPings {
		t.Errorf("MaxRemotePings %d leaves no pings for the node's own checks", MaxRemotePings)
	}
	// A full neighbors packet of IPv6 endpoints fits in a packet.
	full := &Neighbors{Nodes: make([]Neighbor, MaxNeighbors)}
	for i := range full.Nodes {
		full.Nodes[i] = Neighbor{IP: net.ParseIP("2001:db8::1"), UDP: 65535}
		full.Nodes[i].ID[0] = 0xff
	}
	enc, err := Encode(full)
	if err != nil {
		t.Fatalf("a full neighbors packet does not fit: %v", err)
	}
	// A findnode is padded so that a full answer is within
	// MaxAmplification times its size.
	fn, err := Encode(&Findnode{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fn) < FindnodeSize || len(fn) > MaxPacketSize || len(enc) > MaxAmplification*len(fn) {
		t.Fatalf("findnode of %d bytes for a full answer of %d bytes", len(fn), len(enc))
	}
	if p, err := Decode(fn); err != nil {
		t.Fatalf("padded findnode does not decode: %v", err)
	} else if _, ok := p.(*Findnode); !ok {
		t.Fatalf("padded findnode decodes as %T", p)
	}
}
