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

package p2p

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/internal/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

// signedQSRecord returns the encoding of a record of key at ip and udp.
func signedQSRecord(t *testing.T, key *qsconn.Identity, seq uint64, ip net.IP, udp uint16) []byte {
	t.Helper()
	rec := &enode.QSRecord{Seq: seq, IP: ip, TCP: udp, UDP: udp}
	if err := rec.Sign(key); err != nil {
		t.Fatal(err)
	}
	return rec.Encode()
}

func newTestRecordCache() *enode.QSRecordCache {
	return enode.NewQSRecordCache(enode.QSRecordCacheSize, enode.QSRecordVerifyRate, nil)
}

// serveRecordRequests accepts connections on ln as key and answers the
// first message of each with rs, as the server does.
func serveRecordRequests(t *testing.T, ln net.Listener, key *qsconn.Identity, rs *qsRecordServer) {
	go func() {
		for {
			fd, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tr := newQSConn(fd, key, nil).(*qsconnTransport)
				defer tr.close(nil)
				if _, err := tr.doEncHandshake(); err != nil {
					return
				}
				msg, err := tr.peekMsg()
				if err != nil || msg.Code != qsRecordRequestMsg {
					return
				}
				rs.serve(tr, msg, netutil.AddrAddr(fd.RemoteAddr()))
			}()
		}
	}()
}

// fakeAnswerer accepts connections on ln as key, reads the record request and
// answers it with answer, whatever was asked.
func fakeAnswerer(ln net.Listener, key *qsconn.Identity, answer func() []byte) {
	go func() {
		for {
			fd, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c := qsconn.NewConn(fd, nil, qsconn.Config{})
				defer c.Close()
				if _, err := c.Handshake(key); err != nil {
					return
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if code, _, _, err := c.Read(); err != nil || code != qsRecordRequestMsg {
					return
				}
				c.Write(qsRecordAnswerMsg, answer())
				c.Read() // until the fetcher closes
			}()
		}
	}()
}

func listenTCP(t *testing.T) (net.Listener, netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).AddrPort()
}

func fetchFrom(t *testing.T, addr netip.AddrPort, key *qsconn.Identity, id enode.ID) ([]byte, error) {
	t.Helper()
	fd, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	return fetchQSRecord(fd, key, id, 5*time.Second)
}

// TestQSRecordFetchAnswersFromCacheOnly checks that a record request is
// answered from the record cache alone: a cached, verified record is
// answered; a validly signed record that was never cached, and a record
// whose signature failed in the cache, are answered with an empty answer.
// A running server answers its own record, which verifies and names its
// endpoint, and the fetch never becomes a peer.
func TestQSRecordFetchAnswersFromCacheOnly(t *testing.T) {
	server := newQSIdentity(t)
	cached, uncached, forged := newQSIdentity(t), newQSIdentity(t), newQSIdentity(t)
	cache := newTestRecordCache()
	ip := net.IP{10, 0, 0, 1}

	cachedEnc := signedQSRecord(t, cached, 1, ip, 30303)
	if _, err := cache.Add(cachedEnc); err != nil {
		t.Fatal(err)
	}
	signedQSRecord(t, uncached, 1, ip, 30303) // valid but never cached
	forgedEnc := signedQSRecord(t, forged, 1, ip, 30303)
	forgedRec, _ := enode.DecodeQSRecord(forgedEnc)
	forgedRec.Signature = bytes.Clone(forgedRec.Signature)
	forgedRec.Signature[0] ^= 0xff
	if _, err := cache.Add(forgedRec.Encode()); err == nil {
		t.Fatal("record with a bad signature cached")
	}

	ln, addr := listenTCP(t)
	serveRecordRequests(t, ln, server, &qsRecordServer{cache: cache, limit: newQSFetchLimiter(nil)})

	// The request names the asked ID; the server is reached under its own
	// ID, so only the ID in the request varies here.
	ask := func(id enode.ID) ([]byte, error) {
		fd, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		dest := server.ID()
		c := qsconn.NewConn(fd, &dest, qsconn.Config{})
		if _, err := c.Handshake(newQSIdentity(t)); err != nil {
			t.Fatal(err)
		}
		req, _ := rlp.EncodeToBytes(&qsRecordRequest{ID: id})
		if _, err := c.Write(qsRecordRequestMsg, req); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		code, data, _, err := c.Read()
		if err != nil {
			return nil, err
		}
		if code != qsRecordAnswerMsg {
			t.Fatalf("answer code %#x", code)
		}
		return data, nil
	}
	got, err := ask(enode.ID(cached.ID()))
	if err != nil || !bytes.Equal(got, cachedEnc) {
		t.Fatalf("cached record answered as %x (err %v), want the cached record", got, err)
	}
	for name, id := range map[string]qsconn.NodeID{"uncached": uncached.ID(), "forged": forged.ID(), "unknown": newQSIdentity(t).ID()} {
		got, err := ask(enode.ID(id))
		if err != nil || len(got) != 0 {
			t.Fatalf("%s record answered as %d bytes (err %v), want an empty answer", name, len(got), err)
		}
	}

	// A running server answers its own record from its cache.
	srv := startDiscServer(t, "b", server, nil)
	ch := make(chan *PeerEvent, 10)
	sub := srv.SubscribeEvents(ch)
	defer sub.Unsubscribe()
	tcp := srv.listener.Addr().(*net.TCPAddr).AddrPort()
	enc, err := fetchFrom(t, tcp, newQSIdentity(t), enode.ID(server.ID()))
	if err != nil {
		t.Fatalf("fetch of the server's own record: %v", err)
	}
	rec, err := enode.DecodeQSRecord(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("own record does not verify: %v", err)
	}
	if err := checkQSRecord(rec, enode.ID(server.ID()), tcp); err != nil {
		t.Fatalf("own record does not name the server's endpoint: %v", err)
	}
	if cur := srv.records.Get(enode.ID(server.ID())); cur == nil || !bytes.Equal(cur.Encode(), enc) {
		t.Fatal("own record answered is not the cached one")
	}
	if _, err := fetchFrom(t, tcp, newQSIdentity(t), enode.ID(server.ID())); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	// Another ID is not in its cache.
	fd, _ := net.Dial("tcp", tcp.String())
	dest := server.ID()
	c := qsconn.NewConn(fd, &dest, qsconn.Config{})
	if _, err := c.Handshake(newQSIdentity(t)); err != nil {
		t.Fatal(err)
	}
	req, _ := rlp.EncodeToBytes(&qsRecordRequest{ID: enode.ID(uncached.ID())})
	c.Write(qsRecordRequestMsg, req)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if code, data, _, err := c.Read(); err != nil || code != qsRecordAnswerMsg || len(data) != 0 {
		t.Fatalf("server answered an unknown ID with code %#x, %d bytes (err %v), want an empty answer", code, len(data), err)
	}
	c.Close()

	time.Sleep(100 * time.Millisecond)
	select {
	case ev := <-ch:
		t.Fatalf("server event %v after record fetches", ev.Type)
	default:
	}
	if n := srv.PeerCount(); n != 0 {
		t.Fatalf("%d peers after record fetches", n)
	}
}

// TestQSRecordFetchBoundsAnswerAndSource checks the limits of the record
// fetch: an answer over QSRecordMaxSize is refused before it is read; one
// source address gets QSRecordFetchBurst requests answered, then
// QSRecordFetchRate a second, while another source is answered; at most
// QSRecordFetchSources addresses are tracked; and a connection carries one
// request only.
func TestQSRecordFetchBoundsAnswerAndSource(t *testing.T) {
	if enode.QSRecordFetchRate != 1 || enode.QSRecordFetchBurst != 5 || enode.QSRecordFetchSources != 1024 || enode.QSRecordFetchPerConn != 1 {
		t.Fatal("record fetch limits differ from docs/account-transactions.md")
	}

	// The answer size.
	key := newQSIdentity(t)
	for _, size := range []int{enode.QSRecordMaxSize, enode.QSRecordMaxSize + 1} {
		ln, addr := listenTCP(t)
		fakeAnswerer(ln, key, func() []byte { return bytes.Repeat([]byte{0xc0}, size) })
		got, err := fetchFrom(t, addr, newQSIdentity(t), enode.ID(key.ID()))
		switch {
		case size <= enode.QSRecordMaxSize && (err != nil || len(got) != size):
			t.Fatalf("answer of %d bytes: got %d bytes, err %v", size, len(got), err)
		case size > enode.QSRecordMaxSize && err == nil:
			t.Fatalf("answer of %d bytes accepted", size)
		}
	}

	// The per-source bucket.
	var clock mclock.Simulated
	l := newQSFetchLimiter(&clock)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for i := 0; i < enode.QSRecordFetchBurst; i++ {
		if !l.allow(a) {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	if l.allow(a) {
		t.Fatal("request over the burst allowed")
	}
	if l.allow(netip.AddrFrom16(a.As16())) {
		t.Fatal("the IPv4-mapped form of a source has a bucket of its own")
	}
	if !l.allow(b) {
		t.Fatal("another source refused")
	}
	clock.Run(time.Second / enode.QSRecordFetchRate)
	if !l.allow(a) {
		t.Fatal("request refused after the bucket refilled one token")
	}
	if l.allow(a) {
		t.Fatal("bucket refilled more than one token a second")
	}
	for i := 0; i < 3*enode.QSRecordFetchSources; i++ {
		l.allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if n := l.len(); n != enode.QSRecordFetchSources {
		t.Fatalf("%d sources tracked, want %d", n, enode.QSRecordFetchSources)
	}

	// A running server answers a source's burst and refuses the next.
	srvKey := newQSIdentity(t)
	srv := startDiscServer(t, "b", srvKey, func(c *Config) { c.clock = new(mclock.Simulated) })
	tcp := srv.listener.Addr().(*net.TCPAddr).AddrPort()
	for i := 0; i < enode.QSRecordFetchBurst; i++ {
		if _, err := fetchFrom(t, tcp, newQSIdentity(t), enode.ID(srvKey.ID())); err != nil {
			t.Fatalf("fetch %d of the burst: %v", i, err)
		}
	}
	if _, err := fetchFrom(t, tcp, newQSIdentity(t), enode.ID(srvKey.ID())); !errors.Is(err, errRecordNoAnswer) {
		t.Fatalf("fetch over the burst: got %v, want no answer", err)
	}

	// One request per connection: the second is not answered.
	srv2Key := newQSIdentity(t)
	srv2 := startDiscServer(t, "c", srv2Key, nil)
	fd, err := net.Dial("tcp", srv2.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dest := srv2Key.ID()
	c := qsconn.NewConn(fd, &dest, qsconn.Config{})
	defer c.Close()
	if _, err := c.Handshake(newQSIdentity(t)); err != nil {
		t.Fatal(err)
	}
	req, _ := rlp.EncodeToBytes(&qsRecordRequest{ID: enode.ID(srv2Key.ID())})
	for i := 0; i < 2; i++ {
		if _, err := c.Write(qsRecordRequestMsg, req); err != nil {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if code, data, _, err := c.Read(); err != nil || code != qsRecordAnswerMsg || len(data) == 0 {
		t.Fatalf("first request: code %#x, %d bytes, err %v", code, len(data), err)
	}
	if code, _, _, err := c.Read(); err == nil {
		t.Fatalf("second request on the connection answered with code %#x", code)
	}
}

// TestQSRecordVerifierChecksIDAndEndpoint checks that the verifier accepts a
// fetched record only when it verifies, is of the node ID asked for and its
// IP and UDP port are the endpoint that answered, and that a node it cannot
// reach is not accepted.
func TestQSRecordVerifierChecksIDAndEndpoint(t *testing.T) {
	node, other := newQSIdentity(t), newQSIdentity(t)
	id := enode.ID(node.ID())
	loop := net.IP{127, 0, 0, 1}

	ln, addr := listenTCP(t)
	port := addr.Port()
	var answer atomic.Pointer[[]byte]
	setAnswer := func(b []byte) { answer.Store(&b) }
	setAnswer(nil)
	fakeAnswerer(ln, node, func() []byte { return *answer.Load() })

	forged, _ := enode.DecodeQSRecord(signedQSRecord(t, node, 9, loop, port))
	forged.Signature[0] ^= 0xff

	cases := []struct {
		name   string
		answer []byte
		ok     bool
	}{
		{"another node's record", signedQSRecord(t, other, 1, loop, port), false},
		{"another UDP port", signedQSRecord(t, node, 2, loop, port+1), false},
		{"another IP", signedQSRecord(t, node, 3, net.IP{10, 0, 0, 1}, port), false},
		{"bad signature", forged.Encode(), false},
		{"empty answer", nil, false},
		{"not a record", []byte{0x01, 0x02}, false},
		{"the node's record", signedQSRecord(t, node, 10, loop, port), true},
	}
	for _, c := range cases {
		cache := newTestRecordCache()
		v := newQSRecordVerifier(newQSIdentity(t), cache)
		setAnswer(c.answer)
		rec, err := v.VerifyRecord(id, addr)
		if c.ok {
			if err != nil || rec == nil || rec.ID() != id || rec.UDP != port {
				t.Fatalf("%s: refused: %v", c.name, err)
			}
			if cache.Get(id) == nil {
				t.Fatalf("%s: accepted record not cached", c.name)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
		if cache.Len() != 0 {
			t.Fatalf("%s: refused record cached", c.name)
		}
	}

	// Another node answering at the endpoint fails the handshake.
	setAnswer(signedQSRecord(t, other, 1, loop, port))
	v := newQSRecordVerifier(newQSIdentity(t), newTestRecordCache())
	if _, err := v.VerifyRecord(enode.ID(other.ID()), addr); err == nil {
		t.Fatal("record accepted from an endpoint whose handshake names another ID")
	}

	// Nothing listening at the endpoint: not accepted.
	ln.Close()
	if _, err := v.VerifyRecord(id, addr); err == nil {
		t.Fatal("record accepted from an endpoint that cannot be reached")
	}

	// The check itself.
	rec, _ := enode.DecodeQSRecord(signedQSRecord(t, node, 1, loop, 30303))
	ep := netip.MustParseAddrPort("127.0.0.1:30303")
	if err := checkQSRecord(rec, id, ep); err != nil {
		t.Fatalf("matching record refused: %v", err)
	}
	if err := checkQSRecord(rec, id, netip.AddrPortFrom(netip.AddrFrom16(ep.Addr().As16()), 30303)); err != nil {
		t.Fatalf("matching record refused for the IPv4-mapped endpoint: %v", err)
	}
	if err := checkQSRecord(rec, enode.ID(other.ID()), ep); !errors.Is(err, errRecordWrongID) {
		t.Fatalf("record of another ID: %v", err)
	}
	if err := checkQSRecord(rec, id, netip.MustParseAddrPort("127.0.0.1:30304")); !errors.Is(err, errRecordWrongEndpoint) {
		t.Fatalf("record of another port: %v", err)
	}
	if err := checkQSRecord(rec, id, netip.MustParseAddrPort("127.0.0.2:30303")); !errors.Is(err, errRecordWrongEndpoint) {
		t.Fatalf("record of another IP: %v", err)
	}
}

// startDiscServer starts a listening server with discovery on.
func startDiscServer(t *testing.T, name string, key *qsconn.Identity, mod func(*Config), protos ...Protocol) *Server {
	t.Helper()
	cfg := Config{
		Name:       name,
		Identity:   key,
		MaxPeers:   10,
		Protocols:  protos,
		ListenAddr: "127.0.0.1:0",
		Logger:     testlog.Logger(t, log.LvlTrace).New("server", name),
	}
	if mod != nil {
		mod(&cfg)
	}
	srv := &Server{Config: cfg}
	if err := srv.Start(); err != nil {
		t.Fatalf("could not start server %s: %v", name, err)
	}
	t.Cleanup(srv.Stop)
	return srv
}
