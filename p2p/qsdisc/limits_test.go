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
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

// idAtDistance returns the i-th ID at log distance d from self.
func idAtDistance(self enode.ID, d int, i uint32) enode.ID {
	var x enode.ID
	binary.BigEndian.PutUint32(x[28:], i)
	x[0] ^= 0x5a // spread the IDs a little
	// Clear the bits above d-1 and set bit d-1.
	for bit := 255; bit >= d; bit-- {
		x[31-bit/8] &^= 1 << (bit % 8)
	}
	x[31-(d-1)/8] |= 1 << ((d - 1) % 8)
	for k := range x {
		x[k] ^= self[k]
	}
	return x
}

func publicAddr(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, byte(i >> 8), byte(i), 1}), 30303)
}

func TestQSDiscoveryTableLimits(t *testing.T) {
	var self enode.ID
	self[0] = 1
	if got := enode.LogDist(self, idAtDistance(self, 256, 1)); got != 256 {
		t.Fatalf("idAtDistance: distance %d", got)
	}
	now := time.Now()

	t.Run("subnet", func(t *testing.T) {
		tab := newTable(self)
		// Three nodes of one /24 in the farthest bucket: the third is refused.
		for i := range 3 {
			n := Node{ID: idAtDistance(self, 256, uint32(i)), Addr: netip.MustParseAddrPort("1.2.3." + string(rune('1'+i)) + ":1")}
			if added := tab.add(n, now); added != (i < BucketIPLimit) {
				t.Fatalf("node %d of one /24: added %v", i, added)
			}
		}
		// Over all buckets, at most TableIPLimit from one /24.
		tab = newTable(self)
		for d := 240; d <= 256; d++ {
			for i := range BucketIPLimit {
				ip := netip.AddrFrom4([4]byte{1, 2, 3, byte(d - 239 + i*20)})
				tab.add(Node{ID: idAtDistance(self, d, uint32(i)), Addr: netip.AddrPortFrom(ip, 1)}, now)
			}
		}
		if n := tab.len(); n != TableIPLimit {
			t.Fatalf("table holds %d nodes of one /24, want %d", n, TableIPLimit)
		}
		// LAN addresses are not counted, as in the old table.
		tab = newTable(self)
		for i := range BucketSize {
			tab.add(Node{ID: idAtDistance(self, 256, uint32(i)), Addr: netip.MustParseAddrPort("127.0.0.1:1")}, now)
		}
		if n := tab.len(); n != BucketSize {
			t.Fatalf("table holds %d loopback nodes, want %d", n, BucketSize)
		}
	})

	t.Run("buckets-and-replacements", func(t *testing.T) {
		tab := newTable(self)
		for i := range BucketSize + MaxReplacements + 5 {
			tab.add(Node{ID: idAtDistance(self, 256, uint32(i)), Addr: publicAddr(i)}, now)
		}
		b := tab.bucket(idAtDistance(self, 256, 0))
		if len(b.entries) != BucketSize || len(b.replacements) != MaxReplacements {
			t.Fatalf("bucket has %d entries and %d replacements", len(b.entries), len(b.replacements))
		}
		// A dead node is replaced by the newest candidate.
		newest := b.replacements[len(b.replacements)-1].ID
		tab.remove(b.entries[0].ID)
		if _, ok := tab.get(newest); !ok || len(b.entries) != BucketSize {
			t.Fatal("dead node not replaced by the newest candidate")
		}
		// The table never holds more than its buckets.
		for d := 1; d <= 256; d++ {
			for i := range BucketSize + MaxReplacements + 1 {
				tab.add(Node{ID: idAtDistance(self, d, uint32(i)), Addr: publicAddr(d*64 + i)}, now)
			}
		}
		if n := tab.len(); n != NumBuckets*BucketSize {
			t.Fatalf("full table holds %d nodes, want %d", n, NumBuckets*BucketSize)
		}
		if tab.add(Node{ID: self, Addr: publicAddr(9999)}, now) {
			t.Fatal("own ID added")
		}
	})
}

func TestQSDiscoveryPacketLimits(t *testing.T) {
	if _, err := Decode(make([]byte, MaxPacketSize+1)); !errors.Is(err, errPacketTooLarge) {
		t.Fatalf("oversized packet: %v", err)
	}
	over := &Neighbors{Nodes: make([]Neighbor, MaxNeighbors+1)}
	for i := range over.Nodes {
		over.Nodes[i] = Neighbor{IP: net.IPv4(1, 2, 3, 4).To4(), UDP: 1}
	}
	if _, err := Encode(over); !errors.Is(err, errTooManyNodes) {
		t.Fatalf("encoding %d neighbors: %v", len(over.Nodes), err)
	}
	body, err := rlp.EncodeToBytes(over)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append([]byte{NeighborsPacket}, body...)); !errors.Is(err, errTooManyNodes) {
		t.Fatalf("decoding %d neighbors: %v", len(over.Nodes), err)
	}
	ping := &Ping{Token: [TokenSize]byte{1}}
	b, err := Encode(ping)
	if err != nil {
		t.Fatal(err)
	}
	pong, err := Encode(&Pong{Token: ping.Token})
	if err != nil {
		t.Fatal(err)
	}
	if len(pong) > len(b) {
		t.Fatalf("pong of %d bytes answers a ping of %d", len(pong), len(b))
	}
}

// fullNeighbors is the largest neighbors packet: MaxNeighbors IPv6 entries.
func fullNeighbors(b testing.TB) []byte {
	p := &Neighbors{Nodes: make([]Neighbor, MaxNeighbors)}
	for i := range p.Nodes {
		p.Nodes[i] = Neighbor{IP: net.ParseIP("2001:db8::1"), UDP: 65535}
		p.Nodes[i].ID[0], p.Nodes[i].ID[31] = 0xff, byte(i)
	}
	p.From[0] = 0xff
	enc, err := Encode(p)
	if err != nil {
		b.Fatal(err)
	}
	return enc
}

// BenchmarkPacketDecode decodes the largest packet a peer can send.
func BenchmarkPacketDecode(b *testing.B) {
	enc := fullNeighbors(b)
	b.ReportMetric(float64(len(enc)), "packet-bytes")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(enc); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTableMemory measures the heap of a node whose table, with every
// replacement list, and whose source tracking are full: MaxSources token
// buckets of source addresses, MaxSources of requests with our cookie
// and MaxSources endpoints, MaxFailed failures, MaxVerifyStarts starts,
// MaxVerifyRetries queued retries and MaxPendingPings pings. Each table node holds a record of full size that
// nothing else references.
func BenchmarkTableMemory(b *testing.B) {
	var self enode.ID
	self[0] = 1
	for b.Loop() {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		u := newUDP(nil, Config{Self: qsconn.NodeID(self), Verifier: nil})
		now := time.Now()
		n := 0
		for d := 240; d <= 256; d++ {
			for i := range BucketSize + MaxReplacements {
				id := idAtDistance(self, d, uint32(i))
				addr := publicAddr(n)
				rec := &enode.QSRecord{
					Seq:       1,
					Scheme:    qsconn.SchemeMLDSA44,
					PublicKey: make([]byte, qsconn.PublicKeySize),
					IP:        addr.Addr().AsSlice(),
					TCP:       30303,
					UDP:       30303,
					Signature: make([]byte, qsconn.SignatureSize),
				}
				u.tab.add(Node{ID: id, Addr: addr, Record: rec}, now)
				n++
			}
		}
		u.mu.Lock()
		for i := range MaxSources {
			addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{2, byte(i >> 8), byte(i), 1}), 30303)
			u.sources.Add(addr.Addr(), &tokenBucket{tokens: SourceBurst, last: now})
			ep := u.endpointLocked(addr)
			ep.proven, ep.answered = now, now
			ep.cookie[0] = 1
		}
		for i := range MaxFailed {
			u.addFailureLocked(nodeAddr{idAtDistance(self, 200, uint32(i)), publicAddr(i)})
		}
		for i := range MaxVerifyStarts {
			if err := u.mayStartLocked(nodeAddr{idAtDistance(self, 201, uint32(i)), publicAddr(i)}, now); err != nil {
				b.Fatal(err)
			}
		}
		u.mu.Unlock()
		for i := range MaxVerifyRetries {
			u.queueRetry(nodeAddr{idAtDistance(self, 202, uint32(i)), publicAddr(i)})
		}
		u.mu.Lock()
		for i := range MaxPendingPings {
			var token [TokenSize]byte
			binary.BigEndian.PutUint32(token[:], uint32(i))
			pp := &pendingPing{addr: publicAddr(i), done: func(qsconn.NodeID, bool) {}}
			pp.timer = time.AfterFunc(time.Hour, func() {})
			u.pings[token] = pp
			u.pinging[pp.addr]++
		}
		u.mu.Unlock()

		runtime.GC()
		runtime.ReadMemStats(&after)
		if got := u.tab.len(); got != NumBuckets*BucketSize {
			b.Fatalf("table holds %d nodes", got)
		}
		b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "heap-bytes")
		for _, pp := range u.pings {
			pp.timer.Stop()
		}
		runtime.KeepAlive(u)
	}
}
