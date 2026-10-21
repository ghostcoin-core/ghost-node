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

package enode

import (
	"bytes"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

func newTestIdentity(t testing.TB) *qsconn.Identity {
	t.Helper()
	key, err := qsconn.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedTestRecord(t testing.TB, key *qsconn.Identity, seq uint64) *QSRecord {
	t.Helper()
	r := &QSRecord{
		Seq:    seq,
		IP:     net.ParseIP("10.3.58.6"),
		TCP:    30303,
		UDP:    30301,
		ForkID: QSForkID{Hash: [4]byte{0xfc, 0x64, 0xec, 0x04}, Next: 1150000},
	}
	if err := r.Sign(key); err != nil {
		t.Fatal(err)
	}
	return r
}

// countVerify makes the cache count its signature verifications.
func countVerify(c *QSRecordCache) *atomic.Int64 {
	n := new(atomic.Int64)
	verify := c.verify
	c.verify = func(r *QSRecord) error {
		n.Add(1)
		return verify(r)
	}
	return n
}

func TestQSRecordSignVerify(t *testing.T) {
	key := newTestIdentity(t)
	r := signedTestRecord(t, key, 1)
	enc := r.Encode()
	if len(enc) > QSRecordMaxSize {
		t.Fatalf("record is %d bytes, over %d", len(enc), QSRecordMaxSize)
	}
	dec, err := DecodeQSRecord(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := dec.Verify(); err != nil {
		t.Fatalf("record signed by its node key does not verify: %v", err)
	}
	if dec.ID() != ID(key.ID()) {
		t.Fatalf("record ID %v, want the node ID %v", dec.ID(), key.ID())
	}
	if !bytes.Equal(dec.Encode(), enc) {
		t.Fatal("record does not encode back to the same bytes")
	}
	if len(dec.IP) != net.IPv4len || dec.TCP != 30303 || dec.UDP != 30301 || dec.ForkID != r.ForkID || dec.Seq != 1 {
		t.Fatalf("decoded fields differ: %+v", dec)
	}

	// The signature covers every field before it.
	for name, change := range map[string]func(*QSRecord){
		"seq":     func(r *QSRecord) { r.Seq++ },
		"ip":      func(r *QSRecord) { r.IP = net.IP{10, 3, 58, 7} },
		"tcp":     func(r *QSRecord) { r.TCP++ },
		"udp":     func(r *QSRecord) { r.UDP++ },
		"fork id": func(r *QSRecord) { r.ForkID.Next++ },
		"key":     func(r *QSRecord) { r.PublicKey = newTestIdentity(t).PublicKey() },
	} {
		c, _ := DecodeQSRecord(enc)
		change(c)
		if err := c.Verify(); !errors.Is(err, errQSRecordSignature) {
			t.Errorf("record with a changed %s: got %v, want %v", name, err, errQSRecordSignature)
		}
	}
}

func TestQSRecordDropped(t *testing.T) {
	key := newTestIdentity(t)
	good := signedTestRecord(t, key, 1)

	t.Run("too large", func(t *testing.T) {
		big := *good
		big.Signature = make([]byte, QSRecordMaxSize)
		enc := big.Encode()
		if _, err := DecodeQSRecord(enc); !errors.Is(err, errQSRecordTooLarge) {
			t.Fatalf("record of %d bytes: got %v, want %v", len(enc), err, errQSRecordTooLarge)
		}
		// A record with a valid signature and padding is refused by its
		// size before it is decoded.
		raw, _ := rlp.EncodeToBytes([]interface{}{good.Seq, good.Scheme, good.PublicKey, good.IP, good.TCP, good.UDP, good.ForkID, good.Signature, make([]byte, 1000)})
		if len(raw) <= QSRecordMaxSize {
			t.Fatalf("test record is only %d bytes", len(raw))
		}
		if _, err := DecodeQSRecord(raw); !errors.Is(err, errQSRecordTooLarge) {
			t.Fatalf("got %v, want %v", err, errQSRecordTooLarge)
		}
		c := NewQSRecordCache(8, 8, nil)
		n := countVerify(c)
		if _, err := c.Add(enc); err == nil || n.Load() != 0 || c.Len() != 0 {
			t.Fatalf("cache took a record too large: err %v, %d verifications", err, n.Load())
		}
	})

	t.Run("unknown scheme", func(t *testing.T) {
		r := *good
		r.Scheme = 0x0002
		enc := r.Encode()
		if _, err := DecodeQSRecord(enc); !errors.Is(err, errQSRecordScheme) {
			t.Fatalf("got %v, want %v", err, errQSRecordScheme)
		}
		c := NewQSRecordCache(8, 8, nil)
		n := countVerify(c)
		if _, err := c.Add(enc); !errors.Is(err, errQSRecordScheme) || n.Load() != 0 {
			t.Fatalf("got %v after %d verifications, want %v before any", err, n.Load(), errQSRecordScheme)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		r := *good
		r.Signature = append([]byte{}, good.Signature...)
		r.Signature[100] ^= 0x01
		enc := r.Encode()
		dec, err := DecodeQSRecord(enc)
		if err != nil {
			t.Fatal(err)
		}
		if err := dec.Verify(); !errors.Is(err, errQSRecordSignature) {
			t.Fatalf("got %v, want %v", err, errQSRecordSignature)
		}
		c := NewQSRecordCache(8, 8, nil)
		if _, err := c.Add(enc); !errors.Is(err, errQSRecordSignature) {
			t.Fatalf("got %v, want %v", err, errQSRecordSignature)
		}
		if c.Get(r.ID()) != nil || c.Len() != 0 {
			t.Fatal("cache hands out a record whose signature failed")
		}
	})

	t.Run("signed by another key", func(t *testing.T) {
		r := *good
		r.Signature = signedTestRecord(t, newTestIdentity(t), 1).Signature
		if err := r.Verify(); !errors.Is(err, errQSRecordSignature) {
			t.Fatalf("got %v, want %v", err, errQSRecordSignature)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		for name, enc := range map[string][]byte{
			"short key":       func() []byte { r := *good; r.PublicKey = r.PublicKey[1:]; return r.Encode() }(),
			"short signature": func() []byte { r := *good; r.Signature = r.Signature[1:]; return r.Encode() }(),
			"bad ip":          func() []byte { r := *good; r.IP = net.IP{1, 2, 3}; return r.Encode() }(),
			"trailing bytes":  append(good.Encode(), 0x80),
			"extra field":     func() []byte { b, _ := rlp.EncodeToBytes([]interface{}{good.Seq, good.Scheme, good.PublicKey, good.IP, good.TCP, good.UDP, good.ForkID, good.Signature, uint(1)}); return b }(),
		} {
			if _, err := DecodeQSRecord(enc); err == nil {
				t.Errorf("%s: record decoded", name)
			}
		}
	})
}

// TestQSRecordCacheVerifiesOnce checks that a record is verified once: the
// same record again, from many sources at once, a failed record again and an
// older record are all answered without verifying.
func TestQSRecordCacheVerifiesOnce(t *testing.T) {
	key := newTestIdentity(t)
	r1 := signedTestRecord(t, key, 1)
	enc1 := r1.Encode()

	c := NewQSRecordCache(16, 1000, nil)
	n := countVerify(c)

	got, err := c.Add(enc1)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != ID(key.ID()) || got.Seq != 1 {
		t.Fatalf("cache returned %v seq %d", got.ID(), got.Seq)
	}
	if n.Load() != 1 {
		t.Fatalf("%d verifications for one record, want 1", n.Load())
	}
	for i := 0; i < 5; i++ {
		if again, err := c.Add(enc1); err != nil || again != got {
			t.Fatalf("same record again: %v", err)
		}
	}
	// Another signature of the same node ID and seq is the same record:
	// ML-DSA signatures are hedged, but the cache is keyed by ID and seq.
	resigned := signedTestRecord(t, key, 1)
	if again, err := c.Add(resigned.Encode()); err != nil || again != got {
		t.Fatalf("same ID and seq again: %v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("the same record was verified %d times, want once", n.Load())
	}
	if c.Get(ID(key.ID())) != got {
		t.Fatal("cache does not hand out the verified record")
	}

	// A newer seq is verified and replaces it; the older one is then stale.
	r2 := signedTestRecord(t, key, 2)
	if got2, err := c.Add(r2.Encode()); err != nil || got2.Seq != 2 {
		t.Fatalf("newer record: %v", err)
	}
	if _, err := c.Add(enc1); !errors.Is(err, errQSRecordStale) {
		t.Fatalf("older record: got %v, want %v", err, errQSRecordStale)
	}
	if n.Load() != 2 || c.Len() != 1 || c.Get(ID(key.ID())).Seq != 2 {
		t.Fatalf("after a newer record: %d verifications, %d records", n.Load(), c.Len())
	}

	// The same record from many sources at once is verified once.
	other := newTestIdentity(t)
	enc3 := signedTestRecord(t, other, 7).Encode()
	before := n.Load()
	var wg sync.WaitGroup
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < 4*runtime.GOMAXPROCS(0)+8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			if r, err := c.Add(enc3); err != nil || r.Seq != 7 {
				t.Errorf("concurrent add: %v", err)
			}
		}()
	}
	start.Done()
	wg.Wait()
	if v := n.Load() - before; v != 1 {
		t.Fatalf("one record sent at once by many sources verified %d times, want once", v)
	}

	// A record whose signature failed is not verified again.
	bad := signedTestRecord(t, newTestIdentity(t), 1)
	bad.Signature[0] ^= 0x01
	encBad := bad.Encode()
	before = n.Load()
	for i := 0; i < 3; i++ {
		if _, err := c.Add(encBad); !errors.Is(err, errQSRecordSignature) {
			t.Fatalf("bad record: got %v, want %v", err, errQSRecordSignature)
		}
	}
	if v := n.Load() - before; v != 1 {
		t.Fatalf("the same failed record verified %d times, want once", v)
	}
	if c.Get(bad.ID()) != nil {
		t.Fatal("cache hands out an unverified record")
	}
}

// TestQSRecordCacheBounds checks the size of the cache and the budget of
// verifications per second.
func TestQSRecordCacheBounds(t *testing.T) {
	var clock mclock.Simulated
	c := NewQSRecordCache(2, 3, &clock)
	n := countVerify(c)

	keys := make([]*qsconn.Identity, 5)
	encs := make([][]byte, 5)
	for i := range keys {
		keys[i] = newTestIdentity(t)
		encs[i] = signedTestRecord(t, keys[i], 1).Encode()
	}

	// Three verifications in the first second; the fourth is dropped
	// unverified and not cached.
	for i := 0; i < 3; i++ {
		if _, err := c.Add(encs[i]); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, err := c.Add(encs[3]); !errors.Is(err, errQSRecordBusy) {
		t.Fatalf("record beyond the budget: got %v, want %v", err, errQSRecordBusy)
	}
	if n.Load() != 3 {
		t.Fatalf("%d verifications, want the budget of 3", n.Load())
	}
	if c.Get(ID(keys[3].ID())) != nil {
		t.Fatal("record beyond the budget was cached")
	}
	// A cached record costs nothing from the budget.
	if _, err := c.Add(encs[2]); err != nil {
		t.Fatalf("cached record refused once the budget is spent: %v", err)
	}

	// The cache holds two records, dropping the least recently used.
	if c.Len() != 2 {
		t.Fatalf("cache holds %d records, want 2", c.Len())
	}
	if c.Get(ID(keys[0].ID())) != nil {
		t.Fatal("least recently used record was kept")
	}

	// The budget is refilled every second.
	clock.Run(time.Second)
	if _, err := c.Add(encs[3]); err != nil {
		t.Fatalf("after a second: %v", err)
	}
	if c.Len() != 2 || c.Get(ID(keys[3].ID())) == nil {
		t.Fatal("record verified after the refill is not cached")
	}
}

func TestQSRecordCacheLimitsAreSet(t *testing.T) {
	if QSRecordCacheSize != 4096 || QSRecordVerifyRate != 100 {
		t.Fatalf("limits %d records and %d verifications per second differ from docs/account-transactions.md", QSRecordCacheSize, QSRecordVerifyRate)
	}
}

// BenchmarkQSRecordVerify measures the verification of one record.
func BenchmarkQSRecordVerify(b *testing.B) {
	r := signedTestRecord(b, newTestIdentity(b), 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := r.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkQSRecordCacheMemory fills a cache of QSRecordCacheSize records
// and reports the heap it holds.
func BenchmarkQSRecordCacheMemory(b *testing.B) {
	encs := make([][]byte, QSRecordCacheSize)
	for i := range encs {
		encs[i] = signedTestRecord(b, newTestIdentity(b), 1).Encode()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		c := NewQSRecordCache(QSRecordCacheSize, QSRecordCacheSize, nil)
		c.verify = func(*QSRecord) error { return nil }
		for _, enc := range encs {
			if _, err := c.Add(enc); err != nil {
				b.Fatal(err)
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "heap-bytes")
		runtime.KeepAlive(c)
	}
}
