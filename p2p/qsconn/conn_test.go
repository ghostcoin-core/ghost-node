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

package qsconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
)

// captureConn keeps the records written while hold is set instead of sending
// them.
type captureConn struct {
	net.Conn
	mu      sync.Mutex
	hold    bool
	records [][]byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hold {
		c.records = append(c.records, bytes.Clone(p))
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// connectedPair returns two Conns after a handshake; raw is the initiator's
// end of the pipe, for writing records directly.
func connectedPair(t *testing.T) (ini, resp *Conn, capture *captureConn, raw net.Conn) {
	t.Helper()
	iniKey, respKey := newTestIdentity(t), newTestIdentity(t)
	p1, p2 := net.Pipe()
	capture = &captureConn{Conn: p1}
	dest := respKey.ID()
	ini, resp = NewConn(capture, &dest, testConfig), NewConn(p2, nil, testConfig)
	ri, rr := runHandshakes(ini, resp, iniKey, respKey)
	if ri.err != nil || rr.err != nil {
		t.Fatalf("handshake failed: initiator %v, responder %v", ri.err, rr.err)
	}
	t.Cleanup(func() { ini.Close(); resp.Close() })
	return ini, resp, capture, p1
}

// heldRecords has ini write n frames and returns their wire records.
func heldRecords(t *testing.T, ini *Conn, capture *captureConn, n int) [][]byte {
	t.Helper()
	capture.mu.Lock()
	capture.hold = true
	capture.mu.Unlock()
	for i := 0; i < n; i++ {
		if _, err := ini.Write(uint64(i+1), []byte(fmt.Sprintf("frame %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	return capture.records
}

func sendRaw(raw net.Conn, records ...[]byte) {
	go func() {
		for _, r := range records {
			if _, err := raw.Write(r); err != nil {
				return
			}
		}
	}()
}

func expectFrame(t *testing.T, c *Conn, code uint64) {
	t.Helper()
	got, _, _, err := c.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != code {
		t.Fatalf("got code %d, want %d", got, code)
	}
}

func expectRefused(t *testing.T, c *Conn, want error) {
	t.Helper()
	_, _, _, err := c.Read()
	if !errors.Is(err, want) {
		t.Fatalf("read: got %v, want %v", err, want)
	}
	// The connection is closed and stays failed.
	if _, _, _, err2 := c.Read(); err2 != err {
		t.Fatalf("second read: got %v, want %v", err2, err)
	}
	if _, err := c.Write(1, nil); err == nil {
		t.Fatal("write on a refused connection succeeded")
	}
}

func TestFramesInOrder(t *testing.T) {
	ini, resp, capture, raw := connectedPair(t)
	recs := heldRecords(t, ini, capture, 3)
	sendRaw(raw, recs...)
	for i := range recs {
		expectFrame(t, resp, uint64(i+1))
	}
}

func TestModifiedFrameRefused(t *testing.T) {
	size := len(fmt.Sprintf("frame %d", 0))
	for _, off := range []int{0, 3, headerSize, headerSize + codeSize, headerSize + codeSize + size, headerSize + codeSize + size + tagSize - 1} {
		t.Run(fmt.Sprint(off), func(t *testing.T) {
			ini, resp, capture, raw := connectedPair(t)
			rec := bytes.Clone(heldRecords(t, ini, capture, 1)[0])
			rec[off] ^= 0x01
			// Padding, so that a longer announced length is still read.
			sendRaw(raw, rec, make([]byte, 8))
			_, _, _, err := resp.Read()
			// A changed length is refused for its size or for its tag.
			if !errors.Is(err, errFrameAuth) && (off >= headerSize || !errors.Is(err, errFrameSize)) {
				t.Fatalf("read: got %v", err)
			}
		})
	}
}

func TestReplayedFrameRefused(t *testing.T) {
	ini, resp, capture, raw := connectedPair(t)
	recs := heldRecords(t, ini, capture, 2)
	sendRaw(raw, recs[0], recs[0])
	expectFrame(t, resp, 1)
	expectRefused(t, resp, errFrameAuth)
}

func TestReorderedFrameRefused(t *testing.T) {
	ini, resp, capture, raw := connectedPair(t)
	recs := heldRecords(t, ini, capture, 2)
	sendRaw(raw, recs[1], recs[0])
	expectRefused(t, resp, errFrameAuth)
}

func TestFrameLengthRefused(t *testing.T) {
	for _, n := range []uint32{0, codeSize + tagSize - 1, codeSize + testConfig.MaxMessageSize + tagSize + 1, 0xffffffff} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			_, resp, _, raw := connectedPair(t)
			sendRaw(raw, binary.BigEndian.AppendUint32(nil, n))
			expectRefused(t, resp, errFrameSize)
		})
	}
}

func TestRekeyAcrossBoundary(t *testing.T) {
	defer func(old uint64) { rekeyInterval = old }(rekeyInterval)
	rekeyInterval = 4

	ini, resp, _, raw := connectedPair(t)
	// The authentication message was record 0 in each direction.
	if ini.out.counter != 1 || resp.in.counter != 1 {
		t.Fatalf("counters after the handshake: %d, %d", ini.out.counter, resp.in.counter)
	}
	k0 := ini.out.key

	errc := make(chan error, 1)
	const n = 10
	go func() {
		for i := 0; i < n; i++ {
			if _, err := ini.Write(uint64(i), []byte{byte(i)}); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()
	for i := 0; i < n; i++ {
		code, data, _, err := resp.Read()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if code != uint64(i) || !bytes.Equal(data, []byte{byte(i)}) {
			t.Fatalf("frame %d: got %d %x", i, code, data)
		}
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	// 11 records: rekeyed after records 3 and 7, now at counter 3.
	want := nextKey(nextKey(k0))
	if ini.out.key != want || resp.in.key != want {
		t.Fatal("keys after two rekeys are not SHAKE256 twice over the first key")
	}
	if ini.out.counter != 3 || resp.in.counter != 3 {
		t.Fatalf("counters: %d, %d, want 3", ini.out.counter, resp.in.counter)
	}
	// The other direction is unaffected.
	if resp.out.counter != 1 || resp.out.key != ini.in.key {
		t.Fatal("the other direction changed")
	}

	// A record under the key from before the rekey is refused.
	stale := newCipherState(nextKey(k0))
	stale.counter = 3
	sendRaw(raw, stale.seal(append(make([]byte, codeSize), 'x')))
	expectRefused(t, resp, errFrameAuth)
}

func TestRekeyBothDirections(t *testing.T) {
	defer func(old uint64) { rekeyInterval = old }(rekeyInterval)
	rekeyInterval = 2

	ini, resp, _, _ := connectedPair(t)
	for i := 0; i < 7; i++ {
		for _, p := range [][2]*Conn{{ini, resp}, {resp, ini}} {
			errc := make(chan error, 1)
			go func() { _, err := p[0].Write(uint64(i), []byte("x")); errc <- err }()
			if code, _, _, err := p[1].Read(); err != nil || code != uint64(i) {
				t.Fatalf("frame %d: code %d, %v", i, code, err)
			}
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		}
	}
}
