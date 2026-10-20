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
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

var testConfig = Config{HandshakeTimeout: 3 * time.Second, MaxMessageSize: 1024}

func newTestIdentity(t *testing.T) *Identity {
	t.Helper()
	k, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type handshakeResult struct {
	remote *RemoteIdentity
	err    error
}

// runHandshakes runs both sides concurrently and waits for both.
func runHandshakes(ini, resp *Conn, iniKey, respKey *Identity) (handshakeResult, handshakeResult) {
	var wg sync.WaitGroup
	var ri, rr handshakeResult
	wg.Add(2)
	go func() {
		defer wg.Done()
		ri.remote, ri.err = ini.Handshake(iniKey)
		if ri.err != nil {
			ini.Close()
		}
	}()
	go func() {
		defer wg.Done()
		rr.remote, rr.err = resp.Handshake(respKey)
		if rr.err != nil {
			resp.Close()
		}
	}()
	wg.Wait()
	return ri, rr
}

func TestHandshakeAndFrames(t *testing.T) {
	iniKey, respKey := newTestIdentity(t), newTestIdentity(t)
	p1, p2 := net.Pipe()
	dest := respKey.ID()
	ini, resp := NewConn(p1, &dest, testConfig), NewConn(p2, nil, testConfig)
	defer ini.Close()
	defer resp.Close()

	ri, rr := runHandshakes(ini, resp, iniKey, respKey)
	if ri.err != nil || rr.err != nil {
		t.Fatalf("handshake failed: initiator %v, responder %v", ri.err, rr.err)
	}
	if ri.remote.ID != respKey.ID() || !bytes.Equal(ri.remote.PublicKey, respKey.PublicKey()) || ri.remote.Scheme != SchemeMLDSA44 {
		t.Fatalf("initiator sees the wrong remote identity")
	}
	if rr.remote.ID != iniKey.ID() || !bytes.Equal(rr.remote.PublicKey, iniKey.PublicKey()) {
		t.Fatalf("responder sees the wrong remote identity")
	}
	if ini.out.key != resp.in.key || ini.in.key != resp.out.key {
		t.Fatal("the two sides derived different keys")
	}
	if ini.out.key == ini.in.key {
		t.Fatal("both directions use the same key")
	}

	exchange := func(from, to *Conn, code uint64, data []byte) {
		t.Helper()
		errc := make(chan error, 1)
		go func() {
			_, err := from.Write(code, data)
			errc <- err
		}()
		gotCode, gotData, size, err := to.Read()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("write: %v", err)
		}
		if gotCode != code || !bytes.Equal(gotData, data) {
			t.Fatalf("got code %d data %x, want %d %x", gotCode, gotData, code, data)
		}
		if size != headerSize+codeSize+len(data)+tagSize {
			t.Fatalf("wire size %d", size)
		}
	}
	exchange(ini, resp, 0x10, []byte("hello from the dialler"))
	exchange(resp, ini, 0x11, []byte("hello from the listener"))
	exchange(ini, resp, 0, nil)
	exchange(resp, ini, 1<<63, bytes.Repeat([]byte{0xab}, int(testConfig.MaxMessageSize)))

	if _, err := ini.Write(1, make([]byte, testConfig.MaxMessageSize+1)); !errors.Is(err, errTooLarge) {
		t.Fatalf("oversized write: got %v", err)
	}
	if _, err := ini.Handshake(iniKey); !errors.Is(err, errHandshakeRun) {
		t.Fatalf("second handshake: got %v", err)
	}
}

func TestReadWriteBeforeHandshake(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	c := NewConn(p1, nil, testConfig)
	if _, _, _, err := c.Read(); !errors.Is(err, errNoHandshake) {
		t.Fatalf("read: got %v", err)
	}
	if _, err := c.Write(1, nil); !errors.Is(err, errNoHandshake) {
		t.Fatalf("write: got %v", err)
	}
}

// TestHybridKeysNeedBothSharedSecrets is QS-11: changing either the X25519
// or the ML-KEM shared secret changes both session keys.
func TestHybridKeysNeedBothSharedSecrets(t *testing.T) {
	random := func() []byte {
		b := make([]byte, 32)
		rand.Read(b)
		return b
	}
	flip := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[len(c)-1] ^= 1
		return c
	}
	ssK, ssX := random(), random()
	var th [32]byte
	copy(th[:], random())
	a, b := deriveKeys(ssK, ssX, th)
	if a == b {
		t.Fatal("both directions have the same key")
	}
	for name, keys := range map[string][2][keySize]byte{
		"x25519":     pair(deriveKeys(ssK, flip(ssX), th)),
		"mlkem":      pair(deriveKeys(flip(ssK), ssX, th)),
		"transcript": pair(deriveKeys(ssK, ssX, [32]byte(flip(th[:])))),
	} {
		if keys[0] == a || keys[1] == b {
			t.Errorf("changing the %s input left a session key unchanged", name)
		}
	}

	// The real responder: its authentication message opens only under keys
	// derived from both shared secrets as the handshake produced them.
	iniKey, respKey := newTestIdentity(t), newTestIdentity(t)
	p1, p2 := net.Pipe()
	defer p1.Close()
	resp := NewConn(p2, nil, testConfig)
	defer resp.Close()
	respDone := make(chan error, 1)
	go func() {
		_, err := resp.Handshake(respKey)
		respDone <- err
	}()

	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	dk, _ := mlkem.GenerateKey768()
	ourX, ek := eph.PublicKey().Bytes(), dk.EncapsulationKey().Bytes()
	if err := writeMsg(p1, append(bytes.Clone(ourX), ek...)); err != nil {
		t.Fatal(err)
	}
	msg, err := readMsg(p1, RespMsgSize)
	if err != nil {
		t.Fatal(err)
	}
	theirX, ct := msg[:X25519KeySize], msg[X25519KeySize:]
	theirPub, _ := ecdh.X25519().NewPublicKey(theirX)
	realX, err := eph.ECDH(theirPub)
	if err != nil {
		t.Fatal(err)
	}
	realK, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	th = transcriptHash(ourX, ek, theirX, ct)
	kOut, kIn := deriveKeys(realK, realX, th)
	raw := &Conn{conn: p1}
	if err := raw.writeAuth(newCipherState(kOut), iniKey, th); err != nil {
		t.Fatal(err)
	}
	record := make([]byte, headerSize+AuthMsgSize+tagSize)
	if _, err := io.ReadFull(p1, record); err != nil {
		t.Fatal(err)
	}
	if err := <-respDone; err != nil {
		t.Fatalf("responder: %v", err)
	}
	opens := func(key [keySize]byte) bool {
		_, _, err := newCipherState(key).readRecord(bytes.NewReader(record), AuthMsgSize+tagSize, AuthMsgSize+tagSize)
		return err == nil
	}
	if !opens(kIn) {
		t.Fatal("responder record does not open under the derived key")
	}
	if _, in := deriveKeys(realK, flip(realX), th); opens(in) {
		t.Fatal("record opens without the real X25519 shared secret")
	}
	if _, in := deriveKeys(flip(realK), realX, th); opens(in) {
		t.Fatal("record opens without the real ML-KEM shared secret")
	}
	if _, in := deriveKeys(realK, realX, transcriptHash(ourX, ek, theirX, flip(ct))); opens(in) {
		t.Fatal("record opens under another transcript")
	}
}

func pair(a, b [keySize]byte) [2][keySize]byte { return [2][keySize]byte{a, b} }

func TestWrongDialledNodeIDRefused(t *testing.T) {
	iniKey, respKey, other := newTestIdentity(t), newTestIdentity(t), newTestIdentity(t)
	p1, p2 := net.Pipe()
	dest := other.ID()
	ini, resp := NewConn(p1, &dest, testConfig), NewConn(p2, nil, testConfig)
	ri, _ := runHandshakes(ini, resp, iniKey, respKey)
	if !errors.Is(ri.err, errWrongNodeID) {
		t.Fatalf("initiator: got %v, want %v", ri.err, errWrongNodeID)
	}
	if _, _, _, err := ini.Read(); err == nil {
		t.Fatal("read after a failed handshake succeeded")
	}
	if _, err := ini.Write(1, nil); err == nil {
		t.Fatal("write after a failed handshake succeeded")
	}
}

func TestAuthMessageChecks(t *testing.T) {
	other := newTestIdentity(t)
	tests := []struct {
		name string
		hook func([]byte) []byte
		want error
	}{
		{"scheme 0", func(b []byte) []byte { binary.BigEndian.PutUint16(b, 0); return b }, errScheme},
		{"scheme 2", func(b []byte) []byte { binary.BigEndian.PutUint16(b, 2); return b }, errScheme},
		{"scheme ffff", func(b []byte) []byte { binary.BigEndian.PutUint16(b, 0xffff); return b }, errScheme},
		{"other public key", func(b []byte) []byte { copy(b[2:], other.PublicKey()); return b }, errSignature},
		{"bad signature", func(b []byte) []byte { b[len(b)-100] ^= 1; return b }, errSignature},
		{"short", func(b []byte) []byte { return b[:len(b)-1] }, errFrameSize},
		{"long", func(b []byte) []byte { return append(b, 0) }, errFrameSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iniKey, respKey := newTestIdentity(t), newTestIdentity(t)
			p1, p2 := net.Pipe()
			dest := respKey.ID()
			ini, resp := NewConn(p1, &dest, testConfig), NewConn(p2, nil, testConfig)
			ini.authHook = tt.hook
			ri, rr := runHandshakes(ini, resp, iniKey, respKey)
			if !errors.Is(rr.err, tt.want) {
				t.Fatalf("responder: got %v, want %v", rr.err, tt.want)
			}
			if ri.err == nil {
				t.Fatal("initiator completed the handshake")
			}
		})
	}
	// The responder's message is checked by the initiator the same way.
	iniKey, respKey := newTestIdentity(t), newTestIdentity(t)
	p1, p2 := net.Pipe()
	dest := respKey.ID()
	ini, resp := NewConn(p1, &dest, testConfig), NewConn(p2, nil, testConfig)
	resp.authHook = func(b []byte) []byte { binary.BigEndian.PutUint16(b, 2); return b }
	if ri, _ := runHandshakes(ini, resp, iniKey, respKey); !errors.Is(ri.err, errScheme) {
		t.Fatalf("initiator: got %v, want %v", ri.err, errScheme)
	}
}

// flipWriter flips one bit at offset target of the stream written through it.
type flipWriter struct {
	w      io.Writer
	target int64
	bit    byte
	pos    int64
}

func (f *flipWriter) Write(p []byte) (int, error) {
	if f.target >= f.pos && f.target < f.pos+int64(len(p)) {
		p = bytes.Clone(p)
		p[f.target-f.pos] ^= f.bit
	}
	f.pos += int64(len(p))
	return f.w.Write(p)
}

// relay connects ini and resp through a middle that flips one bit of the
// stream in direction dir (0: initiator to responder, 1: back).
func relay(dir int, target int64, bit byte) (iniSide, respSide net.Conn) {
	a1, b1 := net.Pipe()
	a2, b2 := net.Pipe()
	closeAll := func() { b1.Close(); a2.Close() }
	var w0, w1 io.Writer = a2, b1
	if dir == 0 {
		w0 = &flipWriter{w: a2, target: target, bit: bit}
	} else {
		w1 = &flipWriter{w: b1, target: target, bit: bit}
	}
	go func() { io.Copy(w0, b1); closeAll() }()
	go func() { io.Copy(w1, a2); closeAll() }()
	return a1, b2
}

func TestHandshakeBitFlipsRefused(t *testing.T) {
	authLen := int64(headerSize + AuthMsgSize + tagSize)
	messages := []struct {
		name      string
		dir       int
		start     int64
		size      int64
		respFails bool
	}{
		{"initiator key exchange", 0, 0, 4 + InitMsgSize, true},
		{"responder key exchange", 1, 0, 4 + RespMsgSize, true},
		{"initiator auth", 0, 4 + InitMsgSize, authLen, true},
		{"responder auth", 1, 4 + RespMsgSize, authLen, false},
	}
	for _, m := range messages {
		offsets := []int64{0, 3, 4, 4 + 31, 4 + X25519KeySize, m.size / 2, m.size - 1}
		for i, off := range offsets {
			bit := byte(1) << (i % 8)
			t.Run(fmt.Sprintf("%s/%d", m.name, off), func(t *testing.T) {
				iniKey, respKey := newTestIdentity(t), newTestIdentity(t)
				p1, p2 := relay(m.dir, m.start+off, bit)
				dest := respKey.ID()
				ini, resp := NewConn(p1, &dest, testConfig), NewConn(p2, nil, testConfig)
				ri, rr := runHandshakes(ini, resp, iniKey, respKey)
				if ri.err == nil {
					t.Error("initiator completed the handshake")
				}
				if m.respFails && rr.err == nil {
					t.Error("responder completed the handshake")
				}
				ini.Close()
				resp.Close()
			})
		}
	}
}

func TestHandshakeTruncatedRefused(t *testing.T) {
	// The responder gets half a key exchange message, then the end.
	p1, p2 := net.Pipe()
	resp := NewConn(p2, nil, testConfig)
	go func() {
		hdr := binary.BigEndian.AppendUint32(nil, InitMsgSize)
		p1.Write(append(hdr, make([]byte, InitMsgSize/2)...))
		p1.Close()
	}()
	if _, err := resp.Handshake(newTestIdentity(t)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("responder: got %v", err)
	}

	// The initiator gets a truncated reply.
	respKey := newTestIdentity(t)
	p1, p2 = net.Pipe()
	dest := respKey.ID()
	ini := NewConn(p1, &dest, testConfig)
	go func() {
		readMsg(p2, InitMsgSize)
		hdr := binary.BigEndian.AppendUint32(nil, RespMsgSize)
		p2.Write(append(hdr, make([]byte, 10)...))
		p2.Close()
	}()
	if _, err := ini.Handshake(newTestIdentity(t)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("initiator: got %v", err)
	}

	// A truncated message on an open connection runs into the timeout.
	p1, p2 = net.Pipe()
	defer p1.Close()
	resp = NewConn(p2, nil, Config{HandshakeTimeout: 200 * time.Millisecond})
	go func() {
		hdr := binary.BigEndian.AppendUint32(nil, InitMsgSize)
		p1.Write(append(hdr, make([]byte, 100)...))
	}()
	start := time.Now()
	_, err := resp.Handshake(newTestIdentity(t))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("responder: got %v, want a timeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the timeout took %v", d)
	}
	if _, err := p1.Write([]byte{0}); err == nil {
		t.Fatal("connection still open after the timeout")
	}
}

func TestHandshakeLengthRefused(t *testing.T) {
	for _, n := range []uint32{0, InitMsgSize - 1, InitMsgSize + 1, RespMsgSize, 0xffffffff} {
		p1, p2 := net.Pipe()
		resp := NewConn(p2, nil, testConfig)
		go func() {
			p1.Write(binary.BigEndian.AppendUint32(nil, n))
		}()
		if _, err := resp.Handshake(newTestIdentity(t)); !errors.Is(err, errMsgLength) {
			t.Fatalf("responder, length %d: got %v", n, err)
		}
		p1.Close()
	}
	for _, n := range []uint32{0, RespMsgSize - 1, RespMsgSize + 1, InitMsgSize, 0xffffffff} {
		respKey := newTestIdentity(t)
		p1, p2 := net.Pipe()
		dest := respKey.ID()
		ini := NewConn(p1, &dest, testConfig)
		go func() {
			readMsg(p2, InitMsgSize)
			p2.Write(binary.BigEndian.AppendUint32(nil, n))
		}()
		if _, err := ini.Handshake(newTestIdentity(t)); !errors.Is(err, errMsgLength) {
			t.Fatalf("initiator, length %d: got %v", n, err)
		}
		p2.Close()
	}
}

func TestHandshakeBadKeysRefused(t *testing.T) {
	// An encapsulation key with a coefficient out of range.
	p1, p2 := net.Pipe()
	resp := NewConn(p2, nil, testConfig)
	go func() {
		body := make([]byte, InitMsgSize)
		body[0] = 9 // a valid X25519 point
		for i := X25519KeySize; i < InitMsgSize; i++ {
			body[i] = 0xff
		}
		writeMsg(p1, body)
	}()
	if _, err := resp.Handshake(newTestIdentity(t)); !errors.Is(err, errBadKey) {
		t.Fatalf("encapsulation key: got %v", err)
	}
	p1.Close()

	// An all-zero X25519 key gives an all-zero shared secret.
	p1, p2 = net.Pipe()
	resp = NewConn(p2, nil, testConfig)
	go func() {
		dk, _ := mlkem.GenerateKey768()
		writeMsg(p1, append(make([]byte, X25519KeySize), dk.EncapsulationKey().Bytes()...))
	}()
	if _, err := resp.Handshake(newTestIdentity(t)); !errors.Is(err, errBadKey) {
		t.Fatalf("zero X25519 key: got %v", err)
	}
	p1.Close()
}
