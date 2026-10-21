// Copyright 2020 The go-ethereum Authors
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
	"reflect"
	"sync"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/simulations/pipes"
)

func TestProtocolHandshake(t *testing.T) {
	var (
		key0 = newkey()
		id0  = key0.ID()
		hs0  = &protoHandshake{Version: 3, ID: id0[:], Caps: []Cap{{"a", 0}, {"b", 2}}}

		key1 = newkey()
		id1  = key1.ID()
		hs1  = &protoHandshake{Version: 3, ID: id1[:], Caps: []Cap{{"c", 1}, {"d", 3}}}

		wg sync.WaitGroup
	)

	fd0, fd1, err := pipes.TCPPipe()
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer fd0.Close()
		frame := newQSConn(fd0, key0, enode.NewQuantumSafe(enode.ID(id1), nil, 0))
		remote, err := frame.doEncHandshake()
		if err != nil {
			t.Errorf("dial side enc handshake failed: %v", err)
			return
		}
		if !reflect.DeepEqual(remote, remoteIdentity(key1)) {
			t.Errorf("dial side remote identity mismatch: got %v, want %v", remote.ID, id1)
			return
		}

		phs, err := frame.doProtoHandshake(hs0)
		if err != nil {
			t.Errorf("dial side proto handshake error: %v", err)
			return
		}
		phs.Rest = nil
		if !reflect.DeepEqual(phs, hs1) {
			t.Errorf("dial side proto handshake mismatch:\ngot: %s\nwant: %s\n", spew.Sdump(phs), spew.Sdump(hs1))
			return
		}
		frame.close(DiscQuitting)
	}()
	go func() {
		defer wg.Done()
		defer fd1.Close()
		frame := newQSConn(fd1, key1, nil)
		remote, err := frame.doEncHandshake()
		if err != nil {
			t.Errorf("listen side enc handshake failed: %v", err)
			return
		}
		if !reflect.DeepEqual(remote, remoteIdentity(key0)) {
			t.Errorf("listen side remote identity mismatch: got %v, want %v", remote.ID, id0)
			return
		}

		phs, err := frame.doProtoHandshake(hs1)
		if err != nil {
			t.Errorf("listen side proto handshake error: %v", err)
			return
		}
		phs.Rest = nil
		if !reflect.DeepEqual(phs, hs0) {
			t.Errorf("listen side proto handshake mismatch:\ngot: %s\nwant: %s\n", spew.Sdump(phs), spew.Sdump(hs0))
			return
		}

		if err := ExpectMsg(frame, discMsg, []DiscReason{DiscQuitting}); err != nil {
			t.Errorf("error receiving disconnect: %v", err)
		}
	}()
	wg.Wait()
}

func TestProtocolHandshakeErrors(t *testing.T) {
	tests := []struct {
		code uint64
		msg  interface{}
		err  error
	}{
		{
			code: discMsg,
			msg:  []DiscReason{DiscQuitting},
			err:  DiscQuitting,
		},
		{
			code: 0x989898,
			msg:  []byte{1},
			err:  errors.New("expected handshake, got 989898"),
		},
		{
			code: handshakeMsg,
			msg:  make([]byte, baseProtocolMaxMsgSize+2),
			err:  errors.New("message too big"),
		},
		{
			code: handshakeMsg,
			msg:  []byte{1, 2, 3},
			err:  newPeerError(errInvalidMsg, "(code 0) (size 4) rlp: expected input list for p2p.protoHandshake"),
		},
		{
			code: handshakeMsg,
			msg:  &protoHandshake{Version: 3},
			err:  DiscInvalidIdentity,
		},
		{
			// a 64-byte secp256k1 public key is not a node ID
			code: handshakeMsg,
			msg:  &protoHandshake{Version: 3, ID: bytes.Repeat([]byte{1}, 64)},
			err:  DiscInvalidIdentity,
		},
	}

	for i, test := range tests {
		p1, p2 := MsgPipe()
		go Send(p1, test.code, test.msg)
		_, err := readProtocolHandshake(p2)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("test %d: error mismatch: got %q, want %q", i, err, test.err)
		}
	}
}
