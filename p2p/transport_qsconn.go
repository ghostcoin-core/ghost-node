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
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

// qsconnTransport is the transport of every peer connection. It wraps a
// qsconn connection with locks and read/write deadlines.
type qsconnTransport struct {
	rmu, wmu sync.Mutex
	wbuf     bytes.Buffer
	conn     *qsconn.Conn
	key      *qsconn.Identity
	first    *Msg // read by peekMsg, returned by the next ReadMsg
}

// newQSConn wraps fd. dialDest is nil on the accepting side; on the dialling
// side the handshake checks that the remote public key hashes to its ID.
func newQSConn(fd net.Conn, key *qsconn.Identity, dialDest *enode.Node) transport {
	var dest *qsconn.NodeID
	if dialDest != nil {
		id := qsconn.NodeID(dialDest.ID())
		dest = &id
	}
	return &qsconnTransport{
		conn: qsconn.NewConn(fd, dest, qsconn.Config{HandshakeTimeout: handshakeTimeout}),
		key:  key,
	}
}

// doEncHandshake runs the quantum-safe handshake and returns the remote
// identity it authenticated.
func (t *qsconnTransport) doEncHandshake() (*qsconn.RemoteIdentity, error) {
	return t.conn.Handshake(t.key)
}

func (t *qsconnTransport) ReadMsg() (Msg, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()

	if t.first != nil {
		msg := *t.first
		t.first = nil
		return msg, nil
	}
	return t.readMsg(frameReadTimeout)
}

// peekMsg reads the first message after the handshake, waiting at most
// handshakeTimeout for it, and keeps it for the next ReadMsg.
func (t *qsconnTransport) peekMsg() (Msg, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()

	if t.first != nil {
		return *t.first, nil
	}
	msg, err := t.readMsg(handshakeTimeout)
	if err != nil {
		return msg, err
	}
	t.first = &msg
	return msg, nil
}

func (t *qsconnTransport) readMsg(timeout time.Duration) (Msg, error) {
	var msg Msg
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	code, data, wireSize, err := t.conn.Read()
	if err == nil {
		// qsconn returns a fresh buffer for every frame.
		msg = Msg{
			ReceivedAt: time.Now(),
			Code:       code,
			Size:       uint32(len(data)),
			meterSize:  uint32(wireSize),
			Payload:    bytes.NewReader(data),
		}
	}
	return msg, err
}

func (t *qsconnTransport) WriteMsg(msg Msg) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	t.wbuf.Reset()
	if _, err := io.CopyN(&t.wbuf, msg.Payload, int64(msg.Size)); err != nil {
		return err
	}
	t.conn.SetWriteDeadline(time.Now().Add(frameWriteTimeout))
	size, err := t.conn.Write(msg.Code, t.wbuf.Bytes())
	if err != nil {
		return err
	}

	msg.meterSize = size
	if metrics.Enabled && msg.meterCap.Name != "" { // don't meter non-subprotocol messages
		m := fmt.Sprintf("%s/%s/%d/%#02x", egressMeterName, msg.meterCap.Name, msg.meterCap.Version, msg.meterCode)
		metrics.GetOrRegisterMeter(m, nil).Mark(int64(msg.meterSize))
		metrics.GetOrRegisterMeter(m+"/packets", nil).Mark(1)
	}
	return nil
}

func (t *qsconnTransport) close(err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	// Tell the remote end why we're disconnecting if possible. Before the
	// handshake Write fails without sending anything.
	if r, ok := err.(DiscReason); ok && r != DiscNetworkError {
		if err := t.conn.SetWriteDeadline(time.Now().Add(discWriteTimeout)); err == nil {
			t.wbuf.Reset()
			rlp.Encode(&t.wbuf, []DiscReason{r})
			t.conn.Write(discMsg, t.wbuf.Bytes())
		}
	}
	t.conn.Close()
}

// doProtoHandshake exchanges the protocol handshake. The ID field carries the
// 32-byte node ID; frames are not compressed.
func (t *qsconnTransport) doProtoHandshake(our *protoHandshake) (their *protoHandshake, err error) {
	// Writing our handshake happens concurrently, we prefer
	// returning the handshake read error. If the remote side
	// disconnects us early with a valid reason, we should return it
	// as the error so it can be tracked elsewhere.
	werr := make(chan error, 1)
	go func() { werr <- Send(t, handshakeMsg, our) }()
	if their, err = readProtocolHandshake(t); err != nil {
		<-werr // make sure the write terminates too
		return nil, err
	}
	if err := <-werr; err != nil {
		return nil, fmt.Errorf("write error: %v", err)
	}
	return their, nil
}

// nodeFromConn is the node of an accepted connection: its node ID from the
// handshake and the remote address.
func nodeFromConn(id enode.ID, conn net.Conn) *enode.Node {
	var ip net.IP
	var port int
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcp.IP
		port = tcp.Port
	}
	return enode.NewQuantumSafe(id, ip, port)
}
