// Copyright 2014 The go-ethereum Authors
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
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/internal/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
)

// testTransport skips the encryption handshake: it reports the remote
// identity it was made with, and frames messages in the clear (code, size,
// data) on the underlying connection.
type testTransport struct {
	remote   *qsconn.Identity
	fd       net.Conn
	rmu, wmu sync.Mutex
	closeErr error
}

func newTestTransport(remote *qsconn.Identity, fd net.Conn) transport {
	return &testTransport{remote: remote, fd: fd}
}

func (c *testTransport) doEncHandshake() (*qsconn.RemoteIdentity, error) {
	return remoteIdentity(c.remote), nil
}

func (c *testTransport) doProtoHandshake(our *protoHandshake) (*protoHandshake, error) {
	id := c.remote.ID()
	return &protoHandshake{ID: id[:], Name: "test"}, nil
}

func (c *testTransport) ReadMsg() (Msg, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	var hdr [12]byte
	if _, err := io.ReadFull(c.fd, hdr[:]); err != nil {
		return Msg{}, err
	}
	data := make([]byte, binary.BigEndian.Uint32(hdr[8:]))
	if _, err := io.ReadFull(c.fd, data); err != nil {
		return Msg{}, err
	}
	return Msg{
		Code:       binary.BigEndian.Uint64(hdr[:8]),
		Size:       uint32(len(data)),
		meterSize:  uint32(len(data)),
		Payload:    bytes.NewReader(data),
		ReceivedAt: time.Now(),
	}, nil
}

func (c *testTransport) WriteMsg(msg Msg) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	buf := make([]byte, 12, 12+msg.Size)
	binary.BigEndian.PutUint64(buf, msg.Code)
	binary.BigEndian.PutUint32(buf[8:], msg.Size)
	data := make([]byte, msg.Size)
	if _, err := io.ReadFull(msg.Payload, data); err != nil {
		return err
	}
	_, err := c.fd.Write(append(buf, data...))
	return err
}

func (c *testTransport) close(err error) {
	c.fd.Close()
	c.closeErr = err
}

// remoteIdentity is what the handshake reports for a peer holding key.
func remoteIdentity(key *qsconn.Identity) *qsconn.RemoteIdentity {
	return &qsconn.RemoteIdentity{ID: key.ID(), Scheme: key.Scheme(), PublicKey: key.PublicKey()}
}

func startTestServer(t *testing.T, remoteKey *qsconn.Identity, pf func(*Peer)) *Server {
	config := Config{
		Name:        "test",
		MaxPeers:    10,
		ListenAddr:  "127.0.0.1:0",
		NoDiscovery: true,
		Identity:    newkey(),
		Logger:      testlog.Logger(t, log.LvlTrace),
	}
	server := &Server{
		Config:      config,
		newPeerHook: pf,
		newTransport: func(fd net.Conn, key *qsconn.Identity, dialDest *enode.Node) transport {
			return newTestTransport(remoteKey, fd)
		},
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Could not start server: %v", err)
	}
	return server
}

func TestServerListen(t *testing.T) {
	// start the test server
	connected := make(chan *Peer)
	remid := newkey()
	srv := startTestServer(t, remid, func(p *Peer) {
		if p.ID() != enode.ID(remid.ID()) {
			t.Error("peer func called with wrong node id")
		}
		connected <- p
	})
	defer close(connected)
	defer srv.Stop()

	// dial the test server
	conn, err := net.DialTimeout("tcp", srv.ListenAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("could not dial: %v", err)
	}
	defer conn.Close()

	select {
	case peer := <-connected:
		if peer.LocalAddr().String() != conn.RemoteAddr().String() {
			t.Errorf("peer started with wrong conn: got %v, want %v",
				peer.LocalAddr(), conn.RemoteAddr())
		}
		peers := srv.Peers()
		if !reflect.DeepEqual(peers, []*Peer{peer}) {
			t.Errorf("Peers mismatch: got %v, want %v", peers, []*Peer{peer})
		}
	case <-time.After(1 * time.Second):
		t.Error("server did not accept within one second")
	}
}

func TestServerDial(t *testing.T) {
	// run a one-shot TCP server to handle the connection.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not setup listener: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	// start the server
	connected := make(chan *Peer)
	remid := newkey()
	srv := startTestServer(t, remid, func(p *Peer) { connected <- p })
	defer close(connected)
	defer srv.Stop()

	// tell the server to connect
	tcpAddr := listener.Addr().(*net.TCPAddr)
	node := enode.NewQuantumSafe(enode.ID(remid.ID()), tcpAddr.IP, tcpAddr.Port)
	srv.AddPeer(node)

	select {
	case conn := <-accepted:
		defer conn.Close()

		select {
		case peer := <-connected:
			if peer.ID() != enode.ID(remid.ID()) {
				t.Errorf("peer has wrong id")
			}
			if peer.Name() != "test" {
				t.Errorf("peer has wrong name")
			}
			if peer.RemoteAddr().String() != conn.LocalAddr().String() {
				t.Errorf("peer started with wrong conn: got %v, want %v",
					peer.RemoteAddr(), conn.LocalAddr())
			}
			peers := srv.Peers()
			if !reflect.DeepEqual(peers, []*Peer{peer}) {
				t.Errorf("Peers mismatch: got %v, want %v", peers, []*Peer{peer})
			}

			// Test AddTrustedPeer/RemoveTrustedPeer and changing Trusted flags
			// Particularly for race conditions on changing the flag state.
			if peer := srv.Peers()[0]; peer.Info().Network.Trusted {
				t.Errorf("peer is trusted prematurely: %v", peer)
			}
			done := make(chan bool)
			go func() {
				srv.AddTrustedPeer(node)
				if peer := srv.Peers()[0]; !peer.Info().Network.Trusted {
					t.Errorf("peer is not trusted after AddTrustedPeer: %v", peer)
				}
				srv.RemoveTrustedPeer(node)
				if peer := srv.Peers()[0]; peer.Info().Network.Trusted {
					t.Errorf("peer is trusted after RemoveTrustedPeer: %v", peer)
				}
				done <- true
			}()
			// Trigger potential race conditions
			peer = srv.Peers()[0]
			_ = peer.Inbound()
			_ = peer.Info()
			<-done
		case <-time.After(1 * time.Second):
			t.Error("server did not launch peer within one second")
		}

	case <-time.After(1 * time.Second):
		t.Error("server did not connect within one second")
	}
}

// This test checks that RemovePeer disconnects the peer if it is connected.
func TestServerRemovePeerDisconnect(t *testing.T) {
	srv1 := &Server{Config: Config{
		Identity:    newkey(),
		MaxPeers:    1,
		NoDiscovery: true,
		Logger:      testlog.Logger(t, log.LvlTrace).New("server", "1"),
	}}
	srv2 := &Server{Config: Config{
		Identity:    newkey(),
		MaxPeers:    1,
		NoDiscovery: true,
		NoDial:      true,
		ListenAddr:  "127.0.0.1:0",
		Logger:      testlog.Logger(t, log.LvlTrace).New("server", "2"),
	}}
	srv1.Start()
	defer srv1.Stop()
	srv2.Start()
	defer srv2.Stop()

	s := strings.Split(srv2.ListenAddr, ":")
	if len(s) != 2 {
		t.Fatal("invalid ListenAddr")
	}
	if port, err := strconv.Atoi(s[1]); err == nil {
		srv2.localnode.Set(enr.TCP(uint16(port)))
	}

	if !syncAddPeer(srv1, srv2.Self()) {
		t.Fatal("peer not connected")
	}
	srv1.RemovePeer(srv2.Self())
	if srv1.PeerCount() > 0 {
		t.Fatal("removed peer still connected")
	}
}

// This test checks that connections are disconnected just after the encryption handshake
// when the server is at capacity. Trusted connections should still be accepted.
func TestServerAtCap(t *testing.T) {
	trustedNode := newkey()
	trustedID := enode.ID(trustedNode.ID())
	srv := &Server{
		Config: Config{
			Identity:     newkey(),
			MaxPeers:     10,
			NoDial:       true,
			NoDiscovery:  true,
			TrustedNodes: []*enode.Node{newNode(trustedID, "")},
			Logger:       testlog.Logger(t, log.LvlTrace),
		},
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("could not start: %v", err)
	}
	defer srv.Stop()

	newconn := func(id enode.ID) *conn {
		fd, _ := net.Pipe()
		tx := newTestTransport(trustedNode, fd)
		node := enode.SignNull(new(enr.Record), id)
		return &conn{fd: fd, transport: tx, flags: inboundConn, node: node, cont: make(chan error)}
	}

	// Inject a few connections to fill up the peer set.
	for i := 0; i < 10; i++ {
		c := newconn(randomID())
		if err := srv.checkpoint(c, srv.checkpointAddPeer); err != nil {
			t.Fatalf("could not add conn %d: %v", i, err)
		}
	}
	// Try inserting a non-trusted connection.
	anotherID := randomID()
	c := newconn(anotherID)
	if err := srv.checkpoint(c, srv.checkpointPostHandshake); err != DiscTooManyPeers {
		t.Error("wrong error for insert:", err)
	}
	// Try inserting a trusted connection.
	c = newconn(trustedID)
	if err := srv.checkpoint(c, srv.checkpointPostHandshake); err != nil {
		t.Error("unexpected error for trusted conn @posthandshake:", err)
	}
	if !c.is(trustedConn) {
		t.Error("Server did not set trusted flag")
	}

	// Remove from trusted set and try again
	srv.RemoveTrustedPeer(newNode(trustedID, ""))
	c = newconn(trustedID)
	if err := srv.checkpoint(c, srv.checkpointPostHandshake); err != DiscTooManyPeers {
		t.Error("wrong error for insert:", err)
	}

	// Add anotherID to trusted set and try again
	srv.AddTrustedPeer(newNode(anotherID, ""))
	c = newconn(anotherID)
	if err := srv.checkpoint(c, srv.checkpointPostHandshake); err != nil {
		t.Error("unexpected error for trusted conn @posthandshake:", err)
	}
	if !c.is(trustedConn) {
		t.Error("Server did not set trusted flag")
	}
}

// This test checks that a new connection with the same node ID takes the place
// of a registered peer that has gone silent, and not of a working peer.
func TestServerReplacesStalePeerOnDuplicateID(t *testing.T) {
	remoteKey := newkey()
	srv := &Server{
		Config: Config{
			Identity:    newkey(),
			MaxPeers:    10,
			NoDial:      true,
			NoDiscovery: true,
			Logger:      testlog.Logger(t, log.LvlTrace),
		},
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("could not start: %v", err)
	}
	defer srv.Stop()

	id := randomID()
	var remotes []net.Conn
	defer func() {
		for _, fd := range remotes {
			fd.Close()
		}
	}()
	newconn := func() *conn {
		fd, remote := net.Pipe()
		remotes = append(remotes, remote)
		tx := newTestTransport(remoteKey, fd)
		node := enode.SignNull(new(enr.Record), id)
		return &conn{fd: fd, transport: tx, flags: inboundConn, node: node, cont: make(chan error)}
	}
	events := make(chan *PeerEvent, 16)
	sub := srv.SubscribeEvents(events)
	defer sub.Unsubscribe()

	if err := srv.checkpoint(newconn(), srv.checkpointAddPeer); err != nil {
		t.Fatalf("could not add the first connection: %v", err)
	}
	peers := srv.Peers()
	if len(peers) != 1 {
		t.Fatalf("have %d peers after the first connection, want 1", len(peers))
	}
	old := peers[0]

	// The registered peer is working (it was just created): a duplicate is refused.
	dup := newconn()
	if err := srv.checkpoint(dup, srv.checkpointPostHandshake); err != DiscAlreadyConnected {
		t.Fatalf("duplicate of a working peer @posthandshake: got %v, want %v", err, DiscAlreadyConnected)
	}
	if err := srv.checkpoint(dup, srv.checkpointAddPeer); err != DiscAlreadyConnected {
		t.Fatalf("duplicate of a working peer @addpeer: got %v, want %v", err, DiscAlreadyConnected)
	}
	select {
	case <-old.closed:
		t.Fatal("working peer was disconnected by a duplicate connection")
	default:
	}

	// The registered peer goes silent for longer than two ping intervals.
	old.lastRecv.Store(time.Now().Add(-3 * pingInterval).UnixNano())
	fresh := newconn()
	if err := srv.checkpoint(fresh, srv.checkpointPostHandshake); err != nil {
		t.Fatalf("new connection replacing a stale peer @posthandshake: %v", err)
	}
	if err := srv.checkpoint(fresh, srv.checkpointAddPeer); err != nil {
		t.Fatalf("new connection replacing a stale peer @addpeer: %v", err)
	}
	select {
	case <-old.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("stale peer was not disconnected")
	}
	// Wait until the server has processed the stale peer's exit.
	timeout := time.After(5 * time.Second)
	for dropped := false; !dropped; {
		select {
		case ev := <-events:
			dropped = ev.Type == PeerEventTypeDrop && ev.Peer == id
		case <-timeout:
			t.Fatal("no drop event for the stale peer")
		}
	}
	peers = srv.Peers()
	if len(peers) != 1 || peers[0] == old || peers[0].ID() != id {
		t.Fatalf("peer set after the stale peer left is %v, want only the new connection", peers)
	}
	if n := srv.PeerCount(); n != 1 {
		t.Fatalf("peer count after the stale peer left is %d, want 1", n)
	}
	// The new connection is working, so another duplicate is refused again.
	if err := srv.checkpoint(newconn(), srv.checkpointPostHandshake); err != DiscAlreadyConnected {
		t.Fatalf("duplicate of the new peer: got %v, want %v", err, DiscAlreadyConnected)
	}
}

func TestServerPeerLimits(t *testing.T) {
	clientkey := newkey()
	clientID := clientkey.ID()
	clientnode := enode.NewQuantumSafe(enode.ID(clientID), nil, 0)

	var tp = &setupTransport{
		remote: remoteIdentity(clientkey),
		phs: protoHandshake{
			ID: clientID[:],
			// Force "DiscUselessPeer" due to unmatching caps
			// Caps: []Cap{discard.cap()},
		},
	}

	srv := &Server{
		Config: Config{
			Identity:    newkey(),
			MaxPeers:    0,
			NoDial:      true,
			NoDiscovery: true,
			Protocols:   []Protocol{discard},
			Logger:      testlog.Logger(t, log.LvlTrace),
		},
		newTransport: func(net.Conn, *qsconn.Identity, *enode.Node) transport { return tp },
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("couldn't start server: %v", err)
	}
	defer srv.Stop()

	// Check that server is full (MaxPeers=0)
	flags := dynDialedConn
	dialDest := clientnode
	conn, _ := net.Pipe()
	srv.SetupConn(conn, flags, dialDest)
	if tp.closeErr != DiscTooManyPeers {
		t.Errorf("unexpected close error: %q", tp.closeErr)
	}
	conn.Close()

	srv.AddTrustedPeer(clientnode)

	// Check that server allows a trusted peer despite being full.
	conn, _ = net.Pipe()
	srv.SetupConn(conn, flags, dialDest)
	if tp.closeErr == DiscTooManyPeers {
		t.Errorf("failed to bypass MaxPeers with trusted node: %q", tp.closeErr)
	}

	if tp.closeErr != DiscUselessPeer {
		t.Errorf("unexpected close error: %q", tp.closeErr)
	}
	conn.Close()

	srv.RemoveTrustedPeer(clientnode)

	// Check that server is full again.
	conn, _ = net.Pipe()
	srv.SetupConn(conn, flags, dialDest)
	if tp.closeErr != DiscTooManyPeers {
		t.Errorf("unexpected close error: %q", tp.closeErr)
	}
	conn.Close()
}

func TestServerSetupConn(t *testing.T) {
	var (
		clientkey, srvkey, otherkey = newkey(), newkey(), newkey()
		client                      = remoteIdentity(clientkey)
		clientID                    = clientkey.ID()
		srvID                       = srvkey.ID()
		clientnode                  = enode.NewQuantumSafe(enode.ID(clientID), nil, 0)
	)
	// forged claims the client's node ID with another key.
	forged := remoteIdentity(otherkey)
	forged.ID = clientID

	tests := []struct {
		name      string
		dontstart bool
		tt        *setupTransport
		flags     connFlag
		dialDest  *enode.Node

		wantCloseErr error
		wantCalls    string
	}{
		{
			name:         "stopped",
			dontstart:    true,
			tt:           &setupTransport{remote: client},
			wantCalls:    "close,",
			wantCloseErr: errServerStopped,
		},
		{
			name:         "enc-handshake-error",
			tt:           &setupTransport{remote: client, encHandshakeErr: errors.New("handshake failed")},
			flags:        inboundConn,
			wantCalls:    "doEncHandshake,close,",
			wantCloseErr: errEncHandshakeError,
		},
		{
			name:         "dialled-id-mismatch",
			tt:           &setupTransport{remote: remoteIdentity(otherkey)},
			dialDest:     clientnode,
			flags:        dynDialedConn,
			wantCalls:    "doEncHandshake,close,",
			wantCloseErr: errEncHandshakeError,
		},
		{
			name:         "key-does-not-hash-to-id",
			tt:           &setupTransport{remote: forged},
			flags:        inboundConn,
			wantCalls:    "doEncHandshake,close,",
			wantCloseErr: errEncHandshakeError,
		},
		{
			name:         "proto-handshake-identity",
			tt:           &setupTransport{remote: client, phs: protoHandshake{ID: randomID().Bytes()}},
			dialDest:     clientnode,
			flags:        dynDialedConn,
			wantCalls:    "doEncHandshake,doProtoHandshake,close,",
			wantCloseErr: DiscUnexpectedIdentity,
		},
		{
			name:         "proto-handshake-error",
			tt:           &setupTransport{remote: client, protoHandshakeErr: errProtoHandshakeError},
			dialDest:     clientnode,
			flags:        dynDialedConn,
			wantCalls:    "doEncHandshake,doProtoHandshake,close,",
			wantCloseErr: errProtoHandshakeError,
		},
		{
			name:         "self",
			tt:           &setupTransport{remote: remoteIdentity(srvkey), phs: protoHandshake{ID: srvID[:]}},
			flags:        inboundConn,
			wantCalls:    "doEncHandshake,close,",
			wantCloseErr: DiscSelf,
		},
		{
			name:         "useless-peer",
			tt:           &setupTransport{remote: client, phs: protoHandshake{ID: clientID[:]}},
			flags:        inboundConn,
			wantCalls:    "doEncHandshake,doProtoHandshake,close,",
			wantCloseErr: DiscUselessPeer,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{
				Identity:    srvkey,
				MaxPeers:    10,
				NoDial:      true,
				NoDiscovery: true,
				Protocols:   []Protocol{discard},
				Logger:      testlog.Logger(t, log.LvlTrace),
			}
			srv := &Server{
				Config:       cfg,
				newTransport: func(net.Conn, *qsconn.Identity, *enode.Node) transport { return test.tt },
				log:          cfg.Logger,
			}
			if !test.dontstart {
				if err := srv.Start(); err != nil {
					t.Fatalf("couldn't start server: %v", err)
				}
				defer srv.Stop()
			}
			p1, _ := net.Pipe()
			srv.SetupConn(p1, test.flags, test.dialDest)
			if !errors.Is(test.tt.closeErr, test.wantCloseErr) {
				t.Errorf("test %d: close error mismatch: got %q, want %q", i, test.tt.closeErr, test.wantCloseErr)
			}
			if test.tt.calls != test.wantCalls {
				t.Errorf("test %d: calls mismatch: got %q, want %q", i, test.tt.calls, test.wantCalls)
			}
		})
	}
}

type setupTransport struct {
	remote            *qsconn.RemoteIdentity
	encHandshakeErr   error
	phs               protoHandshake
	protoHandshakeErr error

	calls    string
	closeErr error
}

func (c *setupTransport) doEncHandshake() (*qsconn.RemoteIdentity, error) {
	c.calls += "doEncHandshake,"
	if c.encHandshakeErr != nil {
		return nil, c.encHandshakeErr
	}
	return c.remote, nil
}

func (c *setupTransport) doProtoHandshake(our *protoHandshake) (*protoHandshake, error) {
	c.calls += "doProtoHandshake,"
	if c.protoHandshakeErr != nil {
		return nil, c.protoHandshakeErr
	}
	return &c.phs, nil
}
func (c *setupTransport) close(err error) {
	c.calls += "close,"
	c.closeErr = err
}

// setupConn shouldn't write to/read from the connection.
func (c *setupTransport) WriteMsg(Msg) error {
	panic("WriteMsg called on setupTransport")
}
func (c *setupTransport) ReadMsg() (Msg, error) {
	panic("ReadMsg called on setupTransport")
}

// newkey makes a node identity.
func newkey() *qsconn.Identity {
	key, err := qsconn.GenerateIdentity()
	if err != nil {
		panic("couldn't generate identity: " + err.Error())
	}
	return key
}

func randomID() (id enode.ID) {
	for i := range id {
		id[i] = byte(rand.Intn(255))
	}
	return id
}

// This test checks that inbound connections are throttled by IP.
func TestServerInboundThrottle(t *testing.T) {
	const timeout = 5 * time.Second
	newTransportCalled := make(chan struct{})
	srv := &Server{
		Config: Config{
			Identity:    newkey(),
			ListenAddr:  "127.0.0.1:0",
			MaxPeers:    10,
			NoDial:      true,
			NoDiscovery: true,
			Protocols:   []Protocol{discard},
			Logger:      testlog.Logger(t, log.LvlTrace),
		},
		newTransport: func(fd net.Conn, key *qsconn.Identity, dialDest *enode.Node) transport {
			newTransportCalled <- struct{}{}
			return newQSConn(fd, key, dialDest)
		},
		listenFunc: func(network, laddr string) (net.Listener, error) {
			fakeAddr := &net.TCPAddr{IP: net.IP{95, 33, 21, 2}, Port: 4444}
			return listenFakeAddr(network, laddr, fakeAddr)
		},
	}
	if err := srv.Start(); err != nil {
		t.Fatal("can't start: ", err)
	}
	defer srv.Stop()

	// Dial the test server.
	conn, err := net.DialTimeout("tcp", srv.ListenAddr, timeout)
	if err != nil {
		t.Fatalf("could not dial: %v", err)
	}
	select {
	case <-newTransportCalled:
		// OK
	case <-time.After(timeout):
		t.Error("newTransport not called")
	}
	conn.Close()

	// Dial again. This time the server should close the connection immediately.
	connClosed := make(chan struct{}, 1)
	conn, err = net.DialTimeout("tcp", srv.ListenAddr, timeout)
	if err != nil {
		t.Fatalf("could not dial: %v", err)
	}
	defer conn.Close()
	go func() {
		conn.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 10)
		if n, err := conn.Read(buf); err != io.EOF || n != 0 {
			t.Errorf("expected io.EOF and n == 0, got error %q and n == %d", err, n)
		}
		connClosed <- struct{}{}
	}()
	select {
	case <-connClosed:
		// OK
	case <-newTransportCalled:
		t.Error("newTransport called for second attempt")
	case <-time.After(timeout):
		t.Error("connection not closed within timeout")
	}
}

func listenFakeAddr(network, laddr string, remoteAddr net.Addr) (net.Listener, error) {
	l, err := net.Listen(network, laddr)
	if err == nil {
		l = &fakeAddrListener{l, remoteAddr}
	}
	return l, err
}

// fakeAddrListener is a listener that creates connections with a mocked remote address.
type fakeAddrListener struct {
	net.Listener
	remoteAddr net.Addr
}

type fakeAddrConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (l *fakeAddrListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fakeAddrConn{c, l.remoteAddr}, nil
}

func (c *fakeAddrConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func syncAddPeer(srv *Server, node *enode.Node) bool {
	var (
		ch      = make(chan *PeerEvent)
		sub     = srv.SubscribeEvents(ch)
		timeout = time.After(2 * time.Second)
	)
	defer sub.Unsubscribe()
	srv.AddPeer(node)
	for {
		select {
		case ev := <-ch:
			if ev.Type == PeerEventTypeAdd && ev.Peer == node.ID() {
				return true
			}
		case <-timeout:
			return false
		}
	}
}
