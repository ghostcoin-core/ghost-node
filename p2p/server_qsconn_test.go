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
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/internal/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
)

func newQSIdentity(t *testing.T) *qsconn.Identity {
	t.Helper()
	key, err := qsconn.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// startQSServer starts a server that has only a quantum-safe identity.
func startQSServer(t *testing.T, name string, key *qsconn.Identity, listen bool, protos []Protocol, static ...*enode.Node) *Server {
	t.Helper()
	cfg := Config{
		Name:        name,
		Identity:    key,
		MaxPeers:    10,
		NoDiscovery: true,
		Protocols:   protos,
		StaticNodes: static,
		Logger:      testlog.Logger(t, log.LvlTrace).New("server", name),
	}
	if listen {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	srv := &Server{Config: cfg}
	if err := srv.Start(); err != nil {
		t.Fatalf("could not start server %s: %v", name, err)
	}
	t.Cleanup(srv.Stop)
	return srv
}

// waitPeerAdd waits for the first peer added to srv.
func waitPeerAdd(t *testing.T, ch chan *PeerEvent) enode.ID {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Type == PeerEventTypeAdd {
				return ev.Peer
			}
		case <-timeout:
			t.Fatal("no peer added")
		}
	}
}

func qsPeer(t *testing.T, srv *Server, id enode.ID) *Peer {
	t.Helper()
	for _, p := range srv.Peers() {
		if p.ID() == id {
			return p
		}
	}
	t.Fatalf("peer %v not found", id)
	return nil
}

// TestServerQSConnTwoNodes connects two servers that have no secp256k1 key:
// one dials the other from its static list, both identify the other by the
// handshake, and a protocol message goes through in each direction.
func TestServerQSConnTwoNodes(t *testing.T) {
	keyA, keyB := newQSIdentity(t), newQSIdentity(t)
	got := make(chan string, 2)
	proto := Protocol{
		Name:    "qst",
		Version: 1,
		Length:  1,
		Run: func(p *Peer, rw MsgReadWriter) error {
			if err := Send(rw, 0, []string{"hello " + p.Name()}); err != nil {
				return err
			}
			msg, err := rw.ReadMsg()
			if err != nil {
				return err
			}
			var data []string
			if err := msg.Decode(&data); err != nil {
				return err
			}
			got <- data[0]
			_, err = rw.ReadMsg() // until the connection ends
			return err
		},
	}

	srvB := startQSServer(t, "b", keyB, true, []Protocol{proto})
	if srvB.PrivateKey != nil {
		t.Fatal("server has a secp256k1 key")
	}
	urlB := srvB.Self().URLv4()
	wantPrefix := "enode://" + keyB.ID().String() + "@127.0.0.1:"
	if !strings.HasPrefix(urlB, wantPrefix) {
		t.Fatalf("server URL %s, want prefix %s", urlB, wantPrefix)
	}
	nodeB, err := enode.ParseV4(urlB)
	if err != nil {
		t.Fatal(err)
	}
	if srvB.Self().ID() != enode.ID(keyB.ID()) || srvB.LocalNode().ID() != enode.ID(keyB.ID()) {
		t.Fatal("server node ID is not the identity's node ID")
	}

	chB := make(chan *PeerEvent, 10)
	subB := srvB.SubscribeEvents(chB)
	defer subB.Unsubscribe()

	srvA := startQSServer(t, "a", keyA, true, []Protocol{proto}, nodeB)
	chA := make(chan *PeerEvent, 10)
	subA := srvA.SubscribeEvents(chA)
	defer subA.Unsubscribe()

	if id := waitPeerAdd(t, chA); id != enode.ID(keyB.ID()) {
		t.Fatalf("dialling side has peer %v, want %v", id, keyB.ID())
	}
	if id := waitPeerAdd(t, chB); id != enode.ID(keyA.ID()) {
		t.Fatalf("accepting side has peer %v, want %v", id, keyA.ID())
	}
	for _, s := range []struct {
		srv  *Server
		peer enode.ID
	}{{srvA, enode.ID(keyB.ID())}, {srvB, enode.ID(keyA.ID())}} {
		p := qsPeer(t, s.srv, s.peer)
		if _, ok := p.rw.transport.(*qsconnTransport); !ok {
			t.Fatalf("peer runs on %T, want the quantum-safe transport", p.rw.transport)
		}
		if p.Node().Pubkey() != nil {
			t.Fatal("peer node has a secp256k1 key")
		}
		if !strings.HasPrefix(p.Info().Enode, "enode://"+s.peer.String()+"@") {
			t.Fatalf("peer URL %s does not name the node ID", p.Info().Enode)
		}
	}

	want := map[string]bool{"hello a": true, "hello b": true}
	for i := 0; i < 2; i++ {
		select {
		case m := <-got:
			if !want[m] {
				t.Fatalf("unexpected message %q", m)
			}
			delete(want, m)
		case <-time.After(10 * time.Second):
			t.Fatal("protocol message not received")
		}
	}
}

// TestServerQSConnWrongNodeID dials a server under a node ID that is not
// the hash of its public key. The connection is closed and neither side
// adds a peer.
func TestServerQSConnWrongNodeID(t *testing.T) {
	keyA, keyB, other := newQSIdentity(t), newQSIdentity(t), newQSIdentity(t)
	srvB := startQSServer(t, "b", keyB, true, nil)
	chB := make(chan *PeerEvent, 10)
	subB := srvB.SubscribeEvents(chB)
	defer subB.Unsubscribe()
	addrB := srvB.listener.Addr().(*net.TCPAddr)

	srvA := startQSServer(t, "a", keyA, false, nil)

	// The right node ID connects, so the failures below are the ID's.
	fd, err := net.Dial("tcp", addrB.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := srvA.SetupConn(fd, staticDialedConn, enode.NewQuantumSafe(enode.ID(keyB.ID()), addrB.IP, addrB.Port)); err != nil {
		t.Fatalf("dial with the right node ID: %v", err)
	}
	waitPeerAdd(t, chB)
	srvA.RemovePeer(enode.NewQuantumSafe(enode.ID(keyB.ID()), addrB.IP, addrB.Port))
	waitPeerCount(t, srvB, 0)

	wrong := []*enode.Node{
		enode.NewQuantumSafe(enode.ID(other.ID()), addrB.IP, addrB.Port),
		enode.NewV4(&newkey().PublicKey, addrB.IP, addrB.Port, addrB.Port),
	}
	for _, dest := range wrong {
		fd, err := net.Dial("tcp", addrB.String())
		if err != nil {
			t.Fatal(err)
		}
		err = srvA.SetupConn(fd, staticDialedConn, dest)
		if !errors.Is(err, errEncHandshakeError) {
			t.Fatalf("dial %v: got %v, want a handshake error", dest.ID(), err)
		}
		if !strings.Contains(err.Error(), "not the dialled node ID") {
			t.Fatalf("dial %v: got %v, want the node ID mismatch", dest.ID(), err)
		}
		fd.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := fd.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection still open after the mismatch")
		}
	}

	// The same mismatch from the static list.
	srvC := startQSServer(t, "c", newQSIdentity(t), false, nil, wrong[0])
	time.Sleep(500 * time.Millisecond)
	if n := srvA.PeerCount() + srvB.PeerCount() + srvC.PeerCount(); n != 0 {
		t.Fatalf("%d peers after dialling the wrong node ID", n)
	}
	for {
		select {
		case ev := <-chB:
			if ev.Type == PeerEventTypeAdd {
				t.Fatalf("accepting side added peer %v", ev.Peer)
			}
		default:
			return
		}
	}
}

// TestServerQSConnRefusesLegacyPeer has a server with only a secp256k1 key
// dial a quantum-safe server. Neither side falls back to the old handshake.
func TestServerQSConnRefusesLegacyPeer(t *testing.T) {
	keyB := newQSIdentity(t)
	srvB := startQSServer(t, "b", keyB, true, nil)
	addrB := srvB.listener.Addr().(*net.TCPAddr)

	legacy := &Server{Config: Config{
		PrivateKey:  newkey(),
		MaxPeers:    10,
		NoDiscovery: true,
		NoDial:      true,
		Logger:      testlog.Logger(t, log.LvlTrace).New("server", "legacy"),
	}}
	if err := legacy.Start(); err != nil {
		t.Fatal(err)
	}
	defer legacy.Stop()

	fd, err := net.Dial("tcp", addrB.String())
	if err != nil {
		t.Fatal(err)
	}
	// The legacy side needs a secp256k1 key to dial at all; it reaches the
	// quantum-safe server, which closes the connection on the first message.
	dest := enode.NewV4(&newkey().PublicKey, addrB.IP, addrB.Port, addrB.Port)
	if err := legacy.SetupConn(fd, staticDialedConn, dest); !errors.Is(err, errEncHandshakeError) {
		t.Fatalf("legacy handshake to a quantum-safe server: got %v, want a handshake error", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := srvB.PeerCount() + legacy.PeerCount(); n != 0 {
		t.Fatalf("%d peers after a legacy handshake", n)
	}
}

func waitPeerCount(t *testing.T, srv *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for srv.PeerCount() != n {
		if time.Now().After(deadline) {
			t.Fatalf("server has %d peers, want %d", srv.PeerCount(), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
