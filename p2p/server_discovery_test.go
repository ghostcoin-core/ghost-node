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
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsdisc"
)

// syncProtocol sends the peer's name to it and reports what it gets back,
// a stand-in for a protocol that syncs over the connection.
func syncProtocol(got chan<- string) Protocol {
	return Protocol{
		Name:    "qsync",
		Version: 1,
		Length:  1,
		Run: func(p *Peer, rw MsgReadWriter) error {
			if err := Send(rw, 0, []string{"synced " + p.Name()}); err != nil {
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
}

func discNodeIDs(d *qsdisc.UDP) map[enode.ID]qsdisc.Node {
	m := make(map[enode.ID]qsdisc.Node)
	for _, n := range d.Nodes() {
		m[n.ID] = n
	}
	return m
}

// TestServerDiscoveryTwoNodesConnect starts two servers with discovery on
// and no static nodes; A knows B as its bootstrap node only. Each finds and
// verifies the other through p2p/qsdisc, A dials B as a node discovery
// found, and the two connect on the quantum-safe transport and exchange
// protocol messages.
func TestServerDiscoveryTwoNodesConnect(t *testing.T) {
	keyA, keyB := newQSIdentity(t), newQSIdentity(t)
	idA, idB := enode.ID(keyA.ID()), enode.ID(keyB.ID())
	got := make(chan string, 4)

	srvB := startDiscServer(t, "b", keyB, nil, syncProtocol(got))
	if srvB.disc == nil {
		t.Fatal("server with discovery on has no discovery")
	}
	tcpB := srvB.listener.Addr().(*net.TCPAddr)
	if udp := srvB.disc.LocalAddr(); int(udp.Port()) != tcpB.Port {
		t.Fatalf("UDP port %d, want the TCP port %d", udp.Port(), tcpB.Port)
	}
	if info := srvB.NodeInfo(); info.Ports.Discovery != tcpB.Port {
		t.Fatalf("node info discovery port %d, want %d", info.Ports.Discovery, tcpB.Port)
	}
	chB := make(chan *PeerEvent, 10)
	subB := srvB.SubscribeEvents(chB)
	defer subB.Unsubscribe()

	srvA := startDiscServer(t, "a", keyA, func(c *Config) {
		c.BootstrapNodes = []*enode.Node{enode.NewQuantumSafe(idB, tcpB.IP, tcpB.Port)}
	}, syncProtocol(got))
	chA := make(chan *PeerEvent, 10)
	subA := srvA.SubscribeEvents(chA)
	defer subA.Unsubscribe()

	if id := waitPeerAdd(t, chA); id != idB {
		t.Fatalf("A has peer %v, want B %v", id, idB)
	}
	if id := waitPeerAdd(t, chB); id != idA {
		t.Fatalf("B has peer %v, want A %v", id, idA)
	}
	waitPeerCount(t, srvA, 1)
	waitPeerCount(t, srvB, 1)

	// Each found and verified the other: A from its bootstrap node, B from
	// A's ping. The record in the table is the one the node answers.
	deadline := time.Now().Add(10 * time.Second)
	for {
		nA, okA := discNodeIDs(srvA.disc)[idB]
		nB, okB := discNodeIDs(srvB.disc)[idA]
		if okA && okB {
			if nA.Record == nil || nA.Record.ID() != idB || int(nA.Addr.Port()) != tcpB.Port {
				t.Fatalf("A's table holds B as %+v", nA)
			}
			if nB.Record == nil || nB.Record.ID() != idA {
				t.Fatalf("B's table holds A as %+v", nB)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("discovery tables: A knows B %v, B knows A %v", okA, okB)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The connection runs on the quantum-safe handshake only; A dialled B
	// as a discovered node, not a static one.
	pA := qsPeer(t, srvA, idB)
	if !pA.rw.is(dynDialedConn) && !qsPeer(t, srvB, idA).rw.is(dynDialedConn) {
		t.Fatal("no side dialled the other as a discovered node")
	}
	for _, s := range []struct {
		srv  *Server
		peer enode.ID
	}{{srvA, idB}, {srvB, idA}} {
		p := qsPeer(t, s.srv, s.peer)
		if _, ok := p.rw.transport.(*qsconnTransport); !ok {
			t.Fatalf("peer runs on %T, want the quantum-safe transport", p.rw.transport)
		}
		if p.Node().Pubkey() != nil {
			t.Fatal("peer node has a secp256k1 key")
		}
		if p.rw.is(staticDialedConn) {
			t.Fatal("peer dialled as a static node")
		}
	}

	want := map[string]bool{"synced a": true, "synced b": true}
	for len(want) > 0 {
		select {
		case m := <-got:
			delete(want, m)
		case <-time.After(10 * time.Second):
			t.Fatalf("protocol messages not exchanged, missing %v", want)
		}
	}
}

// TestServerDiscoveryBootnodeRetry starts a server whose only bootstrap
// node is not up yet, as on a first start before the network or the seed is
// reachable, then starts the bootstrap node. The server must find it, dial
// it and have it as a peer within a minute of its own start, with no static
// node and no peer added by hand.
func TestServerDiscoveryBootnodeRetry(t *testing.T) {
	keyA, keyB := newQSIdentity(t), newQSIdentity(t)
	idB := enode.ID(keyB.ID())

	// Take a free port for B, TCP and UDP, and leave it closed for now.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpB := *l.Addr().(*net.TCPAddr)
	l.Close()

	start := time.Now()
	srvA := startDiscServer(t, "a", keyA, func(c *Config) {
		c.BootstrapNodes = []*enode.Node{enode.NewQuantumSafe(idB, tcpB.IP, tcpB.Port)}
	})
	chA := make(chan *PeerEvent, 10)
	subA := srvA.SubscribeEvents(chA)
	defer subA.Unsubscribe()

	// The first bootstrap of A finds nobody: its ping of B goes unanswered.
	time.Sleep(qsdisc.PingTimeout + time.Second)
	if n := len(srvA.disc.Nodes()); n != 0 {
		t.Fatalf("A's table holds %d nodes before B is up", n)
	}
	if n := srvA.PeerCount(); n != 0 {
		t.Fatalf("A has %d peers before B is up", n)
	}

	startDiscServer(t, "b", keyB, func(c *Config) { c.ListenAddr = tcpB.String() })

	deadline := time.NewTimer(time.Until(start.Add(time.Minute)))
	defer deadline.Stop()
	for {
		select {
		case ev := <-chA:
			if ev.Type == PeerEventTypeAdd && ev.Peer == idB {
				return
			}
		case <-deadline.C:
			t.Fatalf("A has no peer B %v after its start; peers %d, table %d", time.Since(start), srvA.PeerCount(), len(srvA.disc.Nodes()))
		}
	}
}

// TestServerNoDiscoveryOpensNoUDPPort checks that a server with NoDiscovery
// opens no UDP port and answers no record request, that a server with
// discovery on opens its UDP socket on the TCP port, and that DiscAddr
// chooses another UDP address.
func TestServerNoDiscoveryOpensNoUDPPort(t *testing.T) {
	key := newQSIdentity(t)
	srv := startQSServer(t, "a", key, true, nil)
	if srv.disc != nil || srv.records != nil || srv.recordServer != nil {
		t.Fatal("server with NoDiscovery started discovery")
	}
	tcp := srv.listener.Addr().(*net.TCPAddr)
	if info := srv.NodeInfo(); info.Ports.Discovery != 0 {
		t.Fatalf("node info names discovery port %d", info.Ports.Discovery)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcp.IP, Port: tcp.Port})
	if err != nil {
		t.Fatalf("UDP port of the TCP listener is taken: %v", err)
	}
	conn.Close()
	if _, err := fetchFrom(t, tcp.AddrPort(), newQSIdentity(t), enode.ID(key.ID())); err == nil {
		t.Fatal("server with NoDiscovery answered a record request")
	}

	// With discovery on the port is taken by the server.
	on := startDiscServer(t, "b", newQSIdentity(t), nil)
	onTCP := on.listener.Addr().(*net.TCPAddr)
	if conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: onTCP.IP, Port: onTCP.Port}); err == nil {
		conn.Close()
		t.Fatal("server with discovery on has no UDP socket on its TCP port")
	}

	// DiscAddr names the UDP address.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	discAddr := udp.LocalAddr().String()
	udp.Close()
	other := startDiscServer(t, "c", newQSIdentity(t), func(c *Config) { c.DiscAddr = discAddr })
	if got := other.disc.LocalAddr().String(); got != discAddr {
		t.Fatalf("UDP socket on %s, want DiscAddr %s", got, discAddr)
	}
}

// TestConfigHasNoOldDiscoveryFields checks that the server configuration
// has no switch for the old discovery protocols and no bootstrap list of
// their own: there is no discovery to downgrade to.
func TestConfigHasNoOldDiscoveryFields(t *testing.T) {
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		for _, old := range []string{"DiscoveryV4", "DiscoveryV5", "BootstrapNodesV5", "DiscoveryURLs"} {
			if strings.Contains(name, old) {
				t.Errorf("p2p.Config has field %s", name)
			}
		}
	}
	for _, kept := range []string{"NoDiscovery", "BootstrapNodes", "DiscAddr"} {
		if _, ok := typ.FieldByName(kept); !ok {
			t.Errorf("p2p.Config has no field %s", kept)
		}
	}
}
