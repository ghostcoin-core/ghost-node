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
	"crypto/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsdisc"
)

// qsdiscLookupInterval is the least time between two lookups of the
// discovery iterator, so a small network is not asked again and again.
const qsdiscLookupInterval = time.Second

// startQSDiscovery opens the UDP socket of p2p/qsdisc and starts it. The
// socket is on DiscAddr, or else on the address and port of the TCP
// listener: a record is fetched over TCP at the port number of the UDP
// endpoint that answered, so a node with another UDP port cannot be
// verified by others.
func (srv *Server) startQSDiscovery() error {
	addr := srv.DiscAddr
	if addr == "" && srv.listener != nil {
		addr = srv.listener.Addr().String()
	}
	if addr == "" {
		addr = srv.ListenAddr
	}
	if addr == "" {
		addr = ":0"
	}
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	laddr := conn.LocalAddr().(*net.UDPAddr)
	srv.log.Debug("UDP listener up", "addr", laddr)
	if tcp, ok := srv.listenerTCPAddr(); ok && tcp.Port != laddr.Port {
		srv.log.Warn("Discovery UDP port differs from the TCP port; other nodes cannot fetch this node's record", "udp", laddr.Port, "tcp", tcp.Port)
	}
	// The UDP port goes in the quantum-safe record only, not in the null
	// record of the local node, and is not mapped by NAT: the record is
	// fetched at the UDP port number over TCP, so a node behind NAT
	// forwards the one port number for both itself.
	srv.discPort = uint16(laddr.Port)

	srv.records = enode.NewQSRecordCache(enode.QSRecordCacheSize, enode.QSRecordVerifyRate, nil)
	srv.recordServer = &qsRecordServer{
		cache:   srv.records,
		limit:   newQSFetchLimiter(srv.clock),
		refresh: srv.updateLocalRecord,
	}
	srv.updateLocalRecord()

	var boot []qsdisc.Bootnode
	for _, n := range srv.BootstrapNodes {
		if b, ok := qsBootnode(n); ok {
			boot = append(boot, b)
		} else {
			srv.log.Warn("Bootstrap node has no endpoint", "id", n.ID())
		}
	}
	disc, err := qsdisc.Listen(conn, qsdisc.Config{
		Self:      srv.Identity.ID(),
		Verifier:  newQSRecordVerifier(srv.Identity, srv.records),
		Bootnodes: boot,
		Log:       srv.log,
	})
	if err != nil {
		conn.Close()
		return err
	}
	srv.disc = disc
	srv.discmix.AddSource(newQSDiscIterator(disc))
	return nil
}

func (srv *Server) listenerTCPAddr() (*net.TCPAddr, bool) {
	if srv.listener == nil {
		return nil, false
	}
	tcp, ok := srv.listener.Addr().(*net.TCPAddr)
	return tcp, ok
}

// qsBootnode is the discovery endpoint of a bootstrap node: its IP and its
// UDP port, which is its TCP port when the node names none.
func qsBootnode(n *enode.Node) (qsdisc.Bootnode, bool) {
	ip := n.IPAddr()
	port := n.UDP()
	if port == 0 {
		port = n.TCP()
	}
	if !ip.IsValid() || port == 0 {
		return qsdisc.Bootnode{}, false
	}
	return qsdisc.Bootnode{ID: n.ID(), Addr: netip.AddrPortFrom(ip.Unmap(), uint16(port))}, true
}

// updateLocalRecord signs the node's record from the local node's IP and
// TCP port and the discovery UDP port, when the local node's sequence
// number is newer than the cached record's, and puts it in the record
// cache, the only place record requests are answered from.
func (srv *Server) updateLocalRecord() {
	n := srv.localnode.Node()
	if cur := srv.records.Get(n.ID()); cur != nil && cur.Seq >= n.Seq() {
		return
	}
	srv.recordMu.Lock()
	defer srv.recordMu.Unlock()
	if cur := srv.records.Get(n.ID()); cur != nil && cur.Seq >= n.Seq() {
		return
	}
	ip := n.IP()
	if ip == nil {
		return
	}
	rec := &enode.QSRecord{Seq: n.Seq(), IP: ip, TCP: uint16(n.TCP()), UDP: srv.discPort}
	if err := rec.Sign(srv.Identity); err != nil {
		srv.log.Error("Can't sign the node record", "err", err)
		return
	}
	if _, err := srv.records.Add(rec.Encode()); err != nil {
		srv.log.Debug("Node record not cached", "seq", rec.Seq, "err", err)
	}
}

// qsdiscIterator yields the verified nodes that discovery lookups find, as
// dial candidates on the TCP port of their record.
type qsdiscIterator struct {
	disc    *qsdisc.UDP
	closing chan struct{}
	once    sync.Once

	buf  []*enode.Node
	cur  *enode.Node
	last time.Time
}

func newQSDiscIterator(disc *qsdisc.UDP) *qsdiscIterator {
	return &qsdiscIterator{disc: disc, closing: make(chan struct{})}
}

func (it *qsdiscIterator) Next() bool {
	for len(it.buf) == 0 {
		if wait := qsdiscLookupInterval - time.Since(it.last); !it.last.IsZero() && wait > 0 {
			select {
			case <-time.After(wait):
			case <-it.closing:
				return false
			}
		}
		it.last = time.Now()
		found := make(chan []qsdisc.Node, 1)
		go func() {
			var target enode.ID
			rand.Read(target[:])
			found <- it.disc.Lookup(target)
		}()
		select {
		case nodes := <-found:
			for _, n := range nodes {
				if n.Record == nil || n.Record.TCP == 0 {
					continue
				}
				it.buf = append(it.buf, enode.NewQuantumSafe(n.ID, n.Record.IP, int(n.Record.TCP)))
			}
		case <-it.closing:
			return false
		}
	}
	it.cur, it.buf = it.buf[0], it.buf[1:]
	return true
}

func (it *qsdiscIterator) Node() *enode.Node { return it.cur }

func (it *qsdiscIterator) Close() {
	it.once.Do(func() { close(it.closing) })
}
