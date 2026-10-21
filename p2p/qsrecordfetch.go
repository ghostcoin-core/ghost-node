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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

// The record fetch (spec 09, section 10.3) gets a node's record over the
// authenticated TCP transport, never over UDP. The fetching side dials the
// endpoint that answered its discovery ping, at the same port number over
// TCP, runs the qsconn handshake for the node ID it asks about and sends one
// record request, the first and only message of the connection. The
// answering side answers it from its enode.QSRecordCache only, so it never
// hands out a record that has not verified: the encoded record of the asked
// ID, or an empty answer. The connection then closes.

var (
	errRecordRequestServed = errors.New("node record request answered")
	errRecordFetchLimit    = errors.New("node record requests over the source limit")
	errRecordNoAnswer      = errors.New("node record fetch: no answer")
	errRecordNone          = errors.New("node record fetch: the node has no record for the ID")
	errRecordWrongID       = errors.New("node record fetch: record is not of the node ID asked for")
	errRecordWrongEndpoint = errors.New("node record fetch: record endpoint is not the one that answered")
)

// qsRecordRequest is the body of a record request: the node ID asked for.
type qsRecordRequest struct {
	ID enode.ID
}

// msgPeeker is a transport that can read the first message of a connection
// without taking it from the protocol handshake.
type msgPeeker interface {
	peekMsg() (Msg, error)
}

// qsFetchLimiter bounds the record requests answered for one source IP
// address: a token bucket of enode.QSRecordFetchBurst refilled at
// enode.QSRecordFetchRate a second, for at most enode.QSRecordFetchSources
// addresses, the least recently seen dropped first.
type qsFetchLimiter struct {
	clock mclock.Clock

	mu      sync.Mutex
	sources lru.BasicLRU[netip.Addr, *qsFetchBucket]
}

type qsFetchBucket struct {
	tokens float64
	last   mclock.AbsTime
}

func newQSFetchLimiter(clock mclock.Clock) *qsFetchLimiter {
	if clock == nil {
		clock = mclock.System{}
	}
	return &qsFetchLimiter{
		clock:   clock,
		sources: lru.NewBasicLRU[netip.Addr, *qsFetchBucket](enode.QSRecordFetchSources),
	}
}

// allow takes one request from the bucket of ip.
func (l *qsFetchLimiter) allow(ip netip.Addr) bool {
	ip = ip.Unmap()
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.sources.Get(ip)
	if !ok {
		b = &qsFetchBucket{tokens: enode.QSRecordFetchBurst, last: now}
		l.sources.Add(ip, b)
	}
	b.tokens += time.Duration(now-b.last).Seconds() * enode.QSRecordFetchRate
	if b.tokens > enode.QSRecordFetchBurst {
		b.tokens = enode.QSRecordFetchBurst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *qsFetchLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sources.Len()
}

// qsRecordServer answers record requests from a record cache.
type qsRecordServer struct {
	cache   *enode.QSRecordCache
	limit   *qsFetchLimiter
	refresh func() // puts the node's own record in the cache, if set
}

// serve answers the record request req, the first message of a connection
// from ip. It always returns an error, so the connection is closed after the
// one answer: errRecordRequestServed when it answered.
func (s *qsRecordServer) serve(rw MsgWriter, req Msg, ip netip.Addr) error {
	if !s.limit.allow(ip) {
		return errRecordFetchLimit
	}
	var body qsRecordRequest
	if err := req.Decode(&body); err != nil {
		return err
	}
	if s.refresh != nil {
		s.refresh()
	}
	var answer []byte
	if rec := s.cache.Get(body.ID); rec != nil {
		answer = rec.Encode()
	}
	if len(answer) > enode.QSRecordMaxSize {
		answer = nil // never the case for a record the cache holds
	}
	err := rw.WriteMsg(Msg{Code: qsRecordAnswerMsg, Size: uint32(len(answer)), Payload: bytes.NewReader(answer)})
	if err != nil {
		return err
	}
	return errRecordRequestServed
}

// fetchQSRecord runs the qsconn handshake on fd for the node ID id, sends
// the record request and returns the encoded record of the answer. An answer
// over enode.QSRecordMaxSize bytes is refused before it is read.
func fetchQSRecord(fd net.Conn, key *qsconn.Identity, id enode.ID, timeout time.Duration) ([]byte, error) {
	defer fd.Close()
	dest := qsconn.NodeID(id)
	c := qsconn.NewConn(fd, &dest, qsconn.Config{
		HandshakeTimeout: handshakeTimeout,
		MaxMessageSize:   enode.QSRecordMaxSize,
	})
	defer c.Close()
	remote, err := c.Handshake(key)
	if err != nil {
		return nil, err
	}
	if enode.ID(remote.ID) != id {
		return nil, errRecordWrongID
	}
	c.SetDeadline(time.Now().Add(timeout))
	req, err := rlp.EncodeToBytes(&qsRecordRequest{ID: id})
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(qsRecordRequestMsg, req); err != nil {
		return nil, err
	}
	code, data, _, err := c.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRecordNoAnswer, err)
	}
	if code != qsRecordAnswerMsg {
		return nil, fmt.Errorf("%w: message code %#x", errRecordNoAnswer, code)
	}
	if len(data) == 0 {
		return nil, errRecordNone
	}
	return data, nil
}

// qsRecordVerifier is the record verifier of p2p/qsdisc: it fetches the
// record of a node over qsconn from the endpoint that answered for it,
// verifies it through the record cache and accepts it only when it is of
// the node ID asked for and its IP and UDP port are that endpoint. A node
// that cannot be reached that way is not verified.
type qsRecordVerifier struct {
	key     *qsconn.Identity
	cache   *enode.QSRecordCache
	dial    func(network, addr string) (net.Conn, error)
	timeout time.Duration
}

func newQSRecordVerifier(key *qsconn.Identity, cache *enode.QSRecordCache) *qsRecordVerifier {
	d := &net.Dialer{Timeout: handshakeTimeout}
	return &qsRecordVerifier{key: key, cache: cache, dial: d.Dial, timeout: handshakeTimeout}
}

// VerifyRecord implements qsdisc.RecordVerifier.
func (v *qsRecordVerifier) VerifyRecord(id enode.ID, endpoint netip.AddrPort) (*enode.QSRecord, error) {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return nil, errRecordWrongEndpoint
	}
	endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
	fd, err := v.dial("tcp", endpoint.String())
	if err != nil {
		return nil, err
	}
	enc, err := fetchQSRecord(fd, v.key, id, v.timeout)
	if err != nil {
		return nil, err
	}
	// Check the claims before the signature, so a record of another node
	// never enters the cache.
	rec, err := enode.DecodeQSRecord(enc)
	if err != nil {
		return nil, err
	}
	if err := checkQSRecord(rec, id, endpoint); err != nil {
		return nil, err
	}
	rec, err = v.cache.Add(enc)
	if err != nil {
		return nil, err
	}
	if err := checkQSRecord(rec, id, endpoint); err != nil {
		return nil, err
	}
	return rec, nil
}

// checkQSRecord accepts a record only when it is of id and its IP and UDP
// port are endpoint.
func checkQSRecord(rec *enode.QSRecord, id enode.ID, endpoint netip.AddrPort) error {
	if rec.ID() != id {
		return errRecordWrongID
	}
	ip, ok := netip.AddrFromSlice(rec.IP)
	if !ok || ip.Unmap() != endpoint.Addr().Unmap() || rec.UDP != endpoint.Port() {
		return errRecordWrongEndpoint
	}
	return nil
}
