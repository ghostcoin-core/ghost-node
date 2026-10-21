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

// Package qsdisc is the peer discovery of the quantum-safe node (spec 09,
// section 10.3): a table of nodes by distance from the local node ID, filled
// over UDP by ping, pong, findnode and neighbors packets.
//
// The packets carry node IDs and endpoints only. A node never trusts an
// endpoint for an ID until it has fetched that ID's record from the endpoint
// and verified it (RecordVerifier); a node whose record does not verify, or
// does not name the ID asked for and the endpoint that answered, is refused
// and never enters the table or an answer. A node answers a findnode only
// to an endpoint that proved itself by answering one of our pings with our
// token and that carries the cookie our pong gave it, never with more than
// MaxAmplification times the bytes of the findnode, and everything a
// remote peer can make it hold or do is bounded by the limits of limits.go.
package qsdisc

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
)

var (
	errClosed         = errors.New("qsdisc: closed")
	errTimeout        = errors.New("qsdisc: timeout")
	errTooManyPings   = errors.New("qsdisc: too many pending pings")
	errBusy           = errors.New("qsdisc: verification busy")
	errStarted        = errors.New("qsdisc: verification started")
	errTooSoon        = errors.New("qsdisc: node verified at this endpoint less than a minute ago")
	errTooManyStarts  = errors.New("qsdisc: too many verifications started in the last minute")
	errFailedBefore   = errors.New("qsdisc: node failed verification at this endpoint before")
	errSelf           = errors.New("qsdisc: own node ID")
	errWrongID        = errors.New("qsdisc: endpoint answered with another node ID")
	errRecordID       = errors.New("qsdisc: record is not of the node ID asked for")
	errRecordEndpoint = errors.New("qsdisc: record endpoint is not the one that answered")
	errNoRecord       = errors.New("qsdisc: verifier returned no record")
)

// RecordVerifier fetches the record of a node from the endpoint that
// answered for it and verifies it. It returns the verified record or an
// error. The caller still checks that the record is of the ID asked for and
// names the endpoint, and refuses it otherwise.
type RecordVerifier interface {
	VerifyRecord(id enode.ID, endpoint netip.AddrPort) (*enode.QSRecord, error)
}

// Bootnode is a node to start from: its ID and UDP endpoint. It is verified
// like any other node before it enters the table.
type Bootnode struct {
	ID   enode.ID
	Addr netip.AddrPort
}

// Config is the configuration of a discovery node.
type Config struct {
	Self      qsconn.NodeID // the local node ID
	Verifier  RecordVerifier
	Bootnodes []Bootnode
	Log       log.Logger
}

// UDP is a discovery node on a UDP socket.
type UDP struct {
	conn     *net.UDPConn
	self     enode.ID
	verifier RecordVerifier
	tab      *table
	log      log.Logger
	sem      chan struct{} // running verifications

	mu          sync.Mutex
	closed      bool
	pings       map[[TokenSize]byte]*pendingPing
	remotePings int // pending pings a remote peer triggered
	pinging     map[netip.AddrPort]int
	findnodes   map[[TokenSize]byte]*pendingFindnode
	bondWait    map[netip.AddrPort][]chan struct{}
	cookieKey   [32]byte
	sources     lru.BasicLRU[netip.Addr, *tokenBucket]
	endpoints   lru.BasicLRU[netip.AddrPort, *endpoint]
	verifying   map[nodeAddr]*verification
	starts      map[nodeAddr]time.Time
	startList   *list.List // of verifyStart, oldest first
	retries     map[nodeAddr]*list.Element
	retryList   *list.List // of nodeAddr, oldest first
	failed      map[nodeAddr]struct{}
	failRing    []nodeAddr
	failNext    int

	challengePings int // pending pings proving again a table node's endpoint

	closing chan struct{}
	wg      sync.WaitGroup
}

type pendingPing struct {
	addr      netip.AddrPort
	remote    bool
	challenge bool
	timer     *time.Timer
	done      func(id qsconn.NodeID, ok bool)
}

type pendingFindnode struct {
	addr netip.AddrPort
	ch   chan []Neighbor
}

// endpoint is what a node keeps about a source endpoint: when it proved
// itself and for which ID, when we last answered its ping, and the cookie
// its last pong to us gave our endpoint.
type endpoint struct {
	id       qsconn.NodeID
	proven   time.Time
	answered time.Time
	cookie   [CookieSize]byte
}

type verification struct {
	remote bool
	done   chan struct{}
	node   Node
	err    error
}

// nodeAddr is a node ID at an endpoint. Verifications, their cooldown and
// their failures are kept per nodeAddr: a claim of an ID at one endpoint
// says nothing about the ID at another, so a peer that claims an honest ID
// at its own endpoint cannot hold up or refuse the honest endpoint.
type nodeAddr struct {
	id   enode.ID
	addr netip.AddrPort
}

type verifyStart struct {
	key nodeAddr
	at  time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// Listen starts a discovery node on conn. It owns conn from then on.
func Listen(conn *net.UDPConn, cfg Config) (*UDP, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("qsdisc: no record verifier")
	}
	u := newUDP(conn, cfg)
	u.wg.Add(2)
	go u.readLoop()
	go u.maintainLoop()
	if len(cfg.Bootnodes) > 0 {
		u.wg.Add(1)
		go u.bootstrap(cfg.Bootnodes)
	}
	return u, nil
}

func newUDP(conn *net.UDPConn, cfg Config) *UDP {
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	self := enode.ID(cfg.Self)
	var key [32]byte
	rand.Read(key[:]) // never fails
	return &UDP{
		cookieKey: key,
		conn:      conn,
		self:      self,
		verifier:  cfg.Verifier,
		tab:       newTable(self),
		log:       cfg.Log,
		sem:       make(chan struct{}, MaxVerifications),
		pings:     make(map[[TokenSize]byte]*pendingPing),
		pinging:   make(map[netip.AddrPort]int),
		findnodes: make(map[[TokenSize]byte]*pendingFindnode),
		bondWait:  make(map[netip.AddrPort][]chan struct{}),
		sources:   lru.NewBasicLRU[netip.Addr, *tokenBucket](MaxSources),
		endpoints: lru.NewBasicLRU[netip.AddrPort, *endpoint](MaxSources),
		verifying: make(map[nodeAddr]*verification),
		starts:    make(map[nodeAddr]time.Time),
		startList: list.New(),
		retries:   make(map[nodeAddr]*list.Element),
		retryList: list.New(),
		failed:    make(map[nodeAddr]struct{}),
		failRing:  make([]nodeAddr, MaxFailed),
		closing:   make(chan struct{}),
	}
}

// Close stops the node and closes its socket.
func (u *UDP) Close() {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	close(u.closing)
	u.mu.Unlock()
	u.conn.Close()
	u.wg.Wait()
}

// Self returns the local node ID.
func (u *UDP) Self() enode.ID { return u.self }

// LocalAddr returns the UDP endpoint of the node.
func (u *UDP) LocalAddr() netip.AddrPort {
	return u.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Nodes returns the verified live nodes of the table, closest to the local
// node first.
func (u *UDP) Nodes() []Node {
	return u.tab.closest(u.self, NumBuckets*BucketSize)
}

func (u *UDP) bootstrap(nodes []Bootnode) {
	defer u.wg.Done()
	var wg sync.WaitGroup
	for _, b := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := u.verify(b.ID, b.Addr, true); err != nil {
				u.log.Debug("Bootnode not verified", "id", b.ID, "addr", b.Addr, "err", err)
			}
		}()
	}
	wg.Wait()
	u.Lookup(u.self)
}

// Packet handling.

func (u *UDP) readLoop() {
	defer u.wg.Done()
	buf := make([]byte, MaxPacketSize+1)
	for {
		n, from, err := u.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-u.closing:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			u.log.Debug("Discovery read error", "err", err)
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		u.handlePacket(buf[:n], from)
	}
}

// handlePacket decodes a packet and handles it. The source address of a UDP
// packet is easily forged, so only what a packet makes the node do is
// charged to its source: a ping or a findnode takes one packet of the
// source's token bucket. A packet that does not decode is dropped and
// charges nothing, and a pong or neighbors packet is an answer, handled
// only when it matches a request we sent to that endpoint with its token,
// and charges nothing either. So forged packets from a peer's address can
// use up its open allowance for requests, but never stop its answers to our
// live checks and lookups from getting through.
//
// Nor can they stop the peer's own live checks and lookups of us: the last
// CookieReserve packets of a source's bucket are taken only by requests
// carrying the cookie our pongs gave the endpoint, which only a sender that
// receives our pongs can use. Requests with and without the cookie share
// the one bucket, so a source address never gets more than SourceRate and
// SourceBurst however it mixes them and however many ports it uses.
//
// A findnode is answered with more than a ping is, so it is handled only
// with that cookie: one without it, or with a cookie given to another
// endpoint or node ID, or expired, is dropped before it is charged or
// answered. A findnode forged from a proven peer's address so cannot make
// the node send the peer neighbors packets it did not ask for.
func (u *UDP) handlePacket(b []byte, from netip.AddrPort) {
	if len(b) > MaxPacketSize {
		return // dropped undecoded
	}
	p, err := Decode(b)
	if err != nil {
		return
	}
	now := time.Now()
	switch p := p.(type) {
	case *Pong:
		u.handlePong(p, from)
	case *Neighbors:
		u.handleNeighbors(p, from)
	case *Ping:
		if u.allowRequest(from, p.From, p.Cookie, now) {
			u.handlePing(p, from, now)
		}
	case *Findnode:
		if !u.validCookie(p.Cookie, from, p.From, now) {
			return
		}
		if u.take(from.Addr(), 0, now) {
			u.handleFindnode(p, from, len(b), now)
		}
	}
}

// cookiePeriod is the period of a cookie at time now. A pong gives the
// cookie of the current period, and a cookie is accepted in its period and
// the next one, so it expires at most ProvenTime after it was given, with
// the endpoint's proof, and at least ProvenTime/2 after.
func cookiePeriod(now time.Time) uint64 {
	return uint64(now.UnixNano() / int64(ProvenTime/2))
}

// cookieFor returns the cookie the node gives the node id at the endpoint
// addr at time now: a keyed hash of the endpoint, the node ID and the
// period under the node's secret. It cannot be guessed, and it is good for
// that endpoint and ID alone.
func (u *UDP) cookieFor(addr netip.AddrPort, id qsconn.NodeID, now time.Time) [CookieSize]byte {
	return u.cookieAt(addr, id, cookiePeriod(now))
}

func (u *UDP) cookieAt(addr netip.AddrPort, id qsconn.NodeID, period uint64) [CookieSize]byte {
	mac := hmac.New(sha256.New, u.cookieKey[:])
	enc, _ := addr.MarshalBinary()
	mac.Write(enc)
	mac.Write(id[:])
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], period)
	mac.Write(p[:])
	var c [CookieSize]byte
	copy(c[:], mac.Sum(nil))
	return c
}

// validCookie reports whether cookie is one the node gave the node id at
// addr and has not expired.
func (u *UDP) validCookie(cookie [CookieSize]byte, addr netip.AddrPort, id qsconn.NodeID, now time.Time) bool {
	if cookie == ([CookieSize]byte{}) {
		return false
	}
	p := cookiePeriod(now)
	cur, prev := u.cookieAt(addr, id, p), u.cookieAt(addr, id, p-1)
	return hmac.Equal(cookie[:], cur[:]) || hmac.Equal(cookie[:], prev[:])
}

// allowRequest takes one packet of a ping from the token bucket of its
// source address. A ping carrying the cookie we gave its endpoint and ID
// may take the bucket's last CookieReserve packets; one without it may not.
func (u *UDP) allowRequest(from netip.AddrPort, id qsconn.NodeID, cookie [CookieSize]byte, now time.Time) bool {
	if u.validCookie(cookie, from, id, now) {
		return u.take(from.Addr(), 0, now)
	}
	return u.take(from.Addr(), CookieReserve, now)
}

// take takes one packet from the token bucket of the source address ip
// when more than reserve packets are left in it. Every request of an
// address, whatever its port and cookie, is charged to its one bucket.
func (u *UDP) take(ip netip.Addr, reserve float64, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	b, ok := u.sources.Get(ip)
	if !ok {
		b = &tokenBucket{tokens: SourceBurst, last: now}
		u.sources.Add(ip, b)
	}
	return b.take(reserve, now)
}

// take takes one packet from the bucket, if it holds one over reserve.
func (b *tokenBucket) take(reserve float64, now time.Time) bool {
	b.tokens += now.Sub(b.last).Seconds() * SourceRate
	if b.tokens > SourceBurst {
		b.tokens = SourceBurst
	}
	b.last = now
	if b.tokens < reserve+1 {
		return false
	}
	b.tokens--
	return true
}

func (u *UDP) handlePing(p *Ping, from netip.AddrPort, now time.Time) {
	id := enode.ID(p.From)
	if id == u.self {
		return
	}
	// A pong is no larger than the ping it answers.
	u.send(from, &Pong{From: qsconn.NodeID(u.self), Token: p.Token, Cookie: u.cookieFor(from, p.From, now)})

	u.mu.Lock()
	ep := u.endpointLocked(from)
	ep.answered = now
	waiters := u.bondWait[from]
	delete(u.bondWait, from)
	proven := u.provenLocked(from, p.From, now)
	pinging := u.pinging[from] > 0
	u.mu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}

	if n, ok := u.tab.get(id); ok && n.Addr == from {
		// The proof of a table node's endpoint can be pushed out of the
		// endpoints by pings from other sources. Prove it again with one
		// ping of the MaxChallengePings, so that the node's findnodes are
		// answered once its pong comes; until then they are not.
		if !proven && !pinging {
			u.startPing(from, id, false, true, func(qsconn.NodeID, bool) {})
		}
		return
	}
	if proven {
		u.verifyRemote(id, from)
		return
	}
	if pinging {
		return
	}
	// Prove the endpoint before anything else; then verify the node.
	u.sendPing(from, id, true, func(got qsconn.NodeID, ok bool) {
		if ok && got == p.From {
			u.verifyRemote(id, from)
		}
	})
}

func (u *UDP) handlePong(p *Pong, from netip.AddrPort) {
	u.mu.Lock()
	pp := u.pings[p.Token]
	if pp == nil || pp.addr != from {
		u.mu.Unlock()
		return
	}
	u.removePingLocked(p.Token, pp)
	ep := u.endpointLocked(from)
	ep.id = p.From
	ep.proven = time.Now()
	// Only a pong that answers our ping with its token gives a cookie, so
	// forged packets cannot replace the one a node gave us.
	ep.cookie = p.Cookie
	u.mu.Unlock()
	u.tab.setCookie(enode.ID(p.From), from, p.Cookie)
	pp.timer.Stop()
	pp.done(p.From, true)
}

// handleFindnode answers a findnode of size bytes that carried a valid
// cookie. The answer goes only to an endpoint we proved for the sender's
// ID, and holds no more nodes than fit in MaxAmplification times size, so
// it is never much larger than the request; a findnode padded to
// FindnodeSize, as Encode pads it, gets a full answer.
func (u *UDP) handleFindnode(p *Findnode, from netip.AddrPort, size int, now time.Time) {
	u.mu.Lock()
	proven := u.provenLocked(from, p.From, now)
	u.mu.Unlock()
	if !proven {
		return // never answer more than was asked to an unproven endpoint
	}
	nodes := u.tab.closest(enode.ID(p.Target), MaxNeighbors)
	resp := &Neighbors{From: qsconn.NodeID(u.self), Token: p.Token, Nodes: make([]Neighbor, 0, len(nodes))}
	for _, n := range nodes {
		resp.Nodes = append(resp.Nodes, neighborOf(qsconn.NodeID(n.ID), n.Addr))
	}
	for {
		b, err := Encode(resp)
		if err != nil {
			return
		}
		if len(b) <= MaxAmplification*size {
			u.conn.WriteToUDPAddrPort(b, from)
			return
		}
		if len(resp.Nodes) == 0 {
			return
		}
		resp.Nodes = resp.Nodes[:len(resp.Nodes)-1]
	}
}

// handleNeighbors completes the pending findnode whose token the answer
// echoes, and only when it comes from the endpoint asked. Anything else
// leaves the findnode pending.
func (u *UDP) handleNeighbors(p *Neighbors, from netip.AddrPort) {
	u.mu.Lock()
	f := u.findnodes[p.Token]
	if f == nil || f.addr != from {
		u.mu.Unlock()
		return
	}
	delete(u.findnodes, p.Token)
	u.mu.Unlock()
	f.ch <- p.Nodes // buffered, one answer per findnode
}

func (u *UDP) send(to netip.AddrPort, p any) error {
	b, err := Encode(p)
	if err != nil {
		return err
	}
	_, err = u.conn.WriteToUDPAddrPort(b, to)
	return err
}

// endpointLocked returns the entry of an endpoint, making it when needed.
func (u *UDP) endpointLocked(addr netip.AddrPort) *endpoint {
	ep, ok := u.endpoints.Get(addr)
	if !ok {
		ep = new(endpoint)
		u.endpoints.Add(addr, ep)
	}
	return ep
}

// provenLocked reports whether addr proved itself for id within
// ProvenTime.
func (u *UDP) provenLocked(addr netip.AddrPort, id qsconn.NodeID, now time.Time) bool {
	ep, ok := u.endpoints.Peek(addr)
	return ok && ep.id == id && !ep.proven.IsZero() && now.Sub(ep.proven) < ProvenTime
}

// Pings.

// sendPing sends a ping and calls done with the pong's node ID, or with
// ok false after PingTimeout. done runs on the read loop or a timer and
// must not block. A ping a remote peer triggered (remote) takes one of the
// MaxRemotePings slots; the rest of MaxPendingPings stays for the node's
// own live checks and lookups.
// The ping carries the cookie the node id expected at to gave us.
func (u *UDP) sendPing(to netip.AddrPort, id enode.ID, remote bool, done func(id qsconn.NodeID, ok bool)) error {
	return u.startPing(to, id, remote, false, done)
}

// startPing is sendPing for a ping of either kind a remote peer triggers:
// remote, or a challenge that proves again the endpoint of a table node,
// which takes one of the MaxChallengePings slots instead, so that a flood
// of pings from new sources filling MaxRemotePings cannot stop it.
func (u *UDP) startPing(to netip.AddrPort, id enode.ID, remote, challenge bool, done func(id qsconn.NodeID, ok bool)) error {
	var token [TokenSize]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	cookie := u.cookieOf(id, to)
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return errClosed
	}
	if len(u.pings) >= MaxPendingPings || (remote && u.remotePings >= MaxRemotePings) ||
		(challenge && u.challengePings >= MaxChallengePings) {
		u.mu.Unlock()
		return errTooManyPings
	}
	pp := &pendingPing{addr: to, remote: remote, challenge: challenge, done: done}
	u.pings[token] = pp
	u.pinging[to]++
	if remote {
		u.remotePings++
	}
	if challenge {
		u.challengePings++
	}
	pp.timer = time.AfterFunc(PingTimeout, func() {
		u.mu.Lock()
		if u.pings[token] != pp {
			u.mu.Unlock()
			return
		}
		u.removePingLocked(token, pp)
		u.mu.Unlock()
		done(qsconn.NodeID{}, false)
	})
	u.mu.Unlock()

	if err := u.send(to, &Ping{From: qsconn.NodeID(u.self), Token: token, Cookie: cookie}); err != nil {
		u.mu.Lock()
		if u.pings[token] == pp {
			u.removePingLocked(token, pp)
			pp.timer.Stop()
		}
		u.mu.Unlock()
		return err
	}
	return nil
}

// cookieOf returns the cookie the node id at addr gave our endpoint, or zero.
// It is kept with the endpoint and, for a table node, with the node.
func (u *UDP) cookieOf(id enode.ID, addr netip.AddrPort) [CookieSize]byte {
	var c [CookieSize]byte
	u.mu.Lock()
	if ep, ok := u.endpoints.Peek(addr); ok {
		c = ep.cookie
	}
	u.mu.Unlock()
	if c != ([CookieSize]byte{}) {
		return c
	}
	c, _ = u.tab.cookie(id, addr)
	return c
}

func (u *UDP) removePingLocked(token [TokenSize]byte, pp *pendingPing) {
	delete(u.pings, token)
	if pp.remote {
		u.remotePings--
	}
	if pp.challenge {
		u.challengePings--
	}
	if u.pinging[pp.addr]--; u.pinging[pp.addr] <= 0 {
		delete(u.pinging, pp.addr)
	}
}

// ping sends a ping and waits for its pong. It returns errTimeout only when
// the ping was sent and no pong came; any other error is a local failure
// that says nothing about the remote node.
func (u *UDP) ping(to netip.AddrPort, id enode.ID, remote bool) (qsconn.NodeID, error) {
	type result struct {
		id qsconn.NodeID
		ok bool
	}
	ch := make(chan result, 1)
	if err := u.sendPing(to, id, remote, func(id qsconn.NodeID, ok bool) { ch <- result{id, ok} }); err != nil {
		return qsconn.NodeID{}, err
	}
	select {
	case r := <-ch:
		if !r.ok {
			return qsconn.NodeID{}, errTimeout
		}
		return r.id, nil
	case <-u.closing:
		return qsconn.NodeID{}, errClosed
	}
}

// Verification.

// verifyRemote starts a verification a remote peer triggered. When all
// MaxVerifications are running, it is queued for a retry instead.
func (u *UDP) verifyRemote(id enode.ID, addr netip.AddrPort) {
	if _, err := u.verify(id, addr, false); err == errBusy {
		u.queueRetry(nodeAddr{id, addr})
	}
}

// verify fetches and verifies the record of id from the endpoint addr and
// puts the node in the table. The endpoint must first answer a ping with
// the same ID. A blocking call waits for the result; a non-blocking one, for
// what a remote peer triggers, is refused with errBusy when
// MaxVerifications are running and otherwise runs in the background.
func (u *UDP) verify(id enode.ID, addr netip.AddrPort, blocking bool) (Node, error) {
	if id == u.self {
		return Node{}, errSelf
	}
	if n, ok := u.tab.get(id); ok && n.Addr == addr {
		return n, nil
	}
	key := nodeAddr{id, addr}
	now := time.Now()
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return Node{}, errClosed
	}
	if _, ok := u.failed[key]; ok {
		u.mu.Unlock()
		return Node{}, errFailedBefore
	}
	if v := u.verifying[key]; v != nil {
		u.mu.Unlock()
		if !blocking {
			return Node{}, errStarted
		}
		select {
		case <-v.done:
			return v.node, v.err
		case <-u.closing:
			return Node{}, errClosed
		}
	}
	if !blocking {
		select {
		case u.sem <- struct{}{}:
		default:
			u.mu.Unlock()
			return Node{}, errBusy
		}
	}
	if err := u.mayStartLocked(key, now); err != nil {
		u.mu.Unlock()
		if !blocking {
			<-u.sem
		}
		return Node{}, err
	}
	v := &verification{remote: !blocking, done: make(chan struct{})}
	u.verifying[key] = v
	u.wg.Add(1)
	u.mu.Unlock()

	if !blocking {
		go u.runVerify(v, key)
		return Node{}, errStarted
	}
	select {
	case u.sem <- struct{}{}:
	case <-u.closing:
		u.finishVerify(v, key, Node{}, false, errClosed)
		return Node{}, errClosed
	}
	u.runVerify(v, key)
	return v.node, v.err
}

// mayStartLocked checks whether a verification of a node at an endpoint
// may start now, and records the start. One starts for an ID at one
// endpoint at most every VerifyInterval, and at most MaxVerifyStarts start
// in a VerifyInterval over all IDs and endpoints.
func (u *UDP) mayStartLocked(key nodeAddr, now time.Time) error {
	for e := u.startList.Front(); e != nil; e = u.startList.Front() {
		s := e.Value.(verifyStart)
		if now.Sub(s.at) < VerifyInterval {
			break
		}
		u.startList.Remove(e)
		if u.starts[s.key] == s.at {
			delete(u.starts, s.key)
		}
	}
	if at, ok := u.starts[key]; ok && now.Sub(at) < VerifyInterval {
		return errTooSoon
	}
	if u.startList.Len() >= MaxVerifyStarts {
		return errTooManyStarts
	}
	u.starts[key] = now
	u.startList.PushBack(verifyStart{key, now})
	return nil
}

// runVerify runs a verification holding a slot of u.sem.
func (u *UDP) runVerify(v *verification, key nodeAddr) {
	n, refused, err := u.fetchAndCheck(key.id, key.addr, v.remote)
	<-u.sem
	if err == nil && u.tab.add(n, time.Now()) {
		var c [CookieSize]byte
		u.mu.Lock()
		if ep, ok := u.endpoints.Peek(n.Addr); ok {
			c = ep.cookie
		}
		u.mu.Unlock()
		if c != ([CookieSize]byte{}) {
			u.tab.setCookie(n.ID, n.Addr, c)
		}
	}
	u.finishVerify(v, key, n, refused, err)
}

// finishVerify ends a verification. A refused one, where the endpoint
// answered but the node or its record did not hold, is remembered.
func (u *UDP) finishVerify(v *verification, key nodeAddr, n Node, refused bool, err error) {
	u.mu.Lock()
	delete(u.verifying, key)
	if refused {
		u.addFailureLocked(key)
	}
	v.node, v.err = n, err
	u.mu.Unlock()
	close(v.done)
	u.wg.Done()
	if err != nil {
		u.log.Debug("Node not verified", "id", key.id, "addr", key.addr, "err", err)
	}
}

// fetchAndCheck proves the endpoint for id, then has the verifier fetch and
// verify the record, and accepts it only when it is of id and names addr.
// refused is true when the endpoint answered but the node was refused.
func (u *UDP) fetchAndCheck(id enode.ID, addr netip.AddrPort, remote bool) (n Node, refused bool, err error) {
	u.mu.Lock()
	proven := u.provenLocked(addr, qsconn.NodeID(id), time.Now())
	u.mu.Unlock()
	if !proven {
		got, err := u.ping(addr, id, remote)
		if err != nil {
			return Node{}, false, err
		}
		if enode.ID(got) != id {
			return Node{}, true, errWrongID
		}
	}
	rec, err := u.verifier.VerifyRecord(id, addr)
	if err != nil {
		return Node{}, true, err
	}
	if err := checkRecord(rec, id, addr); err != nil {
		return Node{}, true, err
	}
	return Node{ID: id, Addr: addr, Record: rec}, false, nil
}

// checkRecord accepts a verified record only when it is of id and its IP
// and UDP port are addr.
func checkRecord(rec *enode.QSRecord, id enode.ID, addr netip.AddrPort) error {
	if rec == nil {
		return errNoRecord
	}
	if rec.ID() != id {
		return errRecordID
	}
	ip, ok := netip.AddrFromSlice(rec.IP)
	if !ok || ip.Unmap() != addr.Addr().Unmap() || rec.UDP != addr.Port() {
		return errRecordEndpoint
	}
	return nil
}

func (u *UDP) addFailureLocked(k nodeAddr) {
	if _, ok := u.failed[k]; ok {
		return
	}
	if len(u.failed) >= MaxFailed {
		delete(u.failed, u.failRing[u.failNext])
	}
	u.failRing[u.failNext] = k
	u.failNext = (u.failNext + 1) % MaxFailed
	u.failed[k] = struct{}{}
}

// queueRetry remembers a remote-triggered verification refused for want of
// a free slot, to start it later. At most MaxVerifyRetries are queued; the
// oldest is dropped first.
func (u *UDP) queueRetry(key nodeAddr) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.retries[key]; ok {
		return
	}
	if u.retryList.Len() >= MaxVerifyRetries {
		old := u.retryList.Remove(u.retryList.Front()).(nodeAddr)
		delete(u.retries, old)
	}
	u.retries[key] = u.retryList.PushBack(key)
}

// runRetries starts queued verifications, oldest first, while slots are
// free. Each start is held to the same budgets as a first attempt.
func (u *UDP) runRetries() {
	for {
		u.mu.Lock()
		e := u.retryList.Front()
		if e == nil {
			u.mu.Unlock()
			return
		}
		key := e.Value.(nodeAddr)
		u.retryList.Remove(e)
		delete(u.retries, key)
		u.mu.Unlock()
		if _, err := u.verify(key.id, key.addr, false); err == errBusy {
			u.mu.Lock()
			if _, ok := u.retries[key]; !ok {
				u.retries[key] = u.retryList.PushFront(key)
			}
			u.mu.Unlock()
			return
		}
	}
}

// Live checks.

func (u *UDP) maintainLoop() {
	defer u.wg.Done()
	tick := time.NewTicker(RevalidateInterval / 10)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			u.runRetries()
			if u.revalidate() == errClosed {
				return
			}
		case <-u.closing:
			return
		}
	}
}

// revalidate checks the table node checked longest ago. A node that
// answers with another ID is removed. One that does not answer is removed
// only after MaxRevalidateFails checks in a row went unanswered, so that a
// lost or crowded-out pong does not evict a live node. A local failure,
// such as no free ping slot, leaves it in place to be checked again.
func (u *UDP) revalidate() error {
	n, ok := u.tab.toCheck(time.Now().Add(-RevalidateInterval))
	if !ok {
		return nil
	}
	got, err := u.ping(n.Addr, n.ID, false)
	switch {
	case err == nil && enode.ID(got) != n.ID:
		u.tab.remove(n.ID)
	case err == errTimeout:
		u.tab.checkFailed(n.ID, time.Now())
	case err == nil:
		u.tab.checked(n.ID, time.Now())
	}
	return err
}

// Lookup.

// findnode asks a node for the nodes closest to target and waits
// LookupTimeout for its answer. The request carries a random token that
// the answer must echo from the endpoint asked.
func (u *UDP) findnode(n Node, target enode.ID) ([]Neighbor, error) {
	u.ensureBond(n.ID, n.Addr)
	var token [TokenSize]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	f := &pendingFindnode{addr: n.Addr, ch: make(chan []Neighbor, 1)}
	u.mu.Lock()
	u.findnodes[token] = f
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		if u.findnodes[token] == f {
			delete(u.findnodes, token)
		}
		u.mu.Unlock()
	}()
	req := &Findnode{From: qsconn.NodeID(u.self), Target: qsconn.NodeID(target), Token: token, Cookie: u.cookieOf(n.ID, n.Addr)}
	if err := u.send(n.Addr, req); err != nil {
		return nil, err
	}
	timer := time.NewTimer(LookupTimeout)
	defer timer.Stop()
	select {
	case nodes := <-f.ch:
		return nodes, nil
	case <-timer.C:
		return nil, errTimeout
	case <-u.closing:
		return nil, errClosed
	}
}

// ensureBond makes sure the remote node will answer our findnode. It must
// have proven our endpoint, which it does when it pings us and gets our
// pong, and we must hold a cookie of its that has not expired, which its
// pong to our ping gives. Unless it gave us a cookie within ProvenTime/4,
// ping it; unless we answered a ping from it lately, the ping makes it ping
// us back, and we wait for that ping.
func (u *UDP) ensureBond(id enode.ID, addr netip.AddrPort) {
	now := time.Now()
	u.mu.Lock()
	ep, ok := u.endpoints.Peek(addr)
	answered := ok && !ep.answered.IsZero() && now.Sub(ep.answered) < ProvenTime/2
	cookie := ok && ep.id == qsconn.NodeID(id) && ep.cookie != ([CookieSize]byte{}) && now.Sub(ep.proven) < ProvenTime/4
	if answered && cookie {
		u.mu.Unlock()
		return
	}
	if answered {
		u.mu.Unlock()
		u.ping(addr, id, false)
		return
	}
	ch := make(chan struct{})
	u.bondWait[addr] = append(u.bondWait[addr], ch)
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		list := u.bondWait[addr]
		for i, c := range list {
			if c == ch {
				u.bondWait[addr] = append(list[:i:i], list[i+1:]...)
				break
			}
		}
		if len(u.bondWait[addr]) == 0 {
			delete(u.bondWait, addr)
		}
		u.mu.Unlock()
	}()
	if _, err := u.ping(addr, id, false); err != nil {
		return
	}
	timer := time.NewTimer(PingTimeout)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	case <-u.closing:
	}
}

// Lookup finds the nodes closest to target: it asks the closest verified
// nodes LookupAlpha at a time, verifies every node they name before it is
// used, and returns at most LookupResults verified nodes, closest first.
func (u *UDP) Lookup(target enode.ID) []Node {
	result := u.tab.closest(target, LookupResults)
	// Candidates are told apart by ID and endpoint: a node named at a wrong
	// endpoint must not hide the same ID named at its own.
	seen := make(map[nodeAddr]bool)
	have := map[enode.ID]bool{u.self: true}
	asked := make(map[enode.ID]bool)
	for _, n := range result {
		have[n.ID] = true
	}
	for {
		select {
		case <-u.closing:
			return result
		default:
		}
		var ask []Node
		for _, n := range result {
			if !asked[n.ID] && len(ask) < LookupAlpha {
				asked[n.ID] = true
				ask = append(ask, n)
			}
		}
		if len(ask) == 0 {
			return result
		}
		// Ask, then verify every new node named in the answers.
		answers := make([][]Neighbor, len(ask))
		var wg sync.WaitGroup
		for i, n := range ask {
			wg.Add(1)
			go func() {
				defer wg.Done()
				answers[i], _ = u.findnode(n, target)
			}()
		}
		wg.Wait()
		var cand []Neighbor
		for i, nodes := range answers {
			sender := ask[i].Addr.Addr()
			for _, nb := range nodes {
				key := nodeAddr{enode.ID(nb.ID), nb.Addr()}
				if have[key.id] || seen[key] || netutil.CheckRelayAddr(sender, key.addr.Addr()) != nil || nb.UDP == 0 {
					continue
				}
				seen[key] = true
				cand = append(cand, nb)
			}
		}
		verified := make([]*Node, len(cand))
		for i, nb := range cand {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if n, err := u.verify(enode.ID(nb.ID), nb.Addr(), true); err == nil {
					verified[i] = &n
				}
			}()
		}
		wg.Wait()
		for _, n := range verified {
			if n != nil && !have[n.ID] {
				have[n.ID] = true
				result = append(result, *n)
			}
		}
		sortByDistance(result, target)
		if len(result) > LookupResults {
			result = result[:LookupResults]
		}
	}
}
