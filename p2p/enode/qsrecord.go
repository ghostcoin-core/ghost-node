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

package enode

import (
	"container/list"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// QSRecordMaxSize is the largest encoded quantum-safe node record, in
	// bytes (spec 09, section 10.3). A larger record is dropped undecoded.
	QSRecordMaxSize = 4096

	// QSRecordCacheSize is the number of verified records a node keeps.
	QSRecordCacheSize = 4096

	// QSRecordVerifyRate is the number of record signatures a node verifies
	// per second, over all sources together.
	QSRecordVerifyRate = 100
)

var (
	errQSRecordTooLarge  = errors.New("enode: node record too large")
	errQSRecordScheme    = errors.New("enode: node record has an unknown identity scheme")
	errQSRecordKey       = errors.New("enode: node record public key has the wrong length")
	errQSRecordSigLength = errors.New("enode: node record signature has the wrong length")
	errQSRecordIP        = errors.New("enode: node record IP is neither 4 nor 16 bytes")
	errQSRecordSignature = errors.New("enode: node record signature does not verify")
	errQSRecordStale     = errors.New("enode: node record is older than the cached one")
	errQSRecordBusy      = errors.New("enode: node record verification budget exceeded")
)

// QSForkID is the fork identifier carried by a node record: the CRC32 of the
// genesis hash and the forks passed, and the next fork (EIP-2124).
type QSForkID struct {
	Hash [4]byte
	Next uint64
}

// QSRecord is a quantum-safe node record (spec 09, section 10.3):
//
//	rlp([seq, scheme, public_key, ip, tcp_port, udp_port, fork_id, signature])
//
// signed by the node's ML-DSA-44 key over
// K("ghost/node-record/v1", rlp of the fields before the signature). It is
// separate from the secp256k1 ENR of package enr; neither converts to the
// other.
//
// A record handed out by DecodeQSRecord or QSRecordCache must not be
// modified.
type QSRecord struct {
	Seq       uint64
	Scheme    uint16
	PublicKey []byte
	IP        net.IP
	TCP       uint16
	UDP       uint16
	ForkID    QSForkID
	Signature []byte
}

// qsRecordUnsigned is the list of the fields the signature covers.
type qsRecordUnsigned struct {
	Seq       uint64
	Scheme    uint16
	PublicKey []byte
	IP        net.IP
	TCP       uint16
	UDP       uint16
	ForkID    QSForkID
}

func (r *QSRecord) unsigned() []byte {
	b, err := rlp.EncodeToBytes(&qsRecordUnsigned{
		Seq: r.Seq, Scheme: r.Scheme, PublicKey: r.PublicKey, IP: r.IP,
		TCP: r.TCP, UDP: r.UDP, ForkID: r.ForkID,
	})
	if err != nil {
		panic("enode: can't encode node record: " + err.Error())
	}
	return b
}

// ID returns the node ID of the record, the qsconn node ID of its scheme and
// public key. It does not verify the record.
func (r *QSRecord) ID() ID {
	return ID(qsconn.NodeIDOf(r.Scheme, r.PublicKey))
}

// check checks everything but the signature.
func (r *QSRecord) check() error {
	if r.Scheme != qsconn.SchemeMLDSA44 {
		return fmt.Errorf("%w: %#04x", errQSRecordScheme, r.Scheme)
	}
	if len(r.PublicKey) != qsconn.PublicKeySize {
		return errQSRecordKey
	}
	if len(r.Signature) != qsconn.SignatureSize {
		return errQSRecordSigLength
	}
	if len(r.IP) != net.IPv4len && len(r.IP) != net.IPv6len {
		return errQSRecordIP
	}
	return nil
}

// Sign puts the identity's scheme and public key in the record and signs
// it. An IPv4 address is stored in its 4-byte form.
func (r *QSRecord) Sign(key *qsconn.Identity) error {
	if ip4 := r.IP.To4(); ip4 != nil {
		r.IP = ip4
	}
	r.Scheme = key.Scheme()
	r.PublicKey = key.PublicKey()
	r.Signature = make([]byte, qsconn.SignatureSize)
	if err := r.check(); err != nil {
		return err
	}
	sig, err := key.SignRecord(r.unsigned())
	if err != nil {
		return err
	}
	r.Signature = sig
	if size := len(r.Encode()); size > QSRecordMaxSize {
		return fmt.Errorf("%w: %d bytes", errQSRecordTooLarge, size)
	}
	return nil
}

// Verify checks the record and its signature.
func (r *QSRecord) Verify() error {
	if err := r.check(); err != nil {
		return err
	}
	if !qsconn.VerifyRecord(r.Scheme, r.PublicKey, r.unsigned(), r.Signature) {
		return errQSRecordSignature
	}
	return nil
}

// Encode returns the RLP encoding of the record.
func (r *QSRecord) Encode() []byte {
	b, err := rlp.EncodeToBytes(r)
	if err != nil {
		panic("enode: can't encode node record: " + err.Error())
	}
	return b
}

// DecodeQSRecord decodes a node record and checks its size, its scheme and
// the lengths of its fields, in that order and before anything else. It
// does not verify the signature.
func DecodeQSRecord(b []byte) (*QSRecord, error) {
	if len(b) > QSRecordMaxSize {
		return nil, fmt.Errorf("%w: %d bytes", errQSRecordTooLarge, len(b))
	}
	r := new(QSRecord)
	if err := rlp.DecodeBytes(b, r); err != nil {
		return nil, err
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

// qsRecordKey identifies a cached record.
type qsRecordKey struct {
	id  ID
	seq uint64
}

// qsVerification is a verification in progress; others who bring the same
// encoding wait for it instead of verifying again.
type qsVerification struct {
	done chan struct{}
	rec  *QSRecord
	err  error
}

// QSRecordCache holds verified node records, at most one per node ID, the
// one of the highest seq. A record is verified once: the same node ID and
// seq is answered from the cache, the same encoding that failed is refused
// from a bounded memory of failures, and one being verified is waited for.
// The cache never holds or hands out a record that has not verified.
//
// The cache holds a bounded number of records, dropping the least recently
// used, and verifies a bounded number of records per second; a record
// beyond that budget is dropped unverified.
type QSRecordCache struct {
	clock  mclock.Clock
	size   int
	rate   int
	verify func(*QSRecord) error

	mu       sync.Mutex
	entries  map[ID]*list.Element // of *QSRecord
	lru      *list.List
	pending  map[common.Hash]*qsVerification
	failed   map[common.Hash]struct{}
	failRing []common.Hash
	failNext int
	tokens   int
	refilled mclock.AbsTime
}

// NewQSRecordCache makes a cache of at most size records that verifies at
// most rate records per second. A nil clock is the system clock.
func NewQSRecordCache(size, rate int, clock mclock.Clock) *QSRecordCache {
	if size <= 0 || rate <= 0 {
		panic("enode: node record cache needs a positive size and rate")
	}
	if clock == nil {
		clock = mclock.System{}
	}
	return &QSRecordCache{
		clock:    clock,
		size:     size,
		rate:     rate,
		verify:   (*QSRecord).Verify,
		entries:  make(map[ID]*list.Element),
		lru:      list.New(),
		pending:  make(map[common.Hash]*qsVerification),
		failed:   make(map[common.Hash]struct{}),
		failRing: make([]common.Hash, size),
		tokens:   rate,
		refilled: clock.Now(),
	}
}

// Add decodes a record, verifies it unless the cache already knows it, and
// keeps it. It returns the verified record for the record's node ID and
// seq, or an error when the record is dropped.
func (c *QSRecordCache) Add(b []byte) (*QSRecord, error) {
	r, err := DecodeQSRecord(b)
	if err != nil {
		return nil, err
	}
	key := qsRecordKey{r.ID(), r.Seq}
	hash := crypto.Keccak256Hash(b)

	c.mu.Lock()
	if rec, err, ok := c.lookup(key); ok {
		c.mu.Unlock()
		return rec, err
	}
	if _, ok := c.failed[hash]; ok {
		c.mu.Unlock()
		return nil, errQSRecordSignature
	}
	if v := c.pending[hash]; v != nil {
		c.mu.Unlock()
		<-v.done
		return v.rec, v.err
	}
	if !c.takeToken() {
		c.mu.Unlock()
		return nil, errQSRecordBusy
	}
	v := &qsVerification{done: make(chan struct{})}
	c.pending[hash] = v
	c.mu.Unlock()

	verr := c.verify(r)

	c.mu.Lock()
	delete(c.pending, hash)
	if verr != nil {
		c.addFailure(hash)
		v.err = verr
	} else if rec, err, ok := c.lookup(key); ok {
		// Another encoding of the same node ID and seq verified meanwhile.
		v.rec, v.err = rec, err
	} else {
		c.insert(r)
		v.rec = r
	}
	c.mu.Unlock()
	close(v.done)
	return v.rec, v.err
}

// Get returns the verified record of a node, or nil.
func (c *QSRecordCache) Get(id ID) *QSRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.entries[id]
	if el == nil {
		return nil
	}
	c.lru.MoveToFront(el)
	return el.Value.(*QSRecord)
}

// Len returns the number of cached records.
func (c *QSRecordCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// lookup answers a record from the cache: the cached record for the same
// seq, or errQSRecordStale for an older one. ok is false when the record is
// newer than the cached one or the node has none.
func (c *QSRecordCache) lookup(key qsRecordKey) (rec *QSRecord, err error, ok bool) {
	el := c.entries[key.id]
	if el == nil {
		return nil, nil, false
	}
	cur := el.Value.(*QSRecord)
	switch {
	case key.seq == cur.Seq:
		c.lru.MoveToFront(el)
		return cur, nil, true
	case key.seq < cur.Seq:
		return nil, errQSRecordStale, true
	}
	return nil, nil, false
}

func (c *QSRecordCache) insert(r *QSRecord) {
	id := r.ID()
	if el := c.entries[id]; el != nil {
		el.Value = r
		c.lru.MoveToFront(el)
		return
	}
	if c.lru.Len() >= c.size {
		old := c.lru.Remove(c.lru.Back()).(*QSRecord)
		delete(c.entries, old.ID())
	}
	c.entries[id] = c.lru.PushFront(r)
}

func (c *QSRecordCache) addFailure(hash common.Hash) {
	if len(c.failed) >= c.size {
		delete(c.failed, c.failRing[c.failNext])
	}
	c.failRing[c.failNext] = hash
	c.failNext = (c.failNext + 1) % c.size
	c.failed[hash] = struct{}{}
}

// takeToken takes one verification from the budget, refilled every second.
func (c *QSRecordCache) takeToken() bool {
	if now := c.clock.Now(); now.Sub(c.refilled) >= time.Second {
		c.tokens = c.rate
		c.refilled = now
	}
	if c.tokens == 0 {
		return false
	}
	c.tokens--
	return true
}
