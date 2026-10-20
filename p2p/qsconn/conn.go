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
	"crypto/cipher"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// DefaultHandshakeTimeout bounds the whole handshake.
	DefaultHandshakeTimeout = 5 * time.Second
	// DefaultMaxMessageSize bounds the data of one frame.
	DefaultMaxMessageSize = 16 * 1024 * 1024

	headerSize = 4                          // big-endian length of what follows
	codeSize   = 8                          // big-endian message code
	tagSize    = chacha20poly1305.Overhead  // Poly1305 tag
	keySize    = chacha20poly1305.KeySize   // one direction's key
	nonceSize  = chacha20poly1305.NonceSize // 4 zero bytes, 8-byte counter
)

// rekeyInterval is the number of records after which a direction's key is
// replaced by SHAKE256 over the old key and its counter starts again at zero.
// Tests lower it.
var rekeyInterval uint64 = 1 << 20

// Config holds the limits of a connection. A zero field takes its default.
type Config struct {
	// HandshakeTimeout bounds the whole handshake: when it passes, the
	// connection is closed.
	HandshakeTimeout time.Duration
	// MaxMessageSize is the largest data a frame carries. A frame header
	// announcing more is refused before the frame is read.
	MaxMessageSize uint32
}

func (c Config) withDefaults() Config {
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.MaxMessageSize == 0 {
		c.MaxMessageSize = DefaultMaxMessageSize
	}
	if c.MaxMessageSize > math.MaxUint32-codeSize-tagSize {
		c.MaxMessageSize = math.MaxUint32 - codeSize - tagSize
	}
	return c
}

var (
	errNoHandshake  = errors.New("qsconn: handshake not done")
	errHandshakeRun = errors.New("qsconn: handshake already run")
	errFrameSize    = errors.New("qsconn: frame length out of bounds")
	errFrameAuth    = errors.New("qsconn: frame authentication failed")
	errTooLarge     = errors.New("qsconn: message too large")
)

// cipherState is one direction: its key, its AEAD and its record counter.
type cipherState struct {
	key     [keySize]byte
	aead    cipher.AEAD
	counter uint64
}

func newCipherState(key [keySize]byte) *cipherState {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err) // the key has the right size
	}
	return &cipherState{key: key, aead: aead}
}

func (s *cipherState) nonce() []byte {
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[nonceSize-8:], s.counter)
	return n[:]
}

// advance moves to the next record, rekeying at the boundary.
func (s *cipherState) advance() {
	s.counter++
	if s.counter >= rekeyInterval {
		*s = *newCipherState(nextKey(s.key))
	}
}

// nextKey is the key after a rekey: SHAKE256 over the old key.
func nextKey(old [keySize]byte) (k [keySize]byte) {
	copy(k[:], sha3.SumSHAKE256(old[:], keySize))
	return k
}

// seal returns the wire record for plaintext: the length header, then the
// ciphertext with the header as associated data.
func (s *cipherState) seal(plaintext []byte) []byte {
	out := make([]byte, headerSize, headerSize+len(plaintext)+tagSize)
	binary.BigEndian.PutUint32(out, uint32(len(plaintext)+tagSize))
	out = s.aead.Seal(out, s.nonce(), plaintext, out[:headerSize])
	s.advance()
	return out
}

// readRecord reads one record whose ciphertext length lies in [min, max] and
// returns its plaintext and wire size. The length is checked before the
// ciphertext is read.
func (s *cipherState) readRecord(r io.Reader, min, max uint32) ([]byte, int, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < min || size > max {
		return nil, 0, fmt.Errorf("%w: %d not in [%d, %d]", errFrameSize, size, min, max)
	}
	ct := make([]byte, size)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, 0, err
	}
	pt, err := s.aead.Open(ct[:0], s.nonce(), ct, header[:])
	if err != nil {
		return nil, 0, errFrameAuth
	}
	s.advance()
	return pt, headerSize + int(size), nil
}

// RemoteIdentity is the authenticated identity of the other side.
type RemoteIdentity struct {
	ID        NodeID
	Scheme    uint16
	PublicKey []byte
}

// Conn is a quantum-safe connection. After Handshake, one goroutine may Read
// while another Writes. Any failure closes the underlying connection.
type Conn struct {
	conn     net.Conn
	dialDest *NodeID
	cfg      Config

	hsmu   sync.Mutex
	hsRun  bool
	remote *RemoteIdentity

	rmu  sync.Mutex
	in   *cipherState
	rerr error

	wmu  sync.Mutex
	out  *cipherState
	werr error

	// authHook, when set by a test, changes the authentication plaintext
	// before it is sealed.
	authHook func([]byte) []byte
}

// NewConn wraps conn. dialDest is the node ID that was dialled and is nil on
// the accepting side.
func NewConn(conn net.Conn, dialDest *NodeID, cfg Config) *Conn {
	c := &Conn{conn: conn, cfg: cfg.withDefaults()}
	if dialDest != nil {
		id := *dialDest
		c.dialDest = &id
	}
	return c
}

// Remote returns the other side's identity, nil before the handshake.
func (c *Conn) Remote() *RemoteIdentity {
	c.hsmu.Lock()
	defer c.hsmu.Unlock()
	return c.remote
}

// Read reads one frame and returns its message code, its data and its size on
// the wire. A frame that fails any check closes the connection, and every
// later Read returns the same error.
func (c *Conn) Read() (code uint64, data []byte, wireSize int, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.rerr != nil {
		return 0, nil, 0, c.rerr
	}
	if c.in == nil {
		return 0, nil, 0, errNoHandshake
	}
	pt, size, err := c.in.readRecord(c.conn, codeSize+tagSize, codeSize+c.cfg.MaxMessageSize+tagSize)
	if err != nil {
		c.rerr = err
		c.conn.Close()
		return 0, nil, 0, err
	}
	return binary.BigEndian.Uint64(pt[:codeSize]), pt[codeSize:], size, nil
}

// Write sends one frame and returns its size on the wire. Data above the
// configured maximum is refused without writing. A failed write closes the
// connection.
func (c *Conn) Write(code uint64, data []byte) (uint32, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	if c.out == nil {
		return 0, errNoHandshake
	}
	if uint64(len(data)) > uint64(c.cfg.MaxMessageSize) {
		return 0, fmt.Errorf("%w: %d bytes, the limit is %d", errTooLarge, len(data), c.cfg.MaxMessageSize)
	}
	pt := make([]byte, codeSize, codeSize+len(data))
	binary.BigEndian.PutUint64(pt, code)
	pt = append(pt, data...)
	rec := c.out.seal(pt)
	if _, err := c.conn.Write(rec); err != nil {
		c.werr = err
		c.conn.Close()
		return 0, err
	}
	return uint32(len(rec)), nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.conn.Close() }

// SetDeadline sets the read and write deadlines of the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline of the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline of the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
