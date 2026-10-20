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
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const (
	// X25519KeySize is the size of an ephemeral X25519 public key.
	X25519KeySize = 32
	// MLKEMEncapsulationKeySize is the size of an ML-KEM-768 encapsulation key.
	MLKEMEncapsulationKeySize = mlkem.EncapsulationKeySize768
	// MLKEMCiphertextSize is the size of an ML-KEM-768 ciphertext.
	MLKEMCiphertextSize = mlkem.CiphertextSize768

	// InitMsgSize is the body of the initiator's key exchange message.
	InitMsgSize = X25519KeySize + MLKEMEncapsulationKeySize
	// RespMsgSize is the body of the responder's key exchange message.
	RespMsgSize = X25519KeySize + MLKEMCiphertextSize
	// AuthMsgSize is the plaintext of an authentication message: the
	// scheme, the public key and the signature.
	AuthMsgSize = 2 + PublicKeySize + SignatureSize

	// Tags and the signature context.
	TranscriptTag    = "ghost/p2p-transcript/v1"
	KeyExchangeTag   = "ghost/p2p-kex/v1"
	HandshakeContext = "ghost/p2p-handshake/v1"
)

var (
	errMsgLength   = errors.New("qsconn: handshake message has the wrong length")
	errBadKey      = errors.New("qsconn: invalid key exchange value")
	errScheme      = errors.New("qsconn: unknown identity scheme")
	errSignature   = errors.New("qsconn: handshake signature does not verify")
	errWrongNodeID = errors.New("qsconn: remote public key is not the dialled node ID")
)

// sha3Tagged is S: SHA3-256 over the tag's length as one byte, the ASCII tag
// and the parts in order.
func sha3Tagged(tag string, parts ...[]byte) (out [32]byte) {
	h := sha3.New256()
	h.Write([]byte{byte(len(tag))})
	h.Write([]byte(tag))
	for _, p := range parts {
		h.Write(p)
	}
	h.Sum(out[:0])
	return out
}

// transcriptHash covers both X25519 keys, the encapsulation key and the
// ciphertext.
func transcriptHash(initX25519, encapKey, respX25519, ciphertext []byte) [32]byte {
	return sha3Tagged(TranscriptTag, initX25519, encapKey, respX25519, ciphertext)
}

// deriveKeys computes k = S("ghost/p2p-kex/v1", ss_mlkem, ss_x25519,
// transcript_hash) and expands it with SHAKE256 into the initiator-to-responder
// key followed by the responder-to-initiator key.
func deriveKeys(ssMLKEM, ssX25519 []byte, transcript [32]byte) (initToResp, respToInit [keySize]byte) {
	k := sha3Tagged(KeyExchangeTag, ssMLKEM, ssX25519, transcript[:])
	out := sha3.SumSHAKE256(k[:], 2*keySize)
	copy(initToResp[:], out[:keySize])
	copy(respToInit[:], out[keySize:])
	return initToResp, respToInit
}

// writeMsg writes a key exchange message: its length, then the body.
func writeMsg(w io.Writer, body []byte) error {
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	_, err := w.Write(append(buf, body...))
	return err
}

// readMsg reads a key exchange message whose body must be exactly size bytes.
// The length is checked before the body is read.
func readMsg(r io.Reader, size int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if n := binary.BigEndian.Uint32(header[:]); n != uint32(size) {
		return nil, fmt.Errorf("%w: %d, want %d", errMsgLength, n, size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// Handshake runs the hybrid handshake with key as the local identity and
// returns the authenticated remote identity. The dialling side checks that the
// remote public key hashes to the node ID it dialled. Any failure closes the
// connection. Handshake runs once.
func (c *Conn) Handshake(key *Identity) (*RemoteIdentity, error) {
	c.hsmu.Lock()
	defer c.hsmu.Unlock()
	if c.hsRun {
		return nil, errHandshakeRun
	}
	c.hsRun = true

	c.conn.SetDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	var (
		remote  *RemoteIdentity
		in, out *cipherState
		err     error
	)
	if c.dialDest != nil {
		remote, in, out, err = c.initiate(key)
	} else {
		remote, in, out, err = c.respond(key)
	}
	if err != nil {
		c.conn.Close()
		in, out = nil, nil
	} else {
		c.conn.SetDeadline(time.Time{})
	}
	c.rmu.Lock()
	c.in, c.rerr = in, err
	c.rmu.Unlock()
	c.wmu.Lock()
	c.out, c.werr = out, err
	c.wmu.Unlock()
	if err != nil {
		return nil, err
	}
	c.remote = remote
	return remote, nil
}

func (c *Conn) initiate(key *Identity) (*RemoteIdentity, *cipherState, *cipherState, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, nil, err
	}
	ourX := eph.PublicKey().Bytes()
	ek := dk.EncapsulationKey().Bytes()
	if err := writeMsg(c.conn, append(append([]byte{}, ourX...), ek...)); err != nil {
		return nil, nil, nil, err
	}

	resp, err := readMsg(c.conn, RespMsgSize)
	if err != nil {
		return nil, nil, nil, err
	}
	theirX, ct := resp[:X25519KeySize], resp[X25519KeySize:]
	theirPub, err := ecdh.X25519().NewPublicKey(theirX)
	if err != nil {
		return nil, nil, nil, errBadKey
	}
	ssX, err := eph.ECDH(theirPub)
	if err != nil {
		return nil, nil, nil, errBadKey
	}
	ssK, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, nil, nil, errBadKey
	}
	th := transcriptHash(ourX, ek, theirX, ct)
	kOut, kIn := deriveKeys(ssK, ssX, th)
	in, out := newCipherState(kIn), newCipherState(kOut)

	if err := c.writeAuth(out, key, th); err != nil {
		return nil, nil, nil, err
	}
	remote, err := c.readAuth(in, th, c.dialDest)
	if err != nil {
		return nil, nil, nil, err
	}
	return remote, in, out, nil
}

func (c *Conn) respond(key *Identity) (*RemoteIdentity, *cipherState, *cipherState, error) {
	msg, err := readMsg(c.conn, InitMsgSize)
	if err != nil {
		return nil, nil, nil, err
	}
	theirX, ekBytes := msg[:X25519KeySize], msg[X25519KeySize:]
	theirPub, err := ecdh.X25519().NewPublicKey(theirX)
	if err != nil {
		return nil, nil, nil, errBadKey
	}
	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, nil, nil, errBadKey
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	ssX, err := eph.ECDH(theirPub)
	if err != nil {
		return nil, nil, nil, errBadKey
	}
	ssK, ct := ek.Encapsulate()
	ourX := eph.PublicKey().Bytes()
	if err := writeMsg(c.conn, append(append([]byte{}, ourX...), ct...)); err != nil {
		return nil, nil, nil, err
	}
	th := transcriptHash(theirX, ekBytes, ourX, ct)
	kIn, kOut := deriveKeys(ssK, ssX, th)
	in, out := newCipherState(kIn), newCipherState(kOut)

	remote, err := c.readAuth(in, th, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := c.writeAuth(out, key, th); err != nil {
		return nil, nil, nil, err
	}
	return remote, in, out, nil
}

// writeAuth sends scheme, public key and the signature over the transcript
// hash, sealed under the outgoing key.
func (c *Conn) writeAuth(out *cipherState, key *Identity, th [32]byte) error {
	sig, err := key.sign(th[:], HandshakeContext)
	if err != nil {
		return err
	}
	pt := make([]byte, 0, AuthMsgSize)
	pt = append(pt, schemeBytes(key.Scheme())...)
	pt = append(pt, key.PublicKey()...)
	pt = append(pt, sig...)
	if c.authHook != nil {
		pt = c.authHook(pt)
	}
	_, err = c.conn.Write(out.seal(pt))
	return err
}

// readAuth reads and checks the other side's authentication message. When
// want is set, the public key must hash to it; that is checked before the
// signature.
func (c *Conn) readAuth(in *cipherState, th [32]byte, want *NodeID) (*RemoteIdentity, error) {
	pt, _, err := in.readRecord(c.conn, AuthMsgSize+tagSize, AuthMsgSize+tagSize)
	if err != nil {
		return nil, err
	}
	if len(pt) != AuthMsgSize {
		return nil, errMsgLength
	}
	scheme := binary.BigEndian.Uint16(pt[:2])
	if scheme != SchemeMLDSA44 {
		return nil, fmt.Errorf("%w: %#04x", errScheme, scheme)
	}
	pubBytes := pt[2 : 2+PublicKeySize]
	sig := pt[2+PublicKeySize:]
	id := NodeIDOf(scheme, pubBytes)
	if want != nil && id != *want {
		return nil, fmt.Errorf("%w: got %v, dialled %v", errWrongNodeID, id, *want)
	}
	var pub mldsa44.PublicKey
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return nil, errBadKey
	}
	if !mldsa44.Verify(&pub, th[:], []byte(HandshakeContext), sig) {
		return nil, errSignature
	}
	pk := append([]byte{}, pubBytes...)
	return &RemoteIdentity{ID: id, Scheme: scheme, PublicKey: pk}, nil
}
