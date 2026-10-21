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

// Package qsconn is the quantum-safe peer transport: the node identity, an
// ML-DSA-44 key pair, and a hybrid X25519 + ML-KEM-768 handshake followed by
// ChaCha20-Poly1305 frames (spec 09, section 10). There is one scheme and no
// negotiation.
package qsconn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/crypto/sha3"
)

const (
	// SchemeMLDSA44 is the only node identity scheme: ML-DSA-44 (FIPS 204,
	// pure mode).
	SchemeMLDSA44 uint16 = 0x0001

	// PublicKeySize and SignatureSize are the ML-DSA-44 sizes.
	PublicKeySize = mldsa44.PublicKeySize
	SignatureSize = mldsa44.SignatureSize

	// NodeIDTag is the tag of the node ID hash.
	NodeIDTag = "ghost/node-id/v1"
)

// NodeID is K("ghost/node-id/v1", scheme, public_key).
type NodeID [32]byte

func (id NodeID) String() string { return hex.EncodeToString(id[:]) }

// keccakTagged is K: Keccak-256 over the tag's length as one byte, the ASCII
// tag and the parts in order.
func keccakTagged(tag string, parts ...[]byte) (out [32]byte) {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte{byte(len(tag))})
	h.Write([]byte(tag))
	for _, p := range parts {
		h.Write(p)
	}
	h.Sum(out[:0])
	return out
}

func schemeBytes(scheme uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, scheme)
}

// NodeIDOf returns the node ID of a scheme and a public key. It checks
// nothing.
func NodeIDOf(scheme uint16, publicKey []byte) NodeID {
	return NodeID(keccakTagged(NodeIDTag, schemeBytes(scheme), publicKey))
}

// Identity is a node's ML-DSA-44 key pair.
type Identity struct {
	priv *mldsa44.PrivateKey
	pub  *mldsa44.PublicKey
	id   NodeID
}

// GenerateIdentity makes a new identity from the system's random source.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return newIdentity(priv, pub), nil
}

func newIdentity(priv *mldsa44.PrivateKey, pub *mldsa44.PublicKey) *Identity {
	return &Identity{priv: priv, pub: pub, id: NodeIDOf(SchemeMLDSA44, pub.Bytes())}
}

// ID returns the node ID.
func (k *Identity) ID() NodeID { return k.id }

// Scheme returns the identity scheme, always SchemeMLDSA44.
func (k *Identity) Scheme() uint16 { return SchemeMLDSA44 }

// PublicKey returns the encoded public key, PublicKeySize bytes.
func (k *Identity) PublicKey() []byte { return k.pub.Bytes() }

func (k *Identity) sign(msg []byte, context string) ([]byte, error) {
	sig := make([]byte, SignatureSize)
	if err := mldsa44.SignTo(k.priv, msg, []byte(context), true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// Save writes the private key, hex encoded, to a file only its owner can read
// and write. An existing file is replaced.
func (k *Identity) Save(path string) error {
	data := []byte(hex.EncodeToString(k.priv.Bytes()))
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadIdentity reads an identity written by Save. The file must be readable
// by its owner only and hold exactly the hex encoding of one ML-DSA-44
// private key.
func LoadIdentity(path string) (*Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("qsconn: node key %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("qsconn: node key %s has mode %04o, want it readable by its owner only", path, info.Mode().Perm())
	}
	if info.Size() != 2*mldsa44.PrivateKeySize {
		return nil, fmt.Errorf("qsconn: node key %s has %d bytes, want %d", path, info.Size(), 2*mldsa44.PrivateKeySize)
	}
	text := make([]byte, 2*mldsa44.PrivateKeySize)
	if _, err := f.ReadAt(text, 0); err != nil {
		return nil, err
	}
	return parseIdentity(text)
}

// ParseIdentityHex parses the text of an identity file written by Save: the
// hex encoding of one ML-DSA-44 private key, exactly, with no prefix and no
// line ending.
func ParseIdentityHex(text string) (*Identity, error) {
	if len(text) != 2*mldsa44.PrivateKeySize {
		return nil, fmt.Errorf("qsconn: node key has %d hex chars, want %d", len(text), 2*mldsa44.PrivateKeySize)
	}
	return parseIdentity([]byte(text))
}

// parseIdentity decodes the 2*mldsa44.PrivateKeySize hex chars of a
// private key.
func parseIdentity(text []byte) (*Identity, error) {
	raw := make([]byte, mldsa44.PrivateKeySize)
	if n, err := hex.Decode(raw, text); err != nil || n != len(raw) {
		return nil, errors.New("qsconn: node key is not hex")
	}
	priv := new(mldsa44.PrivateKey)
	if err := priv.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("qsconn: node key: %v", err)
	}
	if !bytes.Equal(priv.Bytes(), raw) {
		return nil, errors.New("qsconn: node key is not canonical")
	}
	pub, ok := priv.Public().(*mldsa44.PublicKey)
	if !ok {
		return nil, errors.New("qsconn: node key has no public key")
	}
	return newIdentity(priv, pub), nil
}
