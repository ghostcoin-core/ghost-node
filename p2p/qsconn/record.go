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

import "github.com/cloudflare/circl/sign/mldsa/mldsa44"

const (
	// RecordTag is the tag of the hash a node record's signature covers
	// (spec 09, section 10.3).
	RecordTag = "ghost/node-record/v1"

	// RecordContext is the ML-DSA context of a node record's signature.
	RecordContext = "ghost/node-record/v1"
)

// RecordHash returns K("ghost/node-record/v1", unsigned), the message a node
// record's signature covers. unsigned is the RLP list of the record's fields
// before the signature.
func RecordHash(unsigned []byte) [32]byte {
	return keccakTagged(RecordTag, unsigned)
}

// SignRecord signs a node record with the identity: it returns the
// signature over RecordHash(unsigned). The record must carry the identity's
// scheme and public key; the caller puts them in before it encodes unsigned.
func (k *Identity) SignRecord(unsigned []byte) ([]byte, error) {
	h := RecordHash(unsigned)
	return k.sign(h[:], RecordContext)
}

// VerifyRecord reports whether sig is a signature of the node record
// unsigned by publicKey under scheme. An unknown scheme or a malformed key
// or signature does not verify.
func VerifyRecord(scheme uint16, publicKey, unsigned, sig []byte) bool {
	if scheme != SchemeMLDSA44 || len(publicKey) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	var pub mldsa44.PublicKey
	if err := pub.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	h := RecordHash(unsigned)
	return mldsa44.Verify(&pub, h[:], []byte(RecordContext), sig)
}
