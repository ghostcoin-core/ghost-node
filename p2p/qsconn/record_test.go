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
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func TestSignRecord(t *testing.T) {
	key, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := []byte{0xc3, 0x01, 0x02, 0x03}
	sig, err := key.SignRecord(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), SignatureSize)
	}
	if !VerifyRecord(SchemeMLDSA44, key.PublicKey(), unsigned, sig) {
		t.Fatal("record signature does not verify")
	}

	// The signature is over K("ghost/node-record/v1", unsigned), with the
	// record context.
	var pub mldsa44.PublicKey
	if err := pub.UnmarshalBinary(key.PublicKey()); err != nil {
		t.Fatal(err)
	}
	h := keccakTagged("ghost/node-record/v1", unsigned)
	if !mldsa44.Verify(&pub, h[:], []byte("ghost/node-record/v1"), sig) {
		t.Fatal("signature is not over the tagged hash of the record")
	}
	if mldsa44.Verify(&pub, h[:], []byte(HandshakeContext), sig) {
		t.Fatal("record signature verifies as a handshake signature")
	}

	other, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyRecord(SchemeMLDSA44, key.PublicKey(), []byte{0xc3, 0x01, 0x02, 0x04}, sig) {
		t.Fatal("signature verifies over another record")
	}
	if VerifyRecord(SchemeMLDSA44, other.PublicKey(), unsigned, sig) {
		t.Fatal("signature verifies under another key")
	}
	if VerifyRecord(0x0002, key.PublicKey(), unsigned, sig) {
		t.Fatal("signature verifies under an unknown scheme")
	}
	if VerifyRecord(SchemeMLDSA44, key.PublicKey()[1:], unsigned, sig) || VerifyRecord(SchemeMLDSA44, key.PublicKey(), unsigned, sig[1:]) {
		t.Fatal("malformed key or signature verifies")
	}
}
