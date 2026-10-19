// Copyright 2025 The go-ethereum Authors
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

//go:build nacl || js || !cgo || gofuzz
// +build nacl js !cgo gofuzz

package crypto

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// badHashes returns digests that are not exactly DigestLength bytes long but
// share their prefix with testmsg.
func badHashes() [][]byte {
	return [][]byte{
		nil,
		testmsg[:DigestLength-1],
		append(common.CopyBytes(testmsg), 0x01),
		append(common.CopyBytes(testmsg), testmsg...),
	}
}

// TestNoCgoSignHashLength checks that Sign rejects digests that are not
// exactly 32 bytes long.
func TestNoCgoSignHashLength(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(testmsg, key); err != nil {
		t.Fatalf("sign with %d byte hash failed: %v", len(testmsg), err)
	}
	for _, hash := range badHashes() {
		if _, err := Sign(hash, key); err == nil {
			t.Errorf("sign accepted %d byte hash", len(hash))
		}
	}
}

// TestNoCgoRecoverHashLength checks that Ecrecover and SigToPub reject
// digests that are not exactly 32 bytes long.
func TestNoCgoRecoverHashLength(t *testing.T) {
	if _, err := Ecrecover(testmsg, testsig); err != nil {
		t.Fatalf("recover with %d byte hash failed: %v", len(testmsg), err)
	}
	for _, hash := range badHashes() {
		if pub, err := Ecrecover(hash, testsig); err == nil {
			t.Errorf("Ecrecover accepted %d byte hash, recovered %x", len(hash), pub)
		}
		if _, err := SigToPub(hash, testsig); err == nil {
			t.Errorf("SigToPub accepted %d byte hash", len(hash))
		}
	}
}

// TestNoCgoVerifyHashLength checks that VerifySignature rejects digests that
// are not exactly 32 bytes long.
func TestNoCgoVerifyHashLength(t *testing.T) {
	sig := testsig[:len(testsig)-1] // remove recovery id
	if !VerifySignature(testpubkey, testmsg, sig) {
		t.Fatalf("can't verify signature with %d byte hash", len(testmsg))
	}
	for _, hash := range badHashes() {
		if VerifySignature(testpubkey, hash, sig) {
			t.Errorf("signature verified with %d byte hash", len(hash))
		}
	}
}
