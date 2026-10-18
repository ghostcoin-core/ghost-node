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

// Package ghostprivtest holds the stub reveal verifier, for tests only. It
// must only ever be imported from _test.go files: a node with it would mint
// for anyone who knows the stub proof format.
//
// A stub proof is the proof field of a reveal whose first 32 bytes are
// K("ghost/test-proof/v1", binding digest) and whose other bytes are zero.
// The stub checks nothing else: membership, the marker's derivation and
// conservation are the real proof's job.
package ghostprivtest

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// TagTestProof is the hash tag of a stub proof.
const TagTestProof = "ghost/test-proof/v1"

// ErrStubProof is returned for a proof that is not the stub proof of the
// binding digest.
var ErrStubProof = errors.New("not the stub proof of the binding digest")

// Proof returns the stub proof of a binding digest: the whole proof field,
// ghostpriv.ProofSize bytes.
func Proof(binding common.Hash) []byte {
	proof := make([]byte, ghostpriv.ProofSize)
	tag := ghosttree.K(TagTestProof, binding[:])
	copy(proof, tag[:])
	return proof
}

// Verifier is the stub verifier: it accepts exactly the stub proof of the
// binding digest the node computed.
type Verifier struct{}

// VerifyReveal implements ghostpriv.Verifier.
func (Verifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	if in == nil || len(proof) != ghostpriv.ProofSize {
		return ErrStubProof
	}
	want := ghosttree.K(TagTestProof, in.Binding[:])
	if common.BytesToHash(proof[:32]) != want {
		return ErrStubProof
	}
	for _, b := range proof[32:] {
		if b != 0 {
			return ErrStubProof
		}
	}
	return nil
}
