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

package ghostprivtest

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// The stub verifier is a ghostpriv.BundleVerifier too.
var _ ghostpriv.BundleVerifier = Verifier{}

// BundleProof returns the stub root proof of a bundle's binding digest: the
// whole root proof field, ghostpriv.ProofSize bytes, whose first 32 bytes are
// K("ghost/test-proof/v1", binding) and whose other bytes are zero. The
// bundle binding has its own tag, so no reveal's stub proof is a bundle's.
func BundleProof(binding common.Hash) []byte {
	return Proof(binding)
}

// VerifyBundle implements ghostpriv.BundleVerifier: it accepts exactly the
// stub root proof of the binding digest the node computed, a field of
// ghostpriv.ProofSize bytes. It checks nothing else: that each bundled
// reveal's proof is valid is the real root proof's job.
func (Verifier) VerifyBundle(in *ghostpriv.BundleInputs, proof []byte) error {
	if in == nil || len(proof) != ghostpriv.ProofSize {
		return ErrStubProof
	}
	if common.BytesToHash(proof[:32]) != ghosttree.K(TagTestProof, in.Binding[:]) {
		return ErrStubProof
	}
	for _, b := range proof[32:] {
		if b != 0 {
			return ErrStubProof
		}
	}
	return nil
}
