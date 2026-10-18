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

package ghostpriv

import (
	"errors"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// ErrNoVerifier is the answer of the default verifier to every reveal: the
// node has no proof verifier linked in, so it cannot confirm any proof.
var ErrNoVerifier = errors.New("no reveal proof verifier in this node")

// VerifyInputs are the public inputs of a reveal's proof, as the node
// computes them: never taken from the proof.
type VerifyInputs struct {
	Binding   common.Hash // the binding digest
	ChainID   uint64
	Domain    common.Hash // the genesis block hash
	Root      common.Hash
	Marker    common.Hash
	Remainder common.Hash
	Recipient common.Address
	Out       *uint256.Int
	Fee       *uint256.Int
	Rule      common.Hash // 32 zero bytes, the empty rule
	Note      [NoteSize]byte
}

// Verifier checks the proof of a reveal against the inputs the node computed.
// It returns nil only for a proof it positively accepts; any doubt is an
// error.
type Verifier interface {
	VerifyReveal(in *VerifyInputs, proof []byte) error
}

// rejectAll is the default verifier.
type rejectAll struct{}

func (rejectAll) VerifyReveal(*VerifyInputs, []byte) error { return ErrNoVerifier }

// DefaultVerifier returns the verifier the node uses until another is set:
// it rejects every reveal.
func DefaultVerifier() Verifier { return rejectAll{} }

type verifierBox struct{ v Verifier }

var active atomic.Pointer[verifierBox]

// ActiveVerifier returns the verifier block processing uses.
func ActiveVerifier() Verifier {
	if b := active.Load(); b != nil && b.v != nil {
		return b.v
	}
	return DefaultVerifier()
}

// SetVerifier makes v the verifier block processing uses, nil for the
// default, and returns a function that restores the one before. It is for
// linking the proof system's verifier in at startup and for tests; nothing
// else calls it.
func SetVerifier(v Verifier) (restore func()) {
	prev := active.Swap(&verifierBox{v: v})
	return func() { active.Store(prev) }
}
