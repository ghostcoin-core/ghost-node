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

//go:build !(cgo && (ghostrelease || ghostproofs) && (linux || darwin))

package ghostpriv

// rejectAll is the default verifier of a build without the proof verifier.
type rejectAll struct{}

func (rejectAll) VerifyReveal(*VerifyInputs, []byte) error { return ErrNoVerifier }

// DefaultVerifier returns the verifier the node uses until another is set.
// This build does not link the proof verifier of the ghost repository (see
// verifier_cgo.go), so it rejects every reveal.
func DefaultVerifier() Verifier { return rejectAll{} }
