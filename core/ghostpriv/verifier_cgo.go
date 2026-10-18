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

//go:build cgo && (ghostrelease || ghostproofs) && (linux || darwin)

package ghostpriv

// The static library is built from ghostverifier/ by
// `go run build/ci.go ghostverifier`, which `build/ci.go install` runs first.
//
// A release build (ghostrelease) names only the library: cgo records its
// linker flags in the compiled package, so a search path holding the
// checkout's directory would make the executable depend on where it was
// built. `build/ci.go install` gives the C linker the directory through
// LIBRARY_PATH instead. Other builds, such as tests with the ghostproofs tag,
// find it in the checkout.

/*
#cgo CFLAGS: -I${SRCDIR}/../../ghostverifier
#cgo !ghostrelease LDFLAGS: -L${SRCDIR}/../../build/cache/ghostverifier/release
#cgo LDFLAGS: -lghostverifier
#cgo linux LDFLAGS: -lm -ldl -lpthread
#cgo darwin LDFLAGS: -lm
#include "ghost_proofs.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// Lengths of the C interface's buffers.
const (
	ghostChainParamsBytes = C.GHOST_PROOFS_CHAIN_PARAMS_BYTES
	ghostCoinRevealBytes  = C.GHOST_PROOFS_COIN_REVEAL_BYTES
	ghostProofMaxBytes    = C.GHOST_PROOFS_PROOF_MAX_BYTES
)

var (
	// ErrProofStatement is returned, without calling the proof verifier, for
	// a statement it does not verify: anything but a coin reveal, which
	// includes every data reveal.
	ErrProofStatement = errors.New("reveal proof verifier checks only coin reveals")

	// ErrProofRejected is returned for every answer of the proof verifier
	// but acceptance; the error names the status.
	ErrProofRejected = errors.New("reveal proof not accepted")
)

// ghostVerifier is the coin reveal verifier of the ghost repository's
// ghost-proofs, linked in through its C interface.
type ghostVerifier struct{}

// DefaultVerifier returns the verifier the node uses until another is set:
// the proof verifier of the ghost repository. It accepts a coin reveal whose
// proof verifies against the inputs and rejects everything else, every data
// reveal included.
func DefaultVerifier() Verifier { return ghostVerifier{} }

// VerifyReveal verifies the proof of a coin reveal against the chain
// parameters and statement it builds from in, in the layout of
// ghost_proofs.h. The proof may be followed by zero bytes, as in the
// reveal's proof field. The binding digest is not passed: the verifier
// computes its own from the same fields.
func (ghostVerifier) VerifyReveal(in *VerifyInputs, proof []byte) error {
	if in == nil {
		return fmt.Errorf("%w: no inputs", ErrProofStatement)
	}
	if in.Kind != ghosttree.Coin || in.Purpose != PurposeReveal {
		return fmt.Errorf("%w: kind %d, purpose %#x", ErrProofStatement, in.Kind, in.Purpose)
	}
	if len(proof) == 0 || len(proof) > ghostProofMaxBytes {
		return fmt.Errorf("%w: proof of %d bytes", ErrProofRejected, len(proof))
	}
	params := ghostChainParams(in)
	statement := ghostCoinStatement(in)
	status := C.ghost_verify_coin_reveal(
		(*C.uint8_t)(unsafe.Pointer(&params[0])), C.size_t(len(params)),
		(*C.uint8_t)(unsafe.Pointer(&statement[0])), C.size_t(len(statement)),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])), C.size_t(len(proof)),
	)
	if status != C.GHOST_PROOFS_ACCEPTED {
		return fmt.Errorf("%w: %s", ErrProofRejected, ghostStatusName(status))
	}
	return nil
}

// ghostChainParams returns the chain parameters: the chain id (8 bytes, big
// endian), the version (2) and the domain, the genesis hash (32).
func ghostChainParams(in *VerifyInputs) []byte {
	b := make([]byte, 0, ghostChainParamsBytes)
	b = binary.BigEndian.AppendUint64(b, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, Version)
	return append(b, in.Domain[:]...)
}

// ghostCoinStatement returns the coin reveal statement: the root, marker and
// remainder (32 each), the remainder's note (156), the recipient (20), out
// and fee as 32-byte amount words and the rule (32). A nil amount is zero.
func ghostCoinStatement(in *VerifyInputs) []byte {
	out, fee := in.Out, in.Fee
	if out == nil {
		out = new(uint256.Int)
	}
	if fee == nil {
		fee = new(uint256.Int)
	}
	b := make([]byte, 0, ghostCoinRevealBytes)
	b = append(b, in.Root[:]...)
	b = append(b, in.Marker[:]...)
	b = append(b, in.Remainder[:]...)
	b = append(b, in.Note[:]...)
	b = append(b, in.Recipient[:]...)
	b = append(b, amountWord(out)...)
	b = append(b, amountWord(fee)...)
	return append(b, in.Rule[:]...)
}

func ghostStatusName(status C.int32_t) string {
	switch status {
	case C.GHOST_PROOFS_REJECTED:
		return "rejected"
	case C.GHOST_PROOFS_MALFORMED_INPUT:
		return "malformed input"
	case C.GHOST_PROOFS_BAD_ARGUMENT:
		return "bad argument"
	case C.GHOST_PROOFS_PANICKED:
		return "verifier panicked"
	default:
		return fmt.Sprintf("unknown status %d", int32(status))
	}
}
