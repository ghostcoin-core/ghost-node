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

package vm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The precompiles of spec 09, section 7 (docs/ghost-evm-profile.md): the
// elliptic-curve precompiles are removed, and a quantum-safe signature-verify
// precompile takes their place.

// SignatureVerifyAddress is the address of the signature-verify precompile.
var SignatureVerifyAddress = common.BytesToAddress([]byte{0x51})

// SignatureVerifyTxContextPrefix starts every context string reserved for the
// signatures of transactions. The precompile refuses such a context, so that
// no contract can be shown a transaction signature as a valid message
// signature.
const SignatureVerifyTxContextPrefix = "ghost/tx/"

var (
	// ErrPrecompileRemoved is returned by every call to a removed precompile.
	ErrPrecompileRemoved = errors.New("precompile removed")

	// ErrSignatureVerifyScheme is returned for a scheme the node does not
	// know or does not accept.
	ErrSignatureVerifyScheme = errors.New("signature verify: scheme not accepted")

	// ErrSignatureVerifyShort is returned for an input shorter than its
	// header, context, public key and signature.
	ErrSignatureVerifyShort = errors.New("signature verify: input too short")

	// ErrSignatureVerifyContext is returned for a context reserved for
	// transaction signatures.
	ErrSignatureVerifyContext = errors.New("signature verify: context reserved for transactions")
)

var (
	signatureValid   = common.LeftPadBytes([]byte{1}, 32)
	signatureInvalid = make([]byte, 32)
)

// removedPrecompile is a precompile Ghost removes. It costs nothing and its
// Run always fails, so a call to it fails and uses all the gas given to it,
// and the value it was sent goes back. It stays in the precompile map, so its
// address stays warm.
type removedPrecompile struct {
	name string
}

func (c *removedPrecompile) RequiredGas(input []byte) uint64 {
	return 0
}

func (c *removedPrecompile) Run(input []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s", ErrPrecompileRemoved, c.name)
}

// signatureVerify is the signature-verify precompile. Its input is
//
//	scheme (2 bytes, big-endian) || ctx_len (1 byte) || ctx || public_key || signature || message
//
// where the public key and the signature have the exact lengths of the
// scheme and the message is the rest. It returns 32 bytes, 1 for a valid
// signature and 0 for an invalid one. It fails for a scheme that is not
// accepted, an input too short for the scheme and a context that begins with
// "ghost/tx/". The gas, charged before verifying, is the scheme's
// verification gas plus ghost.SigVerifyWordGas for each 32-byte word of the
// message.
//
// The schemes and their gas are those of the account transaction: a scheme
// is accepted when ghost.AccountTxVerifyGas gives it gas, and its lengths are
// those of core/types.
type signatureVerify struct{}

// signatureVerifyCall is a parsed input of the signature-verify precompile.
type signatureVerifyCall struct {
	scheme                                 uint16
	context, publicKey, signature, message []byte
}

// signatureVerifySizes returns the public key and signature lengths of an
// accepted scheme, and false for any other scheme.
func signatureVerifySizes(scheme uint16) (publicKey, signature int, ok bool) {
	// The rescue-key schemes 0x0003 and 0x0004 have the verification gas of
	// their base schemes, but they are account transaction schemes only
	// (spec 09, section 5.1): the precompile never accepts them.
	if scheme == types.GhostSchemeMLDSA44Rescue || scheme == types.GhostSchemeSLHDSARescue {
		return 0, 0, false
	}
	if ghost.AccountTxVerifyGas(scheme) == 0 {
		return 0, 0, false
	}
	switch scheme {
	case types.GhostSchemeMLDSA44:
		return types.GhostMLDSA44PublicKeySize, types.GhostMLDSA44SignatureSize, true
	}
	return 0, 0, false
}

func parseSignatureVerify(input []byte) (*signatureVerifyCall, error) {
	const header = 3
	if len(input) < header {
		return nil, ErrSignatureVerifyShort
	}
	scheme := binary.BigEndian.Uint16(input[:2])
	pkSize, sigSize, ok := signatureVerifySizes(scheme)
	if !ok {
		return nil, fmt.Errorf("%w: %#04x", ErrSignatureVerifyScheme, scheme)
	}
	ctxEnd := header + int(input[2])
	pkEnd := ctxEnd + pkSize
	sigEnd := pkEnd + sigSize
	if len(input) < sigEnd {
		return nil, ErrSignatureVerifyShort
	}
	call := &signatureVerifyCall{
		scheme:    scheme,
		context:   input[header:ctxEnd],
		publicKey: input[ctxEnd:pkEnd],
		signature: input[pkEnd:sigEnd],
		message:   input[sigEnd:],
	}
	if bytes.HasPrefix(call.context, []byte(SignatureVerifyTxContextPrefix)) {
		return nil, ErrSignatureVerifyContext
	}
	return call, nil
}

// RequiredGas returns the verification gas of the scheme and the gas of the
// message's words, and nothing for an input that fails: Run then fails and
// the call uses all its gas.
func (c *signatureVerify) RequiredGas(input []byte) uint64 {
	call, err := parseSignatureVerify(input)
	if err != nil {
		return 0
	}
	words := (uint64(len(call.message)) + 31) / 32
	return ghost.AccountTxVerifyGas(call.scheme) + words*ghost.SigVerifyWordGas
}

func (c *signatureVerify) Run(input []byte) ([]byte, error) {
	call, err := parseSignatureVerify(input)
	if err != nil {
		return nil, err
	}
	switch call.scheme {
	case types.GhostSchemeMLDSA44:
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(call.publicKey); err != nil {
			return common.CopyBytes(signatureInvalid), nil
		}
		if mldsa44.Verify(&pk, call.message, call.context, call.signature) {
			return common.CopyBytes(signatureValid), nil
		}
		return common.CopyBytes(signatureInvalid), nil
	}
	// signatureVerifySizes accepts no other scheme.
	return nil, fmt.Errorf("%w: %#04x", ErrSignatureVerifyScheme, call.scheme)
}
