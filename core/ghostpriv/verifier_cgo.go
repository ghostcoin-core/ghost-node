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

// The static library is built from ghostverifier/, with no cargo feature, by
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
#include "ghost_data.h"
#include "ghost_hold.h"
#include "ghost_policy.h"
#include "ghost_action.h"
#include "ghost_preimage.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// Lengths of the C interface's buffers.
const (
	ghostChainParamsBytes = C.GHOST_PROOFS_CHAIN_PARAMS_BYTES
	ghostCoinRevealBytes  = C.GHOST_PROOFS_COIN_REVEAL_BYTES
	ghostCoinRevealV2     = C.GHOST_PROOFS_COIN_REVEAL_V2_BYTES
	ghostPolicyReveal     = C.GHOST_POLICY_REVEAL_BYTES
	ghostActionStatement  = C.GHOST_ACTION_STATEMENT_BYTES
	ghostActionProofBytes = C.GHOST_ACTION_PROOF_BYTES
	ghostPreimageContext  = C.GHOST_PREIMAGE_CONTEXT_BYTES
	ghostPreimageBytes    = C.GHOST_PREIMAGE_STATEMENT_BYTES
	ghostPreimageProof    = C.GHOST_PREIMAGE_PROOF_BYTES
	ghostDataRevealBytes  = C.GHOST_DATA_REVEAL_BYTES
	ghostHoldContextBytes = C.GHOST_HOLD_CONTEXT_BYTES
	ghostProofMaxBytes    = C.GHOST_PROOFS_PROOF_MAX_BYTES
)

// The statement checker's lengths in ghost_preimage.h are the node's: the
// context, the statement (address, y and context) and the proof field.
var (
	_ = [1]struct{}{}[ghostPreimageContext-PreimageContextSize]
	_ = [1]struct{}{}[ghostPreimageBytes-(common.AddressLength+common.HashLength+PreimageContextSize)]
	_ = [1]struct{}{}[ghostPreimageProof-ActionProofSize]
)

var (
	// ErrProofStatement is returned, without calling the proof verifier, for
	// a statement it does not verify: anything but an ordinary coin reveal of
	// version 1 or 2, a policy reveal, policy action or statement checker
	// statement (preimage.go) of version 1, or a data reveal or revoke. An
	// ordinary reveal, policy reveal, policy action or statement checker
	// statement of another version is among them, and its error also wraps
	// ErrStatementUnsupported.
	ErrProofStatement = errors.New("reveal proof verifier checks only coin, policy and data reveals, data revokes, policy actions and statement checks")

	// ErrProofRejected is returned for every answer of the proof verifier
	// but acceptance; the error names the status.
	ErrProofRejected = errors.New("reveal proof not accepted")
)

// ghostVerifier is the reveal verifier of the ghost repository's
// ghost-proofs, linked in through C interfaces: ghost_proofs.h for coin
// reveals of both versions, ghostverifier's ghost_policy.h for policy
// reveals, its ghost_action.h for policy actions (KNOW_ACTION_v1), its
// ghost_preimage.h for the statement checker's statement (KNOW_PREIMAGE_v1)
// and its ghost_data.h for data reveals and revokes.
type ghostVerifier struct{}

// VerifiesPreimage implements PreimageVerifier: the linked library has the
// proof system of KNOW_PREIMAGE_v1, so the statement checker at 0x61 asks it.
func (ghostVerifier) VerifiesPreimage() bool { return true }

// DefaultVerifier returns the verifier the node uses until another is set:
// the proof verifier of the ghost repository. It accepts a coin reveal whose
// proof verifies against the inputs and rejects everything else, and so for
// a data reveal or revoke: it accepts one whose proof verifies, with a fee of
// at most the data reserve and the empty rule. A fee above the reserve or a
// non-empty rule is ErrProofRejected, like any other proof that fails.
func DefaultVerifier() Verifier { return ghostVerifier{} }

// VerifyReveal verifies the proof of an ordinary coin reveal (version 1 or
// 2), a policy reveal, a policy action, a statement checker statement, a
// data reveal or a data revoke against the chain parameters and statement it
// builds from in, in the layout of ghost_proofs.h, ghost_policy.h,
// ghost_action.h, ghost_preimage.h or ghost_data.h.
// The chain parameters carry the statement's own version, as its binding
// does. The proof may be followed by zero bytes, as in the proof field. The binding digest is not
// passed: the verifier computes its own from the same fields.
func (ghostVerifier) VerifyReveal(in *VerifyInputs, proof []byte) error {
	if in == nil {
		return fmt.Errorf("%w: no inputs", ErrProofStatement)
	}
	var verify func(params, statement, proof *C.uint8_t, paramsLen, statementLen, proofLen C.size_t) C.int32_t
	var statement []byte
	version := Version
	switch {
	case in.Kind == ghosttree.Coin && in.Purpose == PurposeReveal && in.Version == RevealVersionV1:
		var err error
		if statement, err = ghostCoinStatement(in); err != nil {
			return err
		}
		verify = func(p, s, q *C.uint8_t, pl, sl, ql C.size_t) C.int32_t {
			return C.ghost_verify_coin_reveal(p, pl, s, sl, q, ql)
		}
	case in.Kind == ghosttree.Coin && in.Purpose == PurposeReveal && in.Version == RevealVersion:
		// Statement S1 version 2: no rule, the full 380-byte note.
		statement, version = ghostCoinStatementV2(in), RevealVersion
		verify = func(p, s, q *C.uint8_t, pl, sl, ql C.size_t) C.int32_t {
			return C.ghost_verify_coin_reveal_v2(p, pl, s, sl, q, ql)
		}
	case in.Kind == ghosttree.Coin && in.Purpose == PurposeReveal:
		return fmt.Errorf("%w: %w: ordinary reveal version %d", ErrProofStatement, ErrStatementUnsupported, in.Version)
	case in.Kind == ghosttree.Coin && in.Purpose == PurposePolicySpend && in.Version == PolicyRevealVersion:
		// Statement S4.
		statement, version = ghostPolicyStatement(in), PolicyRevealVersion
		verify = func(p, s, q *C.uint8_t, pl, sl, ql C.size_t) C.int32_t {
			return C.ghost_verify_policy_reveal(p, pl, s, sl, q, ql)
		}
	case in.Kind == ghosttree.Coin && in.Purpose == PurposePolicySpend:
		return fmt.Errorf("%w: %w: policy reveal version %d", ErrProofStatement, ErrStatementUnsupported, in.Version)
	case in.Kind == ghosttree.Coin && in.Purpose == PurposeAction && in.Version == PolicyActionVersion:
		// KNOW_ACTION_v1, whose proof field is ActionProofSize.
		if len(proof) == 0 || len(proof) > ghostActionProofBytes {
			return fmt.Errorf("%w: proof of %d bytes", ErrProofRejected, len(proof))
		}
		statement, version = ghostActionStatementBytes(in), PolicyActionVersion
		verify = func(p, s, q *C.uint8_t, pl, sl, ql C.size_t) C.int32_t {
			return C.ghost_verify_know_action(p, pl, s, sl, q, ql)
		}
	case in.Kind == ghosttree.Coin && in.Purpose == PurposeAction:
		return fmt.Errorf("%w: %w: policy action version %d", ErrProofStatement, ErrStatementUnsupported, in.Version)
	case in.Kind == ghosttree.Coin && in.Purpose == PurposePreimage && in.Version == PreimageVersion:
		// The statement checker's statement (preimage.go), whose proof
		// field is the policy action's, ActionProofSize.
		if len(proof) == 0 || len(proof) > ghostPreimageProof {
			return fmt.Errorf("%w: proof of %d bytes", ErrProofRejected, len(proof))
		}
		statement, version = ghostPreimageStatementBytes(in), PreimageVersion
		verify = func(p, s, q *C.uint8_t, pl, sl, ql C.size_t) C.int32_t {
			return C.ghost_verify_know_preimage(p, pl, s, sl, q, ql)
		}
	case in.Kind == ghosttree.Coin && in.Purpose == PurposePreimage:
		return fmt.Errorf("%w: %w: statement checker statement version %d", ErrProofStatement, ErrStatementUnsupported, in.Version)
	case in.Kind == ghosttree.Data && (in.Purpose == PurposeReveal || in.Purpose == PurposeRevoke):
		statement = ghostDataStatement(in)
		verify = func(p, s, q *C.uint8_t, pl, sl, ql C.size_t) C.int32_t {
			return C.ghost_verify_data_reveal(p, pl, s, sl, q, ql)
		}
	default:
		return fmt.Errorf("%w: kind %d, purpose %#x", ErrProofStatement, in.Kind, in.Purpose)
	}
	if len(proof) == 0 || len(proof) > ghostProofMaxBytes {
		return fmt.Errorf("%w: proof of %d bytes", ErrProofRejected, len(proof))
	}
	params := ghostChainParamsVersion(in, version)
	status := verify(
		(*C.uint8_t)(unsafe.Pointer(&params[0])),
		(*C.uint8_t)(unsafe.Pointer(&statement[0])),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])),
		C.size_t(len(params)), C.size_t(len(statement)), C.size_t(len(proof)),
	)
	switch status {
	case C.GHOST_PROOFS_ACCEPTED:
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrProofRejected, ghostStatusName(status))
	}
}

// VerifyHold verifies a proof of holding of a data commitment against the
// inputs with the shipped verifier of the ghost repository's ghost-proofs,
// through ghostverifier's ghost_hold.h. The proof may be followed by zero
// bytes. It checks the proof only: that the challenge was issued once and the
// roots are current is the caller's. Any answer but acceptance is
// ErrProofRejected, naming the status.
func VerifyHold(in *HoldInputs, proof []byte) error {
	if in == nil {
		return fmt.Errorf("%w: no inputs", ErrProofStatement)
	}
	if len(proof) == 0 || len(proof) > ghostProofMaxBytes {
		return fmt.Errorf("%w: proof of %d bytes", ErrProofRejected, len(proof))
	}
	params := ghostChainParams(&VerifyInputs{ChainID: in.ChainID, Domain: in.Domain})
	ctx := ghostHoldContext(in)
	status := C.ghost_verify_hold(
		(*C.uint8_t)(unsafe.Pointer(&params[0])), C.size_t(len(params)),
		(*C.uint8_t)(unsafe.Pointer(&ctx[0])), C.size_t(len(ctx)),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])), C.size_t(len(proof)),
	)
	if status == C.GHOST_PROOFS_ACCEPTED {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrProofRejected, ghostStatusName(status))
}

// ghostHoldContext returns the proof of holding context of ghost_hold.h: the
// type DATA_V2 (2), the root, the marker-set root, the verifier, the
// challenge and cf (32 each).
func ghostHoldContext(in *HoldInputs) []byte {
	b := make([]byte, 0, ghostHoldContextBytes)
	b = append(b, C.GHOST_HOLD_TYPE_DATA_V2_0, C.GHOST_HOLD_TYPE_DATA_V2_1)
	b = append(b, in.Root[:]...)
	b = append(b, in.MarkerSetRoot[:]...)
	b = append(b, in.Verifier[:]...)
	b = append(b, in.Challenge[:]...)
	return append(b, in.Cf[:]...)
}

// ghostChainParams returns the chain parameters: the chain id (8 bytes, big
// endian), the version (2) and the domain, the genesis hash (32).
func ghostChainParams(in *VerifyInputs) []byte { return ghostChainParamsVersion(in, Version) }

// ghostChainParamsVersion returns the chain parameters with the given
// version in place of Version: a version 2 ordinary reveal binds version 2.
func ghostChainParamsVersion(in *VerifyInputs, version uint16) []byte {
	b := make([]byte, 0, ghostChainParamsBytes)
	b = binary.BigEndian.AppendUint64(b, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, version)
	return append(b, in.Domain[:]...)
}

// ghostActionStatementBytes returns the KNOW_ACTION_v1 statement of
// ghost_action.h, of GHOST_ACTION_STATEMENT_BYTES: the slot's policy address
// (20), the marker (32), the action nonce (8, big endian), the slot's action
// tag and salt (32 each), the expected remaining and the debit as 32-byte
// amount words, the expiry (8, big endian) and the calldata hash (32), the
// order of the binding. A nil amount is zero.
func ghostActionStatementBytes(in *VerifyInputs) []byte {
	b := make([]byte, 0, ghostActionStatement)
	b = append(b, in.Policy[:]...)
	b = append(b, in.Marker[:]...)
	b = binary.BigEndian.AppendUint64(b, in.ActionNonce)
	b = append(b, in.ActionTag[:]...)
	b = append(b, in.ActionSalt[:]...)
	b = append(b, amountWord(amountOrZero(in.ExpectedRemaining))...)
	b = append(b, amountWord(amountOrZero(in.Debit))...)
	b = binary.BigEndian.AppendUint64(b, in.Expiry)
	return append(b, in.CalldataHash[:]...)
}

// ghostPreimageStatementBytes returns the KNOW_PREIMAGE_v1 statement of
// ghost_preimage.h, of GHOST_PREIMAGE_STATEMENT_BYTES: the calling policy's
// address (20), y (32) and the context (64), the order of the binding.
func ghostPreimageStatementBytes(in *VerifyInputs) []byte {
	b := make([]byte, 0, ghostPreimageBytes)
	b = append(b, in.Policy[:]...)
	b = append(b, in.Y[:]...)
	return append(b, in.Context[:]...)
}

// ghostCoinStatementV2 returns the version 2 coin reveal statement of
// ghost_proofs.h, of GHOST_PROOFS_COIN_REVEAL_V2_BYTES: the root, marker and
// remainder (32 each), the remainder's note (380), the recipient (20) and out
// and fee as 32-byte amount words. There is no rule. A nil amount is zero.
func ghostCoinStatementV2(in *VerifyInputs) []byte {
	b := make([]byte, 0, ghostCoinRevealV2)
	b = append(b, in.Root[:]...)
	b = append(b, in.Marker[:]...)
	b = append(b, in.Remainder[:]...)
	b = append(b, in.Note[:]...)
	b = append(b, in.Recipient[:]...)
	b = append(b, amountWord(amountOrZero(in.Out))...)
	return append(b, amountWord(amountOrZero(in.Fee))...)
}

// ghostPolicyStatement returns the policy reveal statement of ghost_policy.h,
// of GHOST_POLICY_REVEAL_BYTES: the root, marker and remainder (32 each), out
// and fee as 32-byte amount words, the policy address (20), its code hash,
// the parameters hash, the action tag, the action salt and the instruction
// (32 each) and the remainder note (380), the order of the binding.
func ghostPolicyStatement(in *VerifyInputs) []byte {
	b := make([]byte, 0, ghostPolicyReveal)
	b = append(b, in.Root[:]...)
	b = append(b, in.Marker[:]...)
	b = append(b, in.Remainder[:]...)
	b = append(b, amountWord(amountOrZero(in.Out))...)
	b = append(b, amountWord(amountOrZero(in.Fee))...)
	b = append(b, in.Policy[:]...)
	b = append(b, in.PolicyCodeHash[:]...)
	b = append(b, in.ParamsHash[:]...)
	b = append(b, in.ActionTag[:]...)
	b = append(b, in.ActionSalt[:]...)
	b = append(b, in.Instr[:]...)
	return append(b, in.Note[:]...)
}

// ghostCoinStatement returns the version 1 coin reveal statement of
// ghost_proofs.h, of GHOST_PROOFS_COIN_REVEAL_BYTES: the root, marker and
// remainder (32 each), the remainder's note (156), the recipient (20), out
// and fee as 32-byte amount words and the rule (32). A nil amount is zero.
// A note with a non-zero byte past RevealNoteSize is no version 1 note and
// is ErrProofStatement, as is a statement of any other length: no other
// statement ever reaches the library.
func ghostCoinStatement(in *VerifyInputs) ([]byte, error) {
	for _, b := range in.Note[RevealNoteSize:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: version 1 reveal note longer than %d bytes", ErrProofStatement, RevealNoteSize)
		}
	}
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
	b = append(b, in.Note[:RevealNoteSize]...)
	b = append(b, in.Recipient[:]...)
	b = append(b, amountWord(out)...)
	b = append(b, amountWord(fee)...)
	b = append(b, in.Rule[:]...)
	if len(b) != ghostCoinRevealBytes {
		return nil, fmt.Errorf("%w: coin reveal statement of %d bytes, the verifier takes %d", ErrProofStatement, len(b), ghostCoinRevealBytes)
	}
	return b, nil
}

// ghostDataStatement returns the data reveal statement: the purpose (1) in
// the codes of ghost_data.h, which differ from the node's, the root and marker
// (32 each), the party, which is the verifier-or-recipient address left-padded
// with zeros to 32 bytes, the fee as a 32-byte amount word, the rule (32) and
// the content fingerprint cf (32). A nil fee is zero. The caller passes only PurposeReveal or PurposeRevoke.
func ghostDataStatement(in *VerifyInputs) []byte {
	fee := in.Fee
	if fee == nil {
		fee = new(uint256.Int)
	}
	purpose := byte(C.GHOST_DATA_PURPOSE_REVEAL)
	if in.Purpose == PurposeRevoke {
		purpose = C.GHOST_DATA_PURPOSE_REVOKE
	}
	party := common.BytesToHash(in.Recipient[:])
	b := make([]byte, 0, ghostDataRevealBytes)
	b = append(b, purpose)
	b = append(b, in.Root[:]...)
	b = append(b, in.Marker[:]...)
	b = append(b, party[:]...)
	b = append(b, amountWord(fee)...)
	b = append(b, in.Rule[:]...)
	return append(b, in.Cf[:]...)
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
