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

package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The native policy action transaction (spec 10, section 8): it debits an
// open escrow slot by an exact amount against a proof of the slot's action
// key, and calls the slot's policy with its calldata from ACTION_CALLER. A
// type of its own, 0x54, of fixed layout that is not RLP. Like the reveals it
// has no sender, nonce or signature (IsGhostReveal covers it); its checks are
// in core/ghostpriv and its execution in core.
const (
	// GhostPolicyActionTxType is the type byte of a policy action.
	GhostPolicyActionTxType = 0x54

	// GhostPolicyActionPayloadSize is the length of a policy action's
	// payload.
	GhostPolicyActionPayloadSize = 949_372

	// GhostPolicyActionEnvelopeSize is the length of a policy action's
	// envelope, the type byte and the payload.
	GhostPolicyActionEnvelopeSize = 1 + GhostPolicyActionPayloadSize

	// GhostPolicyActionGas is G_ACTION, the gas every policy action takes
	// from the block gas pool, whatever its call uses: 16 per envelope byte,
	// 21,000 and the fixed action charge of 695,000, which holds the proof
	// verification, the policy call's ACTION_CALL_GAS of 250,000 and the
	// slot debit with its result log. Nothing of it is refunded.
	GhostPolicyActionGas = 15_905_968
)

// GhostPolicyActionTx is the payload of a policy action, kept as its exact
// bytes.
type GhostPolicyActionTx struct {
	Payload []byte
}

// NewGhostPolicyActionTx wraps a policy action envelope, the type byte 0x54
// and the payload, into a transaction. The envelope is copied. Only its type
// and length are checked here; the fields are checked when a block includes
// it.
func NewGhostPolicyActionTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostPolicyActionTxType {
		return nil, fmt.Errorf("%w: not a policy action envelope", ErrInvalidTxType)
	}
	inner := new(GhostPolicyActionTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostPolicyActionEnvelope returns a copy of a policy action's envelope, nil
// for any other transaction.
func (tx *Transaction) GhostPolicyActionEnvelope() []byte {
	inner, ok := tx.inner.(*GhostPolicyActionTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostPolicyActionTxType}, inner.Payload...)
}

func (tx *GhostPolicyActionTx) copy() TxData {
	return &GhostPolicyActionTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostPolicyActionTx) txType() byte { return GhostPolicyActionTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostPolicyActionTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostPolicyActionTx) accessList() AccessList { return nil }
func (tx *GhostPolicyActionTx) data() []byte           { return nil }
func (tx *GhostPolicyActionTx) gas() uint64            { return GhostPolicyActionGas }

// A policy action pays with its debit, a field of its payload; it has no gas
// price.
func (tx *GhostPolicyActionTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostPolicyActionTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostPolicyActionTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostPolicyActionTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostPolicyActionTx) nonce() uint64       { return 0 }
func (tx *GhostPolicyActionTx) to() *common.Address { return nil }

func (tx *GhostPolicyActionTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostPolicyActionTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a policy action carries no signature.
func (tx *GhostPolicyActionTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostPolicyActionTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

func (tx *GhostPolicyActionTx) decode(input []byte) error {
	if len(input) != GhostPolicyActionPayloadSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrGhostRevealLength, len(input)+1, GhostPolicyActionEnvelopeSize)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x54 || payload).
func (tx *GhostPolicyActionTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostPolicyActionTxType}, tx.Payload)
}
