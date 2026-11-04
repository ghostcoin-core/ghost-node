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

// The native policy reveal transaction (docs/private-transactions.md, spec
// 10, section 5): it spends a coin into an escrow slot of a frozen policy. A
// type of its own, 0x53, of fixed layout that is not RLP. Like the other
// reveals it has no sender, nonce or signature, and its consensus checks are
// in core/ghostpriv.
const (
	// GhostPolicyRevealTxType is the type byte of a policy reveal.
	GhostPolicyRevealTxType = 0x53

	// GhostPolicyRevealPayloadSize is the length of a policy reveal's
	// payload.
	GhostPolicyRevealPayloadSize = 1_311_450

	// GhostPolicyRevealEnvelopeSize is the length of a policy reveal's
	// envelope, the type byte and the payload.
	GhostPolicyRevealEnvelopeSize = 1 + GhostPolicyRevealPayloadSize

	// GhostPolicyRevealGas is G_POLICY, the gas every policy reveal takes
	// from the block gas pool: 16 per envelope byte, 21,000, the verification
	// charge of 440,000 and the slot opening of 160,000 (spec 10, section
	// 10).
	GhostPolicyRevealGas = 21_604_216
)

// GhostPolicyRevealTx is the payload of a policy reveal, kept as its exact
// bytes.
type GhostPolicyRevealTx struct {
	Payload []byte
}

// NewGhostPolicyRevealTx wraps a policy reveal envelope, the type byte 0x53
// and the payload, into a transaction. The envelope is copied. Only its type
// and length are checked here; the fields are checked when a block includes
// it.
func NewGhostPolicyRevealTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostPolicyRevealTxType {
		return nil, fmt.Errorf("%w: not a policy reveal envelope", ErrInvalidTxType)
	}
	inner := new(GhostPolicyRevealTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostPolicyRevealEnvelope returns a copy of a policy reveal's envelope, nil
// for any other transaction.
func (tx *Transaction) GhostPolicyRevealEnvelope() []byte {
	inner, ok := tx.inner.(*GhostPolicyRevealTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostPolicyRevealTxType}, inner.Payload...)
}

func (tx *GhostPolicyRevealTx) copy() TxData {
	return &GhostPolicyRevealTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostPolicyRevealTx) txType() byte { return GhostPolicyRevealTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostPolicyRevealTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostPolicyRevealTx) accessList() AccessList { return nil }
func (tx *GhostPolicyRevealTx) data() []byte           { return nil }
func (tx *GhostPolicyRevealTx) gas() uint64            { return GhostPolicyRevealGas }

// A policy reveal's fee is a field of its payload; it has no gas price.
func (tx *GhostPolicyRevealTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostPolicyRevealTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostPolicyRevealTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostPolicyRevealTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostPolicyRevealTx) nonce() uint64       { return 0 }
func (tx *GhostPolicyRevealTx) to() *common.Address { return nil }

func (tx *GhostPolicyRevealTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostPolicyRevealTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a policy reveal carries no signature.
func (tx *GhostPolicyRevealTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostPolicyRevealTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

func (tx *GhostPolicyRevealTx) decode(input []byte) error {
	if len(input) != GhostPolicyRevealPayloadSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrGhostRevealLength, len(input)+1, GhostPolicyRevealEnvelopeSize)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x53 || payload).
func (tx *GhostPolicyRevealTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostPolicyRevealTxType}, tx.Payload)
}
