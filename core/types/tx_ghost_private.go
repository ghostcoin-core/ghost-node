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
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The native reveal transaction (docs/private-transactions.md). Its envelope
// is the type byte followed by a payload of fixed layout that is not RLP; it
// has no sender, no nonce and no signature, and its consensus checks are in
// core/ghostpriv.
const (
	// GhostRevealTxType is the type byte of a reveal.
	GhostRevealTxType = 0x50

	// GhostRevealPayloadSize is the length of a reveal's payload.
	GhostRevealPayloadSize = 1_028_490

	// GhostRevealEnvelopeSize is the length of a reveal's envelope, the type
	// byte and the payload.
	GhostRevealEnvelopeSize = 1 + GhostRevealPayloadSize

	// GhostRevealGas is G_PRIV, the gas every reveal takes from the block gas
	// pool.
	GhostRevealGas = 16_569_156
)

var (
	// ErrGhostRevealLength is returned for a reveal whose envelope is not
	// exactly GhostRevealEnvelopeSize bytes.
	ErrGhostRevealLength = errors.New("reveal envelope has the wrong length")

	// ErrNoSender is returned by Sender for a transaction that has no sender
	// account, a reveal.
	ErrNoSender = errors.New("transaction type has no sender")
)

// GhostRevealTx is the payload of a reveal, kept as its exact bytes.
type GhostRevealTx struct {
	Payload []byte
}

// NewGhostRevealTx wraps a reveal envelope, the type byte 0x50 and the
// payload, into a transaction. The envelope is copied. Only its type and
// length are checked here; the fields are checked when a block includes it.
func NewGhostRevealTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostRevealTxType {
		return nil, fmt.Errorf("%w: not a reveal envelope", ErrInvalidTxType)
	}
	inner := new(GhostRevealTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostRevealEnvelope returns a copy of a reveal's envelope, nil for any
// other transaction.
func (tx *Transaction) GhostRevealEnvelope() []byte {
	inner, ok := tx.inner.(*GhostRevealTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostRevealTxType}, inner.Payload...)
}

func (tx *GhostRevealTx) copy() TxData {
	return &GhostRevealTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostRevealTx) txType() byte { return GhostRevealTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostRevealTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostRevealTx) accessList() AccessList { return nil }
func (tx *GhostRevealTx) data() []byte           { return nil }
func (tx *GhostRevealTx) gas() uint64            { return GhostRevealGas }

// The fee of a reveal is a field of its payload, priced from the window's
// base fee; it has no gas price.
func (tx *GhostRevealTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostRevealTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostRevealTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostRevealTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostRevealTx) nonce() uint64       { return 0 }
func (tx *GhostRevealTx) to() *common.Address { return nil }

func (tx *GhostRevealTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostRevealTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a reveal carries no signature.
func (tx *GhostRevealTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostRevealTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

func (tx *GhostRevealTx) decode(input []byte) error {
	if len(input) != GhostRevealPayloadSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrGhostRevealLength, len(input)+1, GhostRevealEnvelopeSize)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x50 || payload).
func (tx *GhostRevealTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostRevealTxType}, tx.Payload)
}

// The native data reveal transaction (docs/data-commitments.md). It is a
// type of its own, 0x51, with the payload size and field offsets of the coin
// reveal, so that a coin reveal and a data reveal can never be taken for each
// other. Like the coin reveal it has no sender, nonce or signature, and its
// consensus checks are in core/ghostpriv.
const (
	// GhostDataRevealTxType is the type byte of a data reveal.
	GhostDataRevealTxType = 0x51

	// GhostDataRevealPayloadSize is the length of a data reveal's payload,
	// that of the coin reveal.
	GhostDataRevealPayloadSize = GhostRevealPayloadSize

	// GhostDataRevealEnvelopeSize is the length of a data reveal's envelope,
	// the type byte and the payload.
	GhostDataRevealEnvelopeSize = 1 + GhostDataRevealPayloadSize

	// GhostDataRevealGas is the gas every data reveal takes from the block
	// gas pool, G_PRIV as for the coin reveal.
	GhostDataRevealGas = GhostRevealGas
)

// IsGhostReveal reports whether tx is a native transaction without an
// account: a coin reveal (0x50) or a data reveal (0x51).
func (tx *Transaction) IsGhostReveal() bool {
	t := tx.Type()
	return t == GhostRevealTxType || t == GhostDataRevealTxType
}

// GhostDataRevealTx is the payload of a data reveal, kept as its exact bytes.
type GhostDataRevealTx struct {
	Payload []byte
}

// NewGhostDataRevealTx wraps a data reveal envelope, the type byte 0x51 and
// the payload, into a transaction. The envelope is copied. Only its type and
// length are checked here; the fields are checked when a block includes it.
func NewGhostDataRevealTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostDataRevealTxType {
		return nil, fmt.Errorf("%w: not a data reveal envelope", ErrInvalidTxType)
	}
	inner := new(GhostDataRevealTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostDataRevealEnvelope returns a copy of a data reveal's envelope, nil for
// any other transaction, a coin reveal included.
func (tx *Transaction) GhostDataRevealEnvelope() []byte {
	inner, ok := tx.inner.(*GhostDataRevealTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostDataRevealTxType}, inner.Payload...)
}

func (tx *GhostDataRevealTx) copy() TxData {
	return &GhostDataRevealTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostDataRevealTx) txType() byte { return GhostDataRevealTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostDataRevealTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostDataRevealTx) accessList() AccessList { return nil }
func (tx *GhostDataRevealTx) data() []byte           { return nil }
func (tx *GhostDataRevealTx) gas() uint64            { return GhostDataRevealGas }

// A data reveal's fee is a field of its payload; it has no gas price.
func (tx *GhostDataRevealTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostDataRevealTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostDataRevealTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostDataRevealTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostDataRevealTx) nonce() uint64       { return 0 }
func (tx *GhostDataRevealTx) to() *common.Address { return nil }

func (tx *GhostDataRevealTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostDataRevealTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a data reveal carries no signature.
func (tx *GhostDataRevealTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostDataRevealTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

func (tx *GhostDataRevealTx) decode(input []byte) error {
	if len(input) != GhostDataRevealPayloadSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrGhostRevealLength, len(input)+1, GhostDataRevealEnvelopeSize)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x51 || payload).
func (tx *GhostDataRevealTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostDataRevealTxType}, tx.Payload)
}
