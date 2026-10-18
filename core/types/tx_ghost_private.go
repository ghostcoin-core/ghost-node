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
