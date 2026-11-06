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

// The direct reveal transaction: an ordinary reveal whose proof field is
// large enough for a reveal proof at 96 queries, so that one reveal can be
// verified natively on its own, without a bundle root. A type of its own,
// 0x58, of fixed layout that is not RLP: the field offsets of the version 2
// coin reveal with version 3 and the larger proof field.
//
//	version (2, 0x0003) | chain id (8) | marker (32) | root (32) | remainder (32) |
//	recipient (20) | out (32) | fee (32) | proof (2,331,648) | note (380)
//
// Like the other reveals it has no sender, nonce or signature. Its envelope
// decodes and encodes, but no consensus rule takes it yet: CheckTxType
// refuses it, so a block that includes one is invalid and no pool takes it,
// until its checks are in core/ghostpriv.
const (
	// GhostDirectRevealTxType is the type byte of a direct reveal.
	GhostDirectRevealTxType = 0x58

	// GhostDirectRevealVersion is the version field of a direct reveal, the
	// version after the version 2 coin reveal.
	GhostDirectRevealVersion = 3

	// GhostDirectRevealHeadSize is the length of the fields before the proof:
	// the version, the chain id, the marker, the root, the remainder, the
	// recipient, out and the fee, those of the version 2 coin reveal.
	GhostDirectRevealHeadSize = 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32

	// GhostDirectRevealProofFloor is the least length the proof field may
	// have: a reveal proof at 96 queries, as modeled.
	GhostDirectRevealProofFloor = 2_330_908

	// GhostDirectRevealProofSize is the length of the proof field: the
	// serialized proof followed by zeros. It is the floor rounded up to a
	// multiple of 1,024 bytes, ceil(2,330,908 / 1,024) * 1,024. Once the
	// prover's real proof length is recorded it becomes ceil(length / 1,024)
	// * 1,024, never below GhostDirectRevealProofFloor.
	GhostDirectRevealProofSize = 2_331_648

	// GhostDirectRevealNoteSize is the length of the remainder note, that of
	// the version 2 coin reveal.
	GhostDirectRevealNoteSize = 380

	// GhostDirectRevealPayloadSize is the length of a direct reveal's
	// payload.
	GhostDirectRevealPayloadSize = GhostDirectRevealHeadSize + GhostDirectRevealProofSize + GhostDirectRevealNoteSize

	// GhostDirectRevealEnvelopeSize is the length of a direct reveal's
	// envelope, the type byte and the payload.
	GhostDirectRevealEnvelopeSize = 1 + GhostDirectRevealPayloadSize

	// GhostDirectRevealGas is the gas a direct reveal takes from the block
	// gas pool, by the rule of G_PRIV for its envelope: 16 per envelope
	// byte, 21,000 and the verification charge of 370,000.
	GhostDirectRevealGas = 16*GhostDirectRevealEnvelopeSize + 21_000 + 370_000
)

// The proof field is never below the floor: a field shorter than a 96-query
// reveal proof does not compile.
const _ uint64 = GhostDirectRevealProofSize - GhostDirectRevealProofFloor

var (
	// ErrGhostDirectRevealLength is returned for a direct reveal whose
	// envelope is not GhostDirectRevealEnvelopeSize bytes.
	ErrGhostDirectRevealLength = errors.New("direct reveal envelope has the wrong length")

	// ErrGhostDirectRevealVersion is returned for a direct reveal whose
	// version field is not GhostDirectRevealVersion.
	ErrGhostDirectRevealVersion = errors.New("direct reveal version is not 3")
)

// GhostDirectRevealTx is the payload of a direct reveal, kept as its exact
// bytes.
type GhostDirectRevealTx struct {
	Payload []byte
}

// NewGhostDirectRevealTx wraps a direct reveal envelope, the type byte 0x58
// and the payload, into a transaction. The envelope is copied. Its type, its
// length and its version are checked here; the other fields are left to the
// chain rules.
func NewGhostDirectRevealTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostDirectRevealTxType {
		return nil, fmt.Errorf("%w: not a direct reveal envelope", ErrInvalidTxType)
	}
	inner := new(GhostDirectRevealTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostDirectRevealEnvelope returns a copy of a direct reveal's envelope, nil
// for any other transaction, a coin reveal included.
func (tx *Transaction) GhostDirectRevealEnvelope() []byte {
	inner, ok := tx.inner.(*GhostDirectRevealTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostDirectRevealTxType}, inner.Payload...)
}

// GhostDirectRevealProof returns a copy of a direct reveal's proof field, the
// GhostDirectRevealProofSize bytes after the head, nil for any other
// transaction.
func (tx *Transaction) GhostDirectRevealProof() []byte {
	inner, ok := tx.inner.(*GhostDirectRevealTx)
	if !ok || len(inner.Payload) != GhostDirectRevealPayloadSize {
		return nil
	}
	return common.CopyBytes(inner.Payload[GhostDirectRevealHeadSize : GhostDirectRevealHeadSize+GhostDirectRevealProofSize])
}

func (tx *GhostDirectRevealTx) copy() TxData {
	return &GhostDirectRevealTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostDirectRevealTx) txType() byte { return GhostDirectRevealTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostDirectRevealTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostDirectRevealTx) accessList() AccessList { return nil }
func (tx *GhostDirectRevealTx) data() []byte           { return nil }
func (tx *GhostDirectRevealTx) gas() uint64            { return GhostDirectRevealGas }

// The fee of a direct reveal is a field of its payload; it has no gas price.
func (tx *GhostDirectRevealTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostDirectRevealTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostDirectRevealTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostDirectRevealTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostDirectRevealTx) nonce() uint64       { return 0 }
func (tx *GhostDirectRevealTx) to() *common.Address { return nil }

func (tx *GhostDirectRevealTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostDirectRevealTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a direct reveal carries no signature.
func (tx *GhostDirectRevealTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostDirectRevealTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

// decode takes a payload of exactly GhostDirectRevealPayloadSize bytes whose
// version field is GhostDirectRevealVersion. Nothing is repaired.
func (tx *GhostDirectRevealTx) decode(input []byte) error {
	if len(input) != GhostDirectRevealPayloadSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrGhostDirectRevealLength, len(input)+1, GhostDirectRevealEnvelopeSize)
	}
	if v := binary.BigEndian.Uint16(input[:2]); v != GhostDirectRevealVersion {
		return fmt.Errorf("%w: version %d", ErrGhostDirectRevealVersion, v)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x58 || payload).
func (tx *GhostDirectRevealTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostDirectRevealTxType}, tx.Payload)
}
