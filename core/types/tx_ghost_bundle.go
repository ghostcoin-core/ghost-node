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

// The native private bundle transaction: one root proof that stands in for
// the proofs of up to GhostBundleMaxReveals version 2 ordinary reveals, each
// carried without its proof field. A type of its own, 0x55, of fixed layout
// that is not RLP:
//
//	version (2) | chain id (8) | count (2) | root proof (1,310,720) | count bodies of 570 bytes
//
// Like the reveals it has no sender, nonce or signature, and its consensus
// checks are in core/ghostpriv. It is not a member of IsGhostReveal: no pool,
// miner or RPC path takes it; a block processor applies it beside the
// reveals.
const (
	// GhostBundleTxType is the type byte of a bundle.
	GhostBundleTxType = 0x55

	// GhostBundleHeaderSize is the length of the fields before the root
	// proof: the version, the chain id and the count.
	GhostBundleHeaderSize = 2 + 8 + 2

	// GhostBundleProofSize is the length of the root proof field, the proof
	// field of a reveal: the serialized proof followed by zeros.
	GhostBundleProofSize = 1_310_720

	// GhostBundleBodySize is the length of one bundled reveal: a version 2
	// reveal payload without its proof field, its first 190 bytes and its
	// 380-byte note.
	GhostBundleBodySize = 570

	// GhostBundleMaxReveals is the largest count of a bundle, 44 batches of
	// 32 reveals.
	GhostBundleMaxReveals = 44 * 32

	// GhostBundleFixedSize is the length of a bundle's payload without its
	// bodies; the payload is GhostBundleFixedSize + 570 * count bytes.
	GhostBundleFixedSize = GhostBundleHeaderSize + GhostBundleProofSize
)

// ErrGhostBundleLength is returned for a bundle whose payload is not
// GhostBundleFixedSize + 570 * count bytes for a count from 1 to
// GhostBundleMaxReveals.
var ErrGhostBundleLength = errors.New("bundle payload length does not match a count of 1 to 1,408 reveals")

// GhostBundlePayloadSize returns the length of the payload of a bundle of
// count reveals.
func GhostBundlePayloadSize(count int) int {
	return GhostBundleFixedSize + GhostBundleBodySize*count
}

// GhostBundleGas returns the gas a bundle of count reveals takes from the
// block gas pool: count times G_PRIV, the sum of what the same reveals take
// as lone reveals.
func GhostBundleGas(count int) uint64 {
	if count <= 0 {
		return 0
	}
	return uint64(count) * GhostRevealGas
}

// GhostBundleTx is the payload of a bundle, kept as its exact bytes.
type GhostBundleTx struct {
	Payload []byte
}

// NewGhostBundleTx wraps a bundle envelope, the type byte 0x55 and the
// payload, into a transaction. The envelope is copied. Only its type, its
// count and the length that count gives are checked here; the fields are
// checked when a block includes it.
func NewGhostBundleTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostBundleTxType {
		return nil, fmt.Errorf("%w: not a bundle envelope", ErrInvalidTxType)
	}
	inner := new(GhostBundleTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostBundleEnvelope returns a copy of a bundle's envelope, nil for any
// other transaction.
func (tx *Transaction) GhostBundleEnvelope() []byte {
	inner, ok := tx.inner.(*GhostBundleTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostBundleTxType}, inner.Payload...)
}

// count returns the payload's count field, zero if the payload is too short
// to hold it.
func (tx *GhostBundleTx) count() int {
	if len(tx.Payload) < GhostBundleHeaderSize {
		return 0
	}
	return int(binary.BigEndian.Uint16(tx.Payload[10:12]))
}

func (tx *GhostBundleTx) copy() TxData {
	return &GhostBundleTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostBundleTx) txType() byte { return GhostBundleTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostBundleTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostBundleTx) accessList() AccessList { return nil }
func (tx *GhostBundleTx) data() []byte           { return nil }

// gas is count times G_PRIV, by the payload's count field.
func (tx *GhostBundleTx) gas() uint64 { return GhostBundleGas(tx.count()) }

// The fees of a bundle are fields of its bodies; it has no gas price.
func (tx *GhostBundleTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostBundleTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostBundleTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostBundleTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostBundleTx) nonce() uint64       { return 0 }
func (tx *GhostBundleTx) to() *common.Address { return nil }

func (tx *GhostBundleTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostBundleTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a bundle carries no signature.
func (tx *GhostBundleTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostBundleTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

// decode takes a payload whose count is 1 to GhostBundleMaxReveals and whose
// length is exactly the one of that count.
func (tx *GhostBundleTx) decode(input []byte) error {
	if len(input) < GhostBundleHeaderSize {
		return fmt.Errorf("%w: %d bytes", ErrGhostBundleLength, len(input)+1)
	}
	count := int(binary.BigEndian.Uint16(input[10:12]))
	if count < 1 || count > GhostBundleMaxReveals {
		return fmt.Errorf("%w: count %d", ErrGhostBundleLength, count)
	}
	if want := GhostBundlePayloadSize(count); len(input) != want {
		return fmt.Errorf("%w: %d bytes for count %d, want %d", ErrGhostBundleLength, len(input)+1, count, want+1)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x55 || payload).
func (tx *GhostBundleTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostBundleTxType}, tx.Payload)
}
