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
	"github.com/ethereum/go-ethereum/rlp"
)

// The public root and the binding transactions.
//
// A binding transaction (type 0x57) is an account transaction whose
// signature is proved by a root proof instead of carried: it has the fields
// of the account transaction (type 0x52) with the 84 binding bytes in place
// of the public key and the signature. A binding is
//
//	account (20) | key identity (32) | transaction hash (32)
//
// where the key identity is the one recorded in state for the account
// (GhostRecordedKeyIdentity) and the transaction hash is GhostBindingTxHash,
// the hash of every field but the binding, bound to the chain's genesis.
//
// The public root (type 0x56) is a transaction of its own, of fixed layout
// that is not RLP, at most one per block and placed before the binding
// transactions it proves:
//
//	version (2) | chain id (8) | count (2) | root proof (1,310,720) | count bindings of 84 bytes
//
// Like the bundle it has no sender, nonce or signature, and its consensus
// checks are in core/ghostpriv; a block processor applies it beside the
// account transactions. A binding transaction is valid only in a block whose
// root proves it: no signer gives it a sender (Sender refuses it), so no
// pool, miner or RPC path takes it. An account transaction with its raw
// signature (type 0x52) stays valid and unchanged.
const (
	// GhostPublicRootTxType is the type byte of a public root.
	GhostPublicRootTxType = 0x56

	// GhostBindingTxType is the type byte of a binding transaction.
	GhostBindingTxType = 0x57

	// GhostBindingSize is the length of a binding: the account, the key
	// identity and the transaction hash.
	GhostBindingSize = common.AddressLength + 2*common.HashLength

	// GhostPublicRootHeaderSize is the length of the fields before the root
	// proof: the version, the chain id and the count.
	GhostPublicRootHeaderSize = 2 + 8 + 2

	// GhostPublicRootProofSize is the length of the root proof field, the
	// proof field of a reveal: the serialized proof followed by zeros.
	GhostPublicRootProofSize = GhostBundleProofSize

	// GhostPublicRootFixedSize is the length of a public root's payload
	// without its bindings; the payload is GhostPublicRootFixedSize + 84 *
	// count bytes.
	GhostPublicRootFixedSize = GhostPublicRootHeaderSize + GhostPublicRootProofSize

	// GhostBindingTxTag is the hash tag of a binding transaction's hash.
	GhostBindingTxTag = "ghost/binding-tx/v1"
)

var (
	// ErrGhostPublicRootLength is returned for a public root whose payload
	// is not GhostPublicRootFixedSize + 84 * count bytes for a count of at
	// least 1.
	ErrGhostPublicRootLength = errors.New("public root payload length does not match a count of at least 1 binding")

	// ErrGhostBindingSender is returned by Sender for a binding transaction:
	// its sender is proved by the public root of its block, never by a
	// signer.
	ErrGhostBindingSender = fmt.Errorf("%w: a binding transaction's sender is proved by its block's public root only", ErrTxTypeNotSupported)
)

// GhostPublicRootPayloadSize returns the length of the payload of a public
// root of count bindings.
func GhostPublicRootPayloadSize(count int) int {
	return GhostPublicRootFixedSize + GhostBindingSize*count
}

// GhostBinding is the 84 bytes a binding transaction carries in place of its
// public key and signature, and a public root proves.
type GhostBinding [GhostBindingSize]byte

// NewGhostBinding returns the binding of an account, a key identity and a
// transaction hash.
func NewGhostBinding(account common.Address, keyIdentity, txHash common.Hash) GhostBinding {
	var b GhostBinding
	copy(b[:common.AddressLength], account[:])
	copy(b[common.AddressLength:common.AddressLength+common.HashLength], keyIdentity[:])
	copy(b[common.AddressLength+common.HashLength:], txHash[:])
	return b
}

// Account returns the binding's account, its first 20 bytes.
func (b GhostBinding) Account() common.Address {
	return common.BytesToAddress(b[:common.AddressLength])
}

// KeyIdentity returns the binding's key identity, its next 32 bytes.
func (b GhostBinding) KeyIdentity() common.Hash {
	return common.BytesToHash(b[common.AddressLength : common.AddressLength+common.HashLength])
}

// TxHash returns the binding's transaction hash, its last 32 bytes.
func (b GhostBinding) TxHash() common.Hash {
	return common.BytesToHash(b[common.AddressLength+common.HashLength:])
}

// GhostSchemeSizes returns the public key and signature lengths of a known
// account transaction scheme, and false for any other scheme.
func GhostSchemeSizes(scheme uint16) (pubKey, sig int, ok bool) {
	return ghostSchemeSizes(scheme)
}

// GhostPublicRootTx is the payload of a public root, kept as its exact bytes.
type GhostPublicRootTx struct {
	Payload []byte
}

// NewGhostPublicRootTx wraps a public root envelope, the type byte 0x56 and
// the payload, into a transaction. The envelope is copied. Only its type,
// its count and the length that count gives are checked here; the fields
// are checked when a block includes it.
func NewGhostPublicRootTx(envelope []byte) (*Transaction, error) {
	if len(envelope) == 0 || envelope[0] != GhostPublicRootTxType {
		return nil, fmt.Errorf("%w: not a public root envelope", ErrInvalidTxType)
	}
	inner := new(GhostPublicRootTx)
	if err := inner.decode(envelope[1:]); err != nil {
		return nil, err
	}
	tx := new(Transaction)
	tx.setDecoded(inner, uint64(len(envelope)))
	return tx, nil
}

// GhostPublicRootEnvelope returns a copy of a public root's envelope, nil for
// any other transaction.
func (tx *Transaction) GhostPublicRootEnvelope() []byte {
	inner, ok := tx.inner.(*GhostPublicRootTx)
	if !ok {
		return nil
	}
	return append([]byte{GhostPublicRootTxType}, inner.Payload...)
}

func (tx *GhostPublicRootTx) copy() TxData {
	return &GhostPublicRootTx{Payload: common.CopyBytes(tx.Payload)}
}

func (tx *GhostPublicRootTx) txType() byte { return GhostPublicRootTxType }

// chainID returns the payload's chain ID field, zero if the payload is too
// short to hold it.
func (tx *GhostPublicRootTx) chainID() *big.Int {
	if len(tx.Payload) < 10 {
		return new(big.Int)
	}
	return new(big.Int).SetUint64(binary.BigEndian.Uint64(tx.Payload[2:10]))
}

func (tx *GhostPublicRootTx) accessList() AccessList { return nil }
func (tx *GhostPublicRootTx) data() []byte           { return nil }

// gas is zero: the root takes nothing from the block gas pool. Each binding
// transaction it proves pays its own gas.
func (tx *GhostPublicRootTx) gas() uint64 { return 0 }

// A public root has no gas price, value, nonce or recipient.
func (tx *GhostPublicRootTx) gasPrice() *big.Int  { return new(big.Int) }
func (tx *GhostPublicRootTx) gasTipCap() *big.Int { return new(big.Int) }
func (tx *GhostPublicRootTx) gasFeeCap() *big.Int { return new(big.Int) }
func (tx *GhostPublicRootTx) value() *big.Int     { return new(big.Int) }
func (tx *GhostPublicRootTx) nonce() uint64       { return 0 }
func (tx *GhostPublicRootTx) to() *common.Address { return nil }

func (tx *GhostPublicRootTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.SetUint64(0)
}

func (tx *GhostPublicRootTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a public root carries no signature.
func (tx *GhostPublicRootTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostPublicRootTx) encode(b *bytes.Buffer) error {
	_, err := b.Write(tx.Payload)
	return err
}

// decode takes a payload whose count is at least 1 and whose length is
// exactly the one of that count.
func (tx *GhostPublicRootTx) decode(input []byte) error {
	if len(input) < GhostPublicRootHeaderSize {
		return fmt.Errorf("%w: %d bytes", ErrGhostPublicRootLength, len(input)+1)
	}
	count := int(binary.BigEndian.Uint16(input[10:12]))
	if count < 1 {
		return fmt.Errorf("%w: count %d", ErrGhostPublicRootLength, count)
	}
	if want := GhostPublicRootPayloadSize(count); len(input) != want {
		return fmt.Errorf("%w: %d bytes for count %d, want %d", ErrGhostPublicRootLength, len(input)+1, count, want+1)
	}
	tx.Payload = common.CopyBytes(input)
	return nil
}

// hash is keccak256(0x56 || payload).
func (tx *GhostPublicRootTx) hash() common.Hash {
	return crypto.Keccak256Hash([]byte{GhostPublicRootTxType}, tx.Payload)
}

// GhostBindingTx is a binding transaction. The eleven fields are in the order
// of their encoding: those of GhostAccountTx with the binding in place of the
// public key and the signature.
type GhostBindingTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // max_priority_fee_per_gas
	GasFeeCap  *big.Int // max_fee_per_gas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	Scheme     [2]byte // the scheme ID of the account's key, big-endian
	Binding    GhostBinding
}

// SchemeID returns the scheme ID.
func (tx *GhostBindingTx) SchemeID() uint16 {
	return uint16(tx.Scheme[0])<<8 | uint16(tx.Scheme[1])
}

// checkShape checks what can be checked of the transaction alone: a known
// scheme and integer fields of at most 256 bits. The binding has its exact
// length by its type.
func (tx *GhostBindingTx) checkShape() error {
	if _, _, ok := ghostSchemeSizes(tx.SchemeID()); !ok {
		return fmt.Errorf("%w: scheme %#04x", ErrGhostAccountScheme, tx.SchemeID())
	}
	for _, v := range []*big.Int{tx.ChainID, tx.GasTipCap, tx.GasFeeCap, tx.Value} {
		if v == nil || v.Sign() < 0 || v.BitLen() > 256 {
			return ErrGhostAccountField
		}
	}
	return nil
}

// unboundHash is keccak256 of the RLP list of the first ten fields, all but
// the binding.
func (tx *GhostBindingTx) unboundHash() common.Hash {
	return rlpHash([]interface{}{
		tx.ChainID,
		tx.Nonce,
		tx.GasTipCap,
		tx.GasFeeCap,
		tx.Gas,
		tx.To,
		tx.Value,
		tx.Data,
		tx.AccessList,
		tx.Scheme,
	})
}

// TxHash returns the transaction hash a binding of the transaction binds on
// the chain of genesis: K("ghost/binding-tx/v1", 0x57, genesis_hash,
// keccak256(unbound)), where unbound is the RLP list of every field but the
// binding. It is what the account's key signs and the root proves; it is not
// the transaction's Hash, which covers the binding too.
func (tx *GhostBindingTx) TxHash(genesis common.Hash) common.Hash {
	unbound := tx.unboundHash()
	return ghostTaggedHash(GhostBindingTxTag, []byte{GhostBindingTxType}, genesis[:], unbound[:])
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *GhostBindingTx) copy() TxData {
	cpy := &GhostBindingTx{
		Nonce:      tx.Nonce,
		To:         copyAddressPtr(tx.To),
		Data:       common.CopyBytes(tx.Data),
		Gas:        tx.Gas,
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
		Scheme:     tx.Scheme,
		Binding:    tx.Binding,
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	return cpy
}

// accessors for innerTx.
func (tx *GhostBindingTx) txType() byte           { return GhostBindingTxType }
func (tx *GhostBindingTx) chainID() *big.Int      { return tx.ChainID }
func (tx *GhostBindingTx) accessList() AccessList { return tx.AccessList }
func (tx *GhostBindingTx) data() []byte           { return tx.Data }
func (tx *GhostBindingTx) gas() uint64            { return tx.Gas }
func (tx *GhostBindingTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *GhostBindingTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *GhostBindingTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *GhostBindingTx) value() *big.Int        { return tx.Value }
func (tx *GhostBindingTx) nonce() uint64          { return tx.Nonce }
func (tx *GhostBindingTx) to() *common.Address    { return tx.To }

func (tx *GhostBindingTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zeros: a binding transaction carries no
// signature.
func (tx *GhostBindingTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: a binding transaction is proved by a
// public root.
func (tx *GhostBindingTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostBindingTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

// decode decodes the payload strictly: exactly eleven items, canonical
// integers and sizes, a binding of exactly 84 bytes, nothing after the list
// and a known scheme. Nothing is repaired.
func (tx *GhostBindingTx) decode(input []byte) error {
	var dec GhostBindingTx
	if err := rlp.DecodeBytes(input, &dec); err != nil {
		return err
	}
	if err := dec.checkShape(); err != nil {
		return err
	}
	*tx = dec
	return nil
}

// GhostBinding returns the scheme ID and the binding of a binding
// transaction, and false for any other transaction.
func (tx *Transaction) GhostBinding() (scheme uint16, binding GhostBinding, ok bool) {
	inner, ok := tx.inner.(*GhostBindingTx)
	if !ok {
		return 0, GhostBinding{}, false
	}
	return inner.SchemeID(), inner.Binding, true
}

// GhostBindingTxHash returns the transaction hash a binding of a binding
// transaction binds on the chain of genesis (GhostBindingTx.TxHash), and
// false for any other transaction.
func (tx *Transaction) GhostBindingTxHash(genesis common.Hash) (common.Hash, bool) {
	inner, ok := tx.inner.(*GhostBindingTx)
	if !ok {
		return common.Hash{}, false
	}
	return inner.TxHash(genesis), true
}

// CheckGhostBindingShape runs the shape checks of a binding transaction: a
// known scheme and integer fields of at most 256 bits. A transaction built
// in memory, not decoded, may fail them.
func (tx *Transaction) CheckGhostBindingShape() error {
	inner, ok := tx.inner.(*GhostBindingTx)
	if !ok {
		return ErrTxTypeNotSupported
	}
	return inner.checkShape()
}
