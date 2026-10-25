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
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// The account transaction (spec 09, section 6; docs/account-transactions.md):
// the only transaction of an account, signed with a quantum-safe signature
// scheme. Its envelope is the type byte followed by an RLP list of twelve
// items. The sender is derived from the scheme and the public key; there is no
// key registry and no public key recovery.
const (
	// GhostAccountTxType is the type byte of an account transaction. Spec 09
	// proposes 0x51, which is the data reveal in this node.
	GhostAccountTxType = 0x52

	// GhostSchemeMLDSA44 is ML-DSA-44 (FIPS 204), pure mode.
	GhostSchemeMLDSA44 uint16 = 0x0001

	// GhostSchemeSLHDSA is SLH-DSA-SHAKE-128s (FIPS 205), pure mode.
	GhostSchemeSLHDSA uint16 = 0x0002

	// GhostSchemeMLDSA44Rescue is an ML-DSA-44 account with an SLH-DSA
	// rescue key (spec 09, section 5.1), signed with its ML-DSA-44 half. It
	// is refused from ML_RESCUE_HEIGHT on.
	GhostSchemeMLDSA44Rescue uint16 = 0x0003

	// GhostSchemeSLHDSARescue is the same account signed with its
	// SLH-DSA-SHAKE-128s half, the rescue key. Its sender is derived with
	// scheme 0x0003, so both IDs name one account.
	GhostSchemeSLHDSARescue uint16 = 0x0004

	// The key and signature lengths of each scheme.
	GhostMLDSA44PublicKeySize = 1312
	GhostMLDSA44SignatureSize = 2420
	GhostSLHDSAPublicKeySize  = 32
	GhostSLHDSASignatureSize  = 7856

	// GhostRescuePublicKeySize is the public key length of schemes 0x0003
	// and 0x0004: the ML-DSA-44 public key followed by the SLH-DSA one.
	GhostRescuePublicKeySize = GhostMLDSA44PublicKeySize + GhostSLHDSAPublicKeySize

	// GhostAccountAddressTag is the hash tag of the sender's address.
	GhostAccountAddressTag = "ghost/account-address/v1"

	// GhostAccountTxTag is the hash tag of the signature hash.
	GhostAccountTxTag = "ghost/account-tx/v1"

	// GhostAccountTxContext is the context string of the signature, for
	// ML-DSA-44 and SLH-DSA alike.
	GhostAccountTxContext = "ghost/tx/v1"
)

// ghostSLHDSAParams is the one SLH-DSA parameter set of scheme 0x0002.
const ghostSLHDSAParams = slhdsa.SHAKE_128s

var (
	// ErrGhostAccountScheme is returned for a scheme the node does not know
	// or does not accept.
	ErrGhostAccountScheme = errors.New("account transaction scheme not accepted")

	// ErrGhostAccountLength is returned for a public key or a signature whose
	// length is not the exact length of the scheme.
	ErrGhostAccountLength = errors.New("account transaction key or signature has the wrong length")

	// ErrGhostAccountField is returned for an integer field of more than 256
	// bits.
	ErrGhostAccountField = errors.New("account transaction field out of range")

	// ErrGhostAccountGenesis is returned by a signer that has no genesis hash
	// to bind the signature to.
	ErrGhostAccountGenesis = errors.New("account transaction signer has no genesis hash")

	// ErrGhostAccountSignature is returned for a signature that does not
	// verify.
	ErrGhostAccountSignature = fmt.Errorf("%w: account transaction signature does not verify", ErrInvalidSig)
)

// GhostAccountTx is an account transaction. The twelve fields are in the
// order of their encoding.
type GhostAccountTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // max_priority_fee_per_gas
	GasFeeCap  *big.Int // max_fee_per_gas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	Scheme     [2]byte // the scheme ID, big-endian
	PublicKey  []byte
	Signature  []byte
}

// GhostScheme encodes a scheme ID as the two bytes of its field.
func GhostScheme(id uint16) [2]byte {
	return [2]byte{byte(id >> 8), byte(id)}
}

// SchemeID returns the scheme ID.
func (tx *GhostAccountTx) SchemeID() uint16 {
	return uint16(tx.Scheme[0])<<8 | uint16(tx.Scheme[1])
}

// ghostSchemeSizes returns the public key and signature lengths of a known
// scheme, and false for any other scheme.
func ghostSchemeSizes(id uint16) (pubKey, sig int, ok bool) {
	switch id {
	case GhostSchemeMLDSA44:
		return GhostMLDSA44PublicKeySize, GhostMLDSA44SignatureSize, true
	case GhostSchemeSLHDSA:
		return GhostSLHDSAPublicKeySize, GhostSLHDSASignatureSize, true
	case GhostSchemeMLDSA44Rescue:
		return GhostRescuePublicKeySize, GhostMLDSA44SignatureSize, true
	case GhostSchemeSLHDSARescue:
		return GhostRescuePublicKeySize, GhostSLHDSASignatureSize, true
	}
	return 0, 0, false
}

// ghostVerify verifies the signature of a sighash under a scheme. The scheme
// and the lengths of the key and signature must have been checked: a key or
// signature of another scheme never reaches a verifier. A rescue-key scheme
// verifies under its half of the public key only: 0x0003 under the first
// 1,312 bytes with ML-DSA-44, 0x0004 under the last 32 bytes with SLH-DSA.
func ghostVerify(scheme uint16, publicKey []byte, sighash common.Hash, sig []byte) error {
	switch scheme {
	case GhostSchemeMLDSA44:
		return ghostVerifyMLDSA44(publicKey, sighash, sig)
	case GhostSchemeSLHDSA:
		return ghostVerifySLHDSA(publicKey, sighash, sig)
	case GhostSchemeMLDSA44Rescue:
		if len(publicKey) != GhostRescuePublicKeySize {
			return ErrGhostAccountLength
		}
		return ghostVerifyMLDSA44(publicKey[:GhostMLDSA44PublicKeySize], sighash, sig)
	case GhostSchemeSLHDSARescue:
		if len(publicKey) != GhostRescuePublicKeySize {
			return ErrGhostAccountLength
		}
		return ghostVerifySLHDSA(publicKey[GhostMLDSA44PublicKeySize:], sighash, sig)
	}
	return fmt.Errorf("%w: scheme %#04x", ErrGhostAccountScheme, scheme)
}

// ghostVerifyMLDSA44 verifies an ML-DSA-44 signature of a sighash.
func ghostVerifyMLDSA44(publicKey []byte, sighash common.Hash, sig []byte) error {
	var pk mldsa44.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("%w: %v", ErrGhostAccountLength, err)
	}
	if !mldsa44.Verify(&pk, sighash[:], []byte(GhostAccountTxContext), sig) {
		return ErrGhostAccountSignature
	}
	return nil
}

// ghostVerifySLHDSA verifies an SLH-DSA-SHAKE-128s signature of a sighash.
func ghostVerifySLHDSA(publicKey []byte, sighash common.Hash, sig []byte) error {
	pk := slhdsa.PublicKey{ID: ghostSLHDSAParams}
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("%w: %v", ErrGhostAccountLength, err)
	}
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(sighash[:]), sig, []byte(GhostAccountTxContext)) {
		return ErrGhostAccountSignature
	}
	return nil
}

// checkShape checks what can be checked of the transaction alone: a known
// scheme, the exact lengths of its key and signature and integer fields of
// at most 256 bits.
func (tx *GhostAccountTx) checkShape() error {
	id := tx.SchemeID()
	pubKeySize, sigSize, ok := ghostSchemeSizes(id)
	if !ok {
		return fmt.Errorf("%w: scheme %#04x", ErrGhostAccountScheme, id)
	}
	if len(tx.PublicKey) != pubKeySize || len(tx.Signature) != sigSize {
		return fmt.Errorf("%w: scheme %#04x, public key %d bytes, signature %d bytes, want %d and %d",
			ErrGhostAccountLength, id, len(tx.PublicKey), len(tx.Signature), pubKeySize, sigSize)
	}
	for _, v := range []*big.Int{tx.ChainID, tx.GasTipCap, tx.GasFeeCap, tx.Value} {
		if v == nil || v.Sign() < 0 || v.BitLen() > 256 {
			return ErrGhostAccountField
		}
	}
	return nil
}

// ghostTaggedHash is K of spec 01: Keccak-256 over the tag's length as one
// byte, the tag's ASCII bytes and the parts in order.
func ghostTaggedHash(tag string, parts ...[]byte) common.Hash {
	data := make([][]byte, 0, len(parts)+1)
	data = append(data, append([]byte{byte(len(tag))}, tag...))
	data = append(data, parts...)
	return crypto.Keccak256Hash(data...)
}

// GhostAccountAddressOf returns the address of the account of a scheme and a
// public key: the first 20 bytes of K("ghost/account-address/v1", scheme,
// public_key). It checks nothing. Scheme 0x0004 is derived as scheme 0x0003:
// both sign for the one account of a rescue public key.
func GhostAccountAddressOf(scheme uint16, publicKey []byte) common.Address {
	if scheme == GhostSchemeSLHDSARescue {
		scheme = GhostSchemeMLDSA44Rescue
	}
	id := GhostScheme(scheme)
	h := ghostTaggedHash(GhostAccountAddressTag, id[:], publicKey)
	return common.BytesToAddress(h[:common.AddressLength])
}

// ghostAccountSigHash is K("ghost/account-tx/v1", 0x52, genesis_hash,
// keccak256(unsigned)).
func ghostAccountSigHash(genesis common.Hash, unsignedHash common.Hash) common.Hash {
	return ghostTaggedHash(GhostAccountTxTag, []byte{GhostAccountTxType}, genesis[:], unsignedHash[:])
}

// unsignedHash is keccak256 of the RLP list of the first eleven fields, all
// but the signature.
func (tx *GhostAccountTx) unsignedHash() common.Hash {
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
		tx.PublicKey,
	})
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *GhostAccountTx) copy() TxData {
	cpy := &GhostAccountTx{
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
		PublicKey:  common.CopyBytes(tx.PublicKey),
		Signature:  common.CopyBytes(tx.Signature),
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
func (tx *GhostAccountTx) txType() byte           { return GhostAccountTxType }
func (tx *GhostAccountTx) chainID() *big.Int      { return tx.ChainID }
func (tx *GhostAccountTx) accessList() AccessList { return tx.AccessList }
func (tx *GhostAccountTx) data() []byte           { return tx.Data }
func (tx *GhostAccountTx) gas() uint64            { return tx.Gas }
func (tx *GhostAccountTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *GhostAccountTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *GhostAccountTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *GhostAccountTx) value() *big.Int        { return tx.Value }
func (tx *GhostAccountTx) nonce() uint64          { return tx.Nonce }
func (tx *GhostAccountTx) to() *common.Address    { return tx.To }

func (tx *GhostAccountTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zeros: the signature of an account transaction
// is no V, R, S triple.
func (tx *GhostAccountTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues does nothing: an account transaction is signed with
// SignGhostAccountTx.
func (tx *GhostAccountTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *GhostAccountTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

// decode decodes the payload strictly: exactly twelve items, canonical
// integers and sizes, nothing after the list, a known scheme and the exact
// key and signature lengths of that scheme. Nothing is repaired.
func (tx *GhostAccountTx) decode(input []byte) error {
	var dec GhostAccountTx
	if err := rlp.DecodeBytes(input, &dec); err != nil {
		return err
	}
	if err := dec.checkShape(); err != nil {
		return err
	}
	*tx = dec
	return nil
}

// GhostAccountAuth returns copies of the scheme ID, the public key and the
// signature of an account transaction, and false for any other transaction.
func (tx *Transaction) GhostAccountAuth() (scheme uint16, publicKey, signature []byte, ok bool) {
	inner, ok := tx.inner.(*GhostAccountTx)
	if !ok {
		return 0, nil, nil, false
	}
	return inner.SchemeID(), common.CopyBytes(inner.PublicKey), common.CopyBytes(inner.Signature), true
}

// GhostAccountAddress returns the sender of an account transaction without
// verifying its signature: the scheme is accepted, the key and signature have
// its lengths, the chain ID is the signer's and the address is derived. It is
// the cheap part of the sender checks, for checks that must run before the
// signature's; the transaction is only valid once Sender has verified it.
func GhostAccountAddress(signer Signer, tx *Transaction) (common.Address, error) {
	inner, ok := tx.inner.(*GhostAccountTx)
	if !ok {
		return common.Address{}, ErrTxTypeNotSupported
	}
	if err := inner.checkShape(); err != nil {
		return common.Address{}, err
	}
	chainID := signer.ChainID()
	if chainID == nil || inner.ChainID.Cmp(chainID) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, inner.ChainID, chainID)
	}
	return GhostAccountAddressOf(inner.SchemeID(), inner.PublicKey), nil
}

// ghostAccountSigner handles account transactions and passes every other
// type to its base signer.
type ghostAccountSigner struct {
	base    Signer
	genesis common.Hash
}

// NewGhostAccountSigner returns a signer that takes account transactions
// (type 0x52), whose signatures are bound to the chain of genesisHash, and
// passes every other type to base. With a zero genesis hash it refuses every
// account transaction.
func NewGhostAccountSigner(base Signer, genesisHash common.Hash) Signer {
	return ghostAccountSigner{base: base, genesis: genesisHash}
}

// Sender checks an account transaction in order, the cheap checks first, and
// verifies its signature last.
func (s ghostAccountSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != GhostAccountTxType {
		return s.base.Sender(tx)
	}
	if s.genesis == (common.Hash{}) {
		return common.Address{}, ErrGhostAccountGenesis
	}
	from, err := GhostAccountAddress(s, tx)
	if err != nil {
		return common.Address{}, err
	}
	inner := tx.inner.(*GhostAccountTx)
	sighash := ghostAccountSigHash(s.genesis, inner.unsignedHash())
	if err := ghostVerify(inner.SchemeID(), inner.PublicKey, sighash, inner.Signature); err != nil {
		return common.Address{}, err
	}
	return from, nil
}

// SignatureValues refuses account transactions, which have no V, R, S
// signature.
func (s ghostAccountSigner) SignatureValues(tx *Transaction, sig []byte) (r, ss, v *big.Int, err error) {
	if tx.Type() == GhostAccountTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	return s.base.SignatureValues(tx, sig)
}

func (s ghostAccountSigner) ChainID() *big.Int {
	return s.base.ChainID()
}

// Hash returns the signature hash of an account transaction,
// K("ghost/account-tx/v1", 0x52, genesis_hash, keccak256(unsigned)).
func (s ghostAccountSigner) Hash(tx *Transaction) common.Hash {
	inner, ok := tx.inner.(*GhostAccountTx)
	if !ok {
		return s.base.Hash(tx)
	}
	return ghostAccountSigHash(s.genesis, inner.unsignedHash())
}

func (s ghostAccountSigner) Equal(s2 Signer) bool {
	x, ok := s2.(ghostAccountSigner)
	return ok && x.genesis == s.genesis && x.base.Equal(s.base)
}

// SignGhostAccountTx signs txdata with an ML-DSA-44 key for the chain of
// signer, which must come from NewGhostAccountSigner. The scheme and public
// key fields are set from the key; the signature is hedged (FIPS 204).
func SignGhostAccountTx(signer Signer, key *mldsa44.PrivateKey, txdata *GhostAccountTx) (*Transaction, error) {
	pub := key.Public().(*mldsa44.PublicKey).Bytes()
	return signGhostAccountTx(signer, GhostSchemeMLDSA44, pub, txdata, func(sighash []byte) ([]byte, error) {
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(key, sighash, []byte(GhostAccountTxContext), true, sig); err != nil {
			return nil, err
		}
		return sig, nil
	})
}

// SignGhostAccountTxSLHDSA signs txdata with an SLH-DSA-SHAKE-128s key for
// the chain of signer, which must come from NewGhostAccountSigner. The scheme
// and public key fields are set from the key; the signature is randomized
// (FIPS 205, algorithm 22).
func SignGhostAccountTxSLHDSA(signer Signer, key *slhdsa.PrivateKey, txdata *GhostAccountTx) (*Transaction, error) {
	if key.ID != ghostSLHDSAParams {
		return nil, fmt.Errorf("%w: SLH-DSA key of %v, want %v", ErrGhostAccountScheme, key.ID, ghostSLHDSAParams)
	}
	pub, err := key.PublicKey().MarshalBinary()
	if err != nil {
		return nil, err
	}
	return signGhostAccountTx(signer, GhostSchemeSLHDSA, pub, txdata, func(sighash []byte) ([]byte, error) {
		return slhdsa.SignRandomized(key, nil, slhdsa.NewMessage(sighash), []byte(GhostAccountTxContext))
	})
}

// GhostRescuePublicKey returns the public key of a rescue-key account,
// schemes 0x0003 and 0x0004: the ML-DSA-44 public key followed by the
// SLH-DSA-SHAKE-128s one. It checks nothing.
func GhostRescuePublicKey(mldsaPub, slhdsaPub []byte) []byte {
	pub := make([]byte, 0, len(mldsaPub)+len(slhdsaPub))
	pub = append(pub, mldsaPub...)
	return append(pub, slhdsaPub...)
}

// SignGhostAccountTxRescue signs txdata as scheme 0x0003 with the ML-DSA-44
// key of a rescue-key account whose SLH-DSA public key is slhdsaPub, for the
// chain of signer, which must come from NewGhostAccountSigner.
func SignGhostAccountTxRescue(signer Signer, mldsaKey *mldsa44.PrivateKey, slhdsaPub []byte, txdata *GhostAccountTx) (*Transaction, error) {
	if len(slhdsaPub) != GhostSLHDSAPublicKeySize {
		return nil, fmt.Errorf("%w: SLH-DSA public key of %d bytes", ErrGhostAccountLength, len(slhdsaPub))
	}
	pub := GhostRescuePublicKey(mldsaKey.Public().(*mldsa44.PublicKey).Bytes(), slhdsaPub)
	return signGhostAccountTx(signer, GhostSchemeMLDSA44Rescue, pub, txdata, func(sighash []byte) ([]byte, error) {
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(mldsaKey, sighash, []byte(GhostAccountTxContext), true, sig); err != nil {
			return nil, err
		}
		return sig, nil
	})
}

// SignGhostAccountTxRescueSLHDSA signs txdata as scheme 0x0004 with the
// SLH-DSA-SHAKE-128s rescue key of an account whose ML-DSA-44 public key is
// mldsaPub, for the chain of signer, which must come from
// NewGhostAccountSigner.
func SignGhostAccountTxRescueSLHDSA(signer Signer, mldsaPub []byte, slhdsaKey *slhdsa.PrivateKey, txdata *GhostAccountTx) (*Transaction, error) {
	if len(mldsaPub) != GhostMLDSA44PublicKeySize {
		return nil, fmt.Errorf("%w: ML-DSA-44 public key of %d bytes", ErrGhostAccountLength, len(mldsaPub))
	}
	if slhdsaKey.ID != ghostSLHDSAParams {
		return nil, fmt.Errorf("%w: SLH-DSA key of %v, want %v", ErrGhostAccountScheme, slhdsaKey.ID, ghostSLHDSAParams)
	}
	slhPub, err := slhdsaKey.PublicKey().MarshalBinary()
	if err != nil {
		return nil, err
	}
	pub := GhostRescuePublicKey(mldsaPub, slhPub)
	return signGhostAccountTx(signer, GhostSchemeSLHDSARescue, pub, txdata, func(sighash []byte) ([]byte, error) {
		return slhdsa.SignRandomized(slhdsaKey, nil, slhdsa.NewMessage(sighash), []byte(GhostAccountTxContext))
	})
}

// signGhostAccountTx sets the scheme and public key of a copy of txdata and
// signs its signature hash with sign.
func signGhostAccountTx(signer Signer, scheme uint16, pub []byte, txdata *GhostAccountTx, sign func(sighash []byte) ([]byte, error)) (*Transaction, error) {
	s, ok := signer.(ghostAccountSigner)
	if !ok {
		return nil, fmt.Errorf("%w: signer %T does not take account transactions", ErrTxTypeNotSupported, signer)
	}
	if s.genesis == (common.Hash{}) {
		return nil, ErrGhostAccountGenesis
	}
	inner := txdata.copy().(*GhostAccountTx)
	inner.Scheme = GhostScheme(scheme)
	inner.PublicKey = pub
	inner.Signature = nil
	sighash := ghostAccountSigHash(s.genesis, inner.unsignedHash())
	sig, err := sign(sighash[:])
	if err != nil {
		return nil, err
	}
	inner.Signature = sig
	tx := new(Transaction)
	tx.setDecoded(inner, 0)
	return tx, nil
}
