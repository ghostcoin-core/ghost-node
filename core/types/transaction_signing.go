// Copyright 2016 The go-ethereum Authors
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
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")

// ErrSecp256k1TxType is returned for a transaction of a type signed with
// secp256k1: legacy (0x00), EIP-2930 (0x01), EIP-1559 (0x02), EIP-4844 (0x03)
// and EIP-7702 (0x04). Ghost refuses them from genesis, on every chain (spec
// 09, sections 6 and 12, QS-1), and no signer recovers their sender.
var ErrSecp256k1TxType = fmt.Errorf("%w: secp256k1 transaction types are refused", ErrTxTypeNotSupported)

// setCodeTxType is the type byte of an EIP-7702 transaction, which this node
// does not decode.
const setCodeTxType = 0x04

// CheckTxType refuses a transaction by its type byte alone, before any
// signature work: the coin reveal (0x50), the data reveal (0x51) and the
// account transaction (0x52) are the only types taken.
func CheckTxType(tx *Transaction) error {
	switch typ := tx.Type(); typ {
	case GhostRevealTxType, GhostDataRevealTxType, GhostAccountTxType:
		return nil
	case LegacyTxType, AccessListTxType, DynamicFeeTxType, BlobTxType, setCodeTxType:
		return fmt.Errorf("%w: type %#x", ErrSecp256k1TxType, typ)
	default:
		return fmt.Errorf("%w: type %#x", ErrTxTypeNotSupported, typ)
	}
}

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config ctypes.ChainConfigurator, blockNumber *big.Int, blockTime uint64) Signer {
	var signer Signer
	switch {
	case config.IsEnabledByTime(config.GetEIP4844TransitionTime, &blockTime), config.IsEnabled(config.GetEIP4844Transition, blockNumber):
		signer = NewCancunSigner(config.GetChainID())
	case config.IsEnabled(config.GetEIP1559Transition, blockNumber):
		signer = NewEIP1559Signer(config.GetChainID())
	case config.IsEnabled(config.GetEIP2930Transition, blockNumber):
		signer = NewEIP2930Signer(config.GetChainID())
	case config.IsEnabled(config.GetEIP155Transition, blockNumber):
		signer = NewEIP155Signer(config.GetChainID())
	case config.IsEnabled(config.GetEIP2Transition, blockNumber):
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
}

// LatestSigner returns the 'most permissive' Signer available for the given chain
// configuration. Specifically, this enables support of all types of transactions
// when their respective forks are scheduled to occur at any block number (or time)
// in the chain config.
//
// Use this in transaction-handling code where the current block number is unknown. If you
// have the current block number available, use MakeSigner instead.
func LatestSigner(config ctypes.ChainConfigurator) Signer {
	if chainID := config.GetChainID(); chainID != nil {
		if config.GetEIP4844TransitionTime() != nil || config.GetEIP4844Transition() != nil {
			return NewCancunSigner(chainID)
		}
		if config.GetEIP1559Transition() != nil {
			return NewEIP1559Signer(chainID)
		}
		if config.GetEIP2930Transition() != nil {
			return NewEIP2930Signer(chainID)
		}
		if config.GetEIP155Transition() != nil {
			return NewEIP155Signer(chainID)
		}
	}
	return HomesteadSigner{}
}

// LatestSignerForChainID returns the 'most permissive' Signer available. Specifically,
// this enables support for EIP-155 replay protection and all implemented EIP-2718
// transaction types if chainID is non-nil.
//
// Use this in transaction-handling code where the current block number and fork
// configuration are unknown. If you have a ChainConfig, use LatestSigner instead.
// If you have a ChainConfig and know the current block number, use MakeSigner instead.
func LatestSignerForChainID(chainID *big.Int) Signer {
	if chainID == nil {
		return HomesteadSigner{}
	}
	// EIP4844Signer == CancunSigner
	return NewCancunSigner(chainID)
}

// SignTx signs the transaction using the given signer and private key.
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// SignNewTx creates a transaction and signs it.
func SignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) (*Transaction, error) {
	tx := NewTx(txdata)
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// MustSignNewTx creates a transaction and signs it.
// This panics if the transaction cannot be signed.
func MustSignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) *Transaction {
	tx, err := SignNewTx(prv, s, txdata)
	if err != nil {
		panic(fmt.Errorf("%w: signer=%T", err, s))
	}
	return tx
}

// Sender returns the sender of an account transaction, verified by the
// signer, and an error for every other transaction: a reveal has no sender,
// and no signer recovers the sender of a secp256k1 transaction type.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	// A coin or data reveal has no account: no signer ever gives it an
	// address.
	if tx.IsGhostReveal() {
		return common.Address{}, ErrNoSender
	}
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil
}

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	Hash(tx *Transaction) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

// The secp256k1 signers below hash and sign the EIP-4844, EIP-1559, EIP-2930,
// EIP-155 and Homestead transactions, but recover no sender: their Sender
// refuses every transaction by its type byte (CheckTxType). Account
// transactions are taken by the signer of NewGhostAccountSigner.

// NewEIP4844Signer returns a signer that hashes and signs
// - EIP-4844 blob transactions
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
type eip4844Signer struct{ eip1559Signer }

func NewCancunSigner(chainId *big.Int) Signer {
	return eip4844Signer{eip1559Signer{eip2930Signer{NewEIP155Signer(chainId)}}}
}

func (s eip4844Signer) Equal(s2 Signer) bool {
	x, ok := s2.(eip4844Signer)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s eip4844Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	txdata, ok := tx.inner.(*BlobTx)
	if !ok {
		return s.eip1559Signer.SignatureValues(tx, sig)
	}
	// Check that chain ID of tx matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the tx.
	if txdata.ChainID.Sign() != 0 && txdata.ChainID.ToBig().Cmp(s.chainId) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
	}
	R, S, _ = decodeSignature(sig)
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip4844Signer) Hash(tx *Transaction) common.Hash {
	if tx.Type() != BlobTxType {
		return s.eip1559Signer.Hash(tx)
	}
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.Nonce(),
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
			tx.BlobGasFeeCap(),
			tx.BlobHashes(),
		})
}

type eip1559Signer struct{ eip2930Signer }

// NewEIP1559Signer returns a signer that hashes and signs
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
func NewEIP1559Signer(chainId *big.Int) Signer {
	return eip1559Signer{eip2930Signer{NewEIP155Signer(chainId)}}
}

func (s eip1559Signer) Equal(s2 Signer) bool {
	x, ok := s2.(eip1559Signer)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s eip1559Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	txdata, ok := tx.inner.(*DynamicFeeTx)
	if !ok {
		return s.eip2930Signer.SignatureValues(tx, sig)
	}
	// Check that chain ID of tx matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the tx.
	if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
	}
	R, S, _ = decodeSignature(sig)
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip1559Signer) Hash(tx *Transaction) common.Hash {
	if tx.Type() != DynamicFeeTxType {
		return s.eip2930Signer.Hash(tx)
	}
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.Nonce(),
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
		})
}

type eip2930Signer struct{ EIP155Signer }

// NewEIP2930Signer returns a signer that hashes and signs EIP-2930 access list
// transactions, EIP-155 replay protected transactions, and legacy Homestead
// transactions.
func NewEIP2930Signer(chainId *big.Int) Signer {
	return eip2930Signer{NewEIP155Signer(chainId)}
}

func (s eip2930Signer) ChainID() *big.Int {
	return s.chainId
}

func (s eip2930Signer) Equal(s2 Signer) bool {
	x, ok := s2.(eip2930Signer)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s eip2930Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	switch txdata := tx.inner.(type) {
	case *LegacyTx:
		return s.EIP155Signer.SignatureValues(tx, sig)
	case *AccessListTx:
		// Check that chain ID of tx matches the signer. We also accept ID zero here,
		// because it indicates that the chain ID was not specified in the tx.
		if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
			return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
		}
		R, S, _ = decodeSignature(sig)
		V = big.NewInt(int64(sig[64]))
	default:
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip2930Signer) Hash(tx *Transaction) common.Hash {
	switch tx.Type() {
	case LegacyTxType:
		return s.EIP155Signer.Hash(tx)
	case AccessListTxType:
		return prefixedRlpHash(
			tx.Type(),
			[]interface{}{
				s.chainId,
				tx.Nonce(),
				tx.GasPrice(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(),
			})
	default:
		// This _should_ not happen, but in case someone sends in a bad
		// json struct via RPC, it's probably more prudent to return an
		// empty hash instead of killing the node with a panic
		//panic("Unsupported transaction type: %d", tx.typ)
		return common.Hash{}
	}
}

// EIP155Signer implements Signer using the EIP-155 rules. This signs transactions which
// are replay-protected as well as unprotected homestead transactions.
type EIP155Signer struct {
	chainId, chainIdMul *big.Int
}

func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155Signer{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155Signer) ChainID() *big.Int {
	return s.chainId
}

func (s EIP155Signer) Equal(s2 Signer) bool {
	eip155, ok := s2.(EIP155Signer)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

// Sender refuses every transaction; the signers built on EIP155Signer take
// this method.
func (s EIP155Signer) Sender(tx *Transaction) (common.Address, error) {
	return refuseSender(tx)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s EIP155Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	R, S, V = decodeSignature(sig)
	if s.chainId.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.chainIdMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		s.chainId, uint(0), uint(0),
	})
}

// HomesteadSigner implements Signer interface using the
// homestead rules.
type HomesteadSigner struct{ FrontierSigner }

func (s HomesteadSigner) ChainID() *big.Int {
	return nil
}

func (s HomesteadSigner) Equal(s2 Signer) bool {
	_, ok := s2.(HomesteadSigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (hs HomesteadSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	return hs.FrontierSigner.SignatureValues(tx, sig)
}

// FrontierSigner implements Signer interface using the
// frontier rules.
type FrontierSigner struct{}

func (s FrontierSigner) ChainID() *big.Int {
	return nil
}

func (s FrontierSigner) Equal(s2 Signer) bool {
	_, ok := s2.(FrontierSigner)
	return ok
}

// Sender refuses every transaction; HomesteadSigner takes this method.
func (fs FrontierSigner) Sender(tx *Transaction) (common.Address, error) {
	return refuseSender(tx)
}

// refuseSender is the Sender of the secp256k1 signers. It looks at the type
// byte only: a secp256k1 type is refused with ErrSecp256k1TxType, and an
// account transaction or a reveal, which these signers do not take, with
// ErrTxTypeNotSupported.
func refuseSender(tx *Transaction) (common.Address, error) {
	if err := CheckTxType(tx); err != nil {
		return common.Address{}, err
	}
	return common.Address{}, fmt.Errorf("%w: type %#x is not taken by a secp256k1 signer", ErrTxTypeNotSupported, tx.Type())
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (fs FrontierSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	r, s, v = decodeSignature(sig)
	return r, s, v, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (fs FrontierSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
	})
}

func decodeSignature(sig []byte) (r, s, v *big.Int) {
	if len(sig) != crypto.SignatureLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength))
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}
