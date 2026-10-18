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

// Package ghostpriv holds the coin rules of the chain: the commit, an
// ordinary transaction that burns public value into a coin commitment, and
// the reveal, the native transaction without an account that mints public
// value out of the hidden set against a proof (docs/private-transactions.md).
package ghostpriv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The hash tags of the coin rules.
const (
	TagCommitment    = "ghost/coin-commitment/v1"
	TagRevealBinding = "ghost/coin-reveal-binding/v1"
	TagCommitReceipt = "ghost/commit-receipt/v1"
	TagRevealReceipt = "ghost/reveal-receipt/v1"
)

// Sizes and constants of the coin rules.
const (
	// NoteSize is the length of a note, the encrypted data stored with a
	// leaf.
	NoteSize = ghosttree.NoteBytes

	// Version is the only version of the commit data and of the reveal
	// payload.
	Version uint16 = 0x0001

	// GasPriv is G_PRIV, the gas of every reveal.
	GasPriv = types.GhostRevealGas
)

// Coin is the type of a coin commitment, COIN. The node supplies it; a
// sender cannot choose a type.
var Coin = [2]byte{0x01, 0x01}

// VMax is the largest amount, 2^96 - 1.
var VMax = new(uint256.Int).Sub(new(uint256.Int).Lsh(uint256.NewInt(1), 96), uint256.NewInt(1))

var (
	// ErrAmountRange is returned for an amount word of 2^96 or more.
	ErrAmountRange = errors.New("amount word not below 2^96")

	// ErrTotals is returned when the totals account cannot take a change: a
	// total that would overflow, or a total out above the total in.
	ErrTotals = errors.New("hidden-set totals out of range")

	// ErrTreeIndexRange is returned for an append whose tree index does not
	// fit the four bytes of the receipt.
	ErrTreeIndexRange = errors.New("tree index does not fit the receipt")
)

// StateDB is the part of the state the coin rules use; it is satisfied by
// *state.StateDB.
type StateDB interface {
	ghosttree.StateDB
	GetBalance(addr common.Address) *uint256.Int
	AddBalance(addr common.Address, amount *uint256.Int)
	SubBalance(addr common.Address, amount *uint256.Int)
	AddLog(log *types.Log)
	Snapshot() int
	RevertToSnapshot(id int)
}

// amountWord returns v as a 32-byte big-endian word.
func amountWord(v *uint256.Int) []byte {
	w := v.Bytes32()
	return w[:]
}

// readAmount reads a 32-byte amount word, which is valid only below 2^96:
// its first 20 bytes must be zero.
func readAmount(w []byte) (*uint256.Int, error) {
	if len(w) != 32 {
		return nil, fmt.Errorf("%w: %d bytes", ErrAmountRange, len(w))
	}
	for _, b := range w[:20] {
		if b != 0 {
			return nil, ErrAmountRange
		}
	}
	return new(uint256.Int).SetBytes(w), nil
}

// Commitment returns the coin commitment of F and v,
// K("ghost/coin-commitment/v1", COIN, F, v as a 32-byte word).
func Commitment(f common.Hash, v *uint256.Int) common.Hash {
	return ghosttree.K(TagCommitment, Coin[:], f[:], amountWord(v))
}

// Slots of the totals account.
const (
	SlotTotalIn  = 0 // value that entered the hidden set
	SlotTotalOut = 1 // value that left it
)

// Totals returns the total that entered the hidden set and the total that
// left it. An absent account reads as zero for both.
func Totals(st StateDB) (in, out *uint256.Int) {
	in = new(uint256.Int).SetBytes32(st.GetState(ghost.PrivTotalsAccount, ghosttree.Slot(SlotTotalIn)).Bytes())
	out = new(uint256.Int).SetBytes32(st.GetState(ghost.PrivTotalsAccount, ghosttree.Slot(SlotTotalOut)).Bytes())
	return in, out
}

// Hidden returns the value in the hidden set, total in minus total out. A
// total out above the total in is ErrTotals.
func Hidden(st StateDB) (*uint256.Int, error) {
	in, out := Totals(st)
	if out.Gt(in) {
		return nil, fmt.Errorf("%w: total out %v above total in %v", ErrTotals, out, in)
	}
	return new(uint256.Int).Sub(in, out), nil
}

// addTotal adds v to a slot of the totals account, which gets nonce 1 when it
// is first written so that the empty-account cleanup never deletes it.
func addTotal(st StateDB, slot uint64, v *uint256.Int) error {
	key := ghosttree.Slot(slot)
	cur := new(uint256.Int).SetBytes32(st.GetState(ghost.PrivTotalsAccount, key).Bytes())
	sum, overflow := new(uint256.Int).AddOverflow(cur, v)
	if overflow {
		return fmt.Errorf("%w: slot %d overflows", ErrTotals, slot)
	}
	if !st.Exist(ghost.PrivTotalsAccount) {
		st.CreateAccount(ghost.PrivTotalsAccount)
	}
	if st.GetNonce(ghost.PrivTotalsAccount) == 0 {
		st.SetNonce(ghost.PrivTotalsAccount, 1)
	}
	st.SetState(ghost.PrivTotalsAccount, key, common.Hash(sum.Bytes32()))
	return nil
}

// receiptLocation is the tree index and position of an append, four bytes
// each.
func receiptLocation(res ghosttree.AppendResult) ([]byte, error) {
	if res.TreeIndex > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %d", ErrTreeIndexRange, res.TreeIndex)
	}
	loc := make([]byte, 8)
	binary.BigEndian.PutUint32(loc[:4], uint32(res.TreeIndex))
	binary.BigEndian.PutUint32(loc[4:], res.Position)
	return loc, nil
}

// Fee is the fee of a reveal in one fee window.
type Fee struct {
	Price    *uint256.Int // U3, the price per gas
	BasePart *uint256.Int // G_PRIV times the price, burned
	Tip      *uint256.Int // a tenth of the base part rounded up, to the coinbase
	Total    *uint256.Int // base part plus tip, the payload's fee field
}

// ErrBaseFee is returned for a reference base fee that is missing, negative
// or too large to price.
var ErrBaseFee = errors.New("reference base fee out of range")

// WindowFee returns the fee of every reveal in a window whose first block has
// the base fee bRef: U0 = bRef, U(j+1) = U(j) + floor(U(j)/8) +
// floor(U(j)/20000) + 1, price = U3, base part = G_PRIV * price, tip =
// ceil(base part / 10), fee = base part + tip.
func WindowFee(bRef *big.Int) (Fee, error) {
	if bRef == nil || bRef.Sign() < 0 {
		return Fee{}, ErrBaseFee
	}
	u, overflow := uint256.FromBig(bRef)
	if overflow {
		return Fee{}, ErrBaseFee
	}
	var (
		eight = uint256.NewInt(8)
		div   = uint256.NewInt(20000)
		one   = uint256.NewInt(1)
	)
	for range 3 {
		next, o1 := new(uint256.Int).AddOverflow(u, new(uint256.Int).Div(u, eight))
		next, o2 := next.AddOverflow(next, new(uint256.Int).Div(u, div))
		next, o3 := next.AddOverflow(next, one)
		if o1 || o2 || o3 {
			return Fee{}, ErrBaseFee
		}
		u = next
	}
	base, overflow := new(uint256.Int).MulOverflow(uint256.NewInt(GasPriv), u)
	if overflow {
		return Fee{}, ErrBaseFee
	}
	tip := new(uint256.Int).Div(base, uint256.NewInt(10))
	if !new(uint256.Int).Mod(base, uint256.NewInt(10)).IsZero() {
		tip.AddUint64(tip, 1)
	}
	total, overflow := new(uint256.Int).AddOverflow(base, tip)
	if overflow {
		return Fee{}, ErrBaseFee
	}
	return Fee{Price: u, BasePart: base, Tip: tip, Total: total}, nil
}

// WindowStart returns the height of the first block of the fee window of a
// block at height h, 4 * floor(h / 4).
func WindowStart(h uint64) uint64 { return h / 4 * 4 }
