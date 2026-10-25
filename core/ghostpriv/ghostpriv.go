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
// It also holds the data rules: the data commit, which appends a data
// commitment without moving value, and the data reveal, which spends a data
// marker once against a proof and moves no value
// (docs/data-commitments.md).
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

// The hash tags of the data rules, none shared with a coin rule, so that no
// coin value can be used as a data value.
const (
	TagDataCommitment    = "ghost/data-commitment/v1"
	TagDataMarker        = "ghost/data-marker/v1"
	TagDataRevealBinding = "ghost/data-reveal-binding/v1"
	TagDataCommitReceipt = "ghost/data-commit-receipt/v1"
	TagDataRevealReceipt = "ghost/data-reveal-receipt/v1"
)

// Sizes and constants of the coin rules.
const (
	// NoteSize is the length of a note, the encrypted data stored with a
	// leaf.
	NoteSize = ghosttree.NoteBytes

	// SaltSize is the length of the per-coin salt a salted commit carries in
	// the clear.
	SaltSize = ghosttree.SaltBytes

	// Version is the only version of the reveal payload and the version of
	// commit data without a salt.
	Version uint16 = 0x0001

	// SaltedCommitVersion is the version of salted commit data, which carries
	// the salt between F and the note.
	SaltedCommitVersion uint16 = 0x0002

	// GasPriv is G_PRIV, the gas of every reveal.
	GasPriv = types.GhostRevealGas
)

// The types of a commitment, COIN and DATA, at each commitment format
// version: the version byte, then 0x01 for a coin or 0x02 for data (spec 01).
// The node supplies the type from the version of the commit data; a sender
// cannot choose a type, and there are no application-defined data types.
var (
	// Coin is COIN at version 1, the type of a coin commitment of unsalted
	// commit data.
	Coin = [2]byte{0x01, 0x01}

	// CoinV2 is COIN at version 2, the type of a coin commitment of salted
	// commit data and of every reveal's remainder.
	CoinV2 = [2]byte{0x02, 0x01}

	// Data is DATA at version 1, the type of a data commitment of unsalted
	// commit data.
	Data = [2]byte{0x01, 0x02}

	// DataV2 is DATA at version 2, the type of a data commitment of salted
	// commit data.
	DataV2 = [2]byte{0x02, 0x02}
)

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

// Commitment returns the version 1 coin commitment of F and v,
// K("ghost/coin-commitment/v1", COIN version 1, F, v as a 32-byte word).
func Commitment(f common.Hash, v *uint256.Int) common.Hash {
	return CommitmentVersion(Version, f, v)
}

// CommitmentVersion returns the coin commitment of F and v at a commitment
// format version, K("ghost/coin-commitment/v1", COIN, F, v as a 32-byte
// word), with COIN of that version: CoinV2 for SaltedCommitVersion, Coin for
// version 1.
func CommitmentVersion(version uint16, f common.Hash, v *uint256.Int) common.Hash {
	typ := Coin
	if version == SaltedCommitVersion {
		typ = CoinV2
	}
	return ghosttree.K(TagCommitment, typ[:], f[:], amountWord(v))
}

// DataCommitment returns the version 1 data commitment of F_d,
// K("ghost/data-commitment/v1", DATA version 1, F_d). It carries no amount.
func DataCommitment(f common.Hash) common.Hash {
	return DataCommitmentVersion(Version, f)
}

// DataCommitmentVersion returns the data commitment of F_d at a commitment
// format version, K("ghost/data-commitment/v1", DATA, F_d), with DATA of that
// version: DataV2 for SaltedCommitVersion, Data for version 1.
func DataCommitmentVersion(version uint16, f common.Hash) common.Hash {
	typ := Data
	if version == SaltedCommitVersion {
		typ = DataV2
	}
	return ghosttree.K(TagDataCommitment, typ[:], f[:])
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

// FeeSteps is the number of worst-case growth steps of the base fee above
// the window's reference base fee in the window price (spec 07, section 4).
const FeeSteps = 1

// Fee is the fee of a reveal in one fee window. WindowFee gives the nominal
// split, Burn the base part and Tip the nominal tip; Cover gives the split of
// one including block.
type Fee struct {
	Price    *uint256.Int // U_FeeSteps, the price per gas
	BasePart *uint256.Int // G_PRIV times the price
	Burn     *uint256.Int // credited to nobody: G_PRIV * max(price, base fee)
	Tip      *uint256.Int // to the coinbase: the total less the burn
	Total    *uint256.Int // base part plus nominal tip, the payload's fee field
}

// ErrBaseFee is returned for a reference base fee that is missing, negative
// or too large to price.
var ErrBaseFee = errors.New("reference base fee out of range")

// ErrRevealCover is returned, wrapped in ErrRevealFee, for a reveal whose
// fee cannot pay G_PRIV times the including block's base fee.
var ErrRevealCover = errors.New("fee below the cover limit of the base fee")

// Cover applies the cover rule of spec 07, section 5, to the window fee f
// in a block with base fee beta: burn = G_PRIV * max(price, beta) and tip =
// total - burn. A negative tip is ErrRevealCover; a missing or unpriceable
// base fee is ErrBaseFee. The tip is never above the nominal tip.
func (f Fee) Cover(beta *big.Int) (Fee, error) {
	if beta == nil || beta.Sign() < 0 {
		return Fee{}, ErrBaseFee
	}
	b, overflow := uint256.FromBig(beta)
	if overflow {
		return Fee{}, fmt.Errorf("%w: base fee %v", ErrRevealCover, beta)
	}
	if b.Lt(f.Price) {
		b = f.Price
	}
	burn, overflow := new(uint256.Int).MulOverflow(uint256.NewInt(GasPriv), b)
	if overflow || burn.Gt(f.Total) {
		return Fee{}, fmt.Errorf("%w: base fee %v, fee %v", ErrRevealCover, beta, f.Total)
	}
	out := f
	out.Burn = burn
	out.Tip = new(uint256.Int).Sub(f.Total, burn)
	return out, nil
}

// WindowFee returns the fee of every reveal in a window whose first block has
// the base fee bRef: U0 = bRef, U(j+1) = U(j) + floor(U(j)/8) +
// floor(U(j)/20000) + 1, price = U(FeeSteps), base part = G_PRIV * price,
// tip = ceil(base part / 10), fee = base part + tip.
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
	for range FeeSteps {
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
	return Fee{Price: u, BasePart: base, Burn: base, Tip: tip, Total: total}, nil
}

// WindowStart returns the height of the first block of the fee window of a
// block at height h, 4 * floor(h / 4).
func WindowStart(h uint64) uint64 { return h / 4 * 4 }
