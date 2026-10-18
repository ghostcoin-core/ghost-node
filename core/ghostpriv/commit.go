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

package ghostpriv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// CommitDataSize is the length of a commit's data: the version (2 bytes), F
// (32) and the note (156).
const CommitDataSize = 2 + 32 + NoteSize

var (
	// ErrCommitData is returned for commit data that is not exactly
	// CommitDataSize bytes of version 1.
	ErrCommitData = errors.New("commit data is not 190 bytes of version 1")

	// ErrCommitZeroF is returned for an all-zero F.
	ErrCommitZeroF = errors.New("commit F is zero")

	// ErrCommitAmount is returned for a commit value of 0 or above V_MAX.
	ErrCommitAmount = errors.New("commit value not between 1 and V_MAX")

	// ErrCommitFunds is returned when the sender cannot pay the value.
	ErrCommitFunds = errors.New("insufficient funds for the commit value")

	// ErrCommitTree is returned when the coin tree cannot take the
	// commitment.
	ErrCommitTree = errors.New("coin tree cannot take the commitment")
)

// Commit is a parsed commit: the value burned, the F the commitment binds it
// to and the note stored with the leaf.
type Commit struct {
	F     common.Hash
	Value *uint256.Int
	Note  [NoteSize]byte
}

// Commitment is the commitment the node records for the commit.
func (c *Commit) Commitment() common.Hash { return Commitment(c.F, c.Value) }

// CommitData returns the data of a commit transaction: version 1, F and the
// note, exactly CommitDataSize bytes.
func CommitData(f common.Hash, note []byte) ([]byte, error) {
	if len(note) != NoteSize {
		return nil, fmt.Errorf("note of %d bytes, want %d", len(note), NoteSize)
	}
	data := make([]byte, 0, CommitDataSize)
	data = binary.BigEndian.AppendUint16(data, Version)
	data = append(data, f[:]...)
	return append(data, note...), nil
}

// ParseCommit checks the data and value of a top-level call to the commit
// entry address, in the order of the coin rules: exactly 190 bytes of
// version 1 (ErrCommitData), F not zero (ErrCommitZeroF), then 1 <= value <=
// V_MAX (ErrCommitAmount). The commitment is computed from F and the value;
// nothing in the data can set it.
func ParseCommit(data []byte, value *big.Int) (*Commit, error) {
	if len(data) != CommitDataSize || binary.BigEndian.Uint16(data[:2]) != Version {
		return nil, fmt.Errorf("%w: %d bytes", ErrCommitData, len(data))
	}
	c := &Commit{F: common.BytesToHash(data[2:34])}
	copy(c.Note[:], data[34:])
	if c.F == (common.Hash{}) {
		return nil, ErrCommitZeroF
	}
	if value == nil || value.Sign() <= 0 {
		return nil, ErrCommitAmount
	}
	v, overflow := uint256.FromBig(value)
	if overflow || v.Gt(VMax) {
		return nil, ErrCommitAmount
	}
	c.Value = v
	return c, nil
}

// ApplyCommit makes the one atomic change of a commit sent by from in the
// block at height: it debits the value from the sender and credits it to
// nobody, appends the commitment to the coin tree with the receipt log, and
// adds the value to the total in. The caller has checked the commit with
// ParseCommit and taken the gas. On an error nothing is changed.
func ApplyCommit(st StateDB, height uint64, from common.Address, c *Commit) error {
	if c == nil || c.Value == nil {
		return ErrCommitAmount
	}
	if st.GetBalance(from).Lt(c.Value) {
		return fmt.Errorf("%w: address %v", ErrCommitFunds, from.Hex())
	}
	leaf := c.Commitment()
	snap := st.Snapshot()
	res, err := ghosttree.Append(st, ghosttree.Coin, height, leaf)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCommitTree, err)
	}
	loc, err := receiptLocation(res)
	if err != nil {
		st.RevertToSnapshot(snap)
		return fmt.Errorf("%w: %w", ErrCommitTree, err)
	}
	if err := addTotal(st, SlotTotalIn, c.Value); err != nil {
		st.RevertToSnapshot(snap)
		return err
	}
	st.SubBalance(from, c.Value)

	data := make([]byte, 0, 8+32+32+NoteSize)
	data = append(data, loc...)
	data = append(data, leaf[:]...)
	data = append(data, amountWord(c.Value)...)
	data = append(data, c.Note[:]...)
	st.AddLog(&types.Log{
		Address:     ghosttree.TreeAccount(ghosttree.Coin),
		Topics:      []common.Hash{ghosttree.K(TagCommitReceipt)},
		Data:        data,
		BlockNumber: height,
	})
	return nil
}

var (
	// ErrDataCommitValue is returned for a data commit with a value other
	// than 0: a data commit moves no value.
	ErrDataCommitValue = errors.New("data commit value is not 0")

	// ErrDataCommitTree is returned when the data tree cannot take the
	// commitment.
	ErrDataCommitTree = errors.New("data tree cannot take the commitment")
)

// DataCommit is a parsed data commit: the F_d the commitment binds and the
// note stored with the leaf. It holds no amount.
type DataCommit struct {
	F    common.Hash
	Note [NoteSize]byte
}

// Commitment is the data commitment the node records for the data commit.
func (c *DataCommit) Commitment() common.Hash { return DataCommitment(c.F) }

// ParseDataCommit checks the data and value of a top-level call to the data
// commit entry address, in this order: exactly 190 bytes of version 1, the
// layout of a coin commit (ErrCommitData), F not zero (ErrCommitZeroF), then
// a value of exactly 0 (ErrDataCommitValue). The commitment is computed from
// F; nothing in the data can set it.
func ParseDataCommit(data []byte, value *big.Int) (*DataCommit, error) {
	if len(data) != CommitDataSize || binary.BigEndian.Uint16(data[:2]) != Version {
		return nil, fmt.Errorf("%w: %d bytes", ErrCommitData, len(data))
	}
	c := &DataCommit{F: common.BytesToHash(data[2:34])}
	copy(c.Note[:], data[34:])
	if c.F == (common.Hash{}) {
		return nil, ErrCommitZeroF
	}
	if value == nil || value.Sign() != 0 {
		return nil, fmt.Errorf("%w: %v", ErrDataCommitValue, value)
	}
	return c, nil
}

// ApplyDataCommit makes the one change of a data commit in the block at
// height: it appends the data commitment to the data tree with the receipt
// log. It moves no value and touches neither the coin tree nor the totals.
// The caller has checked the data commit with ParseDataCommit and taken the
// gas. On an error nothing is changed.
func ApplyDataCommit(st StateDB, height uint64, c *DataCommit) error {
	if c == nil {
		return ErrCommitData
	}
	leaf := c.Commitment()
	snap := st.Snapshot()
	res, err := ghosttree.Append(st, ghosttree.Data, height, leaf)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDataCommitTree, err)
	}
	loc, err := receiptLocation(res)
	if err != nil {
		st.RevertToSnapshot(snap)
		return fmt.Errorf("%w: %w", ErrDataCommitTree, err)
	}

	data := make([]byte, 0, 8+32+NoteSize)
	data = append(data, loc...)
	data = append(data, leaf[:]...)
	data = append(data, c.Note[:]...)
	st.AddLog(&types.Log{
		Address:     ghosttree.TreeAccount(ghosttree.Data),
		Topics:      []common.Hash{ghosttree.K(TagDataCommitReceipt)},
		Data:        data,
		BlockNumber: height,
	})
	return nil
}
