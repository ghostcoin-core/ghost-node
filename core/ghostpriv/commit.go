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

const (
	// CommitDataSize is the length of version 1 commit data: the version (2
	// bytes), F (32) and the note (156).
	CommitDataSize = 2 + 32 + NoteSize

	// SaltedCommitDataSize is the length of salted commit data, version 2:
	// the version (2 bytes), F (32), the salt (16) and the note (156).
	SaltedCommitDataSize = 2 + 32 + SaltSize + NoteSize
)

var (
	// ErrCommitData is returned for commit data that is neither exactly
	// CommitDataSize bytes of version 1 nor exactly SaltedCommitDataSize
	// bytes of SaltedCommitVersion.
	ErrCommitData = errors.New("commit data is not 190 bytes of version 1 or 206 bytes of version 2")

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
// to, the note stored with the leaf and, for salted commit data, the salt
// stored with it (nil for version 1 data).
type Commit struct {
	F     common.Hash
	Value *uint256.Int
	Note  [NoteSize]byte
	Salt  *[SaltSize]byte
}

// Commitment is the commitment the node records for the commit. The salt is
// not an input: it is already in F.
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

// SaltedCommitData returns the salted data of a commit or data commit
// transaction: SaltedCommitVersion, F, the salt and the note, exactly
// SaltedCommitDataSize bytes.
func SaltedCommitData(f common.Hash, salt []byte, note []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt of %d bytes, want %d", len(salt), SaltSize)
	}
	if len(note) != NoteSize {
		return nil, fmt.Errorf("note of %d bytes, want %d", len(note), NoteSize)
	}
	data := make([]byte, 0, SaltedCommitDataSize)
	data = binary.BigEndian.AppendUint16(data, SaltedCommitVersion)
	data = append(data, f[:]...)
	data = append(data, salt...)
	return append(data, note...), nil
}

// parseCommitData splits commit data of either layout into F, the salt (nil
// for version 1) and the note: exactly CommitDataSize bytes of Version, or
// exactly SaltedCommitDataSize bytes of SaltedCommitVersion. Anything else is
// ErrCommitData.
func parseCommitData(data []byte) (f common.Hash, salt *[SaltSize]byte, note [NoteSize]byte, err error) {
	var version uint16
	if len(data) >= 2 {
		version = binary.BigEndian.Uint16(data[:2])
	}
	switch {
	case len(data) == CommitDataSize && version == Version:
		copy(note[:], data[34:])
	case len(data) == SaltedCommitDataSize && version == SaltedCommitVersion:
		salt = new([SaltSize]byte)
		copy(salt[:], data[34:34+SaltSize])
		copy(note[:], data[34+SaltSize:])
	default:
		return common.Hash{}, nil, note, fmt.Errorf("%w: %d bytes", ErrCommitData, len(data))
	}
	return common.BytesToHash(data[2:34]), salt, note, nil
}

// ParseCommit checks the data and value of a top-level call to the commit
// entry address, in the order of the coin rules: exactly 190 bytes of
// version 1 or exactly 206 bytes of version 2 (ErrCommitData), F not zero
// (ErrCommitZeroF), then 1 <= value <= V_MAX (ErrCommitAmount). The
// commitment is computed from F and the value; nothing in the data can set
// it, and the salt only rides along to the receipt and the history.
func ParseCommit(data []byte, value *big.Int) (*Commit, error) {
	f, salt, note, err := parseCommitData(data)
	if err != nil {
		return nil, err
	}
	c := &Commit{F: f, Note: note, Salt: salt}
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

	data := make([]byte, 0, 8+32+32+NoteSize+SaltSize)
	data = append(data, loc...)
	data = append(data, leaf[:]...)
	data = append(data, amountWord(c.Value)...)
	data = append(data, c.Note[:]...)
	if c.Salt != nil {
		data = append(data, c.Salt[:]...)
	}
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

// DataCommit is a parsed data commit: the F_d the commitment binds, the note
// stored with the leaf and, for salted commit data, the salt stored with it
// (nil for version 1 data). It holds no amount.
type DataCommit struct {
	F    common.Hash
	Note [NoteSize]byte
	Salt *[SaltSize]byte
}

// Commitment is the data commitment the node records for the data commit.
// The salt is not an input: it is already in F_d.
func (c *DataCommit) Commitment() common.Hash { return DataCommitment(c.F) }

// ParseDataCommit checks the data and value of a top-level call to the data
// commit entry address, in this order: exactly 190 bytes of version 1 or
// exactly 206 bytes of version 2, the layouts of a coin commit
// (ErrCommitData), F not zero (ErrCommitZeroF), then a value of exactly 0
// (ErrDataCommitValue). The commitment is computed from F; nothing in the
// data can set it.
func ParseDataCommit(data []byte, value *big.Int) (*DataCommit, error) {
	f, salt, note, err := parseCommitData(data)
	if err != nil {
		return nil, err
	}
	c := &DataCommit{F: f, Note: note, Salt: salt}
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

	data := make([]byte, 0, 8+32+NoteSize+SaltSize)
	data = append(data, loc...)
	data = append(data, leaf[:]...)
	data = append(data, c.Note[:]...)
	if c.Salt != nil {
		data = append(data, c.Salt[:]...)
	}
	st.AddLog(&types.Log{
		Address:     ghosttree.TreeAccount(ghosttree.Data),
		Topics:      []common.Hash{ghosttree.K(TagDataCommitReceipt)},
		Data:        data,
		BlockNumber: height,
	})
	return nil
}

// ErrReceiptLog is returned for a log of a tree account that is not a
// well-formed receipt log of a commit, reveal, data commit or data reveal.
var ErrReceiptLog = errors.New("tree account log is not a receipt of the coin or data rules")

var (
	topicCommit     = ghosttree.K(TagCommitReceipt)
	topicReveal     = ghosttree.K(TagRevealReceipt)
	topicDataCommit = ghosttree.K(TagDataCommitReceipt)
	topicDataReveal = ghosttree.K(TagDataRevealReceipt)
)

// HistoryRecords returns the tree history records of a block from its
// receipts, in the order the block wrote them: the leaf, tree index,
// position and note of every commit, reveal remainder and data commit (with
// the salt of a salted commit or data commit, whose log carries it after the
// note), and
// the marker of every reveal and data reveal as a record of
// ghosttree.CoinMarkers or ghosttree.DataMarkers. Only the coin and data rules
// write logs from the tree accounts, which hold no code; a log of a tree
// account that is not one of their receipt logs is ErrReceiptLog.
func HistoryRecords(receipts types.Receipts) ([]ghosttree.Record, error) {
	var (
		coinAccount = ghosttree.TreeAccount(ghosttree.Coin)
		dataAccount = ghosttree.TreeAccount(ghosttree.Data)
		out         []ghosttree.Record
	)
	const (
		commitLog     = 8 + 32 + 32 + NoteSize
		dataCommitLog = 8 + 32 + NoteSize
	)
	leaf := func(kind ghosttree.Kind, data []byte, note []byte) ghosttree.Record {
		r := ghosttree.Record{
			Kind:      kind,
			TreeIndex: uint64(binary.BigEndian.Uint32(data[:4])),
			Position:  binary.BigEndian.Uint32(data[4:8]),
			Leaf:      common.BytesToHash(data[8:40]),
		}
		copy(r.Note[:], note)
		return r
	}
	// salted is the leaf of a salted commit log, whose salt follows the note.
	salted := func(kind ghosttree.Kind, data []byte, note []byte) ghosttree.Record {
		r := leaf(kind, data, note)
		r.Salt = new([SaltSize]byte)
		copy(r.Salt[:], data[len(data)-SaltSize:])
		return r
	}
	for i, receipt := range receipts {
		for j, l := range receipt.Logs {
			if l.Address != coinAccount && l.Address != dataAccount {
				continue
			}
			var topic common.Hash
			if len(l.Topics) > 0 {
				topic = l.Topics[0]
			}
			d := l.Data
			switch {
			case l.Address == coinAccount && topic == topicCommit && len(l.Topics) == 1 && len(d) == commitLog:
				out = append(out, leaf(ghosttree.Coin, d, d[72:]))
			case l.Address == coinAccount && topic == topicCommit && len(l.Topics) == 1 && len(d) == commitLog+SaltSize:
				out = append(out, salted(ghosttree.Coin, d, d[72:72+NoteSize]))
			case l.Address == coinAccount && topic == topicReveal && len(l.Topics) == 2 && len(d) == 8+32+NoteSize+20+32:
				out = append(out, leaf(ghosttree.Coin, d, d[40:40+NoteSize]))
				out = append(out, ghosttree.Record{Kind: ghosttree.CoinMarkers, Leaf: l.Topics[1]})
			case l.Address == dataAccount && topic == topicDataCommit && len(l.Topics) == 1 && len(d) == dataCommitLog:
				out = append(out, leaf(ghosttree.Data, d, d[40:]))
			case l.Address == dataAccount && topic == topicDataCommit && len(l.Topics) == 1 && len(d) == dataCommitLog+SaltSize:
				out = append(out, salted(ghosttree.Data, d, d[40:40+NoteSize]))
			case l.Address == dataAccount && topic == topicDataReveal && len(l.Topics) == 2 && len(d) == 1+20:
				out = append(out, ghosttree.Record{Kind: ghosttree.DataMarkers, Leaf: l.Topics[1]})
			default:
				return nil, fmt.Errorf("%w: receipt %d, log %d", ErrReceiptLog, i, j)
			}
		}
	}
	return out, nil
}
