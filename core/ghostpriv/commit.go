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
	// CommitDataSize is the length of the old version 1 commit data: the
	// version (2 bytes), F (32) and the note. The node refuses it from
	// genesis: two version 1 commits to one key share a marker, so the
	// second coin could never be revealed.
	CommitDataSize = 2 + 32 + NoteSize

	// SaltedCommitDataSize is the length of salted commit data, version 3:
	// the version (2 bytes), F (32), the salt (16), the note (380) and the
	// lookup tag (16), 446 bytes.
	SaltedCommitDataSize = 2 + 32 + SaltSize + NoteSize + LookupTagSize

	// LookupTagSize is the length of the lookup tag a commit and a data
	// commit carry after the note.
	LookupTagSize = ghosttree.LookupTagSize

	// oldCommitNoteSize is the length of the note of a version 2 commit,
	// before notes grew to NoteSize. The node refuses such commits now
	// (ErrCommitData), but the test chain holds some from before, and their
	// 244-byte receipt logs must still enter the tree history.
	oldCommitNoteSize = 156

	// oldSaltedCommitLogSize is the length of the receipt log of a version 2
	// salted commit with an oldCommitNoteSize note: location (8), leaf (32),
	// amount (32), the note (156) and the salt (16), 244 bytes.
	oldSaltedCommitLogSize = 8 + 32 + 32 + oldCommitNoteSize + SaltSize
)

var (
	// ErrCommitData is returned for commit data that is not exactly
	// SaltedCommitDataSize bytes of SaltedCommitVersion: the version 1 and
	// version 2 layouts, the 430 bytes without a lookup tag, and any other
	// length, included.
	ErrCommitData = errors.New("commit data is not 446 bytes of version 3")

	// ErrCommitZeroF is returned for an all-zero F.
	ErrCommitZeroF = errors.New("commit F is zero")

	// ErrCommitLookupTag is returned for commit data whose lookup tag is 16
	// zero bytes, the tag of the lookup index's sentinel.
	ErrCommitLookupTag = errors.New("commit lookup tag is zero")

	// ErrCommitAmount is returned for a commit value of 0 or above V_MAX.
	ErrCommitAmount = errors.New("commit value not between 1 and V_MAX")

	// ErrCommitFunds is returned when the sender cannot pay the value.
	ErrCommitFunds = errors.New("insufficient funds for the commit value")

	// ErrCommitTree is returned when the coin tree cannot take the
	// commitment.
	ErrCommitTree = errors.New("coin tree cannot take the commitment")
)

// Commit is a parsed commit: the value burned, the F the commitment binds it
// to, the note stored with the leaf, for salted commit data the salt stored
// with it (nil for version 1 data), and the lookup tag its leaf takes in the
// coin lookup index; a zero tag, which no commit data carries, gives the
// leaf no entry, as for the recommit of an escrow slot.
type Commit struct {
	F     common.Hash
	Value *uint256.Int
	Note  [NoteSize]byte
	Salt  *[SaltSize]byte
	Tag   ghosttree.LookupTag
}

// CommitVersion is the commitment format version of the commit's data:
// SaltedCommitVersion for salted data, Version for version 1 data.
func (c *Commit) CommitVersion() uint16 { return commitVersion(c.Salt) }

// Commitment is the commitment the node records for the commit, with the
// COIN type of the commit data's version. The salt is not an input: it is
// already in F.
func (c *Commit) Commitment() common.Hash {
	return CommitmentVersion(c.CommitVersion(), c.F, c.Value)
}

// commitVersion is the commitment format version of parsed commit data, told
// by its salt: data with a salt is SaltedCommitVersion, data without one
// version 1.
func commitVersion(salt *[SaltSize]byte) uint16 {
	if salt != nil {
		return SaltedCommitVersion
	}
	return Version
}

// LookupCommitData returns the salted data of a commit or data commit
// transaction: SaltedCommitVersion, F, the salt, the note and the lookup
// tag, exactly SaltedCommitDataSize bytes. A tag that is not
// LookupTagSize bytes, or is all zero, is an error.
func LookupCommitData(f common.Hash, salt []byte, note []byte, tag []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt of %d bytes, want %d", len(salt), SaltSize)
	}
	if len(note) != NoteSize {
		return nil, fmt.Errorf("note of %d bytes, want %d", len(note), NoteSize)
	}
	if len(tag) != LookupTagSize {
		return nil, fmt.Errorf("lookup tag of %d bytes, want %d", len(tag), LookupTagSize)
	}
	if ghosttree.LookupTag(tag).IsZero() {
		return nil, ErrCommitLookupTag
	}
	data := make([]byte, 0, SaltedCommitDataSize)
	data = binary.BigEndian.AppendUint16(data, SaltedCommitVersion)
	data = append(data, f[:]...)
	data = append(data, salt...)
	data = append(data, note...)
	return append(data, tag...), nil
}

// SaltedCommitData is LookupCommitData with the tag FallbackLookupTag(f),
// for a sender that keeps no lookup key. A wallet that finds its notes
// through the lookup index passes the tag of its own key to
// LookupCommitData instead.
func SaltedCommitData(f common.Hash, salt []byte, note []byte) ([]byte, error) {
	tag := FallbackLookupTag(f)
	return LookupCommitData(f, salt, note, tag[:])
}

// FallbackLookupTag is the lookup tag SaltedCommitData gives a commitment to
// f: DeriveLookupTag with f as the key and index 0. It is never zero in
// practice, and anyone who sees f can compute it.
func FallbackLookupTag(f common.Hash) ghosttree.LookupTag {
	return ghosttree.DeriveLookupTag(f, 0)
}

// parseCommitData splits commit data into F, the salt, the note and the
// lookup tag: exactly SaltedCommitDataSize bytes of SaltedCommitVersion.
// Anything else, the version 1 layout, the 206 bytes of version 2 with a
// 156-byte note and the 430 bytes without a tag included, is ErrCommitData.
func parseCommitData(data []byte) (f common.Hash, salt *[SaltSize]byte, note [NoteSize]byte, tag ghosttree.LookupTag, err error) {
	var version uint16
	if len(data) >= 2 {
		version = binary.BigEndian.Uint16(data[:2])
	}
	switch {
	case len(data) == SaltedCommitDataSize && version == SaltedCommitVersion:
		salt = new([SaltSize]byte)
		copy(salt[:], data[34:34+SaltSize])
		copy(note[:], data[34+SaltSize:34+SaltSize+NoteSize])
		copy(tag[:], data[34+SaltSize+NoteSize:])
	default:
		return common.Hash{}, nil, note, tag, fmt.Errorf("%w: %d bytes", ErrCommitData, len(data))
	}
	return common.BytesToHash(data[2:34]), salt, note, tag, nil
}

// ParseCommit checks the data and value of a top-level call to the commit
// entry address, in the order of the coin rules: exactly 446 bytes of
// version 3 (ErrCommitData), F not zero (ErrCommitZeroF), the lookup tag not
// zero (ErrCommitLookupTag), then 1 <= value <= V_MAX (ErrCommitAmount).
// The commitment is computed from F and the value; nothing in the data can
// set it, the salt only rides along to the receipt and the history, and the
// tag goes into the coin lookup index with the leaf.
func ParseCommit(data []byte, value *big.Int) (*Commit, error) {
	f, salt, note, tag, err := parseCommitData(data)
	if err != nil {
		return nil, err
	}
	c := &Commit{F: f, Note: note, Salt: salt, Tag: tag}
	if c.F == (common.Hash{}) {
		return nil, ErrCommitZeroF
	}
	if c.Tag.IsZero() {
		return nil, ErrCommitLookupTag
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
	if err := appendCommit(st, height, c); err != nil {
		return err
	}
	st.SubBalance(from, c.Value)
	return nil
}

// appendCommit makes the effects of a commit but the burn, commit step 10 of
// spec 03 without the debit: it appends the commitment to the coin tree with
// the receipt log, which carries the note and the salt, puts its lookup tag
// into the coin lookup index, and adds the value to the total in. On an
// error nothing is changed.
func appendCommit(st StateDB, height uint64, c *Commit) error {
	leaf := c.Commitment()
	snap := st.Snapshot()
	res, err := ghosttree.AppendTagged(st, ghosttree.Coin, height, leaf, c.Tag)
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
	// than DataReserve: a data commit burns exactly the fee reserve.
	ErrDataCommitValue = errors.New("data commit value is not the data reserve")

	// ErrDataCommitTree is returned when the data tree cannot take the
	// commitment.
	ErrDataCommitTree = errors.New("data tree cannot take the commitment")
)

// DataCommit is a parsed data commit: the F_d the commitment binds, the note
// stored with the leaf, for salted commit data the salt stored with it (nil
// for version 1 data), and the lookup tag its leaf takes in the data lookup
// index. It holds no amount: the value of every data commit is DataReserve.
type DataCommit struct {
	F    common.Hash
	Note [NoteSize]byte
	Salt *[SaltSize]byte
	Tag  ghosttree.LookupTag
}

// CommitVersion is the commitment format version of the data commit's data:
// SaltedCommitVersion for salted data, Version for version 1 data.
func (c *DataCommit) CommitVersion() uint16 { return commitVersion(c.Salt) }

// Commitment is the data commitment the node records for the data commit,
// with the DATA type of the commit data's version. The salt is not an input:
// it is already in F_d.
func (c *DataCommit) Commitment() common.Hash {
	return DataCommitmentVersion(c.CommitVersion(), c.F)
}

// ParseDataCommit checks the data and value of a top-level call to the data
// commit entry address, in this order: exactly 446 bytes of version 3, the
// layout of a coin commit (ErrCommitData), F not zero (ErrCommitZeroF), the
// lookup tag not zero (ErrCommitLookupTag), then a value of exactly
// DataReserve (ErrDataCommitValue). The commitment is computed from F and
// the reserve; nothing in the data can set it.
func ParseDataCommit(data []byte, value *big.Int) (*DataCommit, error) {
	f, salt, note, tag, err := parseCommitData(data)
	if err != nil {
		return nil, err
	}
	c := &DataCommit{F: f, Note: note, Salt: salt, Tag: tag}
	if c.F == (common.Hash{}) {
		return nil, ErrCommitZeroF
	}
	if c.Tag.IsZero() {
		return nil, ErrCommitLookupTag
	}
	if value == nil || value.Cmp(DataReserve.ToBig()) != 0 {
		return nil, fmt.Errorf("%w: %v", ErrDataCommitValue, value)
	}
	return c, nil
}

// ApplyDataCommit makes the one atomic change of a data commit sent by from
// in the block at height: it debits DataReserve from the sender and credits
// it to nobody, appends the data commitment to the data tree with the receipt
// log, and adds the reserve to the total in. It touches no coin tree. The
// caller has checked the data commit with ParseDataCommit and taken the gas.
// On an error nothing is changed.
func ApplyDataCommit(st StateDB, height uint64, from common.Address, c *DataCommit) error {
	if c == nil {
		return ErrCommitData
	}
	if st.GetBalance(from).Lt(DataReserve) {
		return fmt.Errorf("%w: address %v", ErrCommitFunds, from.Hex())
	}
	leaf := c.Commitment()
	snap := st.Snapshot()
	res, err := ghosttree.AppendTagged(st, ghosttree.Data, height, leaf, c.Tag)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDataCommitTree, err)
	}
	loc, err := receiptLocation(res)
	if err != nil {
		st.RevertToSnapshot(snap)
		return fmt.Errorf("%w: %w", ErrDataCommitTree, err)
	}
	if err := addTotal(st, SlotTotalIn, DataReserve); err != nil {
		st.RevertToSnapshot(snap)
		return err
	}
	st.SubBalance(from, DataReserve)

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
	topicCommit       = ghosttree.K(TagCommitReceipt)
	topicReveal       = ghosttree.K(TagRevealReceipt)
	topicPolicyReveal = ghosttree.K(TagPolicyRevealReceipt)
	topicDataCommit   = ghosttree.K(TagDataCommitReceipt)
	topicDataReveal   = ghosttree.K(TagDataRevealReceipt)
)

// HistoryRecords returns the tree history records of a block from its
// receipts, in the order the block wrote them: the leaf, tree index,
// position and note of every commit (whose 156-byte note, for the 244-byte
// log of a commit made before notes were NoteSize bytes, is zero-padded on the
// right to NoteSize), reveal remainder (whose 156-byte note, for a version 1
// reveal, is zero-padded on the right to NoteSize), policy
// reveal remainder and data commit (with the salt of a salted commit or data
// commit, whose log carries it after the note), and the marker of every
// reveal, policy reveal and data reveal as a record of ghosttree.CoinMarkers
// or ghosttree.DataMarkers. Only the coin and data rules write logs from the
// tree accounts, which hold no code; a log of a tree account that is not one
// of their receipt logs is ErrReceiptLog.
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
			case l.Address == coinAccount && topic == topicCommit && len(l.Topics) == 1 && len(d) == oldSaltedCommitLogSize:
				// A salted commit from before notes were NoteSize bytes: the
				// leaf it appended is in the log, as in a new one, and the
				// record holds its 156-byte note zero-padded on the right to
				// NoteSize. The note is no input of the leaf or the root.
				out = append(out, salted(ghosttree.Coin, d, d[72:72+oldCommitNoteSize]))
			case l.Address == coinAccount && topic == topicReveal && len(l.Topics) == 2 && len(d) == revealLogSize:
				out = append(out, leaf(ghosttree.Coin, d, d[40:40+NoteSize]))
				out = append(out, ghosttree.Record{Kind: ghosttree.CoinMarkers, Leaf: l.Topics[1]})
			case l.Address == coinAccount && topic == topicReveal && len(l.Topics) == 2 && len(d) == revealLogSizeV1:
				// The version 1 reveal carries a RevealNoteSize note; the
				// record holds it zero-padded on the right to NoteSize.
				out = append(out, leaf(ghosttree.Coin, d, d[40:40+RevealNoteSize]))
				out = append(out, ghosttree.Record{Kind: ghosttree.CoinMarkers, Leaf: l.Topics[1]})
			case l.Address == coinAccount && topic == topicPolicyReveal && len(l.Topics) == 2 && len(d) == policyRevealLogSize:
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
