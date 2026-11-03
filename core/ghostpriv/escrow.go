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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// Escrow slots (spec 10, sections 7.1, 7.3 and 7.5). A policy reveal with
// out > 0 opens the slot of its marker in the storage of ghost.EscrowAccount,
// holding out for the policy; the policy then pays, recommits or forfeits it,
// or an action debits it. Every change goes through the helpers of this file,
// which keep, for every slot and at all times,
//
//	out = remaining + paid + recommitted + action_debits + forfeited,
//
// and keep total_escrow, slot 2 of the totals account, equal to the sum of
// remaining over all slots, by the accounting table of section 7.3.
const (
	TagEscrowSlot        = "ghost/escrow-slot/v1"
	TagSlotOpened        = "ghost/slot-opened/v1"
	TagSlotPaid          = "ghost/slot-paid/v1"
	TagSlotRecommitted   = "ghost/slot-recommitted/v1"
	TagSlotClosed        = "ghost/slot-closed/v1"
	EscrowSlotWords      = 8       // the storage words of one slot
	SlotOpenGas          = 160_000 // SLOT_OPEN_GAS, eight new words, paid inside G_POLICY
	escrowAmountBytes    = 12      // an amount below 2^96
	escrowAccountedWords = 4       // words 0 to 3, kept on close
)

var (
	// ErrEscrowSlotExists is returned for opening a slot under a marker that
	// already has one, open or closed: a closed slot is never reopened.
	ErrEscrowSlotExists = errors.New("escrow slot already exists")

	// ErrEscrowSlotMissing is returned for a change of a slot that does not
	// exist, or that belongs to another policy.
	ErrEscrowSlotMissing = errors.New("no escrow slot of the policy")

	// ErrEscrowSlotClosed is returned for a change of a closed slot.
	ErrEscrowSlotClosed = errors.New("escrow slot closed")

	// ErrEscrowAmount is returned for an amount out of range: an opening out
	// not between 1 and V_MAX, a pay or recommit not between 1 and the
	// remaining value, or a debit above the remaining value.
	ErrEscrowAmount = errors.New("escrow amount out of range")

	// ErrEscrowDest is returned for a pay to a registered policy or a
	// reserved address.
	ErrEscrowDest = errors.New("escrow pay destination refused")
)

// EscrowSlot is the content of an escrow slot, its eight storage words.
// Amounts are below 2^96.
type EscrowSlot struct {
	// Word 0.
	Policy      common.Address // bytes 0 to 19
	Open        bool           // byte 20
	ActionNonce uint64         // bytes 21 to 28

	// Word 1.
	Remaining *uint256.Int // bytes 0 to 11
	Out       *uint256.Int // bytes 12 to 23
	Height    uint64       // bytes 24 to 31, of the opening block

	// Word 2.
	Timestamp   uint64       // bytes 0 to 7, of the opening block
	Paid        *uint256.Int // bytes 8 to 19
	Recommitted *uint256.Int // bytes 20 to 31

	// Word 3.
	ActionDebits *uint256.Int // bytes 0 to 11
	Forfeited    *uint256.Int // bytes 12 to 23

	// Words 4 to 7, cleared on close.
	ParamsHash common.Hash
	ActionTag  common.Hash
	ActionSalt common.Hash
	Instr      common.Hash
}

// EscrowSlotKey is the storage key of word i of the slot of marker in
// ghost.EscrowAccount: K("ghost/escrow-slot/v1", marker, i as one byte).
func EscrowSlotKey(marker common.Hash, i byte) common.Hash {
	return ghosttree.K(TagEscrowSlot, marker[:], []byte{i})
}

// Balanced reports whether the slot keeps the accounting identity: out =
// remaining + paid + recommitted + action_debits + forfeited.
func (s *EscrowSlot) Balanced() bool {
	sum := new(uint256.Int)
	for _, v := range []*uint256.Int{s.Remaining, s.Paid, s.Recommitted, s.ActionDebits, s.Forfeited} {
		if _, overflow := sum.AddOverflow(sum, amountOrZero(v)); overflow {
			return false
		}
	}
	return sum.Eq(amountOrZero(s.Out))
}

func amountOrZero(v *uint256.Int) *uint256.Int {
	if v == nil {
		return new(uint256.Int)
	}
	return v
}

// putAmount writes v, below 2^96, into the 12 bytes of b.
func putAmount(b []byte, v *uint256.Int) {
	w := amountOrZero(v).Bytes32()
	copy(b[:escrowAmountBytes], w[32-escrowAmountBytes:])
}

func getAmount(b []byte) *uint256.Int {
	return new(uint256.Int).SetBytes(b[:escrowAmountBytes])
}

// words returns the eight storage words of the slot.
func (s *EscrowSlot) words() [EscrowSlotWords]common.Hash {
	var w [EscrowSlotWords]common.Hash
	copy(w[0][0:20], s.Policy[:])
	if s.Open {
		w[0][20] = 1
	}
	binary.BigEndian.PutUint64(w[0][21:29], s.ActionNonce)
	putAmount(w[1][0:], s.Remaining)
	putAmount(w[1][12:], s.Out)
	binary.BigEndian.PutUint64(w[1][24:32], s.Height)
	binary.BigEndian.PutUint64(w[2][0:8], s.Timestamp)
	putAmount(w[2][8:], s.Paid)
	putAmount(w[2][20:], s.Recommitted)
	putAmount(w[3][0:], s.ActionDebits)
	putAmount(w[3][12:], s.Forfeited)
	w[4], w[5], w[6], w[7] = s.ParamsHash, s.ActionTag, s.ActionSalt, s.Instr
	return w
}

// slotFromWords decodes the eight storage words of a slot.
func slotFromWords(w [EscrowSlotWords]common.Hash) *EscrowSlot {
	return &EscrowSlot{
		Policy:       common.BytesToAddress(w[0][0:20]),
		Open:         w[0][20] == 1,
		ActionNonce:  binary.BigEndian.Uint64(w[0][21:29]),
		Remaining:    getAmount(w[1][0:]),
		Out:          getAmount(w[1][12:]),
		Height:       binary.BigEndian.Uint64(w[1][24:32]),
		Timestamp:    binary.BigEndian.Uint64(w[2][0:8]),
		Paid:         getAmount(w[2][8:]),
		Recommitted:  getAmount(w[2][20:]),
		ActionDebits: getAmount(w[3][0:]),
		Forfeited:    getAmount(w[3][12:]),
		ParamsHash:   w[4],
		ActionTag:    w[5],
		ActionSalt:   w[6],
		Instr:        w[7],
	}
}

// ReadEscrowSlot returns the slot of marker, and false when no slot was ever
// opened under it. A closed slot is returned with Open false.
func ReadEscrowSlot(st StateDB, marker common.Hash) (*EscrowSlot, bool) {
	var w [EscrowSlotWords]common.Hash
	for i := range w {
		w[i] = st.GetState(ghost.EscrowAccount, EscrowSlotKey(marker, byte(i)))
	}
	// An opened slot has out >= 1 in word 1 for good: a close keeps words 0
	// to 3.
	exists := false
	for i := 0; i < escrowAccountedWords; i++ {
		if w[i] != (common.Hash{}) {
			exists = true
		}
	}
	if !exists {
		return nil, false
	}
	return slotFromWords(w), true
}

// writeEscrowSlot writes the words of s that differ from old, nil for a new
// slot. The escrow account gets nonce 1 when it is first written, so that the
// empty-account cleanup never deletes it.
func writeEscrowSlot(st StateDB, marker common.Hash, old, s *EscrowSlot) {
	if !st.Exist(ghost.EscrowAccount) {
		st.CreateAccount(ghost.EscrowAccount)
	}
	if st.GetNonce(ghost.EscrowAccount) == 0 {
		st.SetNonce(ghost.EscrowAccount, 1)
	}
	var before [EscrowSlotWords]common.Hash
	if old != nil {
		before = old.words()
	}
	for i, w := range s.words() {
		if w != before[i] {
			st.SetState(ghost.EscrowAccount, EscrowSlotKey(marker, byte(i)), w)
		}
	}
}

// slotLog writes a slot log from the escrow account: topic 0 is K(name),
// topic 1 the marker, and the data the 32-byte words given.
func slotLog(st StateDB, name string, marker common.Hash, height uint64, words ...[]byte) {
	data := make([]byte, 0, 32*len(words))
	for _, w := range words {
		data = append(data, common.LeftPadBytes(w, 32)...)
	}
	st.AddLog(&types.Log{
		Address:     ghost.EscrowAccount,
		Topics:      []common.Hash{ghosttree.K(name), marker},
		Data:        data,
		BlockNumber: height,
	})
}

// OpenEscrowSlot opens the slot of marker for s.Policy with remaining = out
// = s.Out, which must be between 1 and V_MAX, and the opening block's height
// and timestamp, parameters, action tag and salt and instruction of s; every
// other field of s is ignored. It applies the opening row of the accounting
// table: total_out and total_escrow each rise by out; the policy reveal that
// opens the slot adds its fee to total_out itself. It writes the slot-opened
// log. A marker that already has a slot, open or closed, is
// ErrEscrowSlotExists. On an error nothing is changed.
func OpenEscrowSlot(st StateDB, marker common.Hash, s *EscrowSlot) error {
	if s == nil || s.Out == nil || s.Out.IsZero() || s.Out.Gt(VMax) {
		return fmt.Errorf("%w: out of an opening", ErrEscrowAmount)
	}
	if _, ok := ReadEscrowSlot(st, marker); ok {
		return fmt.Errorf("%w: %x", ErrEscrowSlotExists, marker)
	}
	slot := &EscrowSlot{
		Policy:       s.Policy,
		Open:         true,
		Remaining:    new(uint256.Int).Set(s.Out),
		Out:          new(uint256.Int).Set(s.Out),
		Height:       s.Height,
		Timestamp:    s.Timestamp,
		Paid:         new(uint256.Int),
		Recommitted:  new(uint256.Int),
		ActionDebits: new(uint256.Int),
		Forfeited:    new(uint256.Int),
		ParamsHash:   s.ParamsHash,
		ActionTag:    s.ActionTag,
		ActionSalt:   s.ActionSalt,
		Instr:        s.Instr,
	}
	snap := st.Snapshot()
	if err := addTotal(st, SlotTotalOut, slot.Out); err != nil {
		st.RevertToSnapshot(snap)
		return err
	}
	if err := addTotal(st, SlotTotalEscrow, slot.Out); err != nil {
		st.RevertToSnapshot(snap)
		return err
	}
	writeEscrowSlot(st, marker, nil, slot)
	slotLog(st, TagSlotOpened, marker, slot.Height, slot.Policy[:], amountWord(slot.Out), slot.Instr[:])
	return nil
}

// openSlotOf returns the open slot of marker that belongs to policy, and a
// copy of it to change.
func openSlotOf(st StateDB, policy common.Address, marker common.Hash) (old, s *EscrowSlot, err error) {
	old, ok := ReadEscrowSlot(st, marker)
	if !ok || old.Policy != policy {
		return nil, nil, fmt.Errorf("%w: %x", ErrEscrowSlotMissing, marker)
	}
	if !old.Open {
		return nil, nil, fmt.Errorf("%w: %x", ErrEscrowSlotClosed, marker)
	}
	cp := *old
	cp.Remaining = new(uint256.Int).Set(old.Remaining)
	cp.Paid = new(uint256.Int).Set(old.Paid)
	cp.Recommitted = new(uint256.Int).Set(old.Recommitted)
	cp.ActionDebits = new(uint256.Int).Set(old.ActionDebits)
	cp.Forfeited = new(uint256.Int).Set(old.Forfeited)
	return old, &cp, nil
}

// take lowers remaining by amount, which must be at least min and at most
// remaining, and adds it to the given counter. It is the first effect of
// every writing function.
func (s *EscrowSlot) take(amount *uint256.Int, min uint64, counter *uint256.Int) error {
	if amount == nil || amount.LtUint64(min) || amount.Gt(s.Remaining) {
		return fmt.Errorf("%w: %v of remaining %v", ErrEscrowAmount, amount, s.Remaining)
	}
	s.Remaining.Sub(s.Remaining, amount)
	counter.Add(counter, amount)
	return nil
}

// closeIfEmpty closes s when remaining reached zero and reports whether it
// did.
func (s *EscrowSlot) closeIfEmpty() bool {
	if !s.Remaining.IsZero() {
		return false
	}
	s.close()
	return true
}

// close marks s closed and clears words 4 to 7; words 0 to 3 are kept.
func (s *EscrowSlot) close() {
	s.Open = false
	s.ParamsHash, s.ActionTag, s.ActionSalt, s.Instr = common.Hash{}, common.Hash{}, common.Hash{}, common.Hash{}
}

// finish writes the changed slot, and the slot-closed log with forfeited
// when the change closed it.
func finish(st StateDB, marker common.Hash, old, s *EscrowSlot, height uint64, forfeited *uint256.Int) {
	closed := old.Open && !s.Open
	writeEscrowSlot(st, marker, old, s)
	if closed {
		slotLog(st, TagSlotClosed, marker, height, amountWord(amountOrZero(forfeited)))
	}
}

// PayEscrowSlot pays amount, between 1 and remaining, from the open slot of
// marker that belongs to policy to dest as a plain balance credit: no code
// runs at dest. dest may be neither a registered policy nor a reserved
// address (ErrEscrowDest). paid rises and total_escrow falls by amount. It
// writes the slot-paid log, and closes the slot when remaining reaches zero.
// On an error nothing is changed.
func PayEscrowSlot(st StateDB, height uint64, policy common.Address, marker common.Hash, dest common.Address, amount *uint256.Int) error {
	old, s, err := openSlotOf(st, policy, marker)
	if err != nil {
		return err
	}
	if err := s.take(amount, 1, s.Paid); err != nil {
		return err
	}
	if ghost.IsRegisteredPolicy(st, dest) || ghost.IsReservedAddress(dest) {
		return fmt.Errorf("%w: %v", ErrEscrowDest, dest)
	}
	if err := subTotal(st, SlotTotalEscrow, amount); err != nil {
		return err
	}
	s.closeIfEmpty()
	st.AddBalance(dest, amount)
	slotLog(st, TagSlotPaid, marker, height, dest[:], amountWord(amount))
	finish(st, marker, old, s, height, nil)
	return nil
}

// RecommitEscrowSlot moves amount, between 1 and remaining, from the open
// slot of marker that belongs to policy back into the hidden set as a new
// coin: C = K("ghost/coin-commitment/v1", COIN_V2, f, amount), appended to
// the coin tree in the block at height with its note and salt and the commit
// receipt, as commit step 10 without the burn. recommitted and total_in rise
// and total_escrow falls by amount. It writes the slot-recommitted log, and
// closes the slot when remaining reaches zero. A zero f is ErrCommitZeroF; a
// coin tree that cannot take C is ErrCommitTree. On an error nothing is
// changed.
func RecommitEscrowSlot(st StateDB, height uint64, policy common.Address, marker common.Hash, f common.Hash, salt [SaltSize]byte, amount *uint256.Int, note [NoteSize]byte) error {
	old, s, err := openSlotOf(st, policy, marker)
	if err != nil {
		return err
	}
	if err := s.take(amount, 1, s.Recommitted); err != nil {
		return err
	}
	if f == (common.Hash{}) {
		return ErrCommitZeroF
	}
	snap := st.Snapshot()
	if err := subTotal(st, SlotTotalEscrow, amount); err != nil {
		return err
	}
	if err := appendCommit(st, height, &Commit{F: f, Value: new(uint256.Int).Set(amount), Note: note, Salt: &salt}); err != nil {
		st.RevertToSnapshot(snap)
		return err
	}
	s.closeIfEmpty()
	slotLog(st, TagSlotRecommitted, marker, height, amountWord(amount))
	finish(st, marker, old, s, height, nil)
	return nil
}

// CloseEscrowSlot closes the open slot of marker that belongs to policy:
// what remains is forfeited, credited to nobody, and leaves total_escrow; it
// stays out of supply for good. It writes the slot-closed log with the
// forfeited value. On an error nothing is changed.
func CloseEscrowSlot(st StateDB, height uint64, policy common.Address, marker common.Hash) error {
	old, s, err := openSlotOf(st, policy, marker)
	if err != nil {
		return err
	}
	forfeited := new(uint256.Int).Set(s.Remaining)
	if err := subTotal(st, SlotTotalEscrow, forfeited); err != nil {
		return err
	}
	s.Forfeited.Add(s.Forfeited, forfeited)
	s.Remaining.Clear()
	s.close()
	finish(st, marker, old, s, height, forfeited)
	return nil
}

// ErrEscrowNonce is returned for a debit of a slot whose action nonce cannot
// grow any more.
var ErrEscrowNonce = errors.New("escrow slot action nonce exhausted")

// DebitEscrowSlot takes an action's debit, at most remaining, from the open
// slot of marker that belongs to policy and spends the slot's action nonce:
// action_debits rises and total_escrow falls by debit, and the action nonce
// rises by one. The caller burns and tips the debit, and writes the action
// result. The slot closes when remaining reaches zero; its words 0 to 3, the
// nonce among them, are kept. On an error nothing is changed.
func DebitEscrowSlot(st StateDB, height uint64, policy common.Address, marker common.Hash, debit *uint256.Int) error {
	old, s, err := openSlotOf(st, policy, marker)
	if err != nil {
		return err
	}
	if s.ActionNonce == ^uint64(0) {
		return fmt.Errorf("%w: %x", ErrEscrowNonce, marker)
	}
	if err := s.take(debit, 0, s.ActionDebits); err != nil {
		return err
	}
	s.ActionNonce++
	if err := subTotal(st, SlotTotalEscrow, debit); err != nil {
		return err
	}
	s.closeIfEmpty()
	finish(st, marker, old, s, height, nil)
	return nil
}
