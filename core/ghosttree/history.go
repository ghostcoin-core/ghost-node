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

package ghosttree

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	// ErrBadRecord is returned by ApplyBlock for a record that does not
	// continue its tree: a gap, a position already stored, a block number
	// below the record before it, a zero leaf or an unknown kind.
	ErrBadRecord = errors.New("record does not continue its tree")

	// ErrBlockApplied is returned by ApplyBlock for a block already applied.
	ErrBlockApplied = errors.New("block already applied to the tree history")

	// ErrBlockUnknown is returned by RevertBlock for a block not applied.
	ErrBlockUnknown = errors.New("block not in the tree history")

	// ErrRevertOrder is returned by RevertBlock for a block whose trees hold
	// records of a later block, which must be reverted first.
	ErrRevertOrder = errors.New("later records of the tree remain; revert the newest block first")

	// ErrCorruptHistory is returned for stored history that breaks a rule of
	// its layout.
	ErrCorruptHistory = errors.New("corrupt tree history")
)

// Record is one leaf of the history with its note, where it was appended.
type Record struct {
	Kind      Kind
	TreeIndex uint64
	Position  uint32
	Leaf      common.Hash
	Note      [NoteBytes]byte
}

// History is the store of every leaf and note of every tree index of both
// kinds on the canonical chain. The caller applies each block that becomes
// canonical and reverts each block that leaves the canonical chain, newest
// first; the store derives nothing itself and prunes nothing.
type History struct {
	p    Params
	db   ethdb.Database
	lock sync.RWMutex
}

// NewHistory returns the tree history kept in db.
func NewHistory(db ethdb.Database) *History {
	return &History{p: Release, db: db}
}

// stored is a record as kept in the database.
type stored struct {
	number uint64
	leaf   common.Hash
	note   [NoteBytes]byte
}

const storedSize = 8 + common.HashLength + NoteBytes

func (s *stored) encode() []byte {
	enc := make([]byte, storedSize)
	binary.BigEndian.PutUint64(enc, s.number)
	copy(enc[8:], s.leaf[:])
	copy(enc[8+common.HashLength:], s.note[:])
	return enc
}

func decodeStored(enc []byte) (*stored, error) {
	if len(enc) != storedSize {
		return nil, fmt.Errorf("%w: record of %d bytes", ErrCorruptHistory, len(enc))
	}
	s := &stored{number: binary.BigEndian.Uint64(enc)}
	copy(s.leaf[:], enc[8:])
	copy(s.note[:], enc[8+common.HashLength:])
	return s, nil
}

// slot is one position of one tree.
type slot struct {
	kind      Kind
	treeIndex uint64
	position  uint32
}

const slotSize = 1 + 8 + 4

// encodeBlock is the block entry: its number and the slots it wrote.
func encodeBlock(number uint64, slots []slot) []byte {
	enc := make([]byte, 8, 8+len(slots)*slotSize)
	binary.BigEndian.PutUint64(enc, number)
	for _, s := range slots {
		var b [slotSize]byte
		b[0] = byte(s.kind)
		binary.BigEndian.PutUint64(b[1:], s.treeIndex)
		binary.BigEndian.PutUint32(b[9:], s.position)
		enc = append(enc, b[:]...)
	}
	return enc
}

func decodeBlock(enc []byte) (uint64, []slot, error) {
	if len(enc) < 8 || (len(enc)-8)%slotSize != 0 {
		return 0, nil, fmt.Errorf("%w: block entry of %d bytes", ErrCorruptHistory, len(enc))
	}
	number := binary.BigEndian.Uint64(enc)
	var slots []slot
	for b := enc[8:]; len(b) > 0; b = b[slotSize:] {
		slots = append(slots, slot{Kind(b[0]), binary.BigEndian.Uint64(b[1:]), binary.BigEndian.Uint32(b[9:])})
	}
	return number, slots, nil
}

// read returns the stored record at a slot, nil if there is none.
func (h *History) read(s slot) (*stored, error) {
	enc, err := rawdb.ReadGhostTreeLeaf(h.db, uint8(s.kind), s.treeIndex, s.position)
	if err != nil || enc == nil {
		return nil, err
	}
	return decodeStored(enc)
}

// lastPosition is the last position of a full tree.
func (h *History) lastPosition() uint32 { return uint32(h.p.capacity() - 1) }

// ApplyBlock adds the records of a canonical block, in the order the block
// appended them. Every record must continue its tree: the next free
// position, or position 0 of the next index after a tree that filled in an
// earlier block. On an error nothing is written.
func (h *History) ApplyBlock(blockHash common.Hash, number uint64, records []Record) error {
	if err := h.p.pageable(); err != nil {
		return err
	}
	h.lock.Lock()
	defer h.lock.Unlock()

	if enc, err := rawdb.ReadGhostTreeBlock(h.db, blockHash); err != nil {
		return err
	} else if enc != nil {
		return fmt.Errorf("%w: %x", ErrBlockApplied, blockHash)
	}
	pending := make(map[slot]*stored)
	lookup := func(s slot) (*stored, error) {
		if r, ok := pending[s]; ok {
			return r, nil
		}
		return h.read(s)
	}
	batch := h.db.NewBatch()
	slots := make([]slot, 0, len(records))
	for i, r := range records {
		if !r.Kind.valid() || r.Leaf == (common.Hash{}) || uint64(r.Position) >= h.p.capacity() {
			return fmt.Errorf("%w: record %d: kind %v, leaf %x, position %d", ErrBadRecord, i, r.Kind, r.Leaf, r.Position)
		}
		s := slot{r.Kind, r.TreeIndex, r.Position}
		if have, err := lookup(s); err != nil {
			return err
		} else if have != nil {
			return fmt.Errorf("%w: record %d: %v tree %d position %d already stored", ErrBadRecord, i, r.Kind, r.TreeIndex, r.Position)
		}
		// The record before it: the previous position, or the last position
		// of the previous tree, which must have filled in an earlier block.
		prev, strict := slot{r.Kind, r.TreeIndex, r.Position - 1}, false
		if r.Position == 0 {
			prev, strict = slot{r.Kind, r.TreeIndex - 1, h.lastPosition()}, true
		}
		if r.Position > 0 || r.TreeIndex > 0 {
			before, err := lookup(prev)
			if err != nil {
				return err
			}
			if before == nil || before.number > number || (strict && before.number == number) {
				return fmt.Errorf("%w: record %d: %v tree %d position %d does not follow the stored records", ErrBadRecord, i, r.Kind, r.TreeIndex, r.Position)
			}
		}
		rec := &stored{number: number, leaf: r.Leaf, note: r.Note}
		pending[s] = rec
		slots = append(slots, s)
		if err := rawdb.WriteGhostTreeLeaf(batch, uint8(r.Kind), r.TreeIndex, r.Position, rec.encode()); err != nil {
			return err
		}
		// The record that completes a page also stores the page's root.
		if (uint64(r.Position)+1)%PageLeaves == 0 {
			first := r.Position + 1 - PageLeaves
			leaves := make([]common.Hash, PageLeaves)
			for j := range leaves {
				rec, err := lookup(slot{r.Kind, r.TreeIndex, first + uint32(j)})
				if err != nil {
					return err
				}
				if rec == nil {
					return fmt.Errorf("%w: %v tree %d position %d missing below a full page", ErrCorruptHistory, r.Kind, r.TreeIndex, first+uint32(j))
				}
				leaves[j] = rec.leaf
			}
			root := PageRoot(r.Kind, leaves)
			if err := rawdb.WriteGhostTreePageRoot(batch, uint8(r.Kind), r.TreeIndex, r.Position/PageLeaves, root); err != nil {
				return err
			}
		}
	}
	if err := rawdb.WriteGhostTreeBlock(batch, blockHash, encodeBlock(number, slots)); err != nil {
		return err
	}
	return batch.Write()
}

// RevertBlock removes the records of a block that left the canonical chain.
// The block must be the newest applied one in every tree it wrote to. On an
// error nothing is removed.
func (h *History) RevertBlock(blockHash common.Hash) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	enc, err := rawdb.ReadGhostTreeBlock(h.db, blockHash)
	if err != nil {
		return err
	}
	if enc == nil {
		return fmt.Errorf("%w: %x", ErrBlockUnknown, blockHash)
	}
	number, slots, err := decodeBlock(enc)
	if err != nil {
		return err
	}
	mine := make(map[slot]bool, len(slots))
	for _, s := range slots {
		mine[s] = true
	}
	batch := h.db.NewBatch()
	for _, s := range slots {
		rec, err := h.read(s)
		if err != nil {
			return err
		}
		if rec == nil || rec.number != number {
			return fmt.Errorf("%w: %v tree %d position %d of block %x", ErrCorruptHistory, s.kind, s.treeIndex, s.position, blockHash)
		}
		// Whatever follows the record must be the block's own.
		next := slot{s.kind, s.treeIndex, s.position + 1}
		if s.position == h.lastPosition() {
			if s.treeIndex == math.MaxUint64 {
				next = s
			} else {
				next = slot{s.kind, s.treeIndex + 1, 0}
			}
		}
		if !mine[next] {
			if later, err := h.read(next); err != nil {
				return err
			} else if later != nil {
				return fmt.Errorf("%w: %v tree %d position %d", ErrRevertOrder, next.kind, next.treeIndex, next.position)
			}
		}
		if err := rawdb.DeleteGhostTreeLeaf(batch, uint8(s.kind), s.treeIndex, s.position); err != nil {
			return err
		}
		if (uint64(s.position)+1)%PageLeaves == 0 {
			if err := rawdb.DeleteGhostTreePageRoot(batch, uint8(s.kind), s.treeIndex, s.position/PageLeaves); err != nil {
				return err
			}
		}
	}
	if err := rawdb.DeleteGhostTreeBlock(batch, blockHash); err != nil {
		return err
	}
	return batch.Write()
}
