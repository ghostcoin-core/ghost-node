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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	// ErrHistoryNotReady is returned for an anchor the tree history does not
	// hold yet, or while the history and the canonical chain disagree.
	ErrHistoryNotReady = errors.New("tree history does not cover the anchor")

	// errStaleHistory makes Sync build the history again from genesis.
	errStaleHistory = errors.New("stored tree history does not match the chain")
)

// headKey is the block-entry key of the history's head, the block whose
// ancestry the store holds: the zero hash, which no block has. Its value is
// the head's number and hash.
var headKey = common.Hash{}

const headSize = 8 + common.HashLength

// storedKinds are the kinds the history keeps records of.
var storedKinds = [...]Kind{Coin, Data, CoinMarkers, DataMarkers}

// RecordsFunc returns the records a canonical block appended, in the order it
// appended them: the leaves of both trees with their tree index, position and
// note, and the spent markers of both kinds as records of CoinMarkers and
// DataMarkers (see ApplyBlock). An error means the block's records cannot be
// known; the history then stops below the block.
type RecordsFunc func(header *types.Header) ([]Record, error)

// blockID is a block of a branch the history moves along.
type blockID struct {
	number       uint64
	hash, parent common.Hash
}

func (h *History) readHead() (uint64, common.Hash, bool, error) {
	enc, err := rawdb.ReadGhostTreeBlock(h.db, headKey)
	if err != nil || enc == nil {
		return 0, common.Hash{}, false, err
	}
	if len(enc) != headSize {
		return 0, common.Hash{}, false, fmt.Errorf("%w: head of %d bytes", ErrCorruptHistory, len(enc))
	}
	return binary.BigEndian.Uint64(enc), common.BytesToHash(enc[8:]), true, nil
}

// writeHead stores the head with the markers that the history keeps the tag
// index (see ReadNoteBucket) and the spent-marker index, which serves the
// reorg and rebuild bookkeeping: it is written when a block is applied and
// read when a block is reverted.
func writeHead(w ethdb.KeyValueWriter, number uint64, hash common.Hash) error {
	enc := make([]byte, headSize)
	binary.BigEndian.PutUint64(enc, number)
	copy(enc[8:], hash[:])
	if err := rawdb.WriteGhostTreeTagged(w); err != nil {
		return err
	}
	if err := rawdb.WriteGhostTreeMarked(w); err != nil {
		return err
	}
	return rawdb.WriteGhostTreeBlock(w, headKey, enc)
}

// Sync makes the history hold the records of head's ancestry, and nothing
// else: it reverts, newest first, the blocks of the stored head's branch above
// the common ancestor and applies, oldest first, those of head's branch, each
// block in one write together with the new head. A store without a head, or
// one that does not fit the stored headers, is cleared and built again from
// genesis, so a node with an existing chain gets its history on the first
// call. The headers of both branches must be in the database. If records
// fails for a block, the history stays at its parent and the error is
// returned.
func (h *History) Sync(head *types.Header, records RecordsFunc) error {
	if err := h.p.pageable(); err != nil {
		return err
	}
	if head == nil || head.Number == nil || !head.Number.IsUint64() {
		return errors.New("tree history: no head header")
	}
	h.lock.Lock()
	defer h.lock.Unlock()

	err := h.sync(head, records, false)
	if errors.Is(err, errStaleHistory) {
		err = h.sync(head, records, true)
	}
	return err
}

func (h *History) sync(head *types.Header, records RecordsFunc, rebuild bool) error {
	var revert, apply []blockID
	if !rebuild {
		number, hash, ok, err := h.readHead()
		switch {
		case err != nil:
			return fmt.Errorf("%w: %w", errStaleHistory, err)
		case !ok:
			return fmt.Errorf("%w: no head", errStaleHistory)
		}
		// A history built before the tag index has none: built again.
		if tagged, err := rawdb.ReadGhostTreeTagged(h.db); err != nil {
			return fmt.Errorf("%w: %w", errStaleHistory, err)
		} else if !tagged {
			return fmt.Errorf("%w: no tag index", errStaleHistory)
		}
		// So is one built before the spent-marker index.
		if marked, err := rawdb.ReadGhostTreeMarked(h.db); err != nil {
			return fmt.Errorf("%w: %w", errStaleHistory, err)
		} else if !marked {
			return fmt.Errorf("%w: no spent-marker index", errStaleHistory)
		}
		if hash == head.Hash() {
			return nil
		}
		if revert, apply, err = h.plan(number, hash, head); err != nil {
			return err
		}
	} else {
		if err := h.reset(); err != nil {
			return err
		}
		var err error
		if apply, err = h.ancestry(head); err != nil {
			return err
		}
	}
	for _, b := range revert {
		batch := h.db.NewBatch()
		if err := h.revertBlock(batch, b.hash); err != nil {
			return fmt.Errorf("%w: revert block %d: %w", errStaleHistory, b.number, err)
		}
		if err := writeHead(batch, b.number-1, b.parent); err != nil {
			return err
		}
		if err := batch.Write(); err != nil {
			return err
		}
	}
	for i := len(apply) - 1; i >= 0; i-- {
		b := apply[i]
		header := rawdb.ReadHeader(h.db, b.hash, b.number)
		if header == nil {
			return fmt.Errorf("tree history: header %d %x missing", b.number, b.hash)
		}
		recs, err := records(header)
		if err != nil {
			return fmt.Errorf("tree history: records of block %d %x: %w", b.number, b.hash, err)
		}
		batch := h.db.NewBatch()
		if err := h.applyBlock(batch, b.hash, b.number, recs); err != nil {
			return fmt.Errorf("%w: apply block %d: %w", errStaleHistory, b.number, err)
		}
		if err := writeHead(batch, b.number, b.hash); err != nil {
			return err
		}
		if err := batch.Write(); err != nil {
			return err
		}
	}
	return nil
}

// header returns a stored header, errStaleHistory if it is missing.
func (h *History) header(number uint64, hash common.Hash) (*types.Header, error) {
	header := rawdb.ReadHeader(h.db, hash, number)
	if header == nil {
		return nil, fmt.Errorf("%w: header %d %x missing", errStaleHistory, number, hash)
	}
	return header, nil
}

func idOf(header *types.Header) blockID {
	return blockID{header.Number.Uint64(), header.Hash(), header.ParentHash}
}

// plan walks the stored head's branch and head's branch down to their common
// ancestor and returns the blocks to revert and to apply, newest first.
func (h *History) plan(number uint64, hash common.Hash, head *types.Header) (revert, apply []blockID, err error) {
	old, err := h.header(number, hash)
	if err != nil {
		return nil, nil, err
	}
	cur := head
	step := func(x *types.Header) (*types.Header, error) {
		if x.Number.Uint64() == 0 {
			return nil, fmt.Errorf("%w: branches with different genesis blocks", errStaleHistory)
		}
		return h.header(x.Number.Uint64()-1, x.ParentHash)
	}
	for old.Number.Uint64() > cur.Number.Uint64() {
		revert = append(revert, idOf(old))
		if old, err = step(old); err != nil {
			return nil, nil, err
		}
	}
	for cur.Number.Uint64() > old.Number.Uint64() {
		apply = append(apply, idOf(cur))
		if cur, err = step(cur); err != nil {
			return nil, nil, err
		}
	}
	for old.Hash() != cur.Hash() {
		revert = append(revert, idOf(old))
		apply = append(apply, idOf(cur))
		if old, err = step(old); err != nil {
			return nil, nil, err
		}
		if cur, err = step(cur); err != nil {
			return nil, nil, err
		}
	}
	return revert, apply, nil
}

// ancestry returns head and every ancestor down to genesis, newest first.
func (h *History) ancestry(head *types.Header) ([]blockID, error) {
	blocks := make([]blockID, 0, head.Number.Uint64()+1)
	for cur := head; ; {
		blocks = append(blocks, idOf(cur))
		n := cur.Number.Uint64()
		if n == 0 {
			return blocks, nil
		}
		parent := rawdb.ReadHeader(h.db, cur.ParentHash, n-1)
		if parent == nil {
			return nil, fmt.Errorf("tree history: header %d %x missing", n-1, cur.ParentHash)
		}
		cur = parent
	}
}

// reset removes the head, the markers of the tag and spent-marker indexes
// and every record, page root, tag key and spent-marker entry. Block entries
// stay behind, as no list of them is kept; applying a block replaces its
// entry.
func (h *History) reset() error {
	batch := h.db.NewBatch()
	if err := rawdb.DeleteGhostTreeBlock(batch, headKey); err != nil {
		return err
	}
	if err := rawdb.DeleteGhostTreeTagged(batch); err != nil {
		return err
	}
	if err := rawdb.DeleteGhostTreeMarked(batch); err != nil {
		return err
	}
	flush := func(force bool) error {
		if !force && batch.ValueSize() < ethdb.IdealBatchSize {
			return nil
		}
		if err := batch.Write(); err != nil {
			return err
		}
		batch.Reset()
		return nil
	}
	// The head goes first, so a reset cut short is done again.
	if err := flush(true); err != nil {
		return err
	}
	for _, kind := range storedKinds {
		for index := uint64(0); ; index++ {
			count, err := h.countAt(kind, index, math.MaxUint64)
			if err != nil {
				return err
			}
			for pos := uint64(0); pos < count; pos++ {
				if err := rawdb.DeleteGhostTreeLeaf(batch, uint8(kind), index, uint32(pos)); err != nil {
					return err
				}
				if kind.valid() && (pos+1)%PageLeaves == 0 {
					if err := rawdb.DeleteGhostTreePageRoot(batch, uint8(kind), index, uint32(pos/PageLeaves)); err != nil {
						return err
					}
				}
				if err := flush(false); err != nil {
					return err
				}
			}
			if count < h.p.capacity() || index == math.MaxUint64 {
				break
			}
		}
	}
	// Tag keys are removed by their own range, which also takes any left
	// without a record.
	if err := rawdb.DeleteGhostTreeTags(h.db, batch, func() error { return flush(false) }); err != nil {
		return err
	}
	// So are the entries of the spent-marker index.
	if err := rawdb.DeleteGhostTreeMarkers(h.db, batch, func() error { return flush(false) }); err != nil {
		return err
	}
	return flush(true)
}

// Unwind reverts the history's head block if its hash is hash, making its
// parent the head; for any other hash it does nothing. A node rewinding its
// chain calls it for each block it deletes, newest first, while the block's
// header is still stored.
func (h *History) Unwind(hash common.Hash) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	number, head, ok, err := h.readHead()
	if err != nil || !ok || head != hash {
		return err
	}
	header, err := h.header(number, hash)
	if err != nil {
		return err
	}
	batch := h.db.NewBatch()
	if err := h.revertBlock(batch, hash); err != nil {
		return err
	}
	if number == 0 {
		err = rawdb.DeleteGhostTreeBlock(batch, headKey)
	} else {
		err = writeHead(batch, number-1, header.ParentHash)
	}
	if err != nil {
		return err
	}
	return batch.Write()
}

// covers checks that the history holds the canonical anchor at number: its
// head is canonical, at or above the anchor, and the anchor is applied.
func (h *History) covers(anchor common.Hash, number uint64) error {
	headNumber, headHash, ok, err := h.readHead()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: no history head", ErrHistoryNotReady)
	}
	if headNumber < number {
		return fmt.Errorf("%w: history at block %d, anchor at %d", ErrHistoryNotReady, headNumber, number)
	}
	if rawdb.ReadCanonicalHash(h.db, headNumber) != headHash {
		return fmt.Errorf("%w: history head %d %x not canonical", ErrHistoryNotReady, headNumber, headHash)
	}
	enc, err := rawdb.ReadGhostTreeBlock(h.db, anchor)
	if err != nil {
		return err
	}
	if enc == nil {
		return fmt.Errorf("%w: anchor %x not applied", ErrHistoryNotReady, anchor)
	}
	if applied, _, err := decodeBlock(enc); err != nil {
		return err
	} else if applied != number {
		return fmt.Errorf("%w: anchor %x applied at %d", ErrCorruptHistory, anchor, applied)
	}
	return nil
}
