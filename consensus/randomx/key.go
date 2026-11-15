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

package randomx

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

// SeedHeight returns the height of the block whose hash keys RandomX for a
// block at height h, with key interval e (a power of two) and key delay l:
// 0 while h <= e + l, else (h - l - 1) rounded down to a multiple of e. The
// delay lets miners build the next cache before the key changes.
func SeedHeight(h, e, l uint64) uint64 {
	if h <= e+l {
		return 0
	}
	return (h - l - 1) &^ (e - 1)
}

func (r *RandomX) seedHeight(h uint64) uint64 {
	return SeedHeight(h, r.epochLength, r.keyLag)
}

// headerLookup finds a header by hash and number. It returns nil unless the
// header found carries that number.
type headerLookup func(hash common.Hash, number uint64) *types.Header

// numbered returns h if it carries number, else nil.
func numbered(h *types.Header, number uint64) *types.Header {
	if h == nil || h.Number == nil || !h.Number.IsUint64() || h.Number.Uint64() != number {
		return nil
	}
	return h
}

// chainLookup reads headers from the chain only. The chain's header cache
// answers by hash alone, so the number is checked here.
func chainLookup(chain consensus.ChainHeaderReader) headerLookup {
	return func(hash common.Hash, number uint64) *types.Header {
		return numbered(chain.GetHeader(hash, number), number)
	}
}

// batchLookup reads headers from a batch being verified, then from the chain.
func batchLookup(chain consensus.ChainHeaderReader, headers []*types.Header) headerLookup {
	return batchByHash(headers).lookup(chain)
}

// batchHeaders indexes a batch being verified by header hash.
type batchHeaders map[common.Hash]*types.Header

func batchByHash(headers []*types.Header) batchHeaders {
	byHash := make(batchHeaders, len(headers))
	for _, h := range headers {
		byHash[h.Hash()] = h
	}
	return byHash
}

// parent returns the parent of header from the batch or the chain, found by
// hash whatever number it carries, as VerifyHeader finds it, so the caller
// can refuse a wrong number as an invalid number.
func (byHash batchHeaders) parent(chain consensus.ChainHeaderReader, header *types.Header) *types.Header {
	if h := byHash[header.ParentHash]; h != nil {
		return h
	}
	return chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
}

// lookup reads headers from the batch, then from the chain, by hash and
// number.
func (byHash batchHeaders) lookup(chain consensus.ChainHeaderReader) headerLookup {
	return func(hash common.Hash, number uint64) *types.Header {
		if h := numbered(byHash[hash], number); h != nil {
			return h
		}
		return numbered(chain.GetHeader(hash, number), number)
	}
}

// keyOf returns the RandomX key of a header: the hash of its ancestor at the
// seed height, found by following parent hashes on the header's own branch.
// Results are remembered per header hash, for the header and for every
// ancestor passed on the way that shares its seed height. Every ancestor is
// found by hash and the number it must have, so a header claiming a false
// number cannot leave a wrong key remembered for a real ancestor.
func (r *RandomX) keyOf(lookup headerLookup, header *types.Header) (common.Hash, error) {
	number := header.Number.Uint64()
	seed := r.seedHeight(number)
	if number == seed {
		// Only genesis keys itself.
		return header.Hash(), nil
	}
	hash := header.Hash()
	if key, ok := r.keys.Get(hash); ok {
		return key, nil
	}
	var (
		walked []common.Hash
		cur    = header
		key    common.Hash
	)
	for {
		parentNumber := cur.Number.Uint64() - 1
		if parentNumber == seed {
			// The parent is the key block.
			key = cur.ParentHash
			break
		}
		if known, ok := r.keys.Get(cur.ParentHash); ok && r.seedHeight(parentNumber) == seed {
			key = known
			break
		}
		parent := numbered(lookup(cur.ParentHash, parentNumber), parentNumber)
		if parent == nil {
			return common.Hash{}, consensus.ErrUnknownAncestor
		}
		if r.seedHeight(parentNumber) == seed {
			walked = append(walked, cur.ParentHash)
		}
		cur = parent
	}
	r.keys.Add(hash, key)
	for _, h := range walked {
		r.keys.Add(h, key)
	}
	return key, nil
}
