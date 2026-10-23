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
	crand "crypto/rand"
	"encoding/binary"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/core/types"
)

// Seal implements consensus.Engine. The block becomes the work handed to
// remote miners, and the local sealer searches for a nonce on the CPU in
// light mode unless local mining is off. The threads share the key's cache,
// each with its own VM. The first sealed block is sent on results; closing
// stop ends the local search.
func (r *RandomX) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	target := ghostrules.SealTarget(header.Difficulty)
	if target == nil {
		return errInvalidDifficulty
	}
	if wait := r.sealDelay(header.Time); wait > 0 {
		// Every verifier would hold the block as a future block: wait
		// until the clock lets it through, then seal it.
		r.log.Debug("Sealing waits for the clock", "number", header.Number, "wait", wait)
		go func() {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-stop:
			case <-timer.C:
				if err := r.Seal(chain, block, results, stop); err != nil {
					r.log.Error("Failed to seal after waiting for the clock", "err", err)
				}
			}
		}()
		return nil
	}
	key, err := r.keyOf(chainLookup(chain), header)
	if err != nil {
		return err
	}
	r.remote.push(chain, block, key, results)

	threads := r.Threads()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		// Local mining is off: wait for a thread change or the stop.
		go func() {
			select {
			case <-stop:
			case <-r.update:
				if err := r.Seal(chain, block, results, stop); err != nil {
					r.log.Error("Failed to restart sealing after update", "err", err)
				}
			}
		}()
		return nil
	}
	entry, err := r.caches.acquire(key)
	if err != nil {
		return err
	}
	var seed [8]byte
	if _, err := crand.Read(seed[:]); err != nil {
		r.caches.release(entry)
		return err
	}
	var (
		sealHash = r.SealHash(header)
		start    = binary.BigEndian.Uint64(seed[:])
		abort    = make(chan struct{})
		found    = make(chan *types.Block)
		pend     sync.WaitGroup
	)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			r.mine(entry, block, sealHash, target, id, nonce, abort, found)
		}(i, start+uint64(i)<<56)
	}
	go func() {
		defer r.caches.release(entry)
		select {
		case <-stop:
			close(abort)
		case result := <-found:
			select {
			case results <- result:
			default:
				r.log.Warn("Sealing result is not read by miner", "sealhash", sealHash)
			}
			close(abort)
		case <-r.update:
			close(abort)
			pend.Wait()
			if err := r.Seal(chain, block, results, stop); err != nil {
				r.log.Error("Failed to restart sealing after update", "err", err)
			}
		}
		pend.Wait()
	}()
	return nil
}

// sealDelay returns how long a block with the given timestamp must wait
// before the local clock is within the future drift of it, or zero. The
// wait is capped at a minute, after which the caller checks again.
func (r *RandomX) sealDelay(timestamp uint64) time.Duration {
	now, drift := uint64(r.now().Unix()), r.params.FutureDrift
	if timestamp <= drift || timestamp-drift <= now {
		return 0
	}
	return time.Duration(min(timestamp-drift-now, 60)) * time.Second
}

// mine searches nonces upward from nonce until one seals the block or the
// search is aborted.
func (r *RandomX) mine(entry *cacheEntry, block *types.Block, sealHash common.Hash, target *big.Int, id int, nonce uint64, abort <-chan struct{}, found chan<- *types.Block) {
	vm, err := r.caches.vm(entry)
	if err != nil {
		r.log.Error("RandomX sealer cannot start", "miner", id, "err", err)
		return
	}
	defer r.caches.putVM(entry, vm)

	input := sealInput(sealHash, nonce)
	value := new(big.Int)
	for {
		select {
		case <-abort:
			return
		default:
		}
		binary.BigEndian.PutUint64(input[common.HashLength:], nonce)
		out := vm.hash(input)
		r.hashes.Add(1)
		if value.SetBytes(out[:]).Cmp(target) <= 0 {
			header := block.Header()
			header.Nonce = types.EncodeNonce(nonce)
			header.MixDigest = common.Hash{}
			select {
			case found <- block.WithSeal(header):
			case <-abort:
			}
			return
		}
		nonce++
	}
}
