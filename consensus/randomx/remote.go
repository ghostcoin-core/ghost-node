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
	"errors"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	// staleThreshold is how many blocks a work package may fall behind the
	// newest one and still have its solution accepted.
	staleThreshold = 7

	// rateExpiry is how long a submitted remote hash rate counts.
	rateExpiry = 10 * time.Second

	// maxRemoteMiners is how many remote miners' hash rates are kept at once;
	// a rate from a new miner is refused while that many unexpired ones are.
	maxRemoteMiners = 64

	// maxRemoteVerifies is how many submitted solutions are checked at once.
	// Each check needs a RandomX VM; a submission beyond the limit is refused
	// before any VM is taken.
	maxRemoteVerifies = 2
)

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errUnknownWork       = errors.New("work submitted but none pending")
	errStaleWork         = errors.New("work submitted is too old")
	errResultMismatch    = errors.New("submitted result is not the RandomX hash of the work and nonce")
	errNoResultsChannel  = errors.New("sealing result has no receiver")
	errResultNotReadable = errors.New("sealing result is not read by miner")
	errVerifyBusy        = errors.New("too many submitted solutions being checked")
)

// remoteWork is one block handed out to remote miners.
type remoteWork struct {
	block   *types.Block
	key     common.Hash
	chain   consensus.ChainHeaderReader
	results chan<- *types.Block
}

// remoteSealer keeps the blocks handed out to remote miners through
// eth_getWork and checks the solutions they send back through
// eth_submitWork.
type remoteSealer struct {
	r *RandomX

	mu      sync.Mutex
	works   map[common.Hash]*remoteWork // seal hash -> work
	current *remoteWork                 // the newest work
	pkg     [4]string                   // the newest work's package
	rates   map[common.Hash]remoteRate  // miner id -> submitted rate

	verifying chan struct{} // one slot per solution being checked
}

// remoteRate is a hash rate submitted by a remote miner.
type remoteRate struct {
	rate uint64
	ping time.Time
}

func newRemoteSealer(r *RandomX) *remoteSealer {
	return &remoteSealer{
		r:         r,
		works:     make(map[common.Hash]*remoteWork),
		rates:     make(map[common.Hash]remoteRate),
		verifying: make(chan struct{}, maxRemoteVerifies),
	}
}

// push makes block the current work, keyed by key, whose solution goes to
// results. Work that has fallen staleThreshold blocks behind is dropped.
func (s *remoteSealer) push(chain consensus.ChainHeaderReader, block *types.Block, key common.Hash, results chan<- *types.Block) {
	sealHash := s.r.SealHash(block.Header())
	target := ghostrules.SealTarget(block.Difficulty())

	s.mu.Lock()
	defer s.mu.Unlock()
	work := &remoteWork{block: block, key: key, chain: chain, results: results}
	s.current = work
	s.works[sealHash] = work
	s.pkg = [4]string{
		sealHash.Hex(),
		key.Hex(),
		common.BytesToHash(target.Bytes()).Hex(),
		hexutil.EncodeBig(block.Number()),
	}
	for hash, w := range s.works {
		if w.block.NumberU64()+staleThreshold <= block.NumberU64() {
			delete(s.works, hash)
		}
	}
}

// work returns the current work package.
func (s *remoteSealer) work() ([4]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return [4]string{}, errNoMiningWork
	}
	return s.pkg, nil
}

// submit checks a remote miner's nonce for the work with the given seal
// hash and, when it seals the block, hands the sealed block to the miner.
// result is the RandomX hash the remote miner computed; it must equal the
// hash the node computes.
func (s *remoteSealer) submit(nonce types.BlockNonce, sealHash, result common.Hash) error {
	s.mu.Lock()
	work := s.works[sealHash]
	current := s.current
	s.mu.Unlock()
	if work == nil {
		s.r.log.Warn("Work submitted but none pending", "sealhash", sealHash)
		return errUnknownWork
	}
	if work.block.NumberU64()+staleThreshold <= current.block.NumberU64() {
		s.r.log.Warn("Work submitted is too old", "number", work.block.NumberU64(), "sealhash", sealHash)
		return errStaleWork
	}
	// Take a check slot before any RandomX VM, or refuse.
	select {
	case s.verifying <- struct{}{}:
		defer func() { <-s.verifying }()
	default:
		s.r.log.Warn("Work submitted while the checks are full", "sealhash", sealHash)
		return errVerifyBusy
	}
	header := work.block.Header()
	header.Nonce = nonce
	header.MixDigest = common.Hash{}

	// The full RandomX hash under the work's key, then every other check of
	// the sealed header.
	start := time.Now()
	hash, err := s.r.powHash(header, work.key)
	if err != nil {
		return err
	}
	if !ghostrules.SealValid(hash, header.Difficulty) {
		s.r.log.Warn("Invalid proof-of-work submitted", "sealhash", sealHash, "elapsed", common.PrettyDuration(time.Since(start)))
		return errInvalidPoW
	}
	if common.Hash(hash) != result {
		s.r.log.Warn("Submitted result does not match", "sealhash", sealHash, "have", result, "want", common.Hash(hash))
		return errResultMismatch
	}
	if err := s.r.VerifyHeader(work.chain, header, false); err != nil {
		s.r.log.Warn("Sealed header refused", "sealhash", sealHash, "err", err)
		return err
	}
	if work.results == nil {
		return errNoResultsChannel
	}
	solution := work.block.WithSeal(header)

	// The head may have moved on while the seal was checked.
	s.mu.Lock()
	defer s.mu.Unlock()
	if solution.NumberU64()+staleThreshold <= s.current.block.NumberU64() {
		s.r.log.Warn("Work submitted is too old", "number", solution.NumberU64(), "sealhash", sealHash)
		return errStaleWork
	}
	select {
	case work.results <- solution:
		s.r.log.Debug("Work submitted is acceptable", "number", solution.NumberU64(), "sealhash", sealHash, "hash", solution.Hash())
		return nil
	default:
		s.r.log.Warn("Sealing result is not read by miner", "mode", "remote", "sealhash", sealHash)
		return errResultNotReadable
	}
}

// submitRate records a remote miner's hash rate and reports whether it was
// kept. Expired rates are dropped first; a new miner is refused while
// maxRemoteMiners unexpired rates are kept.
func (s *remoteSealer) submitRate(id common.Hash, rate uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpiredRates()
	if _, known := s.rates[id]; !known && len(s.rates) >= maxRemoteMiners {
		return false
	}
	s.rates[id] = remoteRate{rate: rate, ping: time.Now()}
	return true
}

// rate returns the sum of the hash rates remote miners submitted within
// the last rateExpiry, dropping older ones.
func (s *remoteSealer) rate() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpiredRates()
	var total uint64
	for _, r := range s.rates {
		total += r.rate
	}
	return total
}

// dropExpiredRates removes the rates older than rateExpiry. The caller
// holds s.mu.
func (s *remoteSealer) dropExpiredRates() {
	for id, r := range s.rates {
		if time.Since(r.ping) > rateExpiry {
			delete(s.rates, id)
		}
	}
}

// GetWork returns the work package for a remote miner:
//
//	result[0] - the 32-byte seal hash, the first 32 bytes of the RandomX input
//	result[1] - the 32-byte RandomX key, the hash of the key block
//	result[2] - the 32-byte target: a RandomX hash read as a big-endian
//	            number must be at most this value
//	result[3] - the block number
//
// The RandomX input is the seal hash followed by the nonce as 8 big-endian
// bytes.
func (api *API) GetWork() ([4]string, error) {
	return api.r.remote.work()
}

// SubmitWork hands a remote miner's solution to the node: the nonce, the
// seal hash of the work it solves and the RandomX hash the miner computed.
// It reports whether the block was accepted; a wrong nonce, a wrong result,
// unknown work and stale work are all refused.
func (api *API) SubmitWork(nonce types.BlockNonce, hash, result common.Hash) bool {
	return api.r.remote.submit(nonce, hash, result) == nil
}

// SubmitHashrate records a remote miner's hash rate under an id unique to
// that miner, so the node reports the combined rate. It reports false when
// the node already keeps the rates of as many miners as it will.
func (api *API) SubmitHashrate(rate hexutil.Uint64, id common.Hash) bool {
	return api.r.remote.submitRate(id, uint64(rate))
}
