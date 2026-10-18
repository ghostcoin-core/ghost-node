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

// Package randomx implements Ghost's proof-of-work seal engine on RandomX.
//
// The RandomX library is vendored in librandomx/ and built from source with
// cgo; the only change to it is Ghost's Argon2 salt. The engine hashes in
// light mode: every verifier and sealer shares a 256 MiB cache per key, and
// at most three caches are resident in the process.
//
// A block's RandomX input is its seal hash followed by its nonce, and its key
// is the hash of an ancestor chosen by SeedHeight. Difficulty, timestamps and
// the block reward follow the ghostrules package.
package randomx

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/log"
)

// Salt is the Argon2 salt Ghost's RandomX uses: "Ghost-RandomX" followed by
// the byte 0x01. The C library reads it from RANDOMX_ARGON_SALT in the
// vendored configuration.h, which a test keeps equal to this constant.
const Salt = "Ghost-RandomX\x01"

const (
	// DefaultEpochLength is the default key interval E in blocks.
	DefaultEpochLength = 8192

	// DefaultKeyLag is the default key delay L in blocks.
	DefaultKeyLag = 256

	// maxCaches is the number of RandomX caches kept resident at most.
	maxCaches = 3

	// keyMemoSize is the number of header-to-key results remembered.
	keyMemoSize = 1 << 15
)

var (
	// ErrCgoRequired is returned by New when the package was built without
	// cgo, which the vendored RandomX library needs.
	ErrCgoRequired = errors.New("randomx: the engine needs cgo to build the RandomX library")

	errMissingParams = errors.New("randomx: consensus parameters are missing")
	errBadEpoch      = errors.New("randomx: epoch length must be a power of two")
	errBadKeyLag     = errors.New("randomx: key lag must be a power of two")
)

// Config holds the engine's settings.
type Config struct {
	// Params are the chain's consensus constants. There is no default: a
	// zero value is refused.
	Params ghostrules.Params

	// EpochLength is the key interval E in blocks, a power of two. Zero
	// means DefaultEpochLength.
	EpochLength uint64

	// KeyLag is the key delay L in blocks, a power of two. Zero means
	// DefaultKeyLag.
	KeyLag uint64

	// Log receives the engine's messages. Nil means the root logger.
	Log log.Logger
}

// RandomX is a consensus engine sealing blocks with RandomX proof of work.
type RandomX struct {
	params      ghostrules.Params
	epochLength uint64
	keyLag      uint64
	log         log.Logger

	caches *cacheSet
	keys   *lru.Cache[common.Hash, common.Hash] // header hash -> key block hash

	lock    sync.Mutex    // guards threads
	threads int           // mining threads; 0 means one per CPU, negative none
	update  chan struct{} // notifies running sealers of a thread change

	hashes   atomic.Uint64 // hashes computed by the sealer
	rateLock sync.Mutex    // guards the fields below
	rateAt   time.Time
	rateFrom uint64
	rate     float64

	now func() time.Time // the local clock, replaceable in tests
}

var _ consensus.PoW = (*RandomX)(nil)

// New returns a RandomX engine for the given configuration.
func New(config Config) (*RandomX, error) {
	if err := available(); err != nil {
		return nil, err
	}
	if config.Params == (ghostrules.Params{}) {
		return nil, errMissingParams
	}
	if err := config.Params.Validate(); err != nil {
		return nil, fmt.Errorf("randomx: %w", err)
	}
	if config.EpochLength == 0 {
		config.EpochLength = DefaultEpochLength
	}
	if config.KeyLag == 0 {
		config.KeyLag = DefaultKeyLag
	}
	if bits.OnesCount64(config.EpochLength) != 1 {
		return nil, errBadEpoch
	}
	if bits.OnesCount64(config.KeyLag) != 1 {
		return nil, errBadKeyLag
	}
	if config.Log == nil {
		config.Log = log.Root()
	}
	return &RandomX{
		params:      config.Params,
		epochLength: config.EpochLength,
		keyLag:      config.KeyLag,
		log:         config.Log,
		caches:      sharedCaches(),
		keys:        lru.NewCache[common.Hash, common.Hash](keyMemoSize),
		update:      make(chan struct{}),
		now:         time.Now,
	}, nil
}

var (
	sharedOnce sync.Once
	shared     *cacheSet
)

// sharedCaches returns the process-wide cache set, so the cache limit holds
// however many engines a process runs.
func sharedCaches() *cacheSet {
	sharedOnce.Do(func() { shared = newCacheSet(maxCaches, detectFlags()) })
	return shared
}

// Threads returns the number of mining threads.
func (r *RandomX) Threads() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.threads
}

// SetThreads sets the number of mining threads. Zero uses one thread per
// CPU and a negative number stops local mining. A running sealer restarts
// with the new count.
func (r *RandomX) SetThreads(threads int) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.threads = threads
	select {
	case r.update <- struct{}{}:
	default:
	}
}

// Hashrate returns the sealer's hashes per second since the previous call,
// or over the last call's window when called again within a second.
func (r *RandomX) Hashrate() float64 {
	r.rateLock.Lock()
	defer r.rateLock.Unlock()
	now, count := time.Now(), r.hashes.Load()
	if r.rateAt.IsZero() {
		r.rateAt, r.rateFrom = now, count
		return 0
	}
	if elapsed := now.Sub(r.rateAt); elapsed >= time.Second {
		r.rate = float64(count-r.rateFrom) / elapsed.Seconds()
		r.rateAt, r.rateFrom = now, count
	}
	return r.rate
}

// Close implements consensus.Engine. Caches are shared by the process and
// stay resident for other engines; they are freed when evicted.
func (r *RandomX) Close() error {
	return nil
}
