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

package ethapi

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/sync/semaphore"
)

// The limits of the ghost namespace reads (pages, page sets, page roots,
// note buckets, escrow slots). One read is bounded by its own shape; these
// bound the work of many reads together, so that no caller, nor many callers
// at once, can make the node do unbounded work. A read's cost is in pages:
// one page, one page per page of a page set, two for a note bucket page of
// up to ghosttree.MaxBucketEntries entries.
const (
	// ghostReadUnits is the number of page units the node works on at once,
	// over every caller. A read waits for its units.
	ghostReadUnits = 16

	// ghostReadRate is the number of page units one source may read per
	// second, ghostReadBurst at once after a quiet spell.
	ghostReadRate  = 32
	ghostReadBurst = 64

	// ghostReadWait is the longest a read waits, for its source's rate or
	// for units, before it is refused.
	ghostReadWait = 2 * time.Second

	// ghostReadSources bounds the number of sources whose rates are kept. A
	// source not seen recently starts with a full burst.
	ghostReadSources = 4096
)

// limitError is a refusal for a limit of the node, with the JSON-RPC code
// -32005 (limit exceeded): the caller may try again later.
type limitError struct{ msg string }

func (e *limitError) Error() string  { return e.msg }
func (e *limitError) ErrorCode() int { return -32005 }

var (
	errGhostReadRate = &limitError{"ghost read rate of this source exceeded"}
	errGhostReadBusy = &limitError{"ghost reads busy"}
)

// ghostReadLimiter is the limit shared by the ghost namespace reads: a
// weighted count of units in flight and a rate for each source.
type ghostReadLimiter struct {
	units *semaphore.Weighted
	max   int64
	wait  time.Duration

	mu      sync.Mutex
	rate    float64
	burst   float64
	now     func() time.Time
	sources lru.BasicLRU[string, *sourceRate]
}

// sourceRate is the token bucket of one source. Tokens go below zero for
// reads that wait for the refill.
type sourceRate struct {
	tokens float64
	last   time.Time
}

func newGhostReadLimiter(units int64, rate, burst float64, wait time.Duration, sources int, now func() time.Time) *ghostReadLimiter {
	if now == nil {
		now = time.Now
	}
	return &ghostReadLimiter{
		units:   semaphore.NewWeighted(units),
		max:     units,
		wait:    wait,
		rate:    rate,
		burst:   burst,
		now:     now,
		sources: lru.NewBasicLRU[string, *sourceRate](sources),
	}
}

// ghostReads is the limit of every ghost namespace read of the node.
var ghostReads = newGhostReadLimiter(ghostReadUnits, ghostReadRate, ghostReadBurst, ghostReadWait, ghostReadSources, nil)

// reserve takes cost tokens of a source's rate and returns how long the read
// must wait for them; false when that is longer than the limiter's wait, and
// then nothing is taken.
func (l *ghostReadLimiter) reserve(source string, cost float64) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	s, ok := l.sources.Get(source)
	if !ok {
		s = &sourceRate{tokens: l.burst, last: now}
		l.sources.Add(source, s)
	}
	if d := now.Sub(s.last); d > 0 {
		s.tokens = min(l.burst, s.tokens+d.Seconds()*l.rate)
		s.last = now
	}
	left := s.tokens - cost
	var delay time.Duration
	if left < 0 {
		delay = time.Duration(-left / l.rate * float64(time.Second))
	}
	if delay > l.wait {
		return 0, false
	}
	s.tokens = left
	return delay, true
}

// acquire admits a read of cost page units from the caller of ctx: it waits
// for the source's rate (HTTP and WebSocket callers only; IPC and in-process
// callers are the node's own), then for the units, each at most the
// limiter's wait. The returned function gives the units back.
func (l *ghostReadLimiter) acquire(ctx context.Context, cost int64) (func(), error) {
	cost = max(1, min(cost, l.max))
	if info := rpc.PeerInfoFromContext(ctx); info.Transport == "http" || info.Transport == "ws" {
		delay, ok := l.reserve(rpcSource(info), float64(cost))
		if !ok {
			return nil, errGhostReadRate
		}
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			}
		}
	}
	wctx, cancel := context.WithTimeout(ctx, l.wait)
	defer cancel()
	if err := l.units.Acquire(wctx, cost); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errGhostReadBusy
	}
	return func() { l.units.Release(cost) }, nil
}

// rpcSource names the client of an RPC call for its limits: its IP address,
// without the port, so that new connections from one address share one
// limit; an IPv6 address by its /64, which one host may hold whole. A call
// from a loopback address that carries X-Forwarded-For came through a proxy
// on this computer (the public node's Tailscale Funnel, which sets the
// header to the client's address), and is named by the header's last
// address, the one that proxy wrote. Any other caller's header is ignored.
func rpcSource(info rpc.PeerInfo) string {
	host := info.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if addr.IsLoopback() && info.HTTP.ForwardedFor != "" {
		list := strings.Split(info.HTTP.ForwardedFor, ",")
		fwd := strings.TrimSpace(list[len(list)-1])
		if h, _, err := net.SplitHostPort(fwd); err == nil {
			fwd = h
		}
		if a, err := netip.ParseAddr(strings.Trim(fwd, "[]")); err == nil {
			addr = a.Unmap()
		}
	}
	return sourceOf(addr)
}

// sourceOf is the name of an address's source: an IPv4 address whole, an
// IPv6 address by its /64.
func sourceOf(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return addr.String()
	}
	return p.String()
}
