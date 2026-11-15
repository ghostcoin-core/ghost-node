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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

func TestRPCSourceIsTheClientAddress(t *testing.T) {
	peer := func(remote, fwd string) rpc.PeerInfo {
		var info rpc.PeerInfo
		info.Transport, info.RemoteAddr, info.HTTP.ForwardedFor = "http", remote, fwd
		return info
	}
	for _, c := range []struct {
		name string
		info rpc.PeerInfo
		want string
	}{
		{"ipv4 drops the port", peer("203.0.113.7:51000", ""), "203.0.113.7"},
		{"another port is the same source", peer("203.0.113.7:51001", ""), "203.0.113.7"},
		{"ipv6 by its /64", peer("[2001:db8:1:2:aaaa::1]:443", ""), "2001:db8:1:2::/64"},
		{"another ipv6 of the /64", peer("[2001:db8:1:2:bbbb::9]:80", ""), "2001:db8:1:2::/64"},
		{"mapped ipv4", peer("[::ffff:203.0.113.7]:1", ""), "203.0.113.7"},
		{"loopback without a proxy", peer("127.0.0.1:40000", ""), "127.0.0.1"},
		{"proxy on this computer", peer("127.0.0.1:40000", "198.51.100.4"), "198.51.100.4"},
		{"ipv6 loopback proxy", peer("[::1]:40000", "198.51.100.4"), "198.51.100.4"},
		{"last address is the proxy's", peer("127.0.0.1:40000", "10.9.9.9, 198.51.100.4"), "198.51.100.4"},
		{"forwarded with a port", peer("127.0.0.1:40000", "198.51.100.4:999"), "198.51.100.4"},
		{"forwarded ipv6", peer("127.0.0.1:40000", "2001:db8:7:7::5"), "2001:db8:7:7::/64"},
		{"unreadable forwarded address", peer("127.0.0.1:40000", "nonsense"), "127.0.0.1"},
		{"remote caller cannot forward", peer("203.0.113.7:51000", "198.51.100.4"), "203.0.113.7"},
		{"in process", rpc.PeerInfo{}, ""},
	} {
		if got := rpcSource(c.info); got != c.want {
			t.Errorf("%s: source %q, want %q", c.name, got, c.want)
		}
	}
}

// httpPeer is the context, without its cancellation, the HTTP server gives a
// call from a remote address with an X-Forwarded-For header.
func httpPeer(t *testing.T, remote, fwd string) context.Context {
	t.Helper()
	var got context.Context
	srv := rpc.NewServer()
	t.Cleanup(srv.Stop)
	if err := srv.RegisterName("probe", &ctxProbe{save: func(ctx context.Context) { got = ctx }}); err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"probe_save","params":[]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.RemoteAddr = remote
	if fwd != "" {
		req.Header.Set("X-Forwarded-For", fwd)
	}
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil {
		t.Fatal("probe not called")
	}
	// The request is over; its peer information outlives it.
	return context.WithoutCancel(got)
}

type ctxProbe struct{ save func(context.Context) }

func (p *ctxProbe) Save(ctx context.Context) { p.save(ctx) }

func TestHTTPCarriesTheForwardedAddress(t *testing.T) {
	info := rpc.PeerInfoFromContext(httpPeer(t, "127.0.0.1:40000", "198.51.100.4"))
	if info.Transport != "http" || info.HTTP.ForwardedFor != "198.51.100.4" || rpcSource(info) != "198.51.100.4" {
		t.Fatalf("peer info %+v, source %q", info, rpcSource(info))
	}
}

// TestGhostReadRateIsPerSource checks the rate of each source: a burst at
// once, then reads that wait for the refill up to the limiter's wait, then a
// refusal; another source, or the same address on another port, is held to
// the same rate as its address, and IPC callers to none.
func TestGhostReadRateIsPerSource(t *testing.T) {
	var (
		mu  sync.Mutex
		now = time.Unix(1_000_000, 0)
	)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	l := newGhostReadLimiter(64, 10, 20, time.Second, 16, clock)
	for i := 0; i < 20; i++ {
		if d, ok := l.reserve("a", 1); !ok || d != 0 {
			t.Fatalf("read %d of the burst: wait %v, %v", i, d, ok)
		}
	}
	// Ten more fit in the second's wait, each later than the last.
	var last time.Duration
	for i := 0; i < 10; i++ {
		d, ok := l.reserve("a", 1)
		if !ok || d <= last {
			t.Fatalf("read %d past the burst: wait %v after %v, %v", i, d, last, ok)
		}
		last = d
	}
	if _, ok := l.reserve("a", 1); ok {
		t.Fatal("read past the wait admitted")
	}
	if d, ok := l.reserve("b", 20); !ok || d != 0 {
		t.Fatalf("another source: wait %v, %v", d, ok)
	}
	mu.Lock()
	now = now.Add(3 * time.Second)
	mu.Unlock()
	if d, ok := l.reserve("a", 1); !ok || d != 0 {
		t.Fatalf("after the refill: wait %v, %v", d, ok)
	}

	// Through acquire, two ports of one address share the rate; an IPC
	// caller is not held to it.
	l = newGhostReadLimiter(64, 1, 2, 10*time.Millisecond, 16, clock)
	for i, port := range []string{"1", "2"} {
		release, err := l.acquire(httpPeer(t, "203.0.113.7:"+port, ""), 1)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		release()
	}
	if _, err := l.acquire(httpPeer(t, "203.0.113.7:3", ""), 1); err != errGhostReadRate {
		t.Fatalf("third port of the address: %v, want %v", err, errGhostReadRate)
	}
	// Behind the node's own proxy, callers are told apart by the forwarded
	// address.
	if _, err := l.acquire(httpPeer(t, "127.0.0.1:5", "198.51.100.4"), 2); err != nil {
		t.Fatalf("forwarded caller: %v", err)
	}
	if _, err := l.acquire(httpPeer(t, "127.0.0.1:6", "198.51.100.4"), 1); err != errGhostReadRate {
		t.Fatalf("same forwarded caller: %v, want %v", err, errGhostReadRate)
	}
	for i := 0; i < 10; i++ {
		release, err := l.acquire(context.Background(), 2)
		if err != nil {
			t.Fatalf("in-process read %d: %v", i, err)
		}
		release()
	}
	var coded rpc.Error
	if !errors.As(error(errGhostReadRate), &coded) || coded.ErrorCode() != -32005 {
		t.Fatal("rate refusal has no JSON-RPC code -32005")
	}
}

// TestGhostReadUnitsAreShared checks the units in flight: reads of every
// caller together hold at most the limiter's units, a read that finds none
// waits and is refused after the wait, and one is admitted once units are
// given back.
func TestGhostReadUnitsAreShared(t *testing.T) {
	l := newGhostReadLimiter(8, 1000, 1000, 50*time.Millisecond, 16, nil)
	a, err := l.acquire(httpPeer(t, "203.0.113.1:1", ""), 8)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := l.acquire(httpPeer(t, "203.0.113.2:1", ""), 1); err != errGhostReadBusy {
		t.Fatalf("read with no units: %v, want %v", err, errGhostReadBusy)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("refused without waiting")
	}
	if _, err := l.acquire(context.Background(), 1); err != errGhostReadBusy {
		t.Fatalf("in-process read with no units: %v, want %v", err, errGhostReadBusy)
	}
	// A cost above the units is held to all of them, not refused forever.
	done := make(chan error, 1)
	go func() {
		release, err := l.acquire(context.Background(), 100)
		if err == nil {
			release()
		}
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	a()
	if err := <-done; err != nil {
		t.Fatalf("read once units are back: %v", err)
	}
}

// TestGhostReadsShareTheLimit checks that the page, page set, page root and
// bucket reads all take units of the one limiter before any store read.
func TestGhostReadsShareTheLimit(t *testing.T) {
	saved := ghostReads
	ghostReads = newGhostReadLimiter(1, 1000, 1000, 20*time.Millisecond, 16, nil)
	defer func() { ghostReads = saved }()
	hold, err := ghostReads.acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()

	// The history is not nil, so each read reaches the limiter; it is
	// never read, as every read is refused first.
	tree := &GhostAPI{history: emptyHistory(), limit: ghostReads}
	buckets := &GhostBucketAPI{history: emptyHistory(), limit: ghostReads, entries: 1}
	escrow := &GhostEscrowAPI{b: nilEscrowState{}, limit: ghostReads}
	ctx := context.Background()
	anchor := common.Hash{1}
	for name, call := range map[string]func() error{
		"getTreePage":     func() error { _, err := tree.GetTreePage(ctx, 0, 0, 0, anchor); return err },
		"getPageSet":      func() error { _, err := tree.GetPageSet(ctx, 0, 0, []hexutil.Uint64{0}, anchor); return err },
		"getPageRoots":    func() error { _, err := tree.GetPageRoots(ctx, 0, 0, anchor); return err },
		"getPageRootTail": func() error { _, err := tree.GetPageRootTail(ctx, 0, 0, 0, anchor); return err },
		"getNoteBucket":   func() error { _, err := buckets.GetNoteBucket(ctx, 0, 0, 0, 0, anchor, nil); return err },
		"escrowSlot":      func() error { _, err := escrow.EscrowSlot(ctx, anchor); return err },
	} {
		if err := call(); err != errGhostReadBusy {
			t.Errorf("ghost_%s with the units held: %v, want %v", name, err, errGhostReadBusy)
		}
	}
}

// TestRPCSignatureBudgetIsPerSource checks that the signature budget is
// keyed by the client's address: one address on new connections, or one
// forwarded address behind the node's proxy, gets its own budget once and
// cannot use up the node-wide budget, which another source still finds.
func TestRPCSignatureBudgetIsPerSource(t *testing.T) {
	saved := rpcSigBudgets
	rpcSigBudgets = newSigBudgets(2, 5, nil)
	defer func() { rpcSigBudgets = saved }()

	mock := newBackendMock()
	signer := types.NewGhostAccountSigner(types.LatestSigner(mock.config), common.Hash{0x01})
	backend := &sigcheckBackend{backendMock: mock}
	txs := sigcheckTxs(t, signer, mock.config.GetChainID(), 1)

	submit := func(remote, fwd string) error {
		_, err := SubmitTransaction(httpPeer(t, remote, fwd), backend, txs[0])
		return err
	}
	// One address, a new port each time: two reach the pool, the rest are
	// refused by its own budget.
	reached := 0
	for port := 1000; port < 1020; port++ {
		switch err := submit("203.0.113.7:"+strconv.Itoa(port), ""); err {
		case errSigcheckVerified:
			reached++
		case txpool.ErrSignatureBudget:
		default:
			t.Fatalf("port %d: %v", port, err)
		}
	}
	if reached != 2 {
		t.Fatalf("one address on 20 connections reached the pool %d times, want 2", reached)
	}
	// The same behind the proxy with one forwarded address.
	reached = 0
	for port := 1000; port < 1020; port++ {
		if submit("127.0.0.1:"+strconv.Itoa(port), "198.51.100.4") == errSigcheckVerified {
			reached++
		}
	}
	if reached != 2 {
		t.Fatalf("one forwarded address reached the pool %d times, want 2", reached)
	}
	// The node-wide budget of 5 still has room for a third source.
	if err := submit("192.0.2.1:1", ""); err != errSigcheckVerified {
		t.Fatalf("another source after the flood: %v, want it to reach the pool", err)
	}
}

// TestRPCSignatureBudgetAfterCheapChecks checks that an account transaction
// the pool would refuse without its signature takes no check of the budgets.
func TestRPCSignatureBudgetAfterCheapChecks(t *testing.T) {
	saved := rpcSigBudgets
	rpcSigBudgets = newSigBudgets(1, 1, nil)
	defer func() { rpcSigBudgets = saved }()

	mock := newBackendMock()
	signer := types.NewGhostAccountSigner(types.LatestSigner(mock.config), common.Hash{0x01})
	backend := &sigcheckBackend{backendMock: mock}
	good := sigcheckTxs(t, signer, mock.config.GetChainID(), 1)[0]
	wrongChain := accountTx(t, signer, big.NewInt(7), 100000)

	ctx := httpPeer(t, "203.0.113.7:1", "")
	for i := 0; i < 5; i++ {
		_, err := SubmitTransaction(ctx, backend, wrongChain)
		if !errors.Is(err, types.ErrInvalidChainId) {
			t.Fatalf("wrong chain %d: %v, want %v", i, err, types.ErrInvalidChainId)
		}
	}
	var gasErr error
	for _, gas := range []uint64{21000, 30000} {
		low := accountTx(t, signer, mock.config.GetChainID(), gas)
		_, gasErr = SubmitTransaction(ctx, backend, low)
		if !errors.Is(gasErr, core.ErrIntrinsicGas) {
			t.Fatalf("gas %d: %v, want %v", gas, gasErr, core.ErrIntrinsicGas)
		}
	}
	if _, err := SubmitTransaction(ctx, backend, good); err != errSigcheckVerified {
		t.Fatalf("good transaction after junk: %v, want it to reach the pool", err)
	}
}

// accountTx signs one account transaction of a chain ID and gas.
func accountTx(t *testing.T, signer types.Signer, chainID *big.Int, gas uint64) *types.Transaction {
	t.Helper()
	var seed [mldsa44.SeedSize]byte
	seed[0] = 0x43
	_, key := mldsa44.NewKeyFromSeed(&seed)
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   chainID,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       gas,
		To:        &common.Address{0x01},
		Value:     new(big.Int),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// emptyHistory is a tree history over an empty store.
func emptyHistory() *ghosttree.History {
	return ghosttree.NewHistory(rawdb.NewMemoryDatabase())
}

// nilEscrowState has no state.
type nilEscrowState struct{}

func (nilEscrowState) StateAndHeaderByNumber(context.Context, rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
