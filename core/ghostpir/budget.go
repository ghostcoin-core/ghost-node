package ghostpir

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrClientBudget is returned for a request past the per-client budget
	// of the current window. Nothing is served and nothing is charged.
	ErrClientBudget = errors.New("ghostpir: client request budget spent")

	// ErrTotalBudget is returned for a request past the total budget of the
	// current window, whoever makes it. Nothing is served and nothing is
	// charged.
	ErrTotalBudget = errors.New("ghostpir: server request budget spent")

	// ErrBudget is returned for a budget that cannot be enforced.
	ErrBudget = errors.New("ghostpir: invalid request budget")
)

// Budget bounds the requests a restore server answers in every window of
// time: those of one client, and those of all clients together. Every
// request counts once, a bulk read as a PIR query: each has a fixed shape,
// so the work of one request is bounded by the snapshot and the per-request
// bound times the budget bounds the work of a window.
type Budget struct {
	Window    time.Duration // the period the budgets refill over
	PerClient int           // requests one client may make in a window
	Total     int           // requests all clients together may make in a window
}

// DefaultBudget is the budget of a restore server that is given none. A
// restore reads one hint bucket, its overflow run, the note and its witness
// for every note of the wallet, plus the bulk data: 256 requests a minute
// lets a wallet of 60 notes restore in one minute, and 4,096 a minute caps
// the server at 16 such restores at once.
var DefaultBudget = Budget{Window: time.Minute, PerClient: 256, Total: 4096}

// Validate checks that the budget can be enforced: a positive window, a
// positive per-client budget and a total at least the per-client one.
func (b Budget) Validate() error {
	if b.Window <= 0 || b.PerClient <= 0 || b.Total < b.PerClient {
		return fmt.Errorf("%w: %d per client and %d in all per %v", ErrBudget, b.PerClient, b.Total, b.Window)
	}
	return nil
}

// budgeter charges requests to a Budget. Windows are fixed: the first
// request after a window has run out opens the next one with every budget
// full. A client is kept only while it has a request charged in the current
// window, so the clients held are never more than Total.
type budgeter struct {
	budget Budget
	now    func() time.Time

	mu      sync.Mutex
	start   time.Time      // start of the current window; zero before the first request
	total   int            // requests charged in the current window
	clients map[string]int // requests charged to each client in the current window
}

func newBudgeter(b Budget) (*budgeter, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &budgeter{budget: b, now: time.Now, clients: make(map[string]int)}, nil
}

// charge charges one request to client, or refuses it with ErrClientBudget
// or ErrTotalBudget and charges nothing.
func (g *budgeter) charge(client string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if g.start.IsZero() || now.Sub(g.start) >= g.budget.Window || now.Before(g.start) {
		g.start = now
		g.total = 0
		clear(g.clients)
	}
	if g.clients[client] >= g.budget.PerClient {
		return fmt.Errorf("%w: %d requests per %v", ErrClientBudget, g.budget.PerClient, g.budget.Window)
	}
	if g.total >= g.budget.Total {
		return fmt.Errorf("%w: %d requests per %v", ErrTotalBudget, g.budget.Total, g.budget.Window)
	}
	g.clients[client]++
	g.total++
	return nil
}

// used returns the requests charged to client and to all clients in the
// current window.
func (g *budgeter) used(client string) (int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now := g.now(); g.start.IsZero() || now.Sub(g.start) >= g.budget.Window || now.Before(g.start) {
		return 0, 0
	}
	return g.clients[client], g.total
}
