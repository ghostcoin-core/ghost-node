package ethclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestEthGetBlockByNumber_ValidJSONResponse tests that
// JSON RPC API responses to eth_getBlockByNumber meet pattern-based expectations.
// These validations include the null-ness of certain fields for the 'pending' block
// as well existence of all expected keys and values.
func TestEthGetBlockByNumber_ValidJSONResponse(t *testing.T) {
	backend, _ := newTestBackend(t)
	client := backend.Attach()
	defer backend.Close()
	defer client.Close()

	// The miner sets the pending block in the background, so wait for it
	// rather than for a fixed time.
	waitPendingBlock(t, client, pendingWaitLimit)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	// Get a reference block.
	parent, err := NewClient(client).HeaderByNumber(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		t.Fatal("bad test")
	}

	reNull := regexp.MustCompile(`^null$`)
	reHexAnyLen := regexp.MustCompile(`^"0x[a-zA-Z0-9]+"$`)
	reHexHashLen := regexp.MustCompile(fmt.Sprintf(`^"0x[a-zA-Z0-9]{%d}"$`, common.HashLength*2))

	// completeBlockExpectations define expectations for 'earliest' and 'latest' blocks.
	completeBlockExpectations := map[string]*regexp.Regexp{
		"nonce": reHexAnyLen,
		"hash":  reHexHashLen,
		"miner": regexp.MustCompile(fmt.Sprintf(`^"0x[a-zA-Z0-9]{%d}"$`, common.AddressLength*2)),

		"totalDifficulty": reHexAnyLen,

		"mixHash":   regexp.MustCompile(fmt.Sprintf(`^"0x[0]{%d}"$`, common.HashLength*2)),
		"logsBloom": regexp.MustCompile(fmt.Sprintf(`^"0x[0]{%d}"$`, types.BloomByteLength*2)),

		"number":     reHexAnyLen,
		"difficulty": reHexAnyLen,
		"gasLimit":   reHexAnyLen,
		"gasUsed":    reHexAnyLen,
		"size":       reHexAnyLen,
		"timestamp":  reHexAnyLen,
		"extraData":  reHexAnyLen,

		"parentHash":       reHexHashLen,
		"transactionsRoot": reHexHashLen,
		"stateRoot":        reHexHashLen,
		"receiptsRoot":     reHexHashLen,
		"sha3Uncles":       reHexHashLen,

		"baseFeePerGas": reHexAnyLen,

		"uncles":       regexp.MustCompile(`^\[\]$`),
		"transactions": regexp.MustCompile(`^\[.*\]$`),
	}

	// Construct the 'pending' block expectations as a copy of the concrete block
	// expectations.
	pendingBlockExpectations := map[string]*regexp.Regexp{}
	for k, v := range completeBlockExpectations {
		pendingBlockExpectations[k] = v
	}

	// Make 'pending' specific adjustments.
	pendingBlockExpectations["nonce"] = reNull
	pendingBlockExpectations["hash"] = reNull
	pendingBlockExpectations["miner"] = reNull
	pendingBlockExpectations["totalDifficulty"] = reNull

	for blockHeight, cases := range map[string]map[string]*regexp.Regexp{
		"earliest": completeBlockExpectations,
		"latest":   completeBlockExpectations,
		"pending":  pendingBlockExpectations,
	} {
		for _, fullTxes := range []bool{true, false} {
			t.Run(fmt.Sprintf("eth_getBlockByNumber-%s-%v", blockHeight, fullTxes), func(t *testing.T) {
				gotPending := make(map[string]json.RawMessage)
				err := client.CallContext(ctx, &gotPending, "eth_getBlockByNumber", blockHeight, fullTxes)
				if err != nil {
					t.Fatal(err)
				}

				for key, re := range cases {
					gotVal, ok := gotPending[key]
					if !ok {
						t.Errorf("%s: missing key", key)
					}
					if !re.Match(gotVal) {
						t.Errorf("%s want: %v, got: %v", key, re, string(gotVal))
					}
				}

				for k, v := range gotPending {
					if _, ok := cases[k]; !ok {
						t.Errorf("%s: missing key (value: %v)", k, string(v))
					}
				}
			})
		}
	}
}

// waitPendingBlock polls the node until the miner's pending block is built on
// top of the current head, and fails the test if that does not happen within
// limit.
func waitPendingBlock(t *testing.T, client *rpc.Client, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		var latest, pending map[string]json.RawMessage
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		errLatest := client.CallContext(ctx, &latest, "eth_getBlockByNumber", "latest", false)
		errPending := client.CallContext(ctx, &pending, "eth_getBlockByNumber", "pending", false)
		cancel()
		if errLatest == nil && errPending == nil && latest != nil && pending != nil &&
			bytes.Equal(pending["parentHash"], latest["hash"]) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pending block on top of the head after %v (latest error: %v, pending error: %v, pending parent: %s, head: %s)",
				limit, errLatest, errPending, pending["parentHash"], latest["hash"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// newTestBackendWithUncles duplicates the logic of newTestBackend, except that it generates a backend
// on top of a chain that has uncles.
func newTestBackendWithUncles(t *testing.T) (*node.Node, []*types.Block) {
	// Generate test chain.
	genesis, blocks := generateTestChainWithUncles()
	// Create node
	n, err := node.New(&node.Config{})
	if err != nil {
		t.Fatalf("can't create new node: %v", err)
	}
	// Create Ethereum Service
	config := &eth.Config{Genesis: genesis}
	config.Ethash.PowMode = ethash.ModeFake
	ethservice, err := eth.New(n, config)
	if err != nil {
		t.Fatalf("can't create new ethereum service: %v", err)
	}
	// Import the test chain.
	if err := n.Start(); err != nil {
		t.Fatalf("can't start test node: %v", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks[1:]); err != nil {
		t.Fatalf("can't import test blocks: %v", err)
	}
	return n, blocks
}

// generateTestChainWithUncles is a test helper function that essentially duplicates generateTestChain,
// except that the chain generated includes block with uncles.
func generateTestChainWithUncles() (*genesisT.Genesis, []*types.Block) {
	db := rawdb.NewMemoryDatabase()
	config := params.AllEthashProtocolChanges
	genesis := &genesisT.Genesis{
		Config:    config,
		Alloc:     genesisT.GenesisAlloc{testAddr: {Balance: testBalance}},
		ExtraData: []byte("test genesis"),
		Timestamp: 9000,
	}
	generate := func(i int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		if i >= 6 {
			b2 := g.PrevBlock(i - 3).Header()
			b2.Extra = []byte("foo")
			g.AddUncle(b2)
		}
	}
	gblock := core.GenesisToBlock(genesis, db)
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(config, gblock, engine, db, 8, generate)
	blocks = append([]*types.Block{gblock}, blocks...)

	return genesis, blocks
}

// TestUncleResponseEncoding tests the correctness of the JSON encoding of uncle-type responses.
// These, different from canonical or side blocks, should NOT include the transactions field.
func TestUncleResponseEncoding(t *testing.T) {
	backend, chain := newTestBackendWithUncles(t)
	client := backend.Attach()
	defer backend.Close()
	defer client.Close()

	res := make(map[string]json.RawMessage)
	err := client.Call(&res, "eth_getUncleByBlockNumberAndIndex", hexutil.EncodeUint64(uint64(len(chain)-1)), "0x0")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("empty response")
	}

	if v, ok := res["uncles"]; !ok {
		t.Fatal("uncles: missing field")
	} else if !regexp.MustCompile(`^\[\]$`).Match(v) {
		t.Fatal("uncles: should be empty array")
	}

	if _, ok := res["transactions"]; ok {
		t.Fatal("transactions: field not omitted")
	}

	// Sanity check a few other fields
	reHexAnyLen := regexp.MustCompile(`^"0x[a-zA-Z0-9]+"$`)
	for _, field := range []string{"number", "hash", "nonce", "parentHash", "transactionsRoot"} {
		if v, ok := res[field]; !ok {
			t.Fatalf("%s: missing field", field)
		} else if !reHexAnyLen.Match(v) {
			t.Fatalf("%s: unexpected value: %s", field, string(v))
		}
	}
}
