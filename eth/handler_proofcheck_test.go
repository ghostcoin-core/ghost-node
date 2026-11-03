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

package eth

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// handlerProofPolicy is a frozen policy the test chain's genesis registers.
var handlerProofPolicy = common.HexToAddress("0x00000000000000000000000000000000c0ffee30")

// handlerProofSeeds are the funded accounts of the proof test chain.
var handlerProofSeeds = []byte{0x21, 0x22, 0x23, 0x24}

// countingStub is the stub verifier, counting the proofs it verifies.
type countingStub struct {
	mu    sync.Mutex
	calls int
}

func (c *countingStub) VerifiesPreimage() bool { return true }

func (c *countingStub) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return ghostprivtest.Verifier{}.VerifyReveal(in, proof)
}

func (c *countingStub) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// newProofcheckHandler is newSigcheckHandler on a chain whose genesis
// registers handlerProofPolicy as a frozen policy of block 0 and funds the
// accounts of handlerProofSeeds, with a block gas limit that holds a
// proof-carrying transaction.
func newProofcheckHandler(t *testing.T) *sigcheckHandler {
	t.Helper()
	code := []byte{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
	var flag common.Hash
	flag[0] = 0x01 // frozen, created at height 0
	storage := make(map[common.Hash]common.Hash)
	storage[ghost.PolicyRegistryKey(handlerProofPolicy, ghost.PolicyRegistryFlagWord)] = flag
	storage[ghost.PolicyRegistryKey(handlerProofPolicy, ghost.PolicyRegistryCodeHashWord)] = crypto.Keccak256Hash(code)
	alloc := genesisT.GenesisAlloc{
		testAddr:           {Balance: new(big.Int).Lsh(big.NewInt(1), 100)},
		handlerProofPolicy: {Code: code, Nonce: 1},
	}
	alloc[ghost.PolicyRegistryAccount] = genesisT.GenesisAccount{Nonce: 1, Storage: storage}
	for _, seed := range handlerProofSeeds {
		_, _, addr := testAccount(seed)
		alloc[addr] = genesisT.GenesisAccount{Balance: new(big.Int).Lsh(big.NewInt(1), 100)}
	}
	gspec := &genesisT.Genesis{Config: params.TestChainConfig, GasLimit: 30_000_000, Alloc: alloc}
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 1, nil)
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	config := legacypool.DefaultConfig
	config.Journal = ""
	pool, err := txpool.New(config.PriceLimit, chain, []txpool.SubPool{legacypool.New(config, chain)})
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(&handlerConfig{
		Database:   db,
		Chain:      chain,
		TxPool:     pool,
		Merger:     consensus.NewMerger(rawdb.NewMemoryDatabase()),
		Network:    1,
		Sync:       downloader.SnapSync,
		BloomCache: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Start(1000)
	s := &sigcheckHandler{handler: h, chain: chain, pool: pool}
	h.sigDropPeer = func(id string) {
		s.mu.Lock()
		s.dropped = append(s.dropped, id)
		s.mu.Unlock()
		h.removePeer(id)
	}
	t.Cleanup(func() {
		h.Stop()
		pool.Close()
		chain.Stop()
	})
	return s
}

// proofTx signs a transaction from the account of seed to to whose data is
// the checker input of a statement over a context of ctx, made for to, with
// a valid stub proof or a wrong one, after pad zero bytes.
func (s *sigcheckHandler) proofTx(t *testing.T, seed byte, nonce uint64, to common.Address, ctx byte, valid bool, pad int) *types.Transaction {
	t.Helper()
	p := &ghostpriv.Preimage{Y: ghostpriv.PreimageY(common.Hash{0x31})}
	p.Context[0] = ctx
	p.Proof = ghostprivtest.PreimageProof(p.BindingDigest(s.chain.Config().GetChainID().Uint64(), s.chain.Genesis().Hash(), to))
	if !valid {
		p.Proof[64] = 0x01
	}
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := testAccount(seed)
	return signTestTx(s.chain, key, &types.GhostAccountTx{
		Nonce:     nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1_000_000_000),
		Gas:       8_000_000,
		To:        &to,
		Data:      append(make([]byte, pad), input...),
	})
}

// TestHandlerDropsPeerAtProofFailLimit checks that a peer is disconnected at
// its third failed proof check at one head, an oversized delivery and a
// proof refused before counting as one each, and not before; that a peer
// sending a valid proof-carrying transaction is not; and that state failures
// and a used-up budget are not held against a peer.
func TestHandlerDropsPeerAtProofFailLimit(t *testing.T) {
	stub := new(countingStub)
	defer ghostpriv.SetVerifier(stub)()
	s := newProofcheckHandler(t)
	honest, _ := s.connect(t, 1)
	liar, liarRemote := s.connect(t, 2)

	// A valid proof-carrying transaction is admitted.
	good := s.proofTx(t, 0x21, 0, handlerProofPolicy, 0, true, 0)
	if errs := s.handler.addTxsFromPeer(honest.ID(), []*types.Transaction{good}); errs[0] != nil {
		t.Fatalf("valid proof-carrying transaction: %v", errs[0])
	}
	if !s.pool.Has(good.Hash()) || stub.count() != 1 {
		t.Fatalf("valid proof-carrying transaction: in the pool %v, %d verifications", s.pool.Has(good.Hash()), stub.count())
	}

	// Two failed proofs: the peer stays.
	bad := make([]*types.Transaction, 4)
	for i := range bad {
		bad[i] = s.proofTx(t, 0x22, 0, handlerProofPolicy, byte(1+i), false, 0)
	}
	for i := 0; i < 2; i++ {
		errs := s.handler.addTxsFromPeer(liar.ID(), bad[i:i+1])
		if !errors.Is(errs[0], txpool.ErrProofFailed) {
			t.Fatalf("failed proof %d: error %v", i, errs[0])
		}
		if dropped := s.droppedPeers(); len(dropped) != 0 {
			t.Fatalf("peer dropped at failed proof %d: %v", i+1, dropped)
		}
	}
	// The third, by broadcast, disconnects it.
	s.broadcast(t, liar, bad[2])
	if dropped := s.droppedPeers(); len(dropped) != 1 || dropped[0] != liar.ID() {
		t.Fatalf("dropped %v, want peer %s at its third failed proof", dropped, liar.ID())
	}
	if !pipeClosed(liarRemote) {
		t.Fatal("peer at the failed proof limit still connected")
	}
	verified := stub.count()

	// An oversized delivery, dropped unread, and a proof refused before
	// count too.
	other, otherRemote := s.connect(t, 3)
	over := s.proofTx(t, 0x23, 0, handlerProofPolicy, 0, true, ghost.ProofTxMaxBytes)
	errs := s.handler.addTxsFromPeer(other.ID(), []*types.Transaction{over})
	if !errors.Is(errs[0], txpool.ErrProofTxOversized) || s.pool.Has(over.Hash()) || stub.count() != verified {
		t.Fatalf("oversized: error %v, verifications %d", errs[0], stub.count()-verified)
	}
	errs = s.handler.addTxsFromPeer(other.ID(), bad[:1])
	if !errors.Is(errs[0], txpool.ErrProofRejectedBefore) || stub.count() != verified {
		t.Fatalf("refused before: error %v, verifications %d", errs[0], stub.count()-verified)
	}
	if dropped := s.droppedPeers(); len(dropped) != 1 {
		t.Fatalf("peer dropped before its third failure: %v", dropped)
	}
	s.handler.addTxsFromPeer(other.ID(), bad[3:4])
	if dropped := s.droppedPeers(); len(dropped) != 2 || dropped[1] != other.ID() {
		t.Fatalf("dropped %v, want peer %s second", dropped, other.ID())
	}
	if !pipeClosed(otherRemote) {
		t.Fatal("peer at the failed proof limit still connected")
	}

	// State failures are not held against a peer: transactions to an
	// address that is no frozen policy are refused, uncharged, and past the
	// budget of the head the rest are dropped unverified.
	patient, _ := s.connect(t, 4)
	plain := common.HexToAddress("0x00000000000000000000000000000000c0ffee31")
	before := stub.count()
	for i := 0; i < ghost.ProofPeerBudget; i++ {
		errs := s.handler.addTxsFromPeer(patient.ID(), []*types.Transaction{s.proofTx(t, 0x24, 0, plain, byte(i), true, 0)})
		if !errors.Is(errs[0], txpool.ErrOversizedData) || txpool.ProofCharged(errs[0]) {
			t.Fatalf("to no policy %d: error %v", i, errs[0])
		}
	}
	errs = s.handler.addTxsFromPeer(patient.ID(), []*types.Transaction{s.proofTx(t, 0x24, 0, handlerProofPolicy, 9, false, 0)})
	if errs[0] != txpool.ErrProofPeerBudget {
		t.Fatalf("past the budget: error %v, want %v", errs[0], txpool.ErrProofPeerBudget)
	}
	if stub.count() != before {
		t.Fatalf("%d proofs verified for state failures and a used-up budget", stub.count()-before)
	}
	for _, id := range s.droppedPeers() {
		if id == patient.ID() || id == honest.ID() {
			t.Fatalf("peer %s dropped", id)
		}
	}
}
