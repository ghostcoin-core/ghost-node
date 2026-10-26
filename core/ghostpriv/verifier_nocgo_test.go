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

//go:build !(cgo && (ghostrelease || ghostproofs) && (linux || darwin))

package ghostpriv_test

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// errDefaultDataVerifier is the default verifier's answer to a data reveal:
// this build has no proof verifier and rejects every reveal.
var errDefaultDataVerifier = ghostpriv.ErrNoVerifier

// TestDefaultVerifierRejectsEveryReveal checks that the verifier a node runs
// with when the proof verifier is not linked rejects every proof, the stub's
// included, and that a chain built with the stub cannot be imported by such
// a node.
func TestDefaultVerifierRejectsEveryReveal(t *testing.T) {
	useDefault(t)
	def := ghostpriv.DefaultVerifier()
	in := &ghostpriv.VerifyInputs{Binding: common.Hash{1}, Out: new(uint256.Int), Fee: new(uint256.Int)}
	for name, proof := range map[string][]byte{
		"stub proof": ghostprivtest.Proof(in.Binding),
		"zero proof": make([]byte, ghostpriv.ProofSize),
		"empty":      nil,
	} {
		if err := def.VerifyReveal(in, proof); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("%s: %v", name, err)
		}
		if err := def.VerifyReveal(nil, proof); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("%s without inputs: %v", name, err)
		}
		if err := ghostpriv.ActiveVerifier().VerifyReveal(in, proof); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("%s with the active verifier: %v", name, err)
		}
	}

	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	c := testCoin("default", oneGhost)
	restore := ghostpriv.SetVerifier(stub)
	blocks, _ := f.generate(5, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c))
		case 4:
			fee := genWindowFee(t, b).Total
			out := u256(ghostAmount(1, 2))
			rest := new(uint256.Int).Sub(c.value, out)
			rest.Sub(rest, fee)
			b.AddTx(revealTx(t, f.newReveal(genParentRoot(b), testMarker("default"), testCoin("default rest", rest.ToBig()), addrB, out, fee)))
		}
	})
	restore()

	chain := f.newChain()
	n, err := chain.InsertChain(blocks)
	if !errors.Is(err, ghostpriv.ErrRevealProof) || !errors.Is(err, ghostpriv.ErrNoVerifier) {
		t.Fatalf("import with the default verifier: %v", err)
	}
	if n != 4 || chain.CurrentBlock().Number.Uint64() != 4 {
		t.Fatalf("imported up to block %d", chain.CurrentBlock().Number)
	}
	// The same reveal, checked directly with the active verifier.
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	tx := blocks[4].Transactions()[0]
	if _, _, err := ghostpriv.CheckReveal(st, env, ghostpriv.ActiveVerifier(), tx.GhostRevealEnvelope()); !errors.Is(err, ghostpriv.ErrNoVerifier) {
		t.Fatalf("check with the active verifier: %v", err)
	}
	if _, _, err := ghostpriv.CheckReveal(st, env, nil, tx.GhostRevealEnvelope()); !errors.Is(err, ghostpriv.ErrNoVerifier) {
		t.Fatalf("check with no verifier: %v", err)
	}
	if _, _, err := ghostpriv.CheckReveal(st, env, stub, tx.GhostRevealEnvelope()); err != nil {
		t.Fatalf("the reveal is otherwise valid: %v", err)
	}
}

// TestVerifyHoldWithoutVerifier checks that a build without the proof
// verifier rejects every proof of holding.
func TestVerifyHoldWithoutVerifier(t *testing.T) {
	for _, in := range []*ghostpriv.HoldInputs{nil, {Cf: common.Hash{1}}} {
		if err := ghostpriv.VerifyHold(in, make([]byte, 64)); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("inputs %v: %v, want %v", in, err, ghostpriv.ErrNoVerifier)
		}
	}
}
