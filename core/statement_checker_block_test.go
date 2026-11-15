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

package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// checkerCallRuntime is a policy that passes its whole calldata to the
// statement checker by STATICCALL with 1,000,000 gas and returns the call's
// success flag, the first word of its return data and the return data's
// size.
func checkerCallRuntime() []byte {
	code := []byte{byte(vm.CALLDATASIZE), byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.CALLDATACOPY)}
	code = append(code, byte(vm.PUSH1), 0x20, byte(vm.PUSH1), 0x20, byte(vm.CALLDATASIZE), byte(vm.PUSH1), 0)
	code = append(code, byte(vm.PUSH20))
	code = append(code, ghost.StatementCheckerAddress.Bytes()...)
	code = append(code, byte(vm.PUSH3), 0x0f, 0x42, 0x40, byte(vm.STATICCALL))
	code = append(code, byte(vm.PUSH1), 0, byte(vm.MSTORE))
	code = append(code, byte(vm.RETURNDATASIZE), byte(vm.PUSH1), 0x40, byte(vm.MSTORE))
	return append(code, byte(vm.PUSH1), 0x60, byte(vm.PUSH1), 0, byte(vm.RETURN))
}

// revealOnlyVerifier verifies reveals but has no proof system for the
// statement checker's statement, as a verifier that predates it.
type revealOnlyVerifier struct{ ghostprivtest.Verifier }

func (revealOnlyVerifier) VerifiesPreimage() bool { return false }

// noProofVerifier is a node without the proof verifier: every proof is
// refused with ghostpriv.ErrNoVerifier.
type noProofVerifier struct{}

func (noProofVerifier) VerifyReveal(*ghostpriv.VerifyInputs, []byte) error {
	return ghostpriv.ErrNoVerifier
}

func (noProofVerifier) VerifiesPreimage() bool { return true }

// TestStatementCheckerUnverifiableBlockInvalid checks that a block whose
// transaction calls a policy that asks the statement checker about a valid
// proof is accepted by a node that verifies the statement, and refused, as
// an invalid block, by a node that cannot: the build without the proof
// verifier and a verifier with no proof system for the statement. Neither
// answers 0 and goes on to a different state.
func TestStatementCheckerUnverifiableBlockInvalid(t *testing.T) {
	defer ghostpriv.SetVerifier(ghostprivtest.Verifier{})()

	s := newPolicyTestSetup()
	s.initCode = policyDeployCode(checkerCallRuntime())
	s.policy = ghost.PolicyAddress(s.salt, crypto.Keccak256Hash(s.initCode))
	chainID := s.config.GetChainID().Uint64()

	var genesis common.Hash
	_, blocks, receipts := GenerateChainWithGenesis(s.gspec, s.engine, 3, func(i int, b *BlockGen) {
		switch i {
		case 0:
			genesis = b.PrevBlock(-1).Hash()
			b.SetCoinbase(s.account)
		case 1:
			b.AddTx(s.createTx(b, genesis))
		case 2:
			p := &ghostpriv.Preimage{Y: ghostpriv.PreimageY(common.Hash{7})}
			for j := range p.Context {
				p.Context[j] = byte(j)
			}
			p.Proof = ghostprivtest.PreimageProof(p.BindingDigest(chainID, genesis, s.policy))
			input, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			b.AddTx(s.tx(b, genesis, &s.policy, new(big.Int), 20_000_000, input))
		}
	})
	if r := receipts[1][0]; r.Status != types.ReceiptStatusSuccessful {
		t.Fatal("the policy creation fails")
	}
	if r := receipts[2][0]; r.Status != types.ReceiptStatusSuccessful {
		t.Fatal("the call to the checker policy fails")
	}

	// A node that verifies the statement imports the whole chain.
	chain := s.newChain(t)
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("verifying node: block %d: %v", n+1, err)
	}
	chain.Stop()

	for name, v := range map[string]ghostpriv.Verifier{
		"no proof verifier":       noProofVerifier{},
		"no proof system for it":  revealOnlyVerifier{},
		"the build's own default": nil,
	} {
		t.Run(name, func(t *testing.T) {
			restore := ghostpriv.SetVerifier(v)
			defer restore()
			if v == nil && ghostpriv.CanVerifyProofs() {
				t.Skip("this build links the proof verifier")
			}
			chain := s.newChain(t)
			defer chain.Stop()
			if n, err := chain.InsertChain(blocks[:2]); err != nil {
				t.Fatalf("block %d: %v", n+1, err)
			}
			head := chain.CurrentBlock().Hash()
			if _, err := chain.InsertChain(blocks[2:]); !errors.Is(err, vm.ErrStatementUnverifiable) {
				t.Errorf("import error %v, want %v", err, vm.ErrStatementUnverifiable)
			}
			if chain.CurrentBlock().Hash() != head {
				t.Error("the head moved to the block the node cannot verify")
			}
		})
	}
}
