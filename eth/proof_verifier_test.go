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
	"testing"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// TestNoProofVerifierRefusesPublicNetwork checks that a node without the
// proof verifier refuses to start on the public test network, the network a
// node with no genesis runs, while the internal network and developer mode
// still pass the check, and that a node with a verifier passes it everywhere.
func TestNoProofVerifierRefusesPublicNetwork(t *testing.T) {
	testnet := new(big.Int).SetUint64(ghost.TestNetChainID)
	others := []*big.Int{big.NewInt(ghost.InternalNetChainID), big.NewInt(ghost.DeveloperChainID)}

	func() {
		defer ghostpriv.SetVerifier(ghostprivtest.Verifier{})()
		for _, id := range append(others, testnet) {
			if err := checkProofVerifier(id); err != nil {
				t.Errorf("with a verifier, chain ID %v: %v", id, err)
			}
		}
	}()

	defer ghostpriv.SetVerifier(nil)()
	if ghostpriv.CanVerifyProofs() {
		t.Skip("this build links the proof verifier")
	}
	if err := checkProofVerifier(testnet); !errors.Is(err, ErrNoProofVerifier) {
		t.Errorf("public test network: %v, want %v", err, ErrNoProofVerifier)
	}
	for _, id := range others {
		if err := checkProofVerifier(id); err != nil {
			t.Errorf("chain ID %v: %v", id, err)
		}
	}

	// The whole service: a node with no genesis runs the public test
	// network, and refuses.
	stack, err := node.New(&node.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	config := ethconfig.Defaults
	if _, err := New(stack, &config); !errors.Is(err, ErrNoProofVerifier) {
		t.Errorf("eth.New on the public test network: %v, want %v", err, ErrNoProofVerifier)
	}
}
