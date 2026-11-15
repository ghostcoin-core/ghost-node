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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
)

// ErrNoProofVerifier is the refusal of a node built without the reveal proof
// verifier to run a public network.
var ErrNoProofVerifier = errors.New("this node was built without the reveal proof verifier, so it would reject every block that holds a reveal and split off the network; it does not run a public network. Use a release build for Linux or macOS, or build with `go run build/ci.go install`")

// checkProofVerifier refuses to run the public network of chainID on a node
// without a proof verifier (core/ghostpriv/verifier_nocgo.go): it would reject
// the first block holding a reveal and mine a fork of its own. The internal
// network and developer mode still run, for tests and development.
func checkProofVerifier(chainID *big.Int) error {
	if ethconfig.PublicNetwork(chainID) && !ghostpriv.CanVerifyProofs() {
		return fmt.Errorf("%w (chain ID %v)", ErrNoProofVerifier, chainID)
	}
	return nil
}
