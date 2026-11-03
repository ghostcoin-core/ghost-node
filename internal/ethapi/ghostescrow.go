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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"
)

// EscrowStateReader gives the state of a block by number; the Ethereum
// service's API backend is one.
type EscrowStateReader interface {
	StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error)
}

// GhostEscrowAPI serves the escrow slots in the ghost namespace, from the
// head state (spec 10, section 7).
type GhostEscrowAPI struct {
	b EscrowStateReader
}

// NewGhostEscrowAPI returns the escrow slot reads over a backend.
func NewGhostEscrowAPI(b EscrowStateReader) *GhostEscrowAPI {
	return &GhostEscrowAPI{b: b}
}

var errNoEscrowState = errors.New("no head state")

// EscrowSlot, ghost_escrowSlot, returns the escrow slot of marker in the
// head state as the fifteen 32-byte words the native slot() returns, in the
// same order: the policy address, open (1 or 0), the action nonce,
// remaining, out, the opening height and timestamp, paid, recommitted, the
// action debits, forfeited, the parameters hash, the action tag, the action
// salt and the instruction. A closed slot reads with open 0 and its last
// four words zero. It returns null when no slot was ever opened under the
// marker.
func (api *GhostEscrowAPI) EscrowSlot(ctx context.Context, marker common.Hash) ([]common.Hash, error) {
	if api.b == nil {
		return nil, errNoEscrowState
	}
	st, _, err := api.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errNoEscrowState
	}
	slot, ok := ghostpriv.ReadEscrowSlot(st, marker)
	if !ok {
		return nil, nil
	}
	words := vm.EscrowSlotWords(slot)
	out := make([]common.Hash, 0, vm.EscrowSlotWordCount)
	for i := 0; i < len(words); i += common.HashLength {
		out = append(out, common.BytesToHash(words[i:i+common.HashLength]))
	}
	return out, nil
}
