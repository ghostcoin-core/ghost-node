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
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

// escrowBackend serves one state as the head state, and records the block
// number asked for.
type escrowBackend struct {
	st    *state.StateDB
	err   error
	asked []rpc.BlockNumber
}

func (b *escrowBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	b.asked = append(b.asked, number)
	if b.err != nil {
		return nil, nil, b.err
	}
	return b.st, &types.Header{Number: big.NewInt(9)}, nil
}

// TestGhostEscrowSlotRPC checks ghost_escrowSlot: null for a marker with no
// slot; for an open slot the fifteen words of slot() in spec order as
// 32-byte hex strings, read from the head state; for a closed slot open 0
// and the parameters hash, action tag, action salt and instruction zero; and
// the backend's error.
func TestGhostEscrowSlotRPC(t *testing.T) {
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := common.HexToAddress("0x9a11c1e5000000000000000000000000000beef1")
	marker := ghosttree.K("ghost/test-rpc-marker")
	slot := &ghostpriv.EscrowSlot{
		Policy:     policy,
		Out:        uint256.NewInt(5000),
		Height:     7,
		Timestamp:  1_700_000_000,
		ParamsHash: common.Hash{0x11},
		ActionTag:  common.Hash{0x22},
		ActionSalt: common.Hash{0x33},
		Instr:      common.Hash{0x44},
	}
	if err := ghostpriv.OpenEscrowSlot(st, marker, slot); err != nil {
		t.Fatal(err)
	}
	if err := ghostpriv.PayEscrowSlot(st, 8, policy, marker, common.Address{0xde}, uint256.NewInt(100)); err != nil {
		t.Fatal(err)
	}
	if err := ghostpriv.DebitEscrowSlot(st, 8, policy, marker, uint256.NewInt(50)); err != nil {
		t.Fatal(err)
	}

	backend := &escrowBackend{st: st}
	server := rpc.NewServer()
	if err := server.RegisterName("ghost", NewGhostEscrowAPI(backend)); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	client := rpc.DialInProc(server)
	defer client.Close()

	call := func(m common.Hash) (json.RawMessage, error) {
		var raw json.RawMessage
		err := client.Call(&raw, "ghost_escrowSlot", m)
		return raw, err
	}
	// No slot: null.
	raw, err := call(ghosttree.K("ghost/test-rpc-no-slot"))
	if err != nil || string(raw) != "null" {
		t.Fatalf("no slot: %s, %v", raw, err)
	}
	if len(backend.asked) != 1 || backend.asked[0] != rpc.LatestBlockNumber {
		t.Fatalf("the API asked for blocks %v, want the head", backend.asked)
	}

	u := func(v uint64) string { return common.BigToHash(new(big.Int).SetUint64(v)).Hex() }
	want := []string{
		common.BytesToHash(policy[:]).Hex(), // policy
		u(1),                                // open
		u(1),                                // action nonce
		u(4850),                             // remaining
		u(5000),                             // out
		u(7),                                // height
		u(1_700_000_000),                    // timestamp
		u(100),                              // paid
		u(0),                                // recommitted
		u(50),                               // action debits
		u(0),                                // forfeited
		common.Hash{0x11}.Hex(),             // parameters hash
		common.Hash{0x22}.Hex(),             // action tag
		common.Hash{0x33}.Hex(),             // action salt
		common.Hash{0x44}.Hex(),             // instruction
	}
	check := func(name string, want []string) {
		t.Helper()
		raw, err := call(marker)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var words []string
		if err := json.Unmarshal(raw, &words); err != nil {
			t.Fatalf("%s: %s is not a list of strings: %v", name, raw, err)
		}
		if len(words) != 15 {
			t.Fatalf("%s: %d words", name, len(words))
		}
		for i := range want {
			if len(words[i]) != 66 || words[i] != want[i] {
				t.Errorf("%s: word %d is %s, want %s", name, i, words[i], want[i])
			}
		}
	}
	check("open slot", want)

	// Closed: open 0, the rest forfeited, words 11 to 14 zero.
	if err := ghostpriv.CloseEscrowSlot(st, 9, policy, marker); err != nil {
		t.Fatal(err)
	}
	closed := append([]string{}, want...)
	closed[1] = u(0)
	closed[3] = u(0)
	closed[10] = u(4850)
	for i := 11; i < 15; i++ {
		closed[i] = common.Hash{}.Hex()
	}
	check("closed slot", closed)

	// The backend's error is the call's.
	backend.err = errors.New("synthetic state error")
	if _, err := call(marker); err == nil {
		t.Fatal("no error from a backend without state")
	}
	if api := NewGhostEscrowAPI(nil); api != nil {
		if out, err := api.EscrowSlot(context.Background(), marker); err == nil || out != nil {
			t.Fatal("an API without a backend answers")
		}
	}
}
