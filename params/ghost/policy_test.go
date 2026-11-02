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

package ghost_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// policyState is a map-backed state for the registry helpers.
type policyState struct {
	storage map[common.Address]map[common.Hash]common.Hash
	nonces  map[common.Address]uint64
}

func newPolicyState() *policyState {
	return &policyState{storage: map[common.Address]map[common.Hash]common.Hash{}, nonces: map[common.Address]uint64{}}
}

func (s *policyState) GetState(a common.Address, k common.Hash) common.Hash { return s.storage[a][k] }
func (s *policyState) SetState(a common.Address, k, v common.Hash) {
	if s.storage[a] == nil {
		s.storage[a] = map[common.Hash]common.Hash{}
	}
	s.storage[a][k] = v
}
func (s *policyState) GetNonce(a common.Address) uint64    { return s.nonces[a] }
func (s *policyState) SetNonce(a common.Address, n uint64) { s.nonces[a] = n }

// TestFrozenPolicyReserved checks the reserved-address rules, the fixed
// addresses of the policy rules, the tagged hash of the policy address and
// of the registry keys, and the registry entry layout.
func TestFrozenPolicyReserved(t *testing.T) {
	at := func(b ...byte) common.Address { return common.BytesToAddress(b) }
	if ghost.PolicyFactoryAddress != at(0x62) || ghost.EscrowNativeAddress != at(0x60) || ghost.StatementCheckerAddress != at(0x61) {
		t.Fatal("the natives are not at 0x60, 0x61 and 0x62")
	}
	if ghost.PolicyRegistryAccount != common.HexToAddress("0x67686f7374000000000000000000000000000009") {
		t.Fatalf("registry account %v", ghost.PolicyRegistryAccount)
	}

	reserved := []common.Address{
		{}, at(0x01), at(0x05), at(0x09), at(0x11), at(0x51), at(0x60), at(0x61), at(0x62), at(0x01, 0x00), at(0xff, 0xff),
		ghost.CoinTreeAccount, ghost.DataTreeAccount, ghost.CoinMarkerAccount, ghost.DataMarkerAccount,
		ghost.CommitEntryAddress, ghost.PrivTotalsAccount, ghost.DataCommitEntryAddress, ghost.PolicyRegistryAccount,
		common.HexToAddress("0x67686f737400000000000000000000000000ffff"),
	}
	for _, a := range reserved {
		if !ghost.IsReservedAddress(a) {
			t.Errorf("%v is not reserved", a)
		}
	}
	notReserved := []common.Address{
		at(0x01, 0x00, 0x00),
		common.HexToAddress("0x67686f7374000000000000000000000000010000"),
		common.HexToAddress("0x67686f7374010000000000000000000000000001"),
		common.HexToAddress("0x67686f7300000000000000000000000000000001"),
		common.HexToAddress("0x5e4de2000000000000000000000000000000aaaa"),
		ghost.PolicyAddress(common.Hash{1}, crypto.Keccak256Hash([]byte{0x00})),
	}
	for _, a := range notReserved {
		if ghost.IsReservedAddress(a) {
			t.Errorf("%v is reserved", a)
		}
	}

	// The fixed targets a frozen context may call.
	allowed := map[common.Address]bool{at(0x02): true, at(0x03): true, at(0x04): true, at(0x51): true, at(0x60): true, at(0x61): true}
	for b := 0; b < 0x200; b++ {
		a := at(byte(b>>8), byte(b))
		if got := ghost.IsFrozenCallTarget(a); got != allowed[a] {
			t.Errorf("frozen call target %v: %v, want %v", a, got, allowed[a])
		}
	}
	if ghost.IsFrozenCallTarget(ghost.PolicyRegistryAccount) || ghost.IsFrozenCallTarget(common.HexToAddress("0x0100000000000000000000000000000000000002")) {
		t.Error("a non-fixed address is a frozen call target")
	}

	// K is ghosttree.K: the tag's length, the tag, then the inputs.
	a, b := []byte("first"), []byte{0x02, 0x03}
	if got, want := ghost.K("ghost/test/v1", a, b), ghosttree.K("ghost/test/v1", a, b); got != want {
		t.Errorf("K %x, ghosttree.K %x", got, want)
	}
	direct := crypto.Keccak256Hash(append([]byte{byte(len(ghost.TagPolicyRegistry))}, ghost.TagPolicyRegistry...), ghost.PolicyRegistryAccount[:], []byte{0x01})
	if got := ghost.PolicyRegistryKey(ghost.PolicyRegistryAccount, ghost.PolicyRegistryCodeHashWord); got != direct {
		t.Errorf("registry key %x, want %x", got, direct)
	}
	if ghost.TagPolicyRegistry != "ghost/policy-registry/v1" {
		t.Errorf("registry tag %q", ghost.TagPolicyRegistry)
	}

	// The policy address commits to the salt and the init code only.
	salt, code := common.Hash{7}, crypto.Keccak256Hash([]byte{0x60, 0x00})
	addr := ghost.PolicyAddress(salt, code)
	if want := common.BytesToAddress(ghost.K(ghost.TagPolicyAddress, salt[:], code[:]).Bytes()); addr != want {
		t.Errorf("policy address %v, want %v", addr, want)
	}
	if addr == ghost.PolicyAddress(common.Hash{8}, code) || addr == ghost.PolicyAddress(salt, common.Hash{}) {
		t.Error("the policy address ignores its salt or code")
	}

	// The registry entry: flag and height in word 0, code hash in word 1.
	st := newPolicyState()
	if ghost.IsRegisteredPolicy(st, addr) {
		t.Fatal("an empty registry has a policy")
	}
	codeHash := crypto.Keccak256Hash([]byte("runtime"))
	ghost.RegisterPolicy(st, addr, 42, codeHash)
	if !ghost.IsRegisteredPolicy(st, addr) || ghost.IsRegisteredPolicy(st, at(0x62)) {
		t.Fatal("registration is not per address")
	}
	flag := st.GetState(ghost.PolicyRegistryAccount, ghost.PolicyRegistryKey(addr, ghost.PolicyRegistryFlagWord))
	if flag[0] != 0x01 || common.BytesToHash(flag[24:]).Big().Uint64() != 42 || !isZeroBytes(flag[1:24]) {
		t.Errorf("flag word %x", flag)
	}
	if got := st.GetState(ghost.PolicyRegistryAccount, ghost.PolicyRegistryKey(addr, ghost.PolicyRegistryCodeHashWord)); got != codeHash {
		t.Errorf("code hash word %x", got)
	}
	if height, hash, ok := ghost.PolicyRegistryEntry(st, addr); !ok || height != 42 || hash != codeHash {
		t.Errorf("entry: %d %x %v", height, hash, ok)
	}
	if st.GetNonce(ghost.PolicyRegistryAccount) != 1 {
		t.Error("the registry account gets no nonce")
	}
	// Callable from a frozen context only in a later block.
	if ghost.IsCallablePolicy(st, addr, 42) || !ghost.IsCallablePolicy(st, addr, 43) {
		t.Error("a policy is callable in its own block, or not after it")
	}
}

func isZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
