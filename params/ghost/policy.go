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

package ghost

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Frozen policies (spec 10, section 6; docs/ghost-evm-profile.md). A policy
// is a contract created by the policy factory: its address depends only on
// its init code and a salt, it runs in a frozen context, and it never holds a
// balance. The policy registry records every policy the factory created.
var (
	// PolicyFactoryAddress is the native that creates frozen policies.
	PolicyFactoryAddress = common.BytesToAddress([]byte{0x62})

	// EscrowNativeAddress and StatementCheckerAddress are the natives a
	// frozen context may call besides the hash precompiles, the
	// signature-verify precompile and older policies. They are reserved
	// here; the natives themselves come with later changes.
	EscrowNativeAddress     = common.BytesToAddress([]byte{0x60})
	StatementCheckerAddress = common.BytesToAddress([]byte{0x61})

	// PolicyRegistryAccount holds the policy registry in its storage: two
	// words for each policy, at PolicyRegistryKey(addr, 0) the frozen flag
	// and the creation height, at PolicyRegistryKey(addr, 1) the code hash.
	// Like the tree accounts, it holds no code and no balance and gets
	// nonce 1 when it is first written.
	PolicyRegistryAccount = common.HexToAddress("0x67686f7374000000000000000000000000000009")

	// EscrowAccount is ESCROW_ACCOUNT, the native account whose storage
	// holds the escrow slots a policy reveal opens (spec 10, section 7.1),
	// eight words per slot under keys derived from the marker. It emits the
	// slot logs. Like the tree accounts, it holds no code and no balance and
	// gets nonce 1 when it is first written.
	EscrowAccount = common.HexToAddress("0x67686f7374000000000000000000000000000008")
)

// The hash tags of the policy address and of the registry keys.
const (
	TagPolicyAddress  = "ghost/policy-address/v1"
	TagPolicyRegistry = "ghost/policy-registry/v1"
)

// PolicyRegistryGas is REGISTRY_GAS, the gas a factory call pays for the
// registry entry on top of the gas of CREATE2.
const PolicyRegistryGas uint64 = 40_000

// The two registry words of a policy.
const (
	PolicyRegistryFlagWord     byte = 0x00
	PolicyRegistryCodeHashWord byte = 0x01
)

// policyFrozenFlag is the first byte of a registered policy's flag word. The
// creation height is the last eight bytes of the same word.
const policyFrozenFlag byte = 0x01

// K is the tagged hash: Keccak-256 with the original padding over the tag's
// length as one byte, the tag's ASCII bytes and the inputs in order. It is
// the same function as ghosttree.K, which this package cannot import.
func K(tag string, inputs ...[]byte) common.Hash {
	data := make([][]byte, 0, len(inputs)+1)
	data = append(data, append([]byte{byte(len(tag))}, tag...))
	data = append(data, inputs...)
	return common.BytesToHash(crypto.Keccak256(data...))
}

// PolicyAddress is the address the factory creates a policy at: the last 20
// bytes of K(TagPolicyAddress, salt, keccak256(initCode)). The sender is not
// an input, so the same code and salt give the same address whoever creates
// the policy.
func PolicyAddress(salt common.Hash, initCodeHash common.Hash) common.Address {
	return common.BytesToAddress(K(TagPolicyAddress, salt[:], initCodeHash[:]).Bytes())
}

// PolicyRegistryKey is the storage key of word (PolicyRegistryFlagWord or
// PolicyRegistryCodeHashWord) of the registry entry of addr.
func PolicyRegistryKey(addr common.Address, word byte) common.Hash {
	return K(TagPolicyRegistry, addr[:], []byte{word})
}

// PolicyStateReader is the part of the state the registry readers need.
type PolicyStateReader interface {
	GetState(common.Address, common.Hash) common.Hash
}

// PolicyStateWriter is the part of the state RegisterPolicy writes.
type PolicyStateWriter interface {
	PolicyStateReader
	SetState(common.Address, common.Hash, common.Hash)
	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)
}

// PolicyRegistryEntry returns the creation height and the code hash of the
// policy at addr, and false if addr is not a registered policy.
func PolicyRegistryEntry(st PolicyStateReader, addr common.Address) (height uint64, codeHash common.Hash, ok bool) {
	flag := st.GetState(PolicyRegistryAccount, PolicyRegistryKey(addr, PolicyRegistryFlagWord))
	if flag[0] != policyFrozenFlag {
		return 0, common.Hash{}, false
	}
	height = binary.BigEndian.Uint64(flag[24:])
	codeHash = st.GetState(PolicyRegistryAccount, PolicyRegistryKey(addr, PolicyRegistryCodeHashWord))
	return height, codeHash, true
}

// IsRegisteredPolicy reports whether addr is a frozen policy the factory
// created. Every path that would credit a balance refuses a registered
// policy.
func IsRegisteredPolicy(st PolicyStateReader, addr common.Address) bool {
	flag := st.GetState(PolicyRegistryAccount, PolicyRegistryKey(addr, PolicyRegistryFlagWord))
	return flag[0] == policyFrozenFlag
}

// IsCallablePolicy reports whether a frozen context running in block number
// may call the policy at addr: it is registered and was created in an
// earlier block.
func IsCallablePolicy(st PolicyStateReader, addr common.Address, number uint64) bool {
	height, _, ok := PolicyRegistryEntry(st, addr)
	return ok && height < number
}

// RegisterPolicy writes the registry entry of the policy at addr, created at
// height with the given code hash.
func RegisterPolicy(st PolicyStateWriter, addr common.Address, height uint64, codeHash common.Hash) {
	var flag common.Hash
	flag[0] = policyFrozenFlag
	binary.BigEndian.PutUint64(flag[24:], height)
	st.SetState(PolicyRegistryAccount, PolicyRegistryKey(addr, PolicyRegistryFlagWord), flag)
	st.SetState(PolicyRegistryAccount, PolicyRegistryKey(addr, PolicyRegistryCodeHashWord), codeHash)
	if st.GetNonce(PolicyRegistryAccount) == 0 {
		st.SetNonce(PolicyRegistryAccount, 1)
	}
}

// ghostSystemPrefix is "ghost" in ASCII, the first bytes of the reserved
// system accounts.
var ghostSystemPrefix = []byte("ghost")

// IsReservedAddress reports whether addr is reserved for the protocol: the
// precompile and native range (an address below 0x10000, which holds 0x01
// to 0x11, 0x51, the natives 0x60 to 0x62 and 0x0100) and the system
// accounts, "ghost" in ASCII followed by zero bytes and a two-byte counter
// (the trees, the markers, the commit entries, the totals and the policy
// registry). The factory creates no policy at a reserved address, and no
// policy rule may send value to one.
func IsReservedAddress(addr common.Address) bool {
	if isZero(addr[:18]) {
		return true
	}
	return string(addr[:len(ghostSystemPrefix)]) == string(ghostSystemPrefix) && isZero(addr[len(ghostSystemPrefix):18])
}

// IsFrozenCallTarget reports whether addr is one of the fixed addresses a
// frozen context may CALL or STATICCALL: SHA256 (0x02), RIPEMD160 (0x03),
// IDENTITY (0x04), signature verify (0x51), the escrow native (0x60) and the
// statement checker (0x61). Policies created in an earlier block are allowed
// too (IsCallablePolicy); every other target is refused.
func IsFrozenCallTarget(addr common.Address) bool {
	if !isZero(addr[:19]) {
		return false
	}
	switch addr[19] {
	case 0x02, 0x03, 0x04, 0x51, 0x60, 0x61:
		return true
	}
	return false
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
