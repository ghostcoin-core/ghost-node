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

import "github.com/ethereum/go-ethereum/common"

// The reserved addresses of the commit and reveal transactions
// (docs/private-transactions.md). Like the tree accounts, these are
// internal-test values, "ghost" in ASCII followed by a counter, replaced by
// the launch values of the transaction-format specification in a
// constants-only change.
var (
	// CommitEntryAddress is where a commit is sent: a top-level transaction
	// to it burns its value into a coin commitment. It holds nothing, and
	// every EVM call to it fails, so no contract can reach it.
	CommitEntryAddress = common.HexToAddress("0x67686f7374000000000000000000000000000005")

	// PrivTotalsAccount holds the public accounting of the hidden set: slot
	// 0 is the total that entered it, slot 1 the total that left it, each a
	// 32-byte big-endian integer. It gets nonce 1 when it is first written,
	// as the tree accounts do.
	PrivTotalsAccount = common.HexToAddress("0x67686f7374000000000000000000000000000006")

	// DataCommitEntryAddress is where a data commit is sent: a top-level
	// transaction to it with value 0 appends a data commitment to the data
	// tree (docs/data-commitments.md). Like the commit entry address it
	// holds nothing, and every EVM call to it fails.
	DataCommitEntryAddress = common.HexToAddress("0x67686f7374000000000000000000000000000007")
)

// IsCommitEntry reports whether addr is the coin or the data commit entry
// address, which no call from inside the EVM may reach.
func IsCommitEntry(addr common.Address) bool {
	return addr == CommitEntryAddress || addr == DataCommitEntryAddress
}
