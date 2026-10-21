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

// MaxBlockGasLimit is the consensus maximum of a block's gas limit (spec 09,
// section 8.4). A header above it is invalid, and a miner never votes the
// limit above it. At 4 gas per zero calldata byte, a block of this much gas
// carries at most 7,500,000 bytes of calldata, which keeps every message that
// carries a block under the 10 MiB message cap; the measured sizes are
// recorded in docs/account-transactions.md.
const MaxBlockGasLimit uint64 = 30_000_000
