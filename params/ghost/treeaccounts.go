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

// The reserved system accounts that hold the tree states and the spent-marker
// sets in their storage (docs/trees-and-headers.md). They hold no code and no
// balance; each gets nonce 1 when it is first written, so the empty-account
// cleanup of EIP-161 never deletes its storage.
//
// These are internal-test values, "ghost" in ASCII followed by a counter,
// like the internal network's chain ID. The launch values come with the
// transaction-format specification and replace these in a constants-only
// change.
var (
	// CoinTreeAccount holds the coin tree state.
	CoinTreeAccount = common.HexToAddress("0x67686f7374000000000000000000000000000001")

	// DataTreeAccount holds the data tree state.
	DataTreeAccount = common.HexToAddress("0x67686f7374000000000000000000000000000002")

	// CoinMarkerAccount holds the spent coin markers.
	CoinMarkerAccount = common.HexToAddress("0x67686f7374000000000000000000000000000003")

	// DataMarkerAccount holds the spent data markers.
	DataMarkerAccount = common.HexToAddress("0x67686f7374000000000000000000000000000004")
)
