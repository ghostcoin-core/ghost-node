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
	"time"

	"github.com/ethereum/go-ethereum/params/ghost"
)

// TestPublicTestNetGenesisNotInFuture fails when the built-in public test
// network starts later than now. Block 1 must be later than its parent and no
// more than FutureDrift ahead of the clock, so a future genesis time leaves
// every miner waiting at block 0 until that time.
func TestPublicTestNetGenesisNotInFuture(t *testing.T) {
	now := uint64(time.Now().Unix())
	if g := ghost.TestNetGenesis(); g.Timestamp > now {
		t.Errorf("test network genesis time %d (%s) is after now %d (%s): nothing can be mined until then",
			g.Timestamp, time.Unix(int64(g.Timestamp), 0).UTC(), now, time.Unix(int64(now), 0).UTC())
	}
	if ghost.TestNetTimestamp > now {
		t.Errorf("TestNetTimestamp %d is after now %d", uint64(ghost.TestNetTimestamp), now)
	}
}
