// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import "testing"

// TestNoRLPxCommand checks that the tool no longer offers the RLPx commands,
// which spoke the removed RLPx handshake.
func TestNoRLPxCommand(t *testing.T) {
	if app.Command("rlpx") != nil {
		t.Fatal("devp2p still has the rlpx command")
	}
	for _, name := range []string{"enrdump", "key", "nodeset"} {
		if app.Command(name) == nil {
			t.Errorf("devp2p lost the %s command", name)
		}
	}
}

// TestNoSecp256k1DiscoveryCommands checks that the tool no longer offers the
// discovery v4 and v5 commands and the DNS discovery command, whose packets
// and trees are signed with secp256k1.
func TestNoSecp256k1DiscoveryCommands(t *testing.T) {
	for _, name := range []string{"discv4", "discv5", "dns"} {
		if app.Command(name) != nil {
			t.Errorf("devp2p still has the %s command", name)
		}
	}
}
