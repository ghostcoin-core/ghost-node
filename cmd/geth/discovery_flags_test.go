// Copyright 2026 The Ghost Authors
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

import (
	"io"
	"testing"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/urfave/cli/v2"
)

// oldDiscoveryFlags are the names and aliases of the flags of the old
// discovery protocols and of DNS discovery.
var oldDiscoveryFlags = []string{
	"discv4", "discovery.v4",
	"discv5", "discovery.v5", "v5disc",
	"dnsdiscovery", "discovery.dns",
}

func flagNames(fs []cli.Flag) map[string]bool {
	names := make(map[string]bool)
	for _, f := range fs {
		for _, n := range f.Names() {
			names[n] = true
		}
	}
	return names
}

func collectCommandFlags(cmds []*cli.Command, into map[string]bool) {
	for _, c := range cmds {
		for n := range flagNames(c.Flags) {
			into[n] = true
		}
		collectCommandFlags(c.Subcommands, into)
	}
}

// TestOldDiscoveryFlagsRemoved checks that geth has no flag to turn on the
// old discovery protocols or DNS discovery, neither on the command line nor
// in its subcommands or deprecated flags, and refuses them when given,
// while --nodiscover, --bootnodes and --discovery.port remain.
func TestOldDiscoveryFlagsRemoved(t *testing.T) {
	names := flagNames(app.Flags)
	collectCommandFlags(app.Commands, names)
	for n := range flagNames(utils.DeprecatedFlags) {
		names[n] = true
	}
	for _, old := range oldDiscoveryFlags {
		if names[old] {
			t.Errorf("flag --%s still exists", old)
		}
	}
	for _, kept := range []string{"nodiscover", "bootnodes", "discovery.port"} {
		if !names[kept] {
			t.Errorf("flag --%s is missing", kept)
		}
	}

	// The flags are refused when given. The app here has geth's flags and
	// does nothing, so nothing starts if a flag were accepted.
	for _, old := range oldDiscoveryFlags {
		ran := false
		a := &cli.App{
			Name:      "geth",
			Flags:     app.Flags,
			Writer:    io.Discard,
			ErrWriter: io.Discard,
			Action:    func(*cli.Context) error { ran = true; return nil },
		}
		if err := a.Run([]string{"geth", "--" + old}); err == nil || ran {
			t.Errorf("--%s accepted", old)
		}
	}
}
