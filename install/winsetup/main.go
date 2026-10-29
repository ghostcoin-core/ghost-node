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

// ghost-setup installs a Ghost node on Windows for the current user and
// starts it mining, with no administrator rights. install.ps1 and install.cmd,
// the one-line installers, download it, check its SHA-256 against the one
// they pin, and run it:
//
//	ghost-setup.exe             install, or reinstall, the latest release
//	ghost-setup.exe --update    update the installed node to the latest release
//
// It downloads the release archive ghost-node-windows-<arch>.tar.gz and its
// signature, <archive>.sig, the raw 64-byte ed25519 signature of the
// archive's bytes, over https only, and checks the signature against the
// release key pinned in setup.go before it unpacks anything. On any doubt
// about a download, the signature or the archive it stops with nothing
// installed and says why.
//
// It then installs geth.exe in %USERPROFILE%\.ghost-node\bin, writes the
// node's config.toml there with a newly generated mining address (mining on,
// HTTP RPC on 127.0.0.1:8545 for the Ghost web apps), and installs and starts
// the node as the per-user service of internal/winsvc: a value in the
// current user's Run key starts it at every login. The node joins the network
// built into it, the public test network. It prints the mining address and how
// to check on the node.
//
// Updates are on by default: it copies itself to the same directory and adds
// a second value to the Run key that runs "ghost-setup.exe --update --daily"
// at login, which checks for a new release at most once a day. An update
// passes the same checks as an install, keeps the previous geth.exe until the
// node has restarted on the new one, and keeps the config and the mining
// address; a refused update changes nothing and leaves the running node
// alone. GHOST_NO_UPDATE=1 at install time leaves the update out.
//
// GHOST_RELEASE_URL sets where the release is downloaded from, over https
// only, and GHOST_INSTALL_CA_FILE names a certificate file to trust for that
// server; GHOST_HTTP_PORT moves the node's HTTP RPC off 8545. The tests use
// them for a local release server.
//
// The node mines on half this computer's logical cores, rounded down and at
// least 1. GHOST_MINE_THREADS, a whole number from 1 to 9999, chooses the
// number of cores instead; anything else is refused before anything is
// installed. The Run key starts the node with its config and --mine only, so
// the number is GETH_MINER_THREADS, which geth reads as --miner.threads, in
// the user's environment (HKEY_CURRENT_USER\Environment): the node started at
// login inherits it, and the one started here gets it too. A re-run or an
// update keeps the number unless GHOST_MINE_THREADS is set again; an update of
// a node installed before ghost-setup set it restarts the node on the default.
//
// A release archive that holds ghost-dash.exe, the node dashboard, gets it
// installed in the same bin directory, with dashboard-key in the node's
// folder: 32 random bytes in hex, written on the first install, readable only
// by the user (icacls), and kept on re-runs and updates. The dashboard runs as
// its own scheduled task, "Ghost Dashboard", which starts it at the user's
// login, as the user and with no elevation, with --node-dir and --port: 8580,
// or GHOST_DASH_PORT's, which the folder's dashboard-port keeps for re-runs
// and updates. An install refuses a port another program holds. A first
// install opens the dashboard's link in the default browser; every install and
// update prints it. An update replaces ghost-dash.exe when the release's
// differs and restarts the task. GHOST_NO_DASHBOARD=1 at install time leaves
// the dashboard out, and takes out one installed before.
//
// It is built with the standard library and internal/winsvc only, with cgo
// off, for windows/amd64 and windows/arm64.
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/internal/winsvc"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// Stopping the node runs this executable with winsvc.InterruptArgs in a
	// helper process: see winsvc.Interrupt.
	if len(args) == len(winsvc.InterruptArgs)+1 && args[0] == winsvc.InterruptArgs[0] && args[1] == winsvc.InterruptArgs[1] {
		pid, err := strconv.Atoi(args[2])
		if err != nil || pid <= 0 {
			fmt.Fprintf(stderr, "ghost-setup: invalid process id %q\n", args[2])
			return 2
		}
		if err := winsvc.Interrupt(pid); err != nil {
			fmt.Fprintf(stderr, "ghost-setup: %v\n", err)
			return 1
		}
		return 0
	}
	m, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "ghost-node: %v\n", err)
		return 2
	}
	if err := runSystem(m, stdout); err != nil {
		fmt.Fprintf(stderr, "ghost-node: %v\n", err)
		return 1
	}
	return 0
}

// runSystem runs the setup on this computer: its environment, the current
// user's Run key and real processes.
func runSystem(m mode, stdout io.Writer) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find this executable: %w", err)
	}
	s, err := newSetup(os.Getenv, self, stdout)
	if err != nil {
		return err
	}
	sys, err := winsvc.System(s.gethPath(), s.home)
	if err != nil {
		return err
	}
	s.runKey, s.procs = sys.RunKey, sys.Processes
	s.userEnv = systemUserEnv()
	return s.run(m)
}
