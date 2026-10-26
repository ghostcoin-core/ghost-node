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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ethereum/go-ethereum/internal/winsvc"
	"github.com/urfave/cli/v2"
)

var (
	serviceHomeFlag = &cli.StringFlag{
		Name:  "home",
		Usage: `Home directory of the node service: config.toml, node.pid and node.log (default "%LOCALAPPDATA%\ghost-node")`,
	}
	serviceCommand = &cli.Command{
		Name:     "service",
		Usage:    "Run the node as a per-user background service on Windows",
		Category: "MISCELLANEOUS COMMANDS",
		Description: `
The node service starts the node at login and runs it in the background, with
mining on, for the current user and without administrator rights. It is a value
in the user's Run key (HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run)
that runs "geth service start" at login. The node's config is config.toml in
the home directory; the installer writes it. See docs/windows-service.md.

The service is Windows only: on Linux and macOS, install.sh sets up a systemd
user unit or a launchd agent.`,
		Subcommands: []*cli.Command{
			{
				Name:   "install",
				Usage:  "Start the node at every login",
				Action: serviceInstall,
				Flags:  []cli.Flag{serviceHomeFlag},
			},
			{
				Name:   "uninstall",
				Usage:  "Stop starting the node at login (it does not stop a running node)",
				Action: serviceUninstall,
				Flags:  []cli.Flag{serviceHomeFlag},
			},
			{
				Name:   "start",
				Usage:  "Start the node in the background, unless it is running",
				Action: serviceStart,
				Flags:  []cli.Flag{serviceHomeFlag},
			},
			{
				Name:   "stop",
				Usage:  "Shut the background node down and wait for it to exit",
				Action: serviceStop,
				Flags:  []cli.Flag{serviceHomeFlag},
			},
			{
				Name:   "status",
				Usage:  "Show whether the node starts at login and is running",
				Action: serviceStatus,
				Flags:  []cli.Flag{serviceHomeFlag},
			},
			{
				// "geth service stop" runs this in a helper process with no
				// console of its own: see winsvc.Interrupt.
				Name:      winsvc.InterruptArgs[1],
				Usage:     "Send the console interrupt to the background node (used by stop)",
				ArgsUsage: "<pid>",
				Hidden:    true,
				Action:    serviceInterrupt,
			},
		},
	}
)

// makeNodeService returns the node service of this executable.
func makeNodeService(ctx *cli.Context) (*winsvc.Service, error) {
	if ctx.Args().Present() {
		return nil, fmt.Errorf("unexpected arguments: %q", ctx.Args().Slice())
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("finding this executable: %w", err)
	}
	home := ctx.String(serviceHomeFlag.Name)
	var homeErr error
	if home == "" {
		home, homeErr = winsvc.DefaultHome(os.Getenv)
	}
	// Off Windows this is the error to report, whatever the home.
	svc, err := winsvc.System(exe, home)
	if err != nil {
		return nil, err
	}
	if homeErr != nil {
		return nil, homeErr
	}
	if svc.Home, err = filepath.Abs(home); err != nil {
		return nil, err
	}
	return svc, nil
}

func serviceInstall(ctx *cli.Context) error {
	svc, err := makeNodeService(ctx)
	if err != nil {
		return err
	}
	changed, err := svc.Install()
	if err != nil {
		return err
	}
	if changed {
		fmt.Println("The node now starts at login:", svc.RunCommand())
	} else {
		fmt.Println("The node already starts at login:", svc.RunCommand())
	}
	return nil
}

func serviceUninstall(ctx *cli.Context) error {
	svc, err := makeNodeService(ctx)
	if err != nil {
		return err
	}
	changed, err := svc.Uninstall()
	if err != nil {
		return err
	}
	if changed {
		fmt.Println("The node no longer starts at login.")
	} else {
		fmt.Println("The node was not set to start at login.")
	}
	return nil
}

func serviceStart(ctx *cli.Context) error {
	svc, err := makeNodeService(ctx)
	if err != nil {
		return err
	}
	pid, started, err := svc.Start()
	if err != nil {
		return err
	}
	if started {
		fmt.Printf("Started the node, process %d; its log is %s\n", pid, svc.LogPath())
	} else {
		fmt.Printf("The node is already running, process %d\n", pid)
	}
	return nil
}

func serviceStop(ctx *cli.Context) error {
	svc, err := makeNodeService(ctx)
	if err != nil {
		return err
	}
	pid, err := svc.Stop()
	if err != nil {
		return err
	}
	if pid != 0 {
		fmt.Printf("Stopped the node, process %d\n", pid)
	} else {
		fmt.Println("The node is not running.")
	}
	return nil
}

func serviceStatus(ctx *cli.Context) error {
	svc, err := makeNodeService(ctx)
	if err != nil {
		return err
	}
	st, err := svc.Status()
	if err != nil {
		return err
	}
	switch {
	case st.Current:
		fmt.Println("Starts at login: yes")
	case st.Installed:
		fmt.Println("Starts at login: yes, but with another command line:", st.Command)
		fmt.Println("Run 'geth service install' to replace it with:", svc.RunCommand())
	default:
		fmt.Println("Starts at login: no")
	}
	if st.Running {
		fmt.Printf("Running: yes, process %d\n", st.PID)
	} else {
		fmt.Println("Running: no")
	}
	fmt.Println("Home:", svc.Home)
	fmt.Println("Log:", svc.LogPath())
	return nil
}

func serviceInterrupt(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		return errors.New("usage: geth service interrupt <pid>")
	}
	pid, err := strconv.Atoi(ctx.Args().First())
	if err != nil || pid <= 0 {
		return fmt.Errorf("invalid process id %q", ctx.Args().First())
	}
	return winsvc.Interrupt(pid)
}
