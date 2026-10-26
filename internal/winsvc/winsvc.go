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

// Package winsvc runs the node as a per-user background service on Windows,
// with no administrator rights.
//
// The service is two things. A value in the current user's Run key
// (HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run) runs
// "geth service start" at every login. "geth service start" starts the node
// as a detached process and records it in a pid file in the service's home
// directory, which "geth service stop" and "geth service status" read.
//
// The logic here is plain Go behind two small interfaces, RunKey and
// Processes, so it is tested anywhere with fakes. The Windows registry and
// process code is in service_windows.go; elsewhere System returns
// ErrWindowsOnly.
package winsvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// RunKeyPath is the per-user Run key, under HKEY_CURRENT_USER.
	RunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

	// RunValueName is the name of the service's value in the Run key.
	RunValueName = "GhostNode"

	// HomeDirName is the name of the default home directory in the user's
	// local application data directory.
	HomeDirName = "ghost-node"

	configFile = "config.toml"
	pidFile    = "node.pid"
	logFile    = "node.log"
)

// InterruptArgs are the arguments that make the geth executable send the
// console interrupt to the process whose id follows them (see Interrupt). The
// Windows Processes runs them in a helper process, since sending the
// interrupt means attaching to the node's console.
var InterruptArgs = []string{"service", "interrupt"}

// ErrWindowsOnly is returned on every operating system but Windows.
var ErrWindowsOnly = errors.New("the per-user node service is Windows only; on Linux and macOS install.sh sets up a systemd user unit or a launchd agent")

// RunKey is the current user's Run key.
type RunKey interface {
	// Get returns the string value name, and false when there is none.
	Get(name string) (value string, ok bool, err error)
	// Set writes the string value name.
	Set(name, value string) error
	// Delete removes the value name. It is not an error if there is none.
	Delete(name string) error
}

// Processes starts and inspects the node's process.
type Processes interface {
	// Start starts exe with args as a detached background process whose
	// output is appended to logPath, and returns its process id.
	Start(exe string, args []string, logPath string) (pid int, err error)
	// Running reports whether the process pid is running the executable
	// exe. A process id reused by another program is not running.
	Running(pid int, exe string) (bool, error)
	// Interrupt asks the process pid to shut down cleanly.
	Interrupt(pid int) error
}

// Service is the node service of one user.
type Service struct {
	Exe  string // absolute path of the geth executable that runs the node
	Home string // absolute path of the home directory: config, pid file and log

	RunKey    RunKey
	Processes Processes

	// StopTimeout is how long Stop waits for the node to exit, and
	// PollInterval how often it looks. Zero means one minute and one second.
	StopTimeout  time.Duration
	PollInterval time.Duration

	// Sleep waits; nil means time.Sleep. Tests replace it.
	Sleep func(time.Duration)
}

// Status is what Status reports.
type Status struct {
	Installed bool   // the Run key holds the service's value
	Current   bool   // and the value is the command line of this service
	Command   string // the value in the Run key, if any
	Running   bool   // the node recorded in the pid file is running
	PID       int    // its process id, if running
}

// DefaultHome returns the default home directory, ghost-node in the local
// application data directory that getenv's LOCALAPPDATA names.
func DefaultHome(getenv func(string) string) (string, error) {
	local := getenv("LOCALAPPDATA")
	if local == "" {
		return "", errors.New("LOCALAPPDATA is not set, so there is no default home directory; give one with --home")
	}
	return filepath.Join(local, HomeDirName), nil
}

// ConfigPath is the node's config file.
func (s *Service) ConfigPath() string { return filepath.Join(s.Home, configFile) }

// PIDPath is the pid file of the running node.
func (s *Service) PIDPath() string { return filepath.Join(s.Home, pidFile) }

// LogPath is the node's log file.
func (s *Service) LogPath() string { return filepath.Join(s.Home, logFile) }

// NodeArgs are the node's arguments: its config, with mining on.
func (s *Service) NodeArgs() []string {
	return []string{"--config", s.ConfigPath(), "--mine"}
}

// RunCommand is the command line the Run key holds: this executable's
// "service start" for this home directory.
func (s *Service) RunCommand() string {
	return JoinCommandLine(s.Exe, "service", "start", "--home", s.Home)
}

// check fails unless the service's paths and helpers are usable.
func (s *Service) check() error {
	if s.RunKey == nil || s.Processes == nil {
		return errors.New("the node service has no Run key or process access")
	}
	if !filepath.IsAbs(s.Exe) {
		return fmt.Errorf("the node executable %q is not an absolute path", s.Exe)
	}
	if !filepath.IsAbs(s.Home) {
		return fmt.Errorf("the home directory %q is not an absolute path", s.Home)
	}
	for _, p := range []string{s.Exe, s.Home} {
		if strings.ContainsAny(p, "\"\x00\r\n") {
			return fmt.Errorf("the path %q holds a quote or a control character", p)
		}
	}
	if fi, err := os.Stat(s.Exe); err != nil {
		return fmt.Errorf("the node executable: %w", err)
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("the node executable %s is not a regular file", s.Exe)
	}
	if fi, err := os.Stat(s.ConfigPath()); err != nil {
		return fmt.Errorf("the node has no config (%w); the installer writes it", err)
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("the node config %s is not a regular file", s.ConfigPath())
	}
	return nil
}

// Install makes the node start at login. It reports whether it changed the
// Run key: a second Install with the same paths changes nothing.
func (s *Service) Install() (changed bool, err error) {
	if err := s.check(); err != nil {
		return false, err
	}
	want := s.RunCommand()
	have, ok, err := s.RunKey.Get(RunValueName)
	if err != nil {
		return false, fmt.Errorf("reading the Run key: %w", err)
	}
	if ok && have == want {
		return false, nil
	}
	if err := s.RunKey.Set(RunValueName, want); err != nil {
		return false, fmt.Errorf("writing the Run key: %w", err)
	}
	return true, nil
}

// Uninstall stops the node starting at login. It does not stop a running
// node; Stop does. It reports whether it changed the Run key.
func (s *Service) Uninstall() (changed bool, err error) {
	if s.RunKey == nil {
		return false, errors.New("the node service has no Run key access")
	}
	_, ok, err := s.RunKey.Get(RunValueName)
	if err != nil {
		return false, fmt.Errorf("reading the Run key: %w", err)
	}
	if !ok {
		return false, nil
	}
	if err := s.RunKey.Delete(RunValueName); err != nil {
		return false, fmt.Errorf("removing the Run key value: %w", err)
	}
	return true, nil
}

// Start starts the node in the background, unless it is running. It returns
// the node's process id and whether it started it.
func (s *Service) Start() (pid int, started bool, err error) {
	if err := s.check(); err != nil {
		return 0, false, err
	}
	pid, _, running, err := s.running()
	if err != nil {
		return 0, false, err
	}
	if running {
		return pid, false, nil
	}
	// A pid file of a process that is gone is stale.
	if err := removeIfExists(s.PIDPath()); err != nil {
		return 0, false, err
	}
	pid, err = s.Processes.Start(s.Exe, s.NodeArgs(), s.LogPath())
	if err != nil {
		return 0, false, fmt.Errorf("starting the node: %w", err)
	}
	if err := writePIDFile(s.PIDPath(), pid, s.Exe); err != nil {
		// A node nothing records could not be stopped: stop it now.
		if ierr := s.Processes.Interrupt(pid); ierr != nil {
			return 0, false, fmt.Errorf("recording the node's process id: %v; and stopping the node, process %d: %v", err, pid, ierr)
		}
		return 0, false, fmt.Errorf("recording the node's process id: %w; the node was stopped", err)
	}
	return pid, true, nil
}

// Stop stops the node and waits for it to exit. It reports the process id
// it stopped, 0 if the node was not running. When the node does not exit in
// time, Stop returns an error and keeps the pid file.
func (s *Service) Stop() (pid int, err error) {
	if s.Processes == nil {
		return 0, errors.New("the node service has no process access")
	}
	pid, exe, running, err := s.running()
	if err != nil {
		return 0, err
	}
	if !running {
		return 0, removeIfExists(s.PIDPath())
	}
	if err := s.Processes.Interrupt(pid); err != nil {
		return 0, fmt.Errorf("stopping the node, process %d: %w", pid, err)
	}
	timeout, poll, sleep := s.StopTimeout, s.PollInterval, s.Sleep
	if timeout <= 0 {
		timeout = time.Minute
	}
	if poll <= 0 {
		poll = time.Second
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	for waited := time.Duration(0); ; waited += poll {
		alive, err := s.Processes.Running(pid, exe)
		if err != nil {
			return 0, fmt.Errorf("waiting for the node, process %d: %w", pid, err)
		}
		if !alive {
			break
		}
		if waited >= timeout {
			return 0, fmt.Errorf("the node, process %d, did not exit within %v", pid, timeout)
		}
		sleep(poll)
	}
	return pid, removeIfExists(s.PIDPath())
}

// Status reports whether the service is installed and the node running.
func (s *Service) Status() (Status, error) {
	var st Status
	if s.RunKey == nil || s.Processes == nil {
		return st, errors.New("the node service has no Run key or process access")
	}
	cmd, ok, err := s.RunKey.Get(RunValueName)
	if err != nil {
		return st, fmt.Errorf("reading the Run key: %w", err)
	}
	st.Installed, st.Command = ok, cmd
	st.Current = ok && cmd == s.RunCommand()
	pid, _, running, err := s.running()
	if err != nil {
		return st, err
	}
	if running {
		st.Running, st.PID = true, pid
	}
	return st, nil
}

// running reads the pid file and reports whether the process it records is
// running. No pid file means not running.
func (s *Service) running() (pid int, exe string, running bool, err error) {
	pid, exe, err = readPIDFile(s.PIDPath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	running, err = s.Processes.Running(pid, exe)
	if err != nil {
		return 0, "", false, fmt.Errorf("looking for the node, process %d: %w", pid, err)
	}
	return pid, exe, running, nil
}

// The pid file holds the node's process id and the path of its executable,
// one per line, so a process id that Windows gave to another program after
// the node exited is not taken for the node.

func writePIDFile(path string, pid int, exe string) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)+"\n"+exe+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func readPIDFile(path string) (pid int, exe string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	if len(lines) != 2 {
		return 0, "", fmt.Errorf("the pid file %s is not a process id and an executable", path)
	}
	pid, err = strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || pid <= 0 {
		return 0, "", fmt.Errorf("the pid file %s holds no process id", path)
	}
	exe = strings.TrimRight(lines[1], "\r")
	if exe == "" {
		return 0, "", fmt.Errorf("the pid file %s holds no executable", path)
	}
	return pid, exe, nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// JoinCommandLine joins arguments into a Windows command line, quoting each
// as the C runtime and CommandLineToArgvW split it again.
func JoinCommandLine(args ...string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = QuoteArg(a)
	}
	return strings.Join(quoted, " ")
}

// QuoteArg quotes one argument of a Windows command line. Arguments with no
// space, tab or quote are left as they are.
func QuoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			slashes++
		case '"':
			// Backslashes before a quote are doubled, and the quote escaped.
			b.WriteString(strings.Repeat(`\`, 2*slashes+1))
			b.WriteByte('"')
			slashes = 0
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			b.WriteByte(c)
			slashes = 0
		}
	}
	// Backslashes before the closing quote are doubled.
	b.WriteString(strings.Repeat(`\`, 2*slashes))
	b.WriteByte('"')
	return b.String()
}
