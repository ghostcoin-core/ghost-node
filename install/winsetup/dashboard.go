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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/ethereum/go-ethereum/internal/winsvc"
)

const (
	dashExeName     = "ghost-dash.exe"
	dashTaskName    = "Ghost Dashboard"
	dashKeyName     = "dashboard-key"
	dashPortName    = "dashboard-port"
	defaultDashPort = 8580

	schtasksExe = "schtasks.exe"
	icaclsExe   = "icacls.exe"

	// dashStopWait is how long the dashboard has to exit once its task is
	// ended, before its executable is replaced or its port looked at.
	dashStopWait = 2 * time.Second
)

func (s *setup) dashPath() string     { return filepath.Join(s.binDir(), dashExeName) }
func (s *setup) dashKeyPath() string  { return filepath.Join(s.home, dashKeyName) }
func (s *setup) dashPortPath() string { return filepath.Join(s.home, dashPortName) }

// parsePort returns the port number v gives, or 0 when it is none.
func parsePort(v string) int {
	port, err := strconv.Atoi(v)
	if err != nil || port <= 0 || port > 65535 || strings.HasPrefix(v, "0") || strconv.Itoa(port) != v {
		return 0
	}
	return port
}

// dashboardPort returns the dashboard's port: GHOST_DASH_PORT's, else the one
// an earlier install kept, else 8580.
func (s *setup) dashboardPort() int {
	if s.dashPortEnv != 0 {
		return s.dashPortEnv
	}
	if blob, err := os.ReadFile(s.dashPortPath()); err == nil {
		if port := parsePort(strings.TrimSpace(string(blob))); port != 0 {
			return port
		}
	}
	return defaultDashPort
}

func dashLink(port int) string { return fmt.Sprintf("http://127.0.0.1:%d/", port) }

// portInUse reports whether a program listens on 127.0.0.1 at port.
func portInUse(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// dashTaskExists reports whether the dashboard's scheduled task exists.
func (s *setup) dashTaskExists() bool {
	_, err := s.runTool(schtasksExe, "/Query", "/TN", dashTaskName)
	return err == nil
}

// stopDashboard ends the dashboard's task, if there is one, and reports
// whether there was.
func (s *setup) stopDashboard() bool {
	if !s.dashTaskExists() {
		return false
	}
	// Ending a task that is not running is no error worth stopping for.
	s.runTool(schtasksExe, "/End", "/TN", dashTaskName)
	s.sleep(dashStopWait)
	return true
}

func (s *setup) startDashboard() error {
	if out, err := s.runTool(schtasksExe, "/Run", "/TN", dashTaskName); err != nil {
		return fmt.Errorf("could not start the %s task: %v %s", dashTaskName, err, lastLines(out))
	}
	return nil
}

// prepareDashboard runs before an install changes anything: it stops the
// installed dashboard, which holds its own port, and refuses when another
// program holds the port. A refused install starts the dashboard again.
func (s *setup) prepareDashboard() error {
	if s.user == "" {
		return errors.New("USERNAME is not set, so the node dashboard cannot be set to start when you log in")
	}
	port := s.dashboardPort()
	if port == s.httpPort {
		return fmt.Errorf("the node dashboard cannot use port %d, the node's HTTP RPC port; install with GHOST_DASH_PORT set to another port", port)
	}
	had := s.stopDashboard()
	if s.portBusy(port) {
		if had {
			s.startDashboard()
		}
		return fmt.Errorf("port %d on this computer is already in use by another program; stop it, or install with GHOST_DASH_PORT set to a free port", port)
	}
	return nil
}

// installDashboard installs ghost-dash.exe and its key, makes its task start
// it at login and starts it, and opens its link in the browser on a first
// install. The install's closing lines print the link.
func (s *setup) installDashboard(rel *release, work string, first bool) error {
	port := s.dashboardPort()
	if err := installFile(rel.dash, s.dashPath()); err != nil {
		return fmt.Errorf("could not install %s: %w", dashExeName, err)
	}
	if err := s.dashboardKey(); err != nil {
		return err
	}
	if err := writeFileAtomic(s.dashPortPath(), []byte(strconv.Itoa(port)+"\n")); err != nil {
		return fmt.Errorf("could not keep the node dashboard's port: %w", err)
	}
	task, err := s.dashTaskXML(port)
	if err != nil {
		return err
	}
	taskFile := filepath.Join(work, "ghost-dashboard-task.xml")
	if err := os.WriteFile(taskFile, task, 0o600); err != nil {
		return fmt.Errorf("could not write the %s task: %w", dashTaskName, err)
	}
	if out, err := s.runTool(schtasksExe, "/Create", "/TN", dashTaskName, "/XML", taskFile, "/F"); err != nil {
		return fmt.Errorf("could not make the node dashboard start at login, as the %s task: %v %s", dashTaskName, err, lastLines(out))
	}
	if err := s.startDashboard(); err != nil {
		return err
	}
	link := dashLink(port)
	if first {
		if out, err := s.runTool("rundll32.exe", "url.dll,FileProtocolHandler", link); err != nil {
			s.say("could not open the dashboard in the browser (%v %s); open %s yourself", err, lastLines(out), link)
		}
	}
	return nil
}

// dashboardKey writes the dashboard's key, 32 random bytes in hex readable
// only by the user, unless there is one.
func (s *setup) dashboardKey() error {
	key := s.dashKeyPath()
	if isFile(key) {
		return nil
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("could not make the node dashboard's key: %w", err)
	}
	tmp := key + ".new"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(secret[:])+"\n"), 0o600); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("could not write the node dashboard's key: %w", err)
	}
	// Only the user, not the groups the profile lets in, may read it.
	if out, err := s.runTool(icaclsExe, tmp, "/inheritance:r", "/grant:r", s.user+":F"); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("could not make the node dashboard's key readable only by you: %v %s", err, lastLines(out))
	}
	if err := os.Rename(tmp, key); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("could not write the node dashboard's key: %w", err)
	}
	return nil
}

// removeDashboard takes out an installed dashboard for GHOST_NO_DASHBOARD=1,
// so that updates do not bring it back. Its key is kept.
func (s *setup) removeDashboard() error {
	if s.stopDashboard() {
		if out, err := s.runTool(schtasksExe, "/Delete", "/TN", dashTaskName, "/F"); err != nil {
			return fmt.Errorf("could not remove the %s task: %v %s", dashTaskName, err, lastLines(out))
		}
	}
	for _, name := range []string{s.dashPath(), s.dashPortPath()} {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not remove %s: %w", name, err)
		}
	}
	return nil
}

// updateDashboard replaces an installed ghost-dash.exe with the release's
// and restarts its task, and prints the dashboard's link.
func (s *setup) updateDashboard(rel *release) error {
	if !isFile(s.dashPath()) {
		return nil
	}
	if rel.dash != "" {
		have, err := fileSum(s.dashPath())
		if err != nil {
			return err
		}
		if have != rel.dashSum {
			s.stopDashboard()
			if err := installFile(rel.dash, s.dashPath()); err != nil {
				s.startDashboard()
				return fmt.Errorf("could not install the new %s: %w", dashExeName, err)
			}
			if err := s.startDashboard(); err != nil {
				return err
			}
			s.say("updated the node dashboard and restarted it")
		}
	}
	s.say("the node dashboard runs at %s", dashLink(s.dashboardPort()))
	return nil
}

// dashTaskXML is the definition of the dashboard's scheduled task: at the
// user's login, as the user with no elevation, it runs ghost-dash.exe for the
// node's folder and port. schtasks reads it as UTF-16.
func (s *setup) dashTaskXML(port int) ([]byte, error) {
	for _, p := range []string{s.dashPath(), s.home, s.user} {
		if strings.ContainsAny(p, "\"\x00\r\n") {
			return nil, fmt.Errorf("the name %q holds a quote or a control character", p)
		}
	}
	esc := func(v string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	args := winsvc.JoinCommandLine("--node-dir", s.home, "--port", strconv.Itoa(port))
	text := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>The Ghost node dashboard, on this computer only. Installed by ghost-setup.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + esc(s.user) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + esc(s.user) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + esc(s.dashPath()) + `</Command>
      <Arguments>` + esc(args) + `</Arguments>
      <WorkingDirectory>` + esc(s.home) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
	text = strings.ReplaceAll(text, "\n", "\r\n")
	units := utf16.Encode([]rune(text))
	out := make([]byte, 2, 2+2*len(units))
	out[0], out[1] = 0xff, 0xfe
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out, nil
}
