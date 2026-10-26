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

//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// System returns the service of the geth executable exe with the home
// directory home, on the current user's Run key and the real processes.
func System(exe, home string) (*Service, error) {
	return &Service{Exe: exe, Home: home, RunKey: runKey{}, Processes: processes{}}, nil
}

// runKey is the current user's Run key. Only HKEY_CURRENT_USER is touched,
// which needs no administrator rights.
type runKey struct{}

func (runKey) Get(name string) (string, bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, RunKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer k.Close()
	// A value of another type than a string is an error, not ours to replace.
	value, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (runKey) Set(name, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, RunKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func (runKey) Delete(name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, RunKeyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

type processes struct{}

// Start starts the node in a new, hidden console of its own and a new process
// group, at below-normal priority. The console is what lets Interrupt reach
// it with a Ctrl+Break, which the node handles as a clean shutdown.
func (processes) Start(exe string, args []string, logPath string) (int, error) {
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer log.Close()

	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(logPath)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_CONSOLE | windows.CREATE_NEW_PROCESS_GROUP | windows.BELOW_NORMAL_PRIORITY_CLASS,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()
	return pid, nil
}

// Running reports whether pid is a live process whose image is exe.
func (processes) Running(pid int, exe string) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	switch {
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
		// No such process.
		return false, nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		// Another user's or an elevated process: the node runs as this
		// user, unelevated, so this is not the node.
		return false, nil
	case err != nil:
		return false, err
	}
	defer windows.CloseHandle(h)

	event, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false, err
	}
	if event != uint32(windows.WAIT_TIMEOUT) {
		// The process has exited.
		return false, nil
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return false, err
	}
	image := windows.UTF16ToString(buf[:size])
	return strings.EqualFold(filepath.Clean(image), filepath.Clean(exe)), nil
}

// Interrupt runs this executable with InterruptArgs in a helper process with
// no console, which attaches to the node's console to send the Ctrl+Break.
// Doing that here would detach this process from the user's console.
func (processes) Interrupt(pid int) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := append(append([]string{}, InterruptArgs...), strconv.Itoa(pid))
	cmd := exec.Command(self, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	if out, err := cmd.CombinedOutput(); err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = kernel32.NewProc("AttachConsole")
	procFreeConsole   = kernel32.NewProc("FreeConsole")
)

// Interrupt sends Ctrl+Break to the process group pid, which Start made the
// node's own, on the node's console. It is what the helper process that
// InterruptArgs name runs. The calling process leaves its own console first.
func Interrupt(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("no process %d", pid)
	}
	procFreeConsole.Call()
	if r, _, err := procAttachConsole.Call(uintptr(uint32(pid))); r == 0 {
		return fmt.Errorf("attaching to the console of process %d: %w", pid, err)
	}
	defer procFreeConsole.Call()
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid)); err != nil {
		return fmt.Errorf("sending Ctrl+Break to process %d: %w", pid, err)
	}
	return nil
}
