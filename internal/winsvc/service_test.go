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

package winsvc

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// fakeRunKey is a Run key in memory.
type fakeRunKey struct {
	values         map[string]string
	sets, deletes  int
	getErr, setErr error
	deleteErr      error
}

func newFakeRunKey() *fakeRunKey { return &fakeRunKey{values: map[string]string{}} }

func (k *fakeRunKey) Get(name string) (string, bool, error) {
	if k.getErr != nil {
		return "", false, k.getErr
	}
	v, ok := k.values[name]
	return v, ok, nil
}

func (k *fakeRunKey) Set(name, value string) error {
	if k.setErr != nil {
		return k.setErr
	}
	k.sets++
	k.values[name] = value
	return nil
}

func (k *fakeRunKey) Delete(name string) error {
	if k.deleteErr != nil {
		return k.deleteErr
	}
	k.deletes++
	delete(k.values, name)
	return nil
}

// fakeProc is a process of fakeProcesses. After an interrupt it exits once
// Running has seen it alive exitAfter more times, unless it ignores
// interrupts.
type fakeProc struct {
	exe         string
	args        []string
	logPath     string
	alive       bool
	interrupted bool
	ignore      bool
	exitAfter   int
}

type fakeProcesses struct {
	procs      map[int]*fakeProc
	nextPID    int
	starts     int
	interrupts []int
	startErr   error
	exitAfter  int
}

func newFakeProcesses() *fakeProcesses {
	return &fakeProcesses{procs: map[int]*fakeProc{}, nextPID: 4100}
}

func (p *fakeProcesses) Start(exe string, args []string, logPath string) (int, error) {
	if p.startErr != nil {
		return 0, p.startErr
	}
	p.starts++
	p.nextPID++
	p.procs[p.nextPID] = &fakeProc{exe: exe, args: args, logPath: logPath, alive: true, exitAfter: p.exitAfter}
	return p.nextPID, nil
}

func (p *fakeProcesses) Running(pid int, exe string) (bool, error) {
	proc, ok := p.procs[pid]
	if !ok || !proc.alive || proc.exe != exe {
		return false, nil
	}
	if proc.interrupted && !proc.ignore {
		if proc.exitAfter == 0 {
			proc.alive = false
			return false, nil
		}
		proc.exitAfter--
	}
	return true, nil
}

func (p *fakeProcesses) Interrupt(pid int) error {
	p.interrupts = append(p.interrupts, pid)
	if proc, ok := p.procs[pid]; ok {
		proc.interrupted = true
	}
	return nil
}

type fixture struct {
	svc    *Service
	key    *fakeRunKey
	procs  *fakeProcesses
	sleeps []time.Duration
}

// newFixture makes a home directory with a config and an executable, and a
// service on fakes.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home dir")
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{home, bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(bin, "geth.exe")
	if err := os.WriteFile(exe, []byte("fake executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte("[Node]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: newFakeRunKey(), procs: newFakeProcesses()}
	f.svc = &Service{
		Exe:          exe,
		Home:         home,
		RunKey:       f.key,
		Processes:    f.procs,
		StopTimeout:  5 * time.Second,
		PollInterval: time.Second,
		Sleep:        func(d time.Duration) { f.sleeps = append(f.sleeps, d) },
	}
	return f
}

func (f *fixture) pidFile(t *testing.T) (int, string, bool) {
	t.Helper()
	pid, exe, err := readPIDFile(f.svc.PIDPath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return pid, exe, true
}

func TestWinsvcQuoteArg(t *testing.T) {
	tests := []struct{ in, want string }{
		{`geth`, `geth`},
		{`C:\Users\a\geth.exe`, `C:\Users\a\geth.exe`},
		{``, `""`},
		{`C:\Program Files\ghost-node\geth.exe`, `"C:\Program Files\ghost-node\geth.exe"`},
		{`C:\My Data\`, `"C:\My Data\\"`},
		{`a"b`, `"a\"b"`},
		{`a\"b`, `"a\\\"b"`},
		{"tab\there", "\"tab\there\""},
	}
	for _, tt := range tests {
		if got := QuoteArg(tt.in); got != tt.want {
			t.Errorf("QuoteArg(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	got := JoinCommandLine(`C:\Program Files\geth.exe`, "service", "start", "--home", `C:\Users\a b\ghost-node`)
	want := `"C:\Program Files\geth.exe" service start --home "C:\Users\a b\ghost-node"`
	if got != want {
		t.Errorf("JoinCommandLine = %q, want %q", got, want)
	}
}

func TestWinsvcDefaultHome(t *testing.T) {
	env := map[string]string{"LOCALAPPDATA": filepath.Join("Users", "someone", "AppData", "Local")}
	home, err := DefaultHome(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(env["LOCALAPPDATA"], "ghost-node"); home != want {
		t.Errorf("DefaultHome = %q, want %q", home, want)
	}
	if _, err := DefaultHome(func(string) string { return "" }); err == nil {
		t.Error("DefaultHome with no LOCALAPPDATA succeeded")
	}
}

func TestWinsvcInstallIsIdempotent(t *testing.T) {
	f := newFixture(t)
	changed, err := f.svc.Install()
	if err != nil || !changed {
		t.Fatalf("Install = %v, %v; want true, nil", changed, err)
	}
	want := JoinCommandLine(f.svc.Exe, "service", "start", "--home", f.svc.Home)
	if got := f.key.values[RunValueName]; got != want {
		t.Fatalf("Run value = %q, want %q", got, want)
	}
	if RunKeyPath != `Software\Microsoft\Windows\CurrentVersion\Run` {
		t.Fatalf("RunKeyPath = %q", RunKeyPath)
	}

	changed, err = f.svc.Install()
	if err != nil || changed {
		t.Fatalf("second Install = %v, %v; want false, nil", changed, err)
	}
	if f.key.sets != 1 {
		t.Fatalf("Run key written %d times, want 1", f.key.sets)
	}

	// An entry of an older executable is replaced.
	f.key.values[RunValueName] = `"C:\old\geth.exe" service start`
	changed, err = f.svc.Install()
	if err != nil || !changed {
		t.Fatalf("Install over an old entry = %v, %v; want true, nil", changed, err)
	}
	if got := f.key.values[RunValueName]; got != want {
		t.Fatalf("Run value = %q, want %q", got, want)
	}
	st, err := f.svc.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed || !st.Current || st.Command != want || st.Running {
		t.Fatalf("Status = %+v", st)
	}
}

func TestWinsvcInstallFailsClosed(t *testing.T) {
	cases := map[string]func(f *fixture){
		"no config": func(f *fixture) {
			os.Remove(f.svc.ConfigPath())
		},
		"no executable": func(f *fixture) {
			os.Remove(f.svc.Exe)
		},
		"relative executable": func(f *fixture) {
			f.svc.Exe = "geth.exe"
		},
		"relative home": func(f *fixture) {
			f.svc.Home = "ghost-node"
		},
		"quote in home": func(f *fixture) {
			f.svc.Home = filepath.Join(f.svc.Home, `a"b`)
		},
		"unreadable Run key": func(f *fixture) {
			f.key.getErr = errors.New("access denied")
		},
		"unwritable Run key": func(f *fixture) {
			f.key.setErr = errors.New("access denied")
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			breakIt(f)
			changed, err := f.svc.Install()
			if err == nil || changed {
				t.Fatalf("Install = %v, %v; want an error", changed, err)
			}
			if len(f.key.values) != 0 {
				t.Fatalf("Run key changed: %v", f.key.values)
			}
		})
	}
}

func TestWinsvcUninstall(t *testing.T) {
	f := newFixture(t)
	f.key.values["OtherProgram"] = `C:\other.exe`
	if _, err := f.svc.Install(); err != nil {
		t.Fatal(err)
	}
	changed, err := f.svc.Uninstall()
	if err != nil || !changed {
		t.Fatalf("Uninstall = %v, %v; want true, nil", changed, err)
	}
	if _, ok := f.key.values[RunValueName]; ok {
		t.Fatal("Run value still there")
	}
	if f.key.values["OtherProgram"] != `C:\other.exe` {
		t.Fatal("another program's Run value was touched")
	}
	changed, err = f.svc.Uninstall()
	if err != nil || changed {
		t.Fatalf("second Uninstall = %v, %v; want false, nil", changed, err)
	}
	if f.key.deletes != 1 {
		t.Fatalf("Run key deleted %d times, want 1", f.key.deletes)
	}

	// A failure to delete is reported.
	if _, err := f.svc.Install(); err != nil {
		t.Fatal(err)
	}
	f.key.deleteErr = errors.New("access denied")
	if _, err := f.svc.Uninstall(); err == nil {
		t.Fatal("Uninstall hid a failed delete")
	}
}

func TestWinsvcStartAndStop(t *testing.T) {
	f := newFixture(t)
	f.procs.exitAfter = 2

	pid, started, err := f.svc.Start()
	if err != nil || !started || pid == 0 {
		t.Fatalf("Start = %d, %v, %v", pid, started, err)
	}
	proc := f.procs.procs[pid]
	if proc.exe != f.svc.Exe {
		t.Errorf("started %q, want %q", proc.exe, f.svc.Exe)
	}
	if want := []string{"--config", filepath.Join(f.svc.Home, "config.toml"), "--mine"}; !reflect.DeepEqual(proc.args, want) {
		t.Errorf("node args = %q, want %q", proc.args, want)
	}
	if want := filepath.Join(f.svc.Home, "node.log"); proc.logPath != want {
		t.Errorf("log = %q, want %q", proc.logPath, want)
	}
	recorded, exe, ok := f.pidFile(t)
	if !ok || recorded != pid || exe != f.svc.Exe {
		t.Fatalf("pid file = %d %q %v, want %d %q", recorded, exe, ok, pid, f.svc.Exe)
	}

	// A running node is not started twice.
	again, started, err := f.svc.Start()
	if err != nil || started || again != pid {
		t.Fatalf("second Start = %d, %v, %v; want %d, false, nil", again, started, err, pid)
	}
	if f.procs.starts != 1 {
		t.Fatalf("%d processes started, want 1", f.procs.starts)
	}
	st, err := f.svc.Status()
	if err != nil || !st.Running || st.PID != pid || st.Installed {
		t.Fatalf("Status = %+v, %v", st, err)
	}

	stopped, err := f.svc.Stop()
	if err != nil || stopped != pid {
		t.Fatalf("Stop = %d, %v; want %d, nil", stopped, err, pid)
	}
	if !reflect.DeepEqual(f.procs.interrupts, []int{pid}) {
		t.Fatalf("interrupts = %v, want [%d]", f.procs.interrupts, pid)
	}
	if proc.alive {
		t.Fatal("Stop returned before the node exited")
	}
	if len(f.sleeps) != 2 {
		t.Fatalf("Stop waited %d times, want 2", len(f.sleeps))
	}
	if _, _, ok := f.pidFile(t); ok {
		t.Fatal("pid file kept after the node stopped")
	}
	st, err = f.svc.Status()
	if err != nil || st.Running {
		t.Fatalf("Status after Stop = %+v, %v", st, err)
	}

	// Stopping a stopped node does nothing.
	stopped, err = f.svc.Stop()
	if err != nil || stopped != 0 || len(f.procs.interrupts) != 1 {
		t.Fatalf("second Stop = %d, %v, interrupts %v", stopped, err, f.procs.interrupts)
	}

	// And it starts again.
	pid2, started, err := f.svc.Start()
	if err != nil || !started || pid2 == pid {
		t.Fatalf("Start after Stop = %d, %v, %v", pid2, started, err)
	}
}

func TestWinsvcMiningPausedStartsWithoutMine(t *testing.T) {
	f := newFixture(t)
	config := filepath.Join(f.svc.Home, "config.toml")
	if want := []string{"--config", config, "--mine"}; !reflect.DeepEqual(f.svc.NodeArgs(), want) {
		t.Fatalf("NodeArgs = %q, want %q", f.svc.NodeArgs(), want)
	}
	if err := os.WriteFile(filepath.Join(f.svc.Home, "mining-paused"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pid, started, err := f.svc.Start()
	if err != nil || !started {
		t.Fatalf("Start = %d, %v, %v", pid, started, err)
	}
	if want := []string{"--config", config}; !reflect.DeepEqual(f.procs.procs[pid].args, want) {
		t.Fatalf("node args with mining paused = %q, want %q", f.procs.procs[pid].args, want)
	}

	// Removing the file turns mining back on at the next start.
	if _, err := f.svc.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.svc.Home, "mining-paused")); err != nil {
		t.Fatal(err)
	}
	pid, _, err = f.svc.Start()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"--config", config, "--mine"}; !reflect.DeepEqual(f.procs.procs[pid].args, want) {
		t.Fatalf("node args after unpausing = %q, want %q", f.procs.procs[pid].args, want)
	}
}

func TestWinsvcStalePIDFile(t *testing.T) {
	f := newFixture(t)
	// The recorded process has exited.
	if err := writePIDFile(f.svc.PIDPath(), 77, f.svc.Exe); err != nil {
		t.Fatal(err)
	}
	if stopped, err := f.svc.Stop(); err != nil || stopped != 0 {
		t.Fatalf("Stop on a stale pid file = %d, %v", stopped, err)
	}
	if _, _, ok := f.pidFile(t); ok {
		t.Fatal("stale pid file kept")
	}

	// Its process id now belongs to another program, which is left alone.
	f.procs.procs[77] = &fakeProc{exe: `C:\Windows\notepad.exe`, alive: true}
	if err := writePIDFile(f.svc.PIDPath(), 77, f.svc.Exe); err != nil {
		t.Fatal(err)
	}
	if st, err := f.svc.Status(); err != nil || st.Running {
		t.Fatalf("Status with a reused process id = %+v, %v", st, err)
	}
	pid, started, err := f.svc.Start()
	if err != nil || !started || pid == 77 {
		t.Fatalf("Start over a reused process id = %d, %v, %v", pid, started, err)
	}
	if len(f.procs.interrupts) != 0 {
		t.Fatalf("interrupted %v", f.procs.interrupts)
	}
	if recorded, _, _ := f.pidFile(t); recorded != pid {
		t.Fatalf("pid file = %d, want %d", recorded, pid)
	}
}

func TestWinsvcCorruptPIDFileFailsClosed(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.svc.PIDPath(), []byte("not a pid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Start(); err == nil {
		t.Fatal("Start with a corrupt pid file succeeded")
	}
	if _, err := f.svc.Stop(); err == nil {
		t.Fatal("Stop with a corrupt pid file succeeded")
	}
	if f.procs.starts != 0 || len(f.procs.interrupts) != 0 {
		t.Fatalf("starts %d, interrupts %v", f.procs.starts, f.procs.interrupts)
	}
	if data, _ := os.ReadFile(f.svc.PIDPath()); string(data) != "not a pid\n" {
		t.Fatalf("pid file changed to %q", data)
	}
}

func TestWinsvcStopTimeoutKeepsPIDFile(t *testing.T) {
	f := newFixture(t)
	pid, _, err := f.svc.Start()
	if err != nil {
		t.Fatal(err)
	}
	f.procs.procs[pid].ignore = true
	if _, err := f.svc.Stop(); err == nil {
		t.Fatal("Stop of a node that does not exit succeeded")
	}
	if want := int(f.svc.StopTimeout / f.svc.PollInterval); len(f.sleeps) != want {
		t.Fatalf("Stop waited %d times, want %d", len(f.sleeps), want)
	}
	if recorded, _, ok := f.pidFile(t); !ok || recorded != pid {
		t.Fatal("pid file of a running node removed")
	}
}

func TestWinsvcStartFailsClosed(t *testing.T) {
	f := newFixture(t)
	os.Remove(f.svc.ConfigPath())
	if _, _, err := f.svc.Start(); err == nil {
		t.Fatal("Start with no config succeeded")
	}
	if f.procs.starts != 0 {
		t.Fatal("a node was started with no config")
	}

	f = newFixture(t)
	f.procs.startErr = errors.New("cannot start")
	if _, _, err := f.svc.Start(); err == nil {
		t.Fatal("Start hid a failed process start")
	}
	if _, _, ok := f.pidFile(t); ok {
		t.Fatal("pid file written for a node that did not start")
	}
}

func TestWinsvcStartStopsNodeItCannotRecord(t *testing.T) {
	f := newFixture(t)
	// A directory where the pid file is written first makes the write fail.
	if err := os.Mkdir(f.svc.PIDPath()+".new", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Start(); err == nil {
		t.Fatal("Start succeeded without recording the node")
	}
	if f.procs.starts != 1 {
		t.Fatalf("%d processes started, want 1", f.procs.starts)
	}
	if want := []int{f.procs.nextPID}; !reflect.DeepEqual(f.procs.interrupts, want) {
		t.Fatalf("interrupts = %v, want %v: the unrecorded node was left running", f.procs.interrupts, want)
	}
	if _, _, ok := f.pidFile(t); ok {
		t.Fatal("pid file written")
	}
}

func TestWinsvcOnlyOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this checks the other operating systems")
	}
	if _, err := System(`C:\geth.exe`, `C:\ghost-node`); !errors.Is(err, ErrWindowsOnly) {
		t.Fatalf("System = %v, want ErrWindowsOnly", err)
	}
	if err := Interrupt(1); !errors.Is(err, ErrWindowsOnly) {
		t.Fatalf("Interrupt = %v, want ErrWindowsOnly", err)
	}
}

func TestWinsvcPIDFileFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.pid")
	exe := filepath.Join("C:", "Users", "a b", "geth.exe")
	if err := writePIDFile(path, 1234, exe); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(1234) + "\n" + exe + "\n"; string(data) != want {
		t.Fatalf("pid file = %q, want %q", data, want)
	}
	// Windows line ends are read too.
	if err := os.WriteFile(path, []byte("1234\r\n"+exe+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid, got, err := readPIDFile(path)
	if err != nil || pid != 1234 || got != exe {
		t.Fatalf("readPIDFile = %d, %q, %v", pid, got, err)
	}
	for _, bad := range []string{"", "0\nx\n", "-5\nx\n", "12\n", "12\n\n"} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readPIDFile(path); err == nil {
			t.Errorf("readPIDFile(%q) succeeded", bad)
		}
	}
}
