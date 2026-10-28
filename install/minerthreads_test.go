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

//go:build linux

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The tests of how many cores the installed node mines on: half the
// computer's logical cores by default, or GHOST_MINE_THREADS's number, kept
// across re-runs and updates.

const minerThreadsRefusal = "GHOST_MINE_THREADS must be the number of CPU cores to mine on, a whole number from 1 to 9999"

// nodeThreads returns the --miner.threads argument of the running process pid,
// or "" when it has none.
func nodeThreads(t *testing.T, pid int) string {
	t.Helper()
	blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		t.Fatalf("the node, process %d, does not run: %v", pid, err)
	}
	args := strings.Split(strings.TrimRight(string(blob), "\x00"), "\x00")
	for i, arg := range args {
		if arg == "--miner.threads" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// keptThreads returns the number of cores the installed node keeps.
func keptThreads(t *testing.T, env *installEnv) string {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(env.home, ".ghost-node", "miner-threads"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(blob))
}

func nodeUnit(t *testing.T, env *installEnv) string {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(env.home, ".config", "systemd", "user", "ghost-node.service"))
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

// checkMinesOn checks that the node the stub systemd runs, its unit and the
// installed number all mine on threads cores.
func checkMinesOn(t *testing.T, env *installEnv, threads int) {
	t.Helper()
	base := filepath.Join(env.home, ".ghost-node")
	execStart := fmt.Sprintf("ExecStart=%q --config %q --mine --miner.threads %d\n", filepath.Join(base, "bin", "geth"), filepath.Join(base, "config.toml"), threads)
	if unit := nodeUnit(t, env); !strings.Contains(unit, execStart) {
		t.Fatalf("the unit does not run the node on %d cores:\n%s", threads, unit)
	}
	if got := nodeThreads(t, env.servicePID(t)); got != strconv.Itoa(threads) {
		t.Fatalf("the node runs with --miner.threads %q, not %d", got, threads)
	}
	if got := keptThreads(t, env); got != strconv.Itoa(threads) {
		t.Fatalf("the installer keeps %q as the number of cores, not %d", got, threads)
	}
}

// TestMinerThreadsDefaultIsHalfTheCores installs on computers with various
// numbers of logical cores: the node mines on half of them, rounded down, and
// on at least one, also when no tool tells the number, and the installer says
// so and how to change it.
func TestMinerThreadsDefaultIsHalfTheCores(t *testing.T) {
	release, _ := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))

	for _, tt := range []struct {
		name    string
		cpus    int
		want    int
		summary string
	}{
		{"18 cores", 18, 9, "mining on 9 of the 18 logical CPU cores of this computer"},
		{"7 cores", 7, 3, "mining on 3 of the 7 logical CPU cores of this computer"},
		{"2 cores", 2, 1, "mining on 1 of the 2 logical CPU cores of this computer"},
		{"1 core", 1, 1, "mining on 1 of the 1 logical CPU cores of this computer"},
		{"no tool tells", 0, 1, "mining on 1 CPU core;"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: tt.cpus})
			stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
			out, err := env.run(t, script, rs, true)
			if err != nil {
				t.Fatalf("install.sh failed: %v", err)
			}
			checkMinesOn(t, env, tt.want)
			for _, want := range []string{tt.summary, "run the install line again with GHOST_MINE_THREADS", "| GHOST_MINE_THREADS=2 sh\n"} {
				if !strings.Contains(out, want) {
					t.Fatalf("the installer did not say %q", want)
				}
			}
		})
	}

	t.Run("no systemd user services", func(t *testing.T) {
		env := newInstallEnv(t, envOptions{systemctl: stubNoSystemd, cpus: 5})
		pidFile := filepath.Join(env.home, ".ghost-node", "node.pid")
		stopNodeAtCleanup(t, pidFile)
		out, err := env.run(t, script, rs, true)
		if err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(readFile(t, pidFile)))
		if err != nil {
			t.Fatal(err)
		}
		if got := nodeThreads(t, pid); got != "2" {
			t.Fatalf("the node runs with --miner.threads %q, not 2", got)
		}
		if !strings.Contains(out, "mining on 2 of the 5 logical CPU cores") {
			t.Fatal("the installer did not say how many cores the node mines on")
		}
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

// TestMinerThreadsSetting installs with GHOST_MINE_THREADS: the node mines on
// that many cores, whatever the computer has. A re-run or an update without it
// keeps the number, and an update finding nothing new leaves the node alone;
// an update or a re-run with another number restarts the node on it.
func TestMinerThreadsSetting(t *testing.T) {
	release, _ := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))
	serveInstaller(t, rs, key, script)
	env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 4})
	stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
	const restart = "systemctl --user restart ghost-node.service\n"

	out, err := env.run(t, script, rs, true, "GHOST_MINE_THREADS=3")
	if err != nil {
		t.Fatalf("install.sh failed: %v", err)
	}
	checkMinesOn(t, env, 3)
	if !strings.Contains(out, "mining on 3 of the 4 logical CPU cores of this computer") {
		t.Fatal("the installer did not say it mines on GHOST_MINE_THREADS's 3 cores")
	}

	// A re-run without the setting keeps it.
	if out, err = env.run(t, script, rs, true); err != nil {
		t.Fatalf("the re-run failed: %v", err)
	}
	checkMinesOn(t, env, 3)
	if !strings.Contains(out, "mining on 3 of the 4") {
		t.Fatal("the re-run did not say it still mines on 3 cores")
	}

	// An update without it keeps it, and with nothing new does not restart.
	pid, restarts := env.servicePID(t), strings.Count(env.calls(t), restart)
	if out, err = env.update(t, rs); err != nil {
		t.Fatalf("the update failed: %v", err)
	}
	if !strings.Contains(out, "the node is up to date") || !strings.Contains(out, "mining on 3 of the 4") {
		t.Fatal("the update did not say the node is up to date and mines on 3 cores")
	}
	if strings.Count(env.calls(t), restart) != restarts || env.servicePID(t) != pid || !running(pid) {
		t.Fatal("an update keeping the number of cores restarted the node")
	}
	checkMinesOn(t, env, 3)

	// An update with another number restarts the node on it.
	if out, err = env.update(t, rs, "GHOST_MINE_THREADS=1"); err != nil {
		t.Fatalf("the update failed: %v", err)
	}
	checkRestarted(t, env, pid, restarts, restart)
	checkMinesOn(t, env, 1)
	if !strings.Contains(out, "on 1 of the 4 logical CPU cores") {
		t.Fatal("the update did not say it restarted the node on 1 core")
	}

	// As does a re-run.
	pid, restarts = env.servicePID(t), strings.Count(env.calls(t), restart)
	if _, err = env.run(t, script, rs, true, "GHOST_MINE_THREADS=12"); err != nil {
		t.Fatalf("the re-run failed: %v", err)
	}
	checkRestarted(t, env, pid, restarts, restart)
	checkMinesOn(t, env, 12)

	// An update with a malformed number is refused and changes nothing.
	state := snapshot(t, env)
	out, err = env.update(t, rs, "GHOST_MINE_THREADS=0")
	checkUpdateRefused(t, env, state, out, err, minerThreadsRefusal+", not '0'")
	checkMinesOn(t, env, 12)
}

// TestMinerThreadsRefusesMalformed runs the installer with GHOST_MINE_THREADS
// set to what is not a number of cores: it refuses before it downloads
// anything, and installs nothing.
func TestMinerThreadsRefusesMalformed(t *testing.T) {
	verifier := builtVerifier(t)
	key := newSigner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	blob := archive{"geth": fakeGeth(marker)}.tarGz(t)
	rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
	script := writeScript(t, key, sha256Hex(verifier))

	for _, value := range []string{
		"0", "00", "02", "-1", "+2", "1.5", "2 ", " 2", "2\n", "10000", "two", "half", "0x4", "$(touch " + marker + ")",
	} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 8})
			out, err := env.run(t, script, rs, true, "GHOST_MINE_THREADS="+value)
			checkRefused(t, env, out, err, minerThreadsRefusal+", not '"+value+"'; refusing to install. Nothing was installed.", marker)
		})
	}
	if served := rs.servedFiles(); len(served) != 0 {
		t.Fatalf("a refused GHOST_MINE_THREADS downloaded %v", served)
	}
}

// TestMinerThreadsOldInstallGetsDefaultOnUpdate installs a node as the
// installer did before it set the number of cores, one that mines on every
// core, and runs its update with nothing new to install: the update restarts
// the node on half the cores, and keeps that number from then on.
func TestMinerThreadsOldInstallGetsDefaultOnUpdate(t *testing.T) {
	release, _ := internalNetRelease(t)
	verifier := builtVerifier(t)
	key := newSigner(t)
	blob := release.tarGz(t)

	t.Run("systemd", func(t *testing.T) {
		rs := serveRelease(t, "linux", blob, key.sign(blob), verifier)
		script := writeScript(t, key, sha256Hex(verifier))
		serveInstaller(t, rs, key, script)
		env := newInstallEnv(t, envOptions{systemctl: stubSystemctl, cpus: 2})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		if _, err := env.run(t, script, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		checkMinesOn(t, env, 1)

		// The unit of an old install runs the node with no --miner.threads,
		// and no number is kept.
		unitPath := filepath.Join(env.home, ".config", "systemd", "user", "ghost-node.service")
		old := strings.Replace(nodeUnit(t, env), " --mine --miner.threads 1\n", " --mine\n", 1)
		if err := os.WriteFile(unitPath, []byte(old), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(env.home, ".ghost-node", "miner-threads")); err != nil {
			t.Fatal(err)
		}
		// The computer has 8 cores by the time of the update.
		if err := os.WriteFile(filepath.Join(env.stubs, "getconf"), []byte(fmt.Sprintf(stubGetconf, 8)), 0700); err != nil {
			t.Fatal(err)
		}

		const restart = "systemctl --user restart ghost-node.service\n"
		pid, calls := env.servicePID(t), env.calls(t)
		out, err := env.update(t, rs)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		if !strings.Contains(out, "the node is up to date") || !strings.Contains(out, "mining on 4 of the 8 logical CPU cores") {
			t.Fatal("the update did not say the node is up to date and now mines on 4 cores")
		}
		made := strings.TrimPrefix(env.calls(t), calls)
		if !strings.Contains(made, "systemctl --user daemon-reload\n"+restart) {
			t.Fatalf("the update did not reload the rewritten unit and restart the node:\n%s", made)
		}
		checkRestarted(t, env, pid, strings.Count(calls, restart), restart)
		checkMinesOn(t, env, 4)

		// The next update keeps the number and leaves the node alone.
		pid, calls = env.servicePID(t), env.calls(t)
		if out, err = env.update(t, rs); err != nil {
			t.Fatalf("the second update failed: %v", err)
		}
		if env.calls(t) != calls || env.servicePID(t) != pid || !running(pid) {
			t.Fatal("the second update restarted the node")
		}
		checkMinesOn(t, env, 4)
	})

	t.Run("launchd", func(t *testing.T) {
		rs := serveRelease(t, "darwin", blob, key.sign(blob), verifier)
		script := writeScript(t, key, sha256Hex(verifier))
		serveInstaller(t, rs, key, script)
		env := newInstallEnv(t, envOptions{darwin: true, stockMac: true, cpus: 2})
		stopNodeAtCleanup(t, filepath.Join(env.stubs, "service.pid"))
		if _, err := env.run(t, script, rs, true); err != nil {
			t.Fatalf("install.sh failed: %v", err)
		}
		plistPath := filepath.Join(env.home, "Library", "LaunchAgents", "com.ghostcoin.node.plist")
		threadArgs := "\t\t<string>--miner.threads</string>\n\t\t<string>1</string>\n"
		plist := readFile(t, plistPath)
		if !strings.Contains(plist, "<string>--mine</string>\n"+threadArgs) || nodeThreads(t, env.servicePID(t)) != "1" {
			t.Fatalf("the agent does not run the node on 1 core:\n%s", plist)
		}
		if err := os.WriteFile(plistPath, []byte(strings.Replace(plist, threadArgs, "", 1)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(env.home, ".ghost-node", "miner-threads")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.stubs, "sysctl"), []byte(fmt.Sprintf(stubSysctl, 18)), 0700); err != nil {
			t.Fatal(err)
		}

		domain := fmt.Sprintf("gui/%d", os.Getuid())
		bootstrap := fmt.Sprintf("launchctl bootstrap %s %s\n", domain, plistPath)
		pid, calls := env.servicePID(t), env.calls(t)
		out, err := env.update(t, rs)
		if err != nil {
			t.Fatalf("the update failed: %v", err)
		}
		if !strings.Contains(out, "mining on 9 of the 18 logical CPU cores") {
			t.Fatal("the update did not say the node now mines on 9 cores")
		}
		checkRestarted(t, env, pid, strings.Count(calls, bootstrap), bootstrap)
		if got := nodeThreads(t, env.servicePID(t)); got != "9" {
			t.Fatalf("the node runs with --miner.threads %q after the update, not 9", got)
		}
		if plist := readFile(t, plistPath); !strings.Contains(plist, "<string>--miner.threads</string>\n\t\t<string>9</string>\n") {
			t.Fatalf("the update did not rewrite the agent to run the node on 9 cores:\n%s", plist)
		}
		if got := keptThreads(t, env); got != "9" {
			t.Fatalf("the update keeps %q as the number of cores, not 9", got)
		}
	})
}
