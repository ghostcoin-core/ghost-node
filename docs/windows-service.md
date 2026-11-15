# The node on Windows

A Windows build is `geth.exe` for `windows-amd64` or `windows-arm64`. It
runs the node, with RandomX mining, and runs it as a per-user background
service that starts at login. Nothing about it needs administrator rights.
Windows builds are not published yet, and refuse to run a public network:
see [Windows releases are not published](#windows-releases-are-not-published).

## The service

`geth service` manages the service for the current user:

| Command | What it does |
|---|---|
| `geth service install` | makes the node start at every login |
| `geth service uninstall` | stops it starting at login (a running node keeps running) |
| `geth service start` | starts the node in the background, unless it is running |
| `geth service stop` | shuts the node down cleanly and waits for it to exit |
| `geth service status` | says whether the node starts at login and is running |

Each takes `--home DIR`, the service's home directory. The default is
`%LOCALAPPDATA%\ghost-node`. It holds:

- `config.toml`, the node's config. The installer writes it, with the mining
  address and the data directory; `install` and `start` refuse to run without
  it.
- `node.pid`, the running node's process id and executable, written by `start`
  and removed by `stop`.
- `node.log`, the node's output, appended to.

### How it works

- **Start at login.** `install` writes one string value, `GhostNode`, in the
  current user's Run key,
  `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`. Its value
  is the command line `"<path of geth.exe>" service start --home "<home>"`.
  Windows runs it at every login. A second `install` with the same paths
  changes nothing; one from another `geth.exe` or home replaces the value.
  `uninstall` removes the value, and only that value. No other key is
  touched: no machine-wide key, no Windows service, no scheduled task.
- **Background process.** `start` runs
  `geth.exe --config <home>\config.toml --mine` in a new, hidden console of its
  own and its own process group, at below-normal priority, with its output
  appended to `node.log`, and records it in `node.pid`. If the node is already
  running, it does nothing. If it cannot record the process, it stops it again
  and reports an error.
- **Stop.** `stop` sends the node a Ctrl+Break on its console, which the node
  handles like Ctrl+C: it shuts down cleanly. (A small helper, `geth service
  interrupt <pid>`, sends it, since attaching to another console would detach
  `geth service stop` from yours.) It then waits up to a minute for the node to
  exit and removes `node.pid`. A node that does not exit in time is reported
  and its `node.pid` kept.
- **Process ids are checked.** A process id from `node.pid` counts as the node
  only if that process is still running the executable recorded next to it, so
  a process id Windows has since given to another program is never stopped. A
  `node.pid` whose process is gone is stale and is removed.
- **Fail closed.** A missing config or executable, a relative path, a path
  with a quote in it, a Run key that cannot be read or written, a `node.pid`
  that cannot be read: each is reported as an error, and nothing is changed.

At login, Windows runs `geth service start` as a console program, so a console
window shows briefly while it starts the node; the node itself runs with its
console hidden.

On Linux and macOS, `geth service` reports that it is Windows only:
`install/install.sh` sets up a systemd user unit or a launchd agent there.

The code is `internal/winsvc/`. The logic (command line, pid file, start,
stop, status, install and uninstall) is plain Go behind two interfaces, one for
the Run key and one for processes, and `internal/winsvc/service_test.go` tests
it with fakes on any system. `service_windows.go` is the registry and process
code; `service_other.go` returns the "Windows only" error. The command is
`cmd/geth/servicecmd.go`.

## Building the release

A Windows build needs cgo: RandomX and the EVM bindings are C and C++, so
`CGO_ENABLED=0` does not build `cmd/geth`. It also needs a C compiler that
targets Windows on the release's processor:

- On a Windows amd64 machine (such as the GitHub `windows-2025` runner), the
  MinGW-w64 `gcc` on the PATH.
- On a Windows arm64 machine (such as `windows-11-arm`), an llvm-mingw `clang`
  for `aarch64-w64-mingw32`, on the PATH as `CC` or given with `-cc`.
- From Linux, an llvm-mingw toolchain, named with `-cc`.

`build/ci.go install` builds a Windows release when the target is Windows,
either because it runs on Windows or because `-os windows` asks for it:

- the executable is `build/bin/geth.exe`;
- it is statically linked (`-extldflags '-static'`), so it needs no MinGW DLL
  beside it; `-static=false` turns that off;
- it does not build or link the reveal proof verifier (see below);
- it fails when `CGO_ENABLED=0`, when the processor is not amd64 or arm64, and
  when it cross builds with no C compiler (`-cc` or `CC`).

The release commands, run at the repository root:

### windows-amd64

On a Windows amd64 machine, in Git Bash:

```sh
go run build/ci.go install ./cmd/geth
mkdir -p dist/stage && cp build/bin/geth.exe dist/stage/geth.exe
tar -C dist/stage -czf dist/ghost-node-windows-amd64.tar.gz geth.exe
```

From Linux with llvm-mingw:

```sh
go run build/ci.go install -os windows -arch amd64 -cc x86_64-w64-mingw32-clang ./cmd/geth
mkdir -p dist/stage && cp build/bin/geth.exe dist/stage/geth.exe
tar -C dist/stage -czf dist/ghost-node-windows-amd64.tar.gz geth.exe
```

### windows-arm64

On a Windows arm64 machine, in Git Bash, with llvm-mingw's `bin` on the PATH:

```sh
go run build/ci.go install -cc aarch64-w64-mingw32-clang ./cmd/geth
mkdir -p dist/stage && cp build/bin/geth.exe dist/stage/geth.exe
tar -C dist/stage -czf dist/ghost-node-windows-arm64.tar.gz geth.exe
```

From Linux with llvm-mingw:

```sh
go run build/ci.go install -os windows -arch arm64 -cc aarch64-w64-mingw32-clang ./cmd/geth
mkdir -p dist/stage && cp build/bin/geth.exe dist/stage/geth.exe
tar -C dist/stage -czf dist/ghost-node-windows-arm64.tar.gz geth.exe
```

The archive names and contents are the ones `.github/workflows/release.yml`
builds on Windows runners; it does not publish them (see below).

## Windows releases are not published

The reveal proof verifier (`ghostverifier/`, linked by
`core/ghostpriv/verifier_cgo.go`) is built for Linux and macOS only, so a
Windows build has no verifier (`core/ghostpriv/verifier_nocgo.go`). Such a
node would refuse every block that holds a reveal and mine a fork of its own,
so it is not shipped, and nothing runs it on a public network:

- `.github/workflows/release.yml` still builds the Windows archives, which
  keeps the Windows build and its RandomX tests running, but keeps them as
  unpublished workflow artifacts: a release carries no
  `ghost-node-windows-<arch>.tar.gz`.
- `install.ps1`, `install.cmd` and `ghost-setup` refuse to install, with
  nothing installed, and say why.
- A node without the verifier refuses to start on a public network (the
  public test network, and the launch network once it has consensus
  parameters): `eth.New` fails with `eth.ErrNoProofVerifier`. The internal
  network and developer mode still run.
- The statement checker at 0x61 gives no answer on such a node: the
  transaction or policy action that calls it is invalid there
  ([ghost-evm-profile.md](ghost-evm-profile.md)).

Windows releases come back once the verifier is built and linked for
windows-amd64 and windows-arm64, with a test that imports a block holding a
real reveal on a Windows build.

## What is tested where

- `go test ./internal/winsvc/` runs the service logic with a fake Run key and
  fake processes: idempotent install and uninstall, start, stop, stale and
  reused process ids, a node that does not exit, and each fail-closed case.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./internal/winsvc/` and the
  same for `GOARCH=arm64` type-check the Windows registry and process code.
- A full `cmd/geth` build for Windows needs the C toolchain above. The
  development sandbox has none, so the release commands above have not been
  run there; the Windows release runners run them.
