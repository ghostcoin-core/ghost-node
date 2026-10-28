# Ghost node

This is the node for [Ghost](https://github.com/ghostcoin-core/ghost): our own
maintained fork of the proof-of-work Go Ethereum client, taken from
[Core-Geth](https://github.com/etclabscore/core-geth) with its full history.
The plan is to replace its mining algorithm with RandomX and add Ghost's own
consensus parts on top. The reasons are in the Ghost repository's
[base client decision](https://github.com/ghostcoin-core/ghost/blob/main/docs/decisions/0001-base-client.md).

**This project is experimental.** Nothing here has been audited by an outside
firm and the Ghost network has not launched. The only shared network is a
public test network whose coins have no value. Do not run this node for
anything of value.

## Status

The fork point is chosen and recorded, the parts of Core-Geth that Ghost does
not use are removed or turned off, and every change is built reproducibly and
tested in CI. The node mines with RandomX on the public test network built
into it, on the internal test network and in developer mode, and refuses to
start on any other chain. The security catch-up on upstream fixes is still to
come.

- Fork point: [docs/decisions/0001-fork-point.md](docs/decisions/0001-fork-point.md)
- What is removed and turned off: [docs/removed-and-turned-off.md](docs/removed-and-turned-off.md)
- The public test network: [docs/public-testnet.md](docs/public-testnet.md)
- The internal test network: [docs/internal-network.md](docs/internal-network.md)

## Running a node

The goal is that anyone can run a Ghost node by pasting one line into a
terminal, without knowing anything about it. The node is built for that:

- each release is one self-contained executable per platform, built
  reproducibly (on Linux it is statically linked);
- a network's genesis and seed nodes are built in, so `geth` with no flags and
  no config file runs a Ghost node, with sensible defaults for everything
  else.

Until Ghost launches, the network built in is the **public test network**:
`geth` with no flags on an empty data directory writes its genesis, finds its
seed nodes and joins it. It is a test network, not the launch network: its
chain ID and network ID are 6777972, its coins have no value, and it may be
reset. A data directory that already holds a chain keeps it; the built-in
genesis is used only when the data directory holds none. `--bootnodes` or the
config file replace the built-in seed list. See
[docs/public-testnet.md](docs/public-testnet.md).

For development, use developer mode (`geth --dev`), or run the two-node
private internal test network with one command, `scripts/internal-net.sh`
(see [docs/internal-network.md](docs/internal-network.md)).

### The one line

On Linux or macOS (amd64 or arm64), paste this into a terminal:

```sh
curl -fsSL https://get.ghostcoin.com | sh
```

It runs [install/install.sh](install/install.sh), which asks nothing and needs
only the tools a stock Mac or Linux computer has (`sh`, `curl`, `tar`,
`sha256sum` or `shasum`); no OpenSSL. It downloads the release for this
computer, its signature, and `ghost-verify`, a small static signature checker
([install/verify](install/verify)) that it runs only when its SHA-256 is the
one pinned in the script. The checker checks the release's signature against
the release key pinned in the script before anything is unpacked or run; on
any doubt about a download, a hash or the signature the script stops with
nothing installed and says why.

It installs the node in `~/.ghost-node`, writes a config with a new mining
address, and starts the node mining as a user service that also starts at boot
(a systemd user unit on Linux, a launchd agent on macOS). The node joins the
public test network and syncs. The config opens the node's HTTP RPC on
`127.0.0.1:8545` only, to the Ghost web apps. When it finishes it prints the
mining address and how to check on the node.

Updates are on by default: `~/.ghost-node/update`, the same script run with
`--update`, runs daily (a systemd user timer, or a launchd agent) and installs
a newer signed release after the same checks, keeping the config and the
mining address; a refused update changes nothing. Set `GHOST_NO_UPDATE=1` for
the install to leave the timer out.

The key pinned today is a test key that nobody holds the private half of, and
the `ghost-verify` hashes pinned in the script are all-zero placeholders, so
the installer accepts no release yet. The real key replaces the `.pub` file in
`install/` and the same lines in `install.sh`; a test keeps the two equal. The
release fills in the checker's hashes.

On Windows (amd64 or arm64), paste this into PowerShell:

```powershell
irm https://get.ghostcoin.com/win | iex
```

or this into CMD:

```bat
curl -fsSL https://get.ghostcoin.com/win.cmd -o "%TEMP%\ghost-install.cmd" && "%TEMP%\ghost-install.cmd" && del "%TEMP%\ghost-install.cmd"
```

They run [install/install.ps1](install/install.ps1) and
[install/install.cmd](install/install.cmd), which do the same thing and need no
administrator rights: each downloads `ghost-setup-windows-<arch>.exe` from the
release with `curl.exe`, over https only, and runs it only when its SHA-256
(`Get-FileHash` or `certutil -hashfile`) is the one pinned in the script.
`ghost-setup` ([install/winsetup](install/winsetup)) then does what
`install.sh` does: it checks the release archive's ed25519 signature against
the same pinned release key before anything is unpacked, installs `geth.exe`
in `%USERPROFILE%\.ghost-node`, writes a config with a new mining address
(HTTP RPC on `127.0.0.1:8545`, open to the Ghost web apps), and starts the node
mining as the per-user service of `geth service`
([docs/windows-service.md](docs/windows-service.md)), a value in the current
user's Run key that starts it at every login. It prints the mining address and
how to check on the node. On any doubt about a download, a hash, the signature
or the archive it stops with nothing installed and says why.

Updates are on by default: a second Run key value runs
`ghost-setup.exe --update --daily` at login, which checks at most once a day
and installs a newer signed release after the same checks, keeping the
previous `geth.exe` until the node has restarted on the new one; a refused
update changes nothing. Set `GHOST_NO_UPDATE=1` for the install to leave it
out. The `ghost-setup` hashes pinned in the two scripts are all-zero
placeholders until the release publishes the setup executables, so for now
both lines refuse to install.

#### Settings

Each line takes these settings from the environment at install time; a value
the installer cannot use is refused with nothing installed.

- `GHOST_MINE_TO=0x...` mines straight to a wallet address of your own, such
  as the Ghost pop-up wallet's, instead of a newly generated mining key.
- `GHOST_HTTP_PORT=<port>` moves the node's HTTP RPC off `8545`.
- `GHOST_MINE_THREADS=<number>` sets how many CPU cores the node mines on, a
  whole number from 1 to 9999. By default it mines on half the computer's
  logical cores, rounded down and at least 1, so a laptop stays cool and quiet.
  The installer's closing lines say how many cores it mines on. A re-run or an
  update keeps the number unless the setting is given again, and a node
  installed before the setting existed gets the default on its next update.
  To change it, run the install line again with the setting:

  ```sh
  curl -fsSL https://get.ghostcoin.com | GHOST_MINE_THREADS=2 sh
  ```

  ```powershell
  $env:GHOST_MINE_THREADS='2'; irm https://get.ghostcoin.com/win | iex
  ```

  In CMD, run `set "GHOST_MINE_THREADS=2"` before the line above. On Linux and
  macOS the node runs with `--miner.threads`; on Windows `ghost-setup` keeps
  the number as `GETH_MINER_THREADS` in the user's environment, which geth reads
  as the same setting, so the node started at login uses it too.

## Building

You need Go 1.26 (the exact toolchain is pinned in `go.mod`) and a C compiler.

```sh
go run build/ci.go install ./cmd/geth
```

The executable is written to `build/bin/geth`. Release builds use the
`ghostrelease` build tag, which leaves out the fake proof-of-work modes the
tests use. Builds are reproducible: the same commit gives the same bytes on
the same platform, whatever directory it is built in. To check that yourself:

```sh
build/check-reproducible.sh
```

## Tests

```sh
go test ./...
```

The Ethereum execution test fixtures live in git submodules. Fetch them with
`git submodule update --init --recursive --depth 1` before running
`go test ./tests`.

## Contributing

All changes to `main` go through a pull request, and the CI jobs must pass.
Commit messages must be written as the project's own: no AI tool or vendor
names, no `Co-authored-by:` trailers and no "Generated with" lines.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Licence

The node keeps the licences of the code it comes from:

- the library code (everything outside the `cmd` directory) is under the
  [GNU Lesser General Public License v3.0](COPYING.LESSER);
- the programs (everything inside `cmd`) are under the
  [GNU General Public License v3.0](COPYING).

Ghost's own changes are released under the same terms as the files they
change. Ghost's other tools live in the separate
[ghost](https://github.com/ghostcoin-core/ghost) repository under MIT and
Apache 2.0, and talk to this node only over JSON-RPC and the external mining
interface. See [NOTICE](NOTICE) for where this code comes from.
