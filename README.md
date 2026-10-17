# Ghost node

This is the node for [Ghost](https://github.com/ghostcoin-core/ghost): our own
maintained fork of the proof-of-work Go Ethereum client, taken from
[Core-Geth](https://github.com/etclabscore/core-geth) with its full history.
The plan is to replace its mining algorithm with RandomX and add Ghost's own
consensus parts on top. The reasons are in the Ghost repository's
[base client decision](https://github.com/ghostcoin-core/ghost/blob/main/docs/decisions/0001-base-client.md).

**This project is experimental.** Nothing here has been audited by an outside
firm and no Ghost network exists yet. Do not run this node for anything of
value.

## Status

The repository is at its first stage: the fork point is chosen and recorded,
the parts of Core-Geth that Ghost does not use are removed or turned off, and
every change is built reproducibly and tested in CI. It does not yet mine with
RandomX, and the security catch-up on upstream fixes is still to come.

- Fork point: [docs/decisions/0001-fork-point.md](docs/decisions/0001-fork-point.md)
- What is removed and turned off: [docs/removed-and-turned-off.md](docs/removed-and-turned-off.md)

## Running a node

The goal is that anyone can run a Ghost node by pasting one line into a
terminal, without knowing anything about it. The node is built for that:

- each release is one self-contained executable per platform, built
  reproducibly (on Linux it is statically linked);
- when Ghost's network launches, its genesis and bootstrap nodes are built in,
  so `geth` with no flags and no config file runs a Ghost node, with sensible
  defaults for everything else.

No Ghost network exists yet, so today nothing is built in and the node will
not start on an empty data directory rather than join some other chain. To
try it, use developer mode (`geth --dev`), or initialise a private test
network with a genesis file (`geth init genesis.json`).

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
