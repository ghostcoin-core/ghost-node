# Security backports

**Owner:** GhostcoinHQ (primary maintainer)

This file records how the Ghost node keeps up with security fixes published
upstream, and what was decided about each one. A missed upstream fix would be
a Ghost vulnerability, so this is standing work.

## Routine

The owner watches these sources:

- go-ethereum releases and security advisories
  (`ethereum/go-ethereum`);
- the Ethereum Classic clients, `etclabscore/core-geth` and
  `ethereumclassic/core-geth`: their releases and advisories;
- RandomX releases and fixes on its reference repository (`tevador/RandomX`);
- Go security releases, for the toolchain pinned in `go.mod`;
- Go module advisories for this repository's dependencies, checked by running
  `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...` from the repository
  root.

Each source is watched through its GitHub releases and security advisories
(and, for Go, its security release announcements). Every upstream release is
triaged within 7 days of its publication. A triage reads the release notes and
advisories, decides for each security-relevant change whether this node has
the affected code, and logs the result as a row in the table under
[Log](#log). An applied fix names the commit or pull request that brought it
in.

A critical fix at the network level (one that lets a peer or an RPC caller
crash nodes, split the chain or break consensus) goes out under the
[emergency release procedure](docs/emergency-release.md).

## Status values

- `applied`: the fix is in this repository. The evidence names the commit or
  pull request that brought it in.
- `not applicable`: this node does not have the affected code, or the change
  does not affect it. A `not applicable` row must give its reason in the
  evidence.
- `open`: the fix applies, or may apply, and is not in this repository yet.
  The evidence says what is pending.

Every row names where each of its facts came from: the Source column gives the
upstream release, advisory or document, and the Evidence column gives the
commit, file or reason that supports the status.

## Inventory since go-ethereum 1.13.15

The catch-up inventory of upstream fixes since go-ethereum 1.13.15 is added by
the security catch-up work, with its sub-tables added under this heading.

## Log

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | ghostcoin-core/ghost `docs/surveys/randomx.md` and `docs/decisions/0001-base-client.md` | RandomX reference (`tevador/RandomX`): the latest v1 tag is `v1.2.3` (2026-07-17). Fixes not in any release: `c981f99` and `397fd7a` (use-after-free in `randomx_vm_set_cache`), `c1811ac` and `9b012ab` (JIT page-protection errors), `418f549` (signed-overflow in the portable `smulh`). The reference `master` commit `418f5497e60215fcd8a7cff2a16be835135833e5` has all of them. | open | pinned by the RandomX engine work, not merged yet |
