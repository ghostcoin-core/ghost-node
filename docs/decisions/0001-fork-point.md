# Decision 0001: the fork point

Status: settled, 2026-10-17.

## Decision

The Ghost node starts from `etclabscore/core-geth` at commit
`dbbd993123b84d9cc2f5103566b09c7833327ef3` (2026-10-16), with the full
upstream history kept. That commit is the candidate the Ghost project named,
`7ee328ca2d6734ecbda9f0757d35eb6b710a14cd` (2026-09-17, after v1.12.23), plus
46 commits that bring in go-ethereum's toolchain updates (Go 1.23 to 1.25,
golangci-lint v2) and nothing else of substance.

Two fixes that only the `ethereumclassic/core-geth` v1.13.0 release has were
applied on top, with credit in the commit messages:

- the GraphQL query depth limit (GHSA-mh3m-8c74-74xh);
- a limit of 2048 block announcements per `NewBlockHashes` message.

The GraphQL server was then removed altogether. In the pinned graphql-go
v1.3.0, the depth check remembers each fragment it has already visited, so a
fragment first used at a shallow level is not checked again when it is reused
deeper, and a short query can still make the node expand an exponential
selection. Ghost's tools use JSON-RPC only, so removing the server closes the
problem instead of patching the library.

## What was compared

| | A: etclabscore/core-geth | B: ethereumclassic/core-geth v1.13.0 |
|---|---|---|
| Commit | `dbbd993123b8` (master, 2026-10-16), descendant of the candidate `7ee328ca2d67` | `85093c8531f4` (tag `v1.13.0`, 2026-09-14) |
| Shared base | `7ef3ecd7a716` (2024-12-16) | the same |
| Commits since the base (merges left out) | 84 (38 to the candidate, 46 after it) | 202 |
| Who | upstream go-ethereum authors and the Core-Geth maintainer | almost all one author |

Every commit on both sides since the shared base was listed, and each
security-relevant one was checked in the code at both commits, not by its
title.

## Security fixes, side by side

| Fix | A | B |
|---|---|---|
| Delayed decoding of eth and snap messages, and responses checked against pending requests | yes | yes, the same patches |
| Item count checked before decoding (CVE-2026-26313) | yes | covered by delayed decoding only |
| secp256k1 coordinate checks (CVE-2026-26314, CVE-2026-26315) | yes, upstream patches | yes, its own patch |
| ECIES invalid curve and ciphertext length (CVE-2026-22862) | yes, upstream patches | yes, its own patch |
| `UnmarshalPubkey` rejects off-curve points (CVE-2025-24883) | yes, upstream patch | yes, its own patch |
| Trie embedded node size check (go-ethereum #33803) | yes | yes |
| RLPx handshake messages limited to 2 KB (go-ethereum #30029) | yes | **no** |
| GraphQL query depth limit (GHSA-mh3m-8c74-74xh) | no | yes; taken, then the GraphQL server was removed |
| Limit on block announcements per message | no | yes, **taken** |
| Disconnect peers sending invalid KZG proofs (CVE-2026-22868) | no | yes; not needed, Ghost has no blob transactions |
| Bounded snapshot serving | no | yes; logged for the security catch-up |
| Replace a stale peer connection on a duplicate node ID | no | yes; logged for the security catch-up |
| Dependency updates | no: `govulncheck` reports 11 reachable advisories in 7 modules | yes, about 100 modules updated |

## Why A

- **B's release does not build.** Its `go.mod` replaces three modules with
  commits in `github.com/fukuii-project/archive-reference-material`, a
  repository that no longer exists. From an empty module cache, `go build`
  fails on 2026-10-17 with "repository not found". `ethereumclassic/core-geth`
  main fixed this after the release (commit `c26caadbd`), but the tagged
  release itself cannot be rebuilt.
- **B lacks a fix that A has**: the 2 KB RLPx handshake limit.
- **Most of B is Ethereum Classic product work** that Ghost removes or does not
  want: Ethereum Classic as the default network with the Ethereum networks
  refused, ECBP-1100 (MESS) switched on by default and extended, renamed
  binaries, a new documentation site and release pipeline. Ghost would delete
  it again.
- **A is closer to go-ethereum.** Its fixes are mostly upstream patches, which
  keeps later backports from go-ethereum simple.

B's security work is not ignored. The two fixes that matter for Ghost and
apply cleanly are taken now. The rest of B's fixes and A's dependency
advisories are recorded as open items for the security catch-up, which must
finish before any Ghost node is exposed to a public network.

## How it was checked

- `go build ./...` and `go test ./...` at A with Go 1.26.9. Apart from the
  Engine API tests (code Ghost removes), one timing-sensitive binding test
  under load and one floating-point print test that differs on arm64, the
  tests pass, including the Ethereum test fixtures.
- `govulncheck` v1.1.4 at A; the same scan at B stopped on the missing module.
- The commit lists, merge base and code at both commits, from
  `git log` and `git show` on fresh clones of both repositories.
