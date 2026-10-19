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
  The evidence says what is pending. Since the catch-up backports finished,
  the only `open` row allowed is an advisory with no upstream fix: its
  evidence starts with `no upstream fix:` and names the advisory. The test
  `TestNoOpenItemsRemain` in `internal/securitydocs` enforces this.

Every row names where each of its facts came from: the Source column gives the
upstream release, advisory or document, and the Evidence column gives the
commit, file or reason that supports the status.

## Inventory since go-ethereum 1.13.15

The catch-up inventory of upstream fixes since go-ethereum 1.13.15 is added by
the security catch-up work, with its sub-tables added under this heading.

Taken on 2026-10-17. The rows left `open` then were settled by the follow-up
backport work (phase 1b), which had to finish before any Ghost node is exposed
to a public network. Its fixes went in as one commit per subsystem; on
2026-10-18 each of those rows was set to `applied`, naming the commit that
ported the fix and its test, or to `not applicable` with the reason. Where the
code here never had the upstream bug, the commit adds the upstream regression
test only, and the row says so. Upstream pull requests are go-ethereum's unless
named otherwise; a release tag names the go-ethereum release notes of that tag.

### go-ethereum releases after v1.13.15

Every stable tag after v1.13.15 (there is no v1.14.1 tag; its notes were lost
to CI problems upstream and v1.14.2 took its place in the series).

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | go-ethereum tag `v1.14.0` | v1.14.0: topic-filter nesting limits #29535, 2 MB header read cap #29534, data races #29238 and #29343 | applied | `7bcb5532a` (#29535) and `e343ddf9e` (#29534) |
| 2026-10-17 | go-ethereum tag `v1.14.2` | v1.14.2: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.3` | v1.14.3: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.4` | v1.14.4: discovery revalidation crash #29864; Verkle gas | applied | #29864 is in `p2p/discover/table_reval.go`; Verkle is not used by any Ghost chain |
| 2026-10-17 | go-ethereum tag `v1.14.5` | v1.14.5: no security items in the notes (hotfix for a v1.14.4 discovery regression) | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.6` | v1.14.6: 2 KB RLPx handshake limit #30029, discovery seed-node lock #29960, JSON out-of-bounds #30014 | applied | #30029 in `d7b9e6c28`; #29960 in `b42b8c437`; #30014 in `1e864dc16` (see other fixes below) |
| 2026-10-17 | go-ethereum tag `v1.14.7` | v1.14.7: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.8` | v1.14.8: discovery revalidation CPU spin #30239; blob pool flags | applied | #30239 in `b42b8c437` (see other fixes below); blob pool removed (`docs/removed-and-turned-off.md` line 26) |
| 2026-10-17 | go-ethereum tag `v1.14.9` | v1.14.9: blob pool out-of-bounds #30430, zero-amount header request #30305; Prague EIPs | applied | #30305 in `c19cf21c6`; #30430 not applicable (no blob pool, `docs/removed-and-turned-off.md` line 26); Prague is post-Cancun work (line 71) |
| 2026-10-17 | go-ethereum tag `v1.14.10` | v1.14.10: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.11` | v1.14.11: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.12` | v1.14.12: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.14.13` | v1.14.13: security release for CVE-2025-24883 (#31100) | applied | `ae6bad2d3` |
| 2026-10-17 | go-ethereum tag `v1.15.0` | v1.15.0: carries the CVE-2025-24883 fix; otherwise the Prague execution features | applied | `ae6bad2d3`; Prague is post-Cancun work (`docs/removed-and-turned-off.md` line 71) |
| 2026-10-17 | go-ethereum tag `v1.15.1` | v1.15.1: crash fixes in raw-data debug RPC #31157 and genesis handling #31171 | applied | #31157 in `354c6165b` (test `TestGetRawNotFoundNoPanic`); #31171: `0461b3b07` adds the regression test `TestSetupGenesisNoPanic`, and `core/genesis.go` needed no change |
| 2026-10-17 | go-ethereum tag `v1.15.2` | v1.15.2: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.15.3` | v1.15.3: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.15.4` | v1.15.4: blob p2p disconnects #31219 and a Pectra txpool regression | not applicable | blob transactions are off (line 43) and the blob pool is removed (line 26); the regression is in Prague code (line 71) |
| 2026-10-17 | go-ethereum tag `v1.15.5` | v1.15.5: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.15.6` | v1.15.6: no security items in the notes (a low-nonce regression in newer pool code) | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.15.7` | v1.15.7: log indexer trie deletion #31525 | not applicable | the log indexer (filter maps) is not in this code |
| 2026-10-17 | go-ethereum tag `v1.15.8` | v1.15.8: header traversal overflow #31522, discv5 challenge resend #31543 | applied | #31522 in `c19cf21c6`; #31543 in `e9c60f300` (see other fixes below) |
| 2026-10-17 | go-ethereum tag `v1.15.9` | v1.15.9: Prague mainnet activation, failed system call rule #31639, blob fee history crash #31663 | not applicable | Prague is post-Cancun work (line 71); blob transactions are off (line 43) |
| 2026-10-17 | go-ethereum tag `v1.15.10` | v1.15.10: log indexer deadlock #31708 | not applicable | the log indexer (filter maps) is not in this code |
| 2026-10-17 | go-ethereum tag `v1.15.11` | v1.15.11: RPC method name length limit #31711 | applied | #31711 in `1e864dc16` (see other fixes below) |
| 2026-10-17 | go-ethereum tag `v1.16.0` | v1.16.0: no security items in the notes (eth/69, early Fusaka work, Engine API) | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.16.1` | v1.16.1: `eth_getLogs` address limit of 1000 | applied | `efefa17d8`: `maxAddresses` of 1000 in `eth/filters/api.go` and `filter_system.go` (test `TestGetLogsAddressLimit`) |
| 2026-10-17 | go-ethereum tag `v1.16.2` | v1.16.2: oversized transaction announcements #32210, log filter validation #31877 | applied | #32210 in `0481e6ce8`; #31877 in `efefa17d8` (test `TestLogFilterValidation`) |
| 2026-10-17 | go-ethereum tag `v1.16.3` | v1.16.3: modexp input bounds #32363, GraphQL depth limit #32344, websocket read limit #32279 | applied | #32279 in `1e864dc16` (test `TestWebsocketServerReadLimit`); #32363 not applicable (Osaka modexp rules, post-Cancun work, `docs/removed-and-turned-off.md` line 71); GraphQL removed (line 21) |
| 2026-10-17 | go-ethereum tag `v1.16.4` | v1.16.4: KZG library fix (#32640, #32639) usable only after Osaka; txpool cost overflow #32544 | applied | #32544 in `0a5e92121`; KZG not applicable (blob transactions off, `docs/removed-and-turned-off.md` line 43) |
| 2026-10-17 | go-ethereum tag `v1.16.5` | v1.16.5: drop peers sending duplicate transactions #32728; discovery regressions #32912 and #32572 | applied | #32728 is in `eth/handler_eth.go`; the discovery regressions are in code this fork does not have |
| 2026-10-17 | go-ethereum tag `v1.16.6` | v1.16.6: `debug_traceCall` crash #33015, tx fetcher alternates leak #32947 | applied | #32947 in `0a5e92121`; #33015: `354c6165b` adds the regression test `TestTraceCallNoCrash`, and `BlockOverrides.Apply` in `internal/ethapi/api.go` leaves an unset block number alone, so no code change was needed |
| 2026-10-17 | go-ethereum tag `v1.16.7` | v1.16.7: c-kzg-4844 fix #33093 (post-Fusaka only), nocgo signature hash length #33104 | applied | #33104 in `d3f47b80b`; KZG not applicable (blob transactions off, `docs/removed-and-turned-off.md` line 43) |
| 2026-10-17 | go-ethereum tag `v1.16.8` | v1.16.8: security release for CVE-2026-22862 and CVE-2026-22868 | applied | CVE-2026-22862 in `348942271` and `6d4968db5`; CVE-2026-22868 not applicable (see the advisories table) |
| 2026-10-17 | go-ethereum tag `v1.16.9` | v1.16.9: security hotfix for CVE-2026-26314 and CVE-2026-26315 | applied | `0ebf49228`, `46bba8dfc`, `348942271` |
| 2026-10-17 | go-ethereum tag `v1.17.0` | v1.17.0: CVE-2026-26313, CVE-2026-26314, CVE-2026-26315, ECIES #33669, delayed decoding #33835; tx-unindex loop #33573, unsupported announcements #33378, heartbeat leak #33704 | applied | the CVEs, #33669 and #33835 are applied (see the Core-Geth table); #33573, #33378 and #33704 in `0a5e92121` |
| 2026-10-17 | go-ethereum tag `v1.17.1` | v1.17.1: request tracker crash #33940; snap sync fixes #33790 and #33898 | applied | #33940 is in `p2p/tracker/tracker.go` (test `TestRequestTrackerNoCrash` in `7ff2c26cb`); #33790 and #33898 in `7ff2c26cb` (tests `TestSnapSyncFix33790` and `TestSnapSyncFix33898`) |
| 2026-10-17 | go-ethereum tag `v1.17.2` | v1.17.2: `eth_getProof` slot limits #34617, tx lookup deadlock #34039; witness and simulate RPC limits | applied | #34617 in `354c6165b` (test `TestGetProofSlotLimit`); #34039: `0a5e92121` adds the regression test `TestTxLookupNoDeadlock`, and lookups here take no lock that a reorg holds, so no code change was needed; the witness and simulate RPCs are not in this code |
| 2026-10-17 | go-ethereum tag `v1.17.3` | v1.17.3: drop peers sending invalid bodies or receipts #34745 #34870, nocgo hash length #33839, discovery races #34888 #34743 #34878 | applied | #34745 and #34870 are in `eth/downloader/fetchers_concurrent.go` (tests `TestDownloaderDropsPeerInvalidBodies` and `TestDownloaderDropsPeerInvalidReceipts` in `0461b3b07`); #33839 in `d3f47b80b`; #34743, #34878 and #34888 in `b42b8c437` |
| 2026-10-17 | go-ethereum tag `v1.17.4` | v1.17.4: snapshot shutdown race #33540, GraphQL body limit #35034, log range validation #35032 | applied | #33540 in `0461b3b07` (test `TestSnapshotShutdownRace`); #35032 in `efefa17d8` (test `TestLogFilterRangeValidation`); GraphQL removed (`docs/removed-and-turned-off.md` line 21) |
| 2026-10-17 | go-ethereum tag `v1.17.5` | v1.17.5: no security items in the notes | not applicable | no security items in the notes |
| 2026-10-17 | go-ethereum tag `v1.17.6` | v1.17.6: RPC null-argument check #35576, JSON key unescaping #35587, tx type fork validation #35588, log range check #35070 | applied | #35576 in `1e864dc16` (test `TestRPCNullArguments`); #35587: `1e864dc16` adds the regression test `TestRPCKeyUnescape`, and `rpc` decodes messages with `encoding/json`, which unescapes keys, so no code change was needed; #35588 in `354c6165b` (test `TestTxArgsTypeForkValidation`); #35070 in `efefa17d8` (test `TestLogFilterRangeCheck`) |
| 2026-10-17 | go-ethereum tag `v1.17.7` | v1.17.7: block prefetcher memory leak on stop #35821 | applied | `0461b3b07`: `core/blockchain.go` waits for the block prefetchers on stop (test `TestPrefetcherStopNoLeak`) |
| 2026-10-17 | go-ethereum tag `v1.17.8` | v1.17.8: eth/snap handler DoS fixes #35862 #35904 #35857 #35856, IP predictor #35861, receipts #35859, cells #35883, STUN crash #35863 | applied | #35862, #35904 and #35857 in `c19cf21c6`, #35856 in `7ff2c26cb`, #35861 in `b42b8c437`; #35859 (eth/69), #35883 (eth/72 blobs) and #35863 (no STUN client) not applicable |

### go-ethereum security advisories after v1.13.15

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-4xc9-8hmq-j652 | GHSA-4xc9-8hmq-j652 (CVE-2024-32972, published 2024-05-06): memory exhaustion through a malicious header request, fixed in v1.13.15 | applied | `e343ddf9e` (#29534) |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-q26p-9cq4-7fc2 | GHSA-q26p-9cq4-7fc2 (CVE-2025-24883): crash on an off-curve handshake public key, fixed in v1.14.13 | applied | `ae6bad2d3` (#31100) |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-mr7q-c9w9-wh4h | GHSA-mr7q-c9w9-wh4h (CVE-2026-22862): crash through a malicious p2p message (ECIES), fixed in v1.16.8 | applied | `348942271` and `6d4968db5` |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-mq3p-rrmp-79jg | GHSA-mq3p-rrmp-79jg (CVE-2026-22868): CPU exhaustion through invalid KZG proofs, fixed in v1.16.8 | not applicable | no blob transactions and no blob pool (`docs/removed-and-turned-off.md` lines 26 and 43) |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-689v-6xwf-5jf3 | GHSA-689v-6xwf-5jf3 (CVE-2026-26313): memory exhaustion through a malicious p2p message, fixed in v1.17.0 | applied | `7940b2816` and the delayed decoding commits (see the Core-Geth table) |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-2gjw-fg97-vg3r | GHSA-2gjw-fg97-vg3r (CVE-2026-26314): secp256k1 coordinate check, fixed in v1.16.9 | applied | `0ebf49228` |
| 2026-10-17 | https://osv.dev/vulnerability/GHSA-m6j8-rg6r-7mv8 | GHSA-m6j8-rg6r-7mv8 (CVE-2026-26315): public key validation in the RLPx handshake, fixed in v1.16.9 | applied | `0ebf49228`, `46bba8dfc` and `348942271` |

### Other go-ethereum fixes after v1.13.15

Fixes in `p2p`, `rlp`, `trie`, `core/txpool`, `core/vm`, `crypto`, `rpc` and
`eth/protocols` (and their callers) that describe a crash, panic, resource
exhaustion, consensus split or invalid-input bug.

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | go-ethereum #35862 (v1.17.8) | eth: reject block bodies listing more items than their size allows | applied | `c19cf21c6`: `checkBodyItemCounts` in `eth/protocols/eth/handlers.go` (test `TestServeBodiesRejectOversizedCount`) |
| 2026-10-17 | go-ethereum #35904 (v1.17.8) | eth: the same check for receipts | applied | `c19cf21c6`: `checkReceiptItemCounts` in `handleReceipts`, with the minimum receipt size of the eth/68 consensus encoding (test `TestServeReceiptsRejectOversizedCount`) |
| 2026-10-17 | go-ethereum #35857 (v1.17.8) | eth: cap lookups per pooled-transactions request at 4096 | applied | `c19cf21c6`: `maxPooledTxServe` in `eth/protocols/eth/handler.go` (test `TestPooledTxLookupCap`) |
| 2026-10-17 | go-ethereum #35856 (v1.17.8) | snap: charge at least one load per requested trie node | applied | `7ff2c26cb`: `loads += max(resolved, 1)` in `eth/protocols/snap/handler.go` (test `TestSnapServeTrieNodeLoadCharge`) |
| 2026-10-17 | go-ethereum #35861 (v1.17.8) | p2p/discover: only bonded peers feed the IP predictor | applied | `b42b8c437`: `handlePing` in `p2p/discover/v4_udp.go` checks the bond first (test `TestV4IPPredictorBondedOnly`) |
| 2026-10-17 | go-ethereum #35859, #35883, #35881, #35865, #35890, #35863 (v1.17.8) | eth/69 receipts, eth/72 cells, JUMPDEST cache, block access lists, STUN client | not applicable | this code speaks eth/68 only, has no blob cells, no global JUMPDEST cache, no Amsterdam code and no STUN client |
| 2026-10-17 | go-ethereum #35289 | eth, snap: discard the message before the size check | applied | `eth/protocols/eth/handler.go` and `eth/protocols/snap/handler.go` defer `msg.Discard()` |
| 2026-10-17 | go-ethereum #33940 (v1.17.1) | p2p/tracker: crash in `clean()` after stop | applied | `p2p/tracker/tracker.go` |
| 2026-10-17 | go-ethereum #33245 (v1.17.0) | rlp: list iterator stops after a parse error | applied | `rlp/iterator.go` |
| 2026-10-17 | go-ethereum #30918 | eth: response dispatch hangs when the peer disconnects | applied | `eth/protocols/eth/dispatcher.go` |
| 2026-10-17 | go-ethereum #32947 (v1.16.6) | eth/fetcher: a dropped peer's alternates are never removed (memory leak) | applied | `0a5e92121`: a dropped peer is removed from `alternates` in `eth/fetcher/tx_fetcher.go` (test `TestTxFetcherDropClearsAlternates`) |
| 2026-10-17 | go-ethereum #33378 (v1.17.0) | core/txpool: ignore announcements of unsupported transaction types | applied | `0a5e92121`: `TxPool.FilterType`, passed to the tx fetcher by `eth/handler.go` (test `TestHandlerIgnoresUnsupportedTxAnnouncements`) |
| 2026-10-17 | go-ethereum #33704 (v1.17.0) | core/txpool/legacypool: heartbeat entries leak | applied | `0a5e92121`: `bumpBeat` in `core/txpool/legacypool/legacypool.go` (test `TestLegacyPoolHeartbeatNoLeak`) |
| 2026-10-17 | go-ethereum #32544 (v1.16.4) | core/txpool/legacypool: overflow check on the list's total cost | applied | `0a5e92121`: `AddOverflow` in `core/txpool/legacypool/list.go` (test `TestListTotalCostOverflow`) |
| 2026-10-17 | go-ethereum #30430 (v1.14.9) and the blob pool size caps #33474 #34831 #35367 #35766 | core/txpool/blobpool fixes | not applicable | the blob pool is removed from the node (`docs/removed-and-turned-off.md` line 26) |
| 2026-10-17 | go-ethereum #31522 (v1.15.8) | eth: overflow in header request traversal | applied | `c19cf21c6`: overflow and underflow checks in `serviceNonContiguousBlockHeaderQuery` (test `TestHeaderTraversalOverflow`) |
| 2026-10-17 | go-ethereum #30305 (v1.14.9) | eth: return early on a zero-amount header request | applied | `c19cf21c6`: `ServiceGetBlockHeadersQuery` in `eth/protocols/eth/handlers.go` (test `TestZeroAmountHeaderRequest`) |
| 2026-10-17 | go-ethereum #29864 (v1.14.4) | p2p/discover: crash when a node is removed during revalidation | applied | `p2p/discover/table_reval.go` |
| 2026-10-17 | go-ethereum #30239 (v1.14.8) | p2p/discover: revalidation CPU spin | applied | `b42b8c437`: the new `run()` in `p2p/discover/table_reval.go` (test `TestRevalidationNoCPUSpin`) |
| 2026-10-17 | go-ethereum #29960 (v1.14.6) | p2p/discover: missing lock when loading seed nodes (data race) | applied | `b42b8c437`: `loadSeedNodes` in `p2p/discover/table.go` holds the table mutex (test `TestTableLoadSeedNodesLocked`) |
| 2026-10-17 | go-ethereum #34743, #34878, #34888 (v1.17.3) | p2p/discover: v4 timeout loop, clock-warp error routing, read buffer race | applied | `b42b8c437`: `p2p/discover/v4_udp.go` (tests `TestV4TimeoutLoop`, `TestV4ClockWarpErrorRouting` and `TestV4ReadBufferNoRace`) |
| 2026-10-17 | go-ethereum #35043 | p2p/discover: v5 node wait hangs on a zero response count | applied | `e9c60f300`: `p2p/discover/v5_udp.go` (test `TestV5WaitZeroResponses`) |
| 2026-10-17 | go-ethereum #31356, #31543 | p2p/discover/v5: resend the current challenge during a handshake | applied | `e9c60f300`: `p2p/discover/v5_udp.go` and `p2p/discover/v5wire` (tests `TestV5ResendChallenge` and `TestV5ResendChallengeDuringHandshake`) |
| 2026-10-17 | go-ethereum #33104, #33839 (v1.16.7, v1.17.3) | crypto: hash length checks in the nocgo signature code | applied | `d3f47b80b`: `crypto/signature_nocgo.go` (tests `TestNoCgoSignHashLength`, `TestNoCgoRecoverHashLength` and `TestNoCgoVerifyHashLength`) |
| 2026-10-17 | go-ethereum #35686 | crypto/bn256/cloudflare: `twistPoint.Neg` zeroes its input | applied | `d3f47b80b`: `crypto/bn256/cloudflare/twist.go` (test `TestTwistPointNegKeepsInput`) |
| 2026-10-17 | go-ethereum #29644 | eth/gasprice: at most 100 reward percentiles in fee history | applied | `efefa17d8`: `maxQueryLimit` in `eth/gasprice/feehistory.go` (test `TestFeeHistoryPercentileLimit`) |
| 2026-10-17 | go-ethereum #31711, #35038 | rpc: method name length limit | applied | `1e864dc16`: `maxMethodNameLength` of 2048 in `rpc/json.go`, checked in `rpc/handler.go` (test `TestRPCMethodNameLengthLimit`) |
| 2026-10-17 | go-ethereum #33545 (v1.16.8) | rpc: limited buffer write fix | not applicable | `rpc` has no `limitedBuffer` |
| 2026-10-17 | go-ethereum #30014 (v1.14.6) | common/math: out of bounds on a lone quote in hex-or-decimal JSON | applied | `1e864dc16`: `common/math/big.go`, `integer.go` and `uint256.go` (test `TestHexOrDecimalLoneQuote`) |
| 2026-10-17 | go-ethereum #32363, #31818 | core/vm: modexp input bounds (EIP-7823) | not applicable | Osaka is post-Cancun work (`docs/removed-and-turned-off.md` line 71) |

### Core-Geth fixes

The rows of the fork-point comparison in
[decision 0001](docs/decisions/0001-fork-point.md), the two
`ethereumclassic/core-geth` v1.13.0 hardening fixes (tag commit
`85093c8531f4`), and later Core-Geth commits.

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | Delayed decoding of eth and snap messages, responses checked against pending requests | applied | `887da91c6`, `717942ef3`, `de544c0c3`, `4a2b0effc`, `4cdebb034`, `0f8924182` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | Item count checked before decoding (CVE-2026-26313) | applied | `7940b2816` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | secp256k1 coordinate checks (CVE-2026-26314, CVE-2026-26315) | applied | `0ebf49228`, `46bba8dfc` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | ECIES invalid curve and ciphertext length (CVE-2026-22862) | applied | `348942271`, `6d4968db5` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | `UnmarshalPubkey` rejects off-curve points (CVE-2025-24883) | applied | `ae6bad2d3` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | Trie embedded node size check (go-ethereum #33803) | applied | `b432ea26a` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | RLPx handshake messages limited to 2 KB (go-ethereum #30029) | applied | `d7b9e6c28` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | GraphQL query depth limit (GHSA-mh3m-8c74-74xh) | not applicable | taken in `31c8fc212`, then the GraphQL server was removed in `8ba1038d5` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | Limit of 2048 block announcements per `NewBlockHashes` message | applied | `9903f5c37` |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | Disconnect peers sending invalid KZG proofs (CVE-2026-22868) | not applicable | no blob transactions (`docs/removed-and-turned-off.md` lines 26 and 43) |
| 2026-10-17 | `ethereumclassic/core-geth` commit `cb07055da` | Bounded snapshot serving: readiness check in all four snap handlers, 2-second limit for every snap query, a yield after each message, iterator errors checked, snapshot rebuild safety net | applied | `eth/protocols/snap/handler.go`, `eth/handler.go`; test `TestSnapServingBoundedAndReadyChecked` |
| 2026-10-17 | `ethereumclassic/core-geth` commit `034051590` | Stale peer connection dropped for a new one on a duplicate node ID | applied | `p2p/peer.go`, `p2p/server.go`; test `TestServerReplacesStalePeerOnDuplicateID` |
| 2026-10-17 | `ethereumclassic/core-geth` commit `cb07055da` | The snapshot generator status RPC (`SnapshotGeneratorStatus` in `eth/api_debug.go`) | not applicable | an observability addition, not a fix |
| 2026-10-17 | `ethereumclassic/core-geth` commits `034051590` and `cb07055da` | Their `cmd/utils/flags.go` and Ethereum Classic DNS and bootnode hunks | not applicable | Ethereum Classic node lists are removed (`docs/removed-and-turned-off.md` line 13) |
| 2026-10-17 | `docs/decisions/0001-fork-point.md` | Dependency updates (11 reachable advisories in 7 modules) | applied | six modules raised in `09b1cd074`; the x/crypto advisory has no fix and is not applicable (see the dependency advisories table) |
| 2026-10-17 | `etclabscore/core-geth` master | Later Core-Geth commits after `dbbd993123b8` | not applicable | none: `dbbd993123b8` is still the tip on 2026-10-17, with no newer release or advisory |

### Dependency advisories

From `govulncheck` v1.1.4 at the fork point (11 reachable advisories in 7
modules).

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2026-6278 | GO-2026-6278 in `gorilla/websocket` v1.5.0, fixed in v1.5.3 | applied | `go.mod` requires v1.5.3 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2026-5970 | GO-2026-5970 in the Go `x/text` module v0.34.0, fixed in v0.39.0 | applied | `go.mod` requires v0.39.0 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2026-5932 | GO-2026-5932 in the Go `x/crypto` module v0.48.0 (v0.53.0 since `09b1cd074`): its `openpgp` packages are unsafe by design, no fixed version | not applicable | the vulnerable symbols are all of `x/crypto/openpgp`; only `internal/build/pgp.go` (`PGPSignFile`, `PGPKeyID`) imports it, called from `build/ci.go`, the release tooling; no node package imports it |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2026-5026 | GO-2026-5026 in the Go `x/net` module v0.50.0, fixed in v0.55.0 | applied | `go.mod` requires v0.56.0 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2025-4087 | GO-2025-4087 in `consensys/gnark-crypto` v0.12.1, fixed in v0.18.1 | applied | `go.mod` requires v0.18.1 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2025-3553 | GO-2025-3553 in `golang-jwt/jwt/v4` v4.5.0, fixed in v4.5.2 | applied | `go.mod` requires v4.5.2 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2024-3250 | GO-2024-3250 in `golang-jwt/jwt/v4` v4.5.0, fixed in v4.5.1 | applied | `go.mod` requires v4.5.2 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2022-0957 | GO-2022-0957 in `tidwall/gjson` v1.6.0, fixed in v1.6.5 | applied | `go.mod` requires v1.9.3 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2021-0265 | GO-2021-0265 in `tidwall/gjson` v1.6.0, fixed in v1.9.3 | applied | `go.mod` requires v1.9.3 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2021-0059 | GO-2021-0059 in `tidwall/gjson` v1.6.0, fixed in v1.6.4 | applied | `go.mod` requires v1.9.3 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |
| 2026-10-17 | https://pkg.go.dev/vuln/GO-2021-0054 | GO-2021-0054 in `tidwall/gjson` v1.6.0, fixed in v1.6.6 | applied | `go.mod` requires v1.9.3 (`09b1cd074`); test `TestDependencyAdvisoriesFixed` |

### Go toolchain

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | https://go.dev/doc/devel/release | `toolchain go1.26.9` in `go.mod`; go1.26.9 (2026-10-08) is the newest go1.26 release and carries its security fixes | not applicable | no newer go1.26 patch release exists, so the toolchain line stays |

## Log

| Logged | Source | Item | Status | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-17 | ghostcoin-core/ghost `docs/surveys/randomx.md` and `docs/decisions/0001-base-client.md` | RandomX reference (`tevador/RandomX`): the latest v1 tag is `v1.2.3` (2026-07-17). Fixes not in any release: `c981f99` and `397fd7a` (use-after-free in `randomx_vm_set_cache`), `c1811ac` and `9b012ab` (JIT page-protection errors), `418f549` (signed-overflow in the portable `smulh`). The reference `master` commit `418f5497e60215fcd8a7cff2a16be835135833e5` has all of them. | applied | the vendored library is pinned to `418f5497e602` (`5c3fe1999`; `consensus/randomx/librandomx/VENDORED.md`, `docs/decisions/0002-randomx-binding.md`) |
