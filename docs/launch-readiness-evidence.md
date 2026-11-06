# Launch readiness evidence

This record shows, item by item, where the launch readiness gate stands. The
gate is the list of conditions that must hold before a launch date is set:
genesis supply, the authority checks of a release build, mining, the
installer, the outline's pre-launch list and the release timing. Each item
names the check that shows it, the command that runs the check, what the
check covers and what it leaves out.

An item is **met** only when its check runs and passes on the commit recorded
under [Results](#results). An item that needs something this repository
cannot hold (a frozen release, a second operator, an announcement) is
**open** until that evidence is added here.

Choosing the launch date is the founder's decision and is not part of this
record.

## Status

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Zero genesis balances; no mint path except the block reward and Reveal | Met on this tree; open against the frozen release | `TestSupplyChangesOnlyByRewardAndReveal` |
| 2a | No fake-seal mode in release builds | Met | `TestReleaseHasNoFakeSeals` |
| 2b | No verifier swap in release builds | Met | `TestReleaseBuildInstallsNoVerifier` |
| 2c | No checkpoint override in release builds | Met | `TestReleaseHasNoCheckpointOverride` |
| 3 | Two independent operators derive the same genesis, byte for byte, from the frozen software's Bitcoin-block rule | Open | Needs the frozen release and two operators' records |
| 4 | Solo mining through getWork with an existing RandomX miner configured for Ghost | Met for the getWork protocol; open for a named third-party miner | `TestSoloMiningExternalMiner`, [mining.md](mining.md) |
| 5a | The one-command installer verifies signatures | Met | `TestPinVerifierHashesInstalls` and the installer's refusal tests |
| 5b | A normal downloadable app exists | Open | Needs the published app |
| 6 | The outline's pre-launch list is complete | Open | Needs the list checked item by item |
| 7 | The date was made public 30 or more days ahead; the final software was frozen and published 14 or more days ahead | Open | Needs the frozen release and the announcement |

Items 3, 5b, 6 and 7, and item 1 against the frozen release, are carried by
the follow-up work on the frozen-release genesis derivation, the installer
app and the announcement timing.

"Release build" below means this tree built with the `ghostrelease` tag, the
tag `build/ci.go` builds `geth` with. No release has been frozen yet, so
every check here must be run again on the frozen release's commit, and that
commit recorded under [Results](#results), before the gate closes.

## 1. Genesis supply and mint paths

**Check:** `TestSupplyChangesOnlyByRewardAndReveal` in
`core/genesis_supply_test.go`.

```sh
go test ./core/ -run '^TestSupplyChangesOnlyByRewardAndReveal$' -v
```

The test runs a `core.BlockChain` on the internal network's genesis
(`params/ghost.InternalNetGenesis`, whose `Alloc` is empty) and builds,
seals with RandomX and imports blocks through exported interfaces only. It
reads the total balance of every account from the whole account trie, so an
account the test does not know of still counts. It checks:

- the total balance and the hidden set after the genesis are both zero;
- across empty blocks, an ML-DSA-44 transfer, a commit and a reveal, each
  block changes the total balance by exactly the block reward, plus what a
  reveal credits (its out and its tip), less the base fee burned and the
  value committed into the hidden set;
- the running total always equals everything minted less everything removed;
- after the reveal the hidden set holds what was committed less what the
  reveal took out, and `total_escrow` is zero.

In the code, the places that credit a balance without debiting another
account are the block reward (`consensus/randomx/consensus.go`,
`Finalize`) and the exits from the hidden set and escrow: a reveal's out and
tip (`core/ghostpriv/reveal.go`), the tips of policy reveals and policy
actions (`core/ghostpriv/policy_reveal.go`, `core/ghostpriv/policy_action.go`)
and escrow payments (`core/ghostpriv/escrow.go`, `PayEscrowSlot`), which pay
out of `total_escrow` that a policy reveal filled from the hidden set. All of
these spend value that a commit first removed from public balances.

**Limits.**

- The test runs on the internal network's genesis, not a launch genesis: no
  launch genesis is built in yet. The zero-balance check against the frozen
  release's genesis is open (item 3 derives that genesis).
- The test installs the stub reveal verifier, so it runs in a test build,
  not a `ghostrelease` build. The rules it checks are the same in both; only
  the proof check differs.
- It exercises the block reward and the plain reveal. Policy reveals, policy
  actions and escrow payments are not exercised by this test; a supply test
  covering them is a gap to file.

## 2. Authority checks in release builds

### 2a. No fake-seal mode

**Check:** `TestReleaseHasNoFakeSeals` in
`consensus/ethash/fakeseal_release_test.go`, built only with `ghostrelease`.

```sh
go test -tags ghostrelease ./consensus/ethash/ -run '^TestReleaseHasNoFakeSeals$' -v
```

It checks that `FakeSealsAllowed` is false; that no fake mode counts as fake;
that every constructor of a fake engine (`NewFaker`, `NewFakeFailer`,
`NewFakeDelayer`, `NewPoissonFaker`, `NewFullFaker`, `NewTester`, and `New`
with `ModeFake`, `ModeFullFake`, `ModePoissonFake` or `ModeTest`) panics
instead of building one; and that the release remote sealer verifies every
submitted seal. CI runs it (`build/ci-gate.sh`, "Release builds have no
fake seals").

The RandomX engine, which seals every Ghost chain, has no fake or
skip-verification mode at all (`consensus/randomx` holds none).

### 2b. No verifier swap

**Check:** `TestReleaseBuildInstallsNoVerifier` in
`core/ghostpriv/ghostprivtest/install_default_test.go`.

```sh
go run build/ci.go ghostverifier
LIBRARY_PATH=$PWD/build/cache/ghostverifier/release CGO_ENABLED=1 \
  go test -tags ghostrelease ./core/ghostpriv/ghostprivtest/ -run '^TestReleaseBuildInstallsNoVerifier$' -v
```

The first line builds the proof verifier's static library, which a
`ghostrelease` build with cgo links (see [Results](#results)).

It imports the stub verifier package without the test-depth tag and checks
that the active verifier is not the stub and that it rejects the stub proof
of a coin reveal and of a data reveal.

What keeps a release build from swapping the verifier:

- The stub installs itself only under the `ghosttreetest14` tag
  (`core/ghostpriv/ghostprivtest/install.go`), and `geth` links it only under
  that tag (`cmd/geth/ghostprivtest_install.go`).
- `core/ghosttree/depth_refuse.go` stops any build that has both
  `ghostrelease` and `ghosttreetest14`.
- `ghostpriv.SetVerifier` has no caller outside tests and the stub package.

### 2c. No checkpoint override

**Check:** `TestReleaseHasNoCheckpointOverride` in
`eth/ethconfig/checkpoint_release_test.go`, built only with `ghostrelease`.

```sh
LIBRARY_PATH=$PWD/build/cache/ghostverifier/release CGO_ENABLED=1 \
  go test -tags ghostrelease ./eth/ethconfig/ -run '^TestReleaseHasNoCheckpointOverride$' -v
```

This needs the verifier library built by `go run build/ci.go ghostverifier`,
as in 2b.

It checks that `CheckpointsAllowed` is false; that `ethconfig.Config` has no
checkpoint field; that a configuration file naming `SyncFromCheckpoint`,
`Checkpoint` or `CheckpointOracle` is refused, with any value or none; that
the encoded configuration names no checkpoint; that a chain configuration
with a trusted checkpoint or checkpoint oracle is refused (core-geth and
go-ethereum forms); and that no command-line flag in `cmd/utils` or
`cmd/geth` names a checkpoint. CI runs it with the proof verifier's library
linked (`build/ci-gate.sh`, "Release builds have no checkpoint override").

## 3. Genesis derived independently by two operators

**Open.** It needs the frozen software's Bitcoin-block rule run by two
operators who do not share a machine or a build, each recording the Bitcoin
block used, the software's commit and checksum, and the hash and SHA-256 of
the genesis they derived. This repository holds no launch genesis yet
([removed-and-turned-off.md](removed-and-turned-off.md), "Left for later
phases").

## 4. Solo mining through getWork

**Check:** `TestSoloMiningExternalMiner` in `eth/solo_mining_test.go`.

```sh
go test ./eth/ -run '^TestSoloMiningExternalMiner$' -v
```

The test starts a node on the internal network with mining on and no local
CPU threads, as `--mine --miner.threads=-1` does, so only an external miner
can seal. Over the node's HTTP RPC, as a separate miner program would, it:

- takes work with `eth_getWork` and checks it is for block 1 and keyed by
  the genesis hash;
- solves it outside the node's sealer with its own RandomX hash loop, using
  the byte order in [mining.md](mining.md);
- checks that a solution for work the node never handed out is refused;
- submits the solution with `eth_submitWork` and sees block 1 on the chain
  with the submitted nonce, paid to the configured mining address.

[mining.md](mining.md) lists what an existing RandomX miner must set for
Ghost: the Argon2 salt `Ghost-RandomX` followed by `0x01`, rebuilding the
cache when the key changes, big-endian nonce and target comparison, and the
full 8-byte nonce space.

**Limits.** The miner in the test is a RandomX hash loop in the test, not a
third-party miner program. A run of a named existing miner, built with
Ghost's salt and pointed at a node's getWork, is not recorded yet.

## 5. Installer and app

### 5a. The one-command installer verifies signatures

**Check:** `TestPinVerifierHashesInstalls` in `install/pin_test.go` (Linux).

```sh
go test ./install/ -run '^TestPinVerifierHashesInstalls$' -v
```

The release pins the SHA-256 of each platform's `ghost-verify` in
`install.sh` (`install/pin-verifier-hashes.sh`) before it signs the script.
The test pins a release folder's checkers and checks that each pinned line
holds its own file's hash, that nothing else in the script changes, that the
pinned script installs a signed release on Linux and on a Mac, and that a
checker whose hash is not the one pinned for its platform is refused before
anything runs.

`install.sh` checks the ed25519 signature of everything it downloads with
the pinned `ghost-verify` and the release key (`install/release-key.pub`)
before it unpacks or runs it. The refusals are covered in
`install/install_test.go`: `TestInstallScriptRefusesTamperedArchive`,
`TestInstallScriptRefusesWrongSignature`,
`TestInstallScriptRefusesUntrustedServer`,
`TestInstallScriptRefusesUnpinnedVerifier`,
`TestInstallScriptRefusesUntrustedNewerRelease` and
`TestInstallScriptRefusesTamperedUpdate`.

### 5b. A normal downloadable app

**Open.** It needs the published app, its download page and its signature
or notarisation recorded here.

## 6. The outline's pre-launch list

**Open.** Each entry of the outline's pre-launch list needs its own line
here with the evidence that it is done. Items 1 to 5 of this record cover
part of it; the rest has not been checked yet.

## 7. Release timing

**Open.** It needs the date and place of the public announcement of the
launch date, 30 or more days before it, and the commit, tag, checksums and
publication date of the frozen final software, 14 or more days before it.

## Results

Recorded on 2026-11-05 on the tree of commit `45c831497`, whose code is that
of `a3a43d0b8` (the record changes only this file), on linux/arm64 with
Go 1.26.9 and rustc 1.99.1. The commands above were run in order from the
repository root, as one command that stops at the first failure, with the
verifier library built by `go run build/ci.go ghostverifier` before the
release checks that link `core/ghostpriv`:

| Check | Result |
|---|---|
| `TestSupplyChangesOnlyByRewardAndReveal` | PASS (0.79s) |
| `TestReleaseHasNoFakeSeals` | PASS (0.00s) |
| `go run build/ci.go ghostverifier` | Built (`cargo build --release --locked`) |
| `TestReleaseBuildInstallsNoVerifier` | PASS (0.00s) |
| `TestReleaseHasNoCheckpointOverride` | PASS (0.01s) |
| `TestSoloMiningExternalMiner` | PASS (1.05s) |
| `TestPinVerifierHashesInstalls` | PASS (28.40s): linux, darwin and another platform's checker refused |

A `ghostrelease` build with cgo on Linux or macOS links the proof verifier's
static library (`core/ghostpriv/verifier_cgo.go`), and a release build names
only the library, not its folder. So, as CI does (`build/ci-gate.sh`), the
library is built first and the release checks of packages that link
`core/ghostpriv` (2b and 2c) are run with
`LIBRARY_PATH=$PWD/build/cache/ghostverifier/release CGO_ENABLED=1`. An
earlier run on the same code without them stopped at
`TestReleaseBuildInstallsNoVerifier` with `ld: cannot find -lghostverifier`.

With every row passing, items 2a, 2b, 2c and 5a are met on this tree, item 1
is met on this tree and item 4 is met for the getWork protocol, each within
the limits stated in its section. All of them must be run again on the
frozen release's commit.

## Gaps found

- No supply test covers policy reveals, policy actions or escrow payments
  (item 1).
- No run of a named existing RandomX miner against getWork is recorded
  (item 4).
- The release checks of packages that link `core/ghostpriv` build only with
  the proof verifier's library on the linker path, so they cannot be run as
  plain `go test -tags ghostrelease` commands; they need the steps in 2b
  (see [Results](#results)). This is how the release build works, not a
  defect, but anyone rerunning this record must follow those steps.
