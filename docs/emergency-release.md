# Releases and the emergency release procedure

This is how the Ghost node is released, and how a security fix that cannot
wait for the normal flow of pull requests ships: for example a critical fix to
consensus, peer-to-peer or RPC handling found by a report or by the upstream
triage in [SECURITY-BACKPORTS.md](../SECURITY-BACKPORTS.md). An emergency
release is an ordinary release cut sooner; it follows the same steps and the
same checks.

## What a release is

A release is a GitHub release of ghostcoin-core/ghost-node, built and signed
by [.github/workflows/release.yml](../.github/workflows/release.yml) when a tag
of the form `vMAJOR.MINOR.PATCH` is pushed (each part a number from 0 to 999,
without leading zeros). It is marked latest.

A merge to `main` publishes nothing. Merges run the repository's checks
(typecheck, build, unit tests and the Ethereum fixture tests), which `main`
requires before a pull request can merge.

Every installed node runs its update script once a day. The update downloads
the latest release's `install.sh` and its signature, checks the signature
against the release key pinned in the node's own copy, and only then runs it.
So a published release reaches every node that has updates on within about a
day. That is why publishing needs a person's approval, below.

## Build numbers: no downgrades

Each release's `install.sh` carries a build number, written in by the release
before the script is signed, so the signature covers it. The number is
`MAJOR*1000000 + MINOR*1000 + PATCH` of the tag: `v1.2.3` is build 1002003.

- The publish job refuses a tag whose build number is not higher than the
  latest release's.
- An installed node records the build number it runs in
  `~/.ghost-node/release-build`. Its update refuses a latest release whose
  signed `install.sh` carries a lower number, or none (a script from before
  build numbers), and changes nothing. An older signed release put back as
  latest is therefore never installed as a downgrade.
- The same signed `install.sh` pins the SHA-256 of its own release's archive
  for each Linux and macOS platform, so a validly signed archive of an older
  release swapped into a newer release is refused too.
- After a successful update the node's update script is replaced by the new
  release's installer, so a node picks up newer checks as it updates.

A node can still be moved to an older release by hand: running an older
release's install line is an install, not an update, and is the operator's
choice.

## How a release is cut

1. The change is merged into `main` through a pull request whose checks
   passed. For a fix that must stay private until it ships, it is prepared in a
   private GitHub security advisory fork of ghostcoin-core/ghost-node, and a
   backport of an upstream change is reviewed by a different AI model from the
   one that prepared it, before it is merged.
2. A maintainer reads the change and its review, picks the next version, and
   pushes a tag on the merged commit of `main`:

       git fetch origin main
       git tag -a v1.2.3 -m "Ghost node v1.2.3" origin/main
       git push origin v1.2.3

3. The Release workflow builds every archive, installer and checker for the
   tag. Its sign and publish job waits for approval in the `release`
   environment.
4. A required reviewer of the `release` environment opens the run in GitHub,
   checks that the tag, its commit and the change are the ones meant for
   release, and approves the deployment. Nothing is signed without that
   approval.
5. The job checks that the tag is well formed, that its commit is on `main`,
   and that its build number is above the latest release's. It then signs and
   publishes the release as latest. Any failed check fails the run and
   publishes nothing.

Tags matching `v*` cannot be moved or deleted once pushed (a repository rule),
so a published release's tag always names the commit it was built from. A
mistaken tag is fixed by releasing the next version.

## Who builds

GitHub Actions builds the release from the tagged commit, through the
repository's reproducible build. CI checks on five platforms that the build is
reproducible: the same commit gives the same bytes, so anyone can rebuild a
release from its tag and compare it with what was published.

## Who signs

The release workflow signs, in its sign and publish job, and only in the
`release` environment. The signing key is the ed25519 private key whose
public half is [install/release-key.pub](../install/release-key.pub), which
every installer pins. It is stored as the `release` environment's secret
`GHOST_RELEASE_SIGNING_KEY` and is not a repository secret, so no other job,
branch or pull request can read it. The environment accepts runs only for
`v*` tags and holds each one until a required reviewer approves it.

Each archive, installer and checker gets a detached `.sig` file: the raw
64-byte ed25519 signature of the file's bytes. The release also carries
`SHA256SUMS`, the SHA-256 of every published file.

The approval is only as strong as the GitHub accounts that can give it, so
every member of the organisation must sign in to GitHub with two-factor
authentication.

## How operators are told

Operators are told through a GitHub security advisory and the release notes on
ghostcoin-core/ghost-node, with a notice in the
[ghost](https://github.com/ghostcoin-core/ghost) repository pointing to them.
The advisory says what is affected, which release fixes it, and whether the
fix changes consensus. Nodes with updates on install the release within about
a day; an operator who installed with `GHOST_NO_UPDATE=1` runs
`~/.ghost-node/update` to update.

## Release signing is not chain authority

Release signing is not chain authority. Maintainers can publish software, but
they have no power over the chain: a signature only says who built a release,
not which rules the network follows. A node installs signed releases on its
own only while its daily update is on; an operator can turn that off at
install time with `GHOST_NO_UPDATE=1` and choose when to upgrade, and whether
to run a release at all.
