# Emergency release procedure

This is how the Ghost node ships a security fix that cannot wait for the
normal flow of pull requests: for example a critical fix to consensus,
peer-to-peer or RPC handling found by a report or by the upstream triage in
[SECURITY-BACKPORTS.md](../SECURITY-BACKPORTS.md).

**Nothing is signed or released today.** No release key exists yet, so no
release of this node has been signed or published. The steps below are the
procedure that applies from the first public release on.

## How a fix is prepared

1. The fix is prepared in a private GitHub security advisory fork of
   ghostcoin-core/ghost-node, so it is not public before the release.
2. When the fix is a backport of an upstream change, the backport is prepared
   on that fork, reviewed by a different AI model from the one that prepared
   it, and tested with the repository's checks.
3. A maintainer reads the change and the review and signs it off. Nothing is
   released without that sign-off.
4. The fix is merged and the release commit is tagged.

## Who builds

The primary maintainer's account builds the release from the tagged commit,
through the repository's reproducible build. CI checks on five platforms that
the build is reproducible: the same commit gives the same bytes, so anyone can
rebuild a release from its tag and compare it with what was published.

## Who signs

The primary maintainer signs the release. The signature is a detached
signature over the SHA-256 checksum file of the release, made with the
maintainer's release key. The fingerprint of that key is published in
[SECURITY.md](../SECURITY.md) before the first public release.

No release key exists yet, so nothing is signed today and no fingerprint is
published.

## How operators are told

Operators are told through a GitHub security advisory and the release notes on
ghostcoin-core/ghost-node, with a notice in the
[ghost](https://github.com/ghostcoin-core/ghost) repository pointing to them.
The advisory says what is affected, which release fixes it, and whether the
fix changes consensus.

## Release signing is not chain authority

Release signing is not chain authority. Maintainers can publish software, but
they have no power over the chain: a signature only says who built a release,
not which rules the network follows. The node never updates itself. Each
operator chooses when to upgrade, and whether to run a release at all.
