# Security policy

The Ghost node is experimental. Nothing here has been audited by an outside
firm and no Ghost network exists yet, but we still want to hear about every
security problem, and we treat reports privately until a fix is ready.

## Reporting a vulnerability

Send reports privately to **[hello@ghostcoin.com](mailto:hello@ghostcoin.com)**,
the project's official address, until a dedicated security address exists.
Please do not open a public issue or pull request for a vulnerability.

A useful report says which package or command is affected, what goes wrong,
and how to reproduce it. We will acknowledge the report, keep you informed
while we work on it, and credit you when the fix is published unless you ask us
not to.

## Maintainers

- **Primary maintainer:** GhostcoinHQ
- **Backup maintainer:** to be named by the founder

## What this policy covers

This policy covers the node in this repository:

- the consensus rules the node enforces;
- the RandomX integration, and the RandomX source it is built against once
  it lands;
- peer-to-peer and RPC handling;
- build reproducibility, so that a release can be rebuilt byte for byte from
  its tagged commit;
- release signing.

Ghost's other tools, its specification and its proofs live in the
[ghost](https://github.com/ghostcoin-core/ghost) repository, under that
repository's own security policy.

## Upstream fixes

This node is a fork of Core-Geth, which is based on go-ethereum, and it uses
RandomX for proof of work. A fix published by go-ethereum, Core-Geth or
RandomX may apply here. If you know of one that this repository has missed,
reports are welcome: send it the same way as any other report.

How upstream fixes are watched, triaged and recorded is in
[SECURITY-BACKPORTS.md](SECURITY-BACKPORTS.md). How a fix is built, signed and
announced when it cannot wait is in
[docs/emergency-release.md](docs/emergency-release.md).
