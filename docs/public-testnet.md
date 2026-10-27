# The public test network

The public test network is the network built into the node. `geth` with no
flags and no config file, started on an empty data directory, writes the test
network's genesis, contacts its seed nodes and joins it. Nothing else has to
be given.

It is a test network, not the launch network. Its coins have no value, it may
be reset, and none of its values are launch values.

## The chain

| | |
|---|---|
| Chain ID and network ID | 6777972 (the internal network's 6777971 plus one) |
| Genesis time | 1793124000, 2026-10-27 18:00:00 UTC |
| Genesis difficulty | 16384 (2^14), the start difficulty |
| Genesis extra data | `ghost public test network`: a header carries no chain ID, and this keeps the first block apart from the internal network's |
| Genesis hash | `0xdfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436` |
| Allocation | none: coins come only from mined rewards |
| EVM | the Ghost EVM profile from block 0, as on the internal network |
| Consensus constants | its own (`ghost.TestNetParams`), below |

The genesis is `ghost.TestNetGenesis` and the seed list
`ghost.TestNetBootnodes`, both in `params/ghost/testnet.go`.

## Consensus constants

The test network uses the 30-second launch preset (`ghostrules.Launch30s`)
with a lower start and minimum difficulty, sized for a CPU miner in light
mode. They are not launch values, and they are not the internal network's
one-second blocks at difficulty 1.

| | |
|---|---|
| Block time | 30 s |
| ASERT half-life | 3600 s |
| Start difficulty | 16384 (2^14) |
| Minimum difficulty | 4096 (2^12) |
| Future drift | 30 s |
| Rewards | those of `ghostrules.Launch30s` |

The difficulty is the expected number of hashes per block. Light-mode RandomX
measured about 35 to 50 hashes a second per thread, about 550 a second on 16
threads, so the start difficulty is about 30 seconds of work for that machine
and the minimum about 7.5 seconds. ASERT moves the difficulty to whatever the
network's hash rate needs for 30-second blocks.

ASERT measures each block's lag from the genesis time, and each hour of lag
halves the difficulty, down to the minimum. The genesis time lies in the past,
or nothing could be mined until then, but it should lie close to when the
network starts: a network started long after its genesis time makes blocks at
the minimum difficulty, faster than 30 seconds, until the chain has caught up
with the lag. A reset that is more than a few hours after the genesis time
should move the genesis time to just before the reset, which gives a new
genesis hash.

`params/ghost/testnet_pacing_test.go` checks the constants and simulates the
chain with ASERT, a miner of fixed hash rate and a fake clock: blocks come
about every 30 seconds, and a genesis time far in the past leaves the first
blocks at the minimum difficulty, never at 1.

## Seed nodes

The node bootstraps discovery from these seeds, in order:

```
enode://3fdaf0ab54eca22eddd4f0aae6479d56318ddbdc0d08ad44b3c1ecee8d7093cb@65.21.102.174:30303
enode://2ef843c2bd12dd54c344966752e97d72b4e380597d438025f2cd2b2434a5405f@65.21.102.174:30304
enode://d438702bc0ce195458046d316ec67a9da0d9cac60c28179b9685d0c6136c0d80@65.21.102.174:30305
```

`--bootnodes` replaces the list, and so does a `BootstrapNodes` list in the
config file.

## Stored chains are kept

The built-in genesis is used only when the data directory holds no genesis.
A data directory that already holds a chain, such as one initialised with
`geth init` for the internal network, keeps that chain; the node never
replaces a stored chain with the built-in one. Developer mode (`--dev`) and
`scripts/internal-net.sh` work as before.

## Tests

`cmd/geth/publictestnet_test.go` starts local seed processes and a node on an
empty data directory with only local networking flags (`--datadir`,
`--port 0`, `--authrpc.port 0`, `--nat none`). The test binary, never the
shipped `geth`, replaces `TestNetBootnodes` with the local seeds, so the tests
never contact the seed hosts above.
