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
| Genesis time | 1790812800, 2026-10-01 00:00:00 UTC |
| Genesis extra data | `ghost public test network`: the time is the internal network's, and this keeps the two first blocks apart |
| Genesis hash | `0xeecbc41f98be17f5a47dec0c9fab9ad566107669b70323d0588a171390f6ab58` |
| Allocation | none: coins come only from mined rewards |
| EVM | the Ghost EVM profile from block 0, as on the internal network |
| Consensus constants | the internal network's (`ghost.InternalNetParams`) |

The genesis is `ghost.TestNetGenesis` and the seed list
`ghost.TestNetBootnodes`, both in `params/ghost/testnet.go`.

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
