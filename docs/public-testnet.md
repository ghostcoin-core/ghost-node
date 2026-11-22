# The public test network

The public test network is the network built into the node. `geth` with no
flags and no config file, started on an empty data directory, writes the test
network's genesis, contacts its seed nodes and joins it. Nothing else has to
be given.

It is a test network, not the launch network. Its coins have no value, it may
be reset, and none of its values are launch values.

## Join it

These steps install a node on Linux or macOS (amd64 or arm64), sync it to the
network the public test nodes run, and then start it mining. You need a
terminal, an internet connection and about 1 GB of free disk. The node
listens for peers on TCP and UDP port 30303; it syncs without an open port,
but opening it helps the network.

### 1. Install with mining paused

```sh
mkdir -p ~/.ghost-node && touch ~/.ghost-node/mining-paused
curl -fsSL https://get.specter.cash | sh
```

The first line makes the node start without mining. The second is the one-line
installer: it checks the release's signature, installs the node in
`~/.ghost-node` with a new mining address, and starts it as a user service.
It ends by printing the mining address and the commands below.

Why pause first: a node that starts with mining on gives up the fast sync
(snap sync) and instead replays every block from block 0. The current
release (build 79) cannot replay the test network's early blocks, because
block 1394 holds a commit in an older format that the release now refuses, so
a node installed with mining on stops at block 1393 and never reaches the
network. Starting without mining keeps snap sync, which takes the recent state
from peers and does not replay old blocks.

### 2. Wait until it has synced

Ask the node for its head block, its peer count and whether it is still
syncing:

```sh
~/.ghost-node/bin/geth attach --exec '[eth.blockNumber, net.peerCount, eth.syncing !== false]' ~/.ghost-node/data/geth.ipc
```

It prints three values: the head block, the number of peers, and `true` while
it is syncing. For the first minute it may print `[0, 0, true]` while it finds
peers. The head stays at 0 while snap sync downloads headers, blocks and
state, then jumps to the network's head. On a computer with a few cores this
took about 10 minutes at block 68,000. The node has synced when the last value
is `false`, the head is above 0 and, run again a minute later, the head has
risen.

### 3. Check that it is on the same chain

The Ghost web app publishes a recent block of the network the public test
nodes run, its height and its hash:

```sh
curl -fsSL https://app.specter.cash/pin.json
```

Look at the `height` and `hash` at the start of the reply. Ask your node for
its hash at that height, replacing `HEIGHT` with the number:

```sh
~/.ghost-node/bin/geth attach --exec 'eth.getBlock(HEIGHT).hash' ~/.ghost-node/data/geth.ipc
```

The two hashes must be the same. Your node's first block must also be this
network's genesis, `0xdfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436`:

```sh
~/.ghost-node/bin/geth attach --exec 'eth.getBlock(0).hash' ~/.ghost-node/data/geth.ipc
```

### 4. Start mining

```sh
rm ~/.ghost-node/mining-paused
curl -fsSL https://get.specter.cash | sh
```

Running the line again keeps the node, its chain, its config and its mining
address, and restarts it with mining on. The node then mines on half the
computer's cores (`GHOST_MINE_THREADS` changes that; see the README). On Linux,
`journalctl --user -u ghost-node -f` shows its log, with a
`Successfully sealed new block` line for each block it finds. The Ghost Node
Dashboard link the installer printed shows the same in a browser.

On Linux, the node stops when you log out unless lingering is on. To keep it
running, run `loginctl enable-linger` (some systems need
`sudo loginctl enable-linger $USER`).

### If it is stuck at block 1393

A node installed without step 1 stops at block 1393, and its log
(`journalctl --user -u ghost-node` on Linux) shows `BAD BLOCK` for block 1394
with `commit data is not 430 bytes of version 3`. While stuck it still mines
blocks of its own on top of block 1393, which no other node takes, and its
rewards count for nothing. Remove its chain and sync it again; this keeps the
mining address, its key and the config:

```sh
systemctl --user stop ghost-node
rm -rf ~/.ghost-node/data/geth/chaindata
touch ~/.ghost-node/mining-paused
curl -fsSL https://get.specter.cash | sh
```

(On macOS, stop the node with
`launchctl bootout gui/$(id -u)/com.ghostcoin.node` instead of the first
line.) Then carry on from step 2.

## The chain

| | |
|---|---|
| Chain ID and network ID | 6777972 (the internal network's 6777971 plus one) |
| Genesis time | 1793124000, 2026-10-27 18:00:00 UTC |
| Genesis difficulty | 16384 (2^14), the start difficulty |
| Genesis extra data | `ghost public test network`: a header carries no chain ID, and this keeps the first block apart from the internal network's |
| Genesis hash | `0xdfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436` for the network the public test nodes run now (release build 79); the code on main gives `0x1beeb3088d741bdde1f5285fec7fea05b2d598237657e37741099d3e82867176`, because its headers carry the lookup fields, so the next release resets the network (see "Stored chains are kept") |
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
config file. The installer's config sets neither, nor a network ID, and it
initialises no chain for a release with the network built in;
`install/peers_test.go` checks that.

## Mining waits for a peer

On the public test network a node with no peers does not mine. Alone it
would build a fork of its own that no other node follows, and its blocks and
rewards would count for nothing. `--mine` still starts the miner, which keeps
its pending block current, but it hands no block to the sealer while the node
has zero peers. It logs `Not mining: waiting for a peer on the public test
network`, at most once a minute, and starts sealing within a recommit interval
of the first peer connecting. When the last peer leaves, the miner stops
handing out new work. A block already being sealed may still be found.

The gate checks only the chain ID and the peer count: the consensus rules are
unchanged. Developer mode, the internal network (6777971) and any other chain
mine with no peers as before. The peers counted are those the p2p server
connected that completed the eth handshake on this chain, which
`eth/backend.go` passes to the miner; `miner/peergate_test.go` checks the
gate.

## Mining and snap sync

A node started with `--mine` on an empty data directory keeps snap sync on,
with the default hash-based state database (`--state.scheme=hash`, which the
installer uses).
Starting the miner marks the node synced, so it imports the blocks its peers
propagate, but it no longer turns snap sync off: a node joining a long chain
takes the recent state by snap sync instead of replaying every block from
genesis. It logs `Mining with snap sync kept on until the chain reaches the
network's head`.

Snap sync ends, with `Snap sync complete, auto disabling`, when a sync
completes or when a block a peer propagated imports onto the node's chain.
The second covers nodes started together on a new network: their chains
never fall behind by more than a block or two, so they may never run a sync,
and a propagated block can import only onto a chain that holds its parent,
which means the node is at the network's head. That is the rule a restart
applies too: a chain past its genesis, with its state, full-syncs.

While snap sync is on and a peer has a heavier chain, the miner on the public
test network seals nothing, as when it has no peers. It logs `Not mining: a
peer is ahead and snap sync has not finished`, at most once a minute, and
seals within a recommit interval once the sync ends. So a joining node mines
no fork of its own on genesis in the seconds before its sync starts, nor on
a half-synced chain if a sync fails. Once snap sync is off the hold never
applies again, so a peer that announces a heavier chain it cannot serve
cannot stop a synced miner. The hold is `snapSyncPending` in
`eth/handler.go`, passed to the miner in `eth/backend.go`;
`miner/peergate_test.go` checks it.

With `--state.scheme=path` starting the miner still turns snap sync off, as
before: a snap sync turns the path-based database off until it finishes,
which a miner cannot mine through. Such a node full-syncs from genesis,
which works on the test network from the next reset on (see below). Start
it without mining, or with the hash-based database, to snap sync.
`eth/snap_mining_test.go` checks both.

## Consensus changes on the test network

From the next reset on, a change to the consensus rules (what a block, a
commit or a reveal must be for a node to accept it) reaches the running test
network in one of two ways, never silently:

- with an activation height, so a node checks blocks below it by the old
  rules and full sync from genesis still works; or
- with a new genesis, so every test node moves its old chain aside (see
  below) and the network starts again.

A change that does neither leaves old blocks that new nodes refuse, as build
79 refused block 1394 of the chain before this reset, and only snap sync
can join such a chain.

## Stored chains are kept

The built-in genesis is written only when the data directory holds no genesis.
A data directory that already holds a chain, such as one initialised with
`geth init` for the internal network, keeps that chain. Developer mode
(`--dev`) and `scripts/internal-net.sh` work as before, and a genesis
mismatch on those chains still fails as before.

The one exception is a public test network chain from before a reset. When
the node runs the built-in network (no genesis given, not developer mode) and
the stored chain has the test network's chain ID, 6777972, but a genesis hash
other than the built-in one, the node moves that chain aside before opening
it and starts on the built-in genesis. Without this it would start on the old
chain, find no peers there and mine alone.

The chain data is renamed to a dated sibling folder, such as
`chaindata.old-2026-10-27` (`chaindata.old-2026-10-27-2` and so on if that
exists), and a freezer kept elsewhere with `--datadir.ancient` is renamed the
same way beside it. Nothing is deleted. The keystore and the node key are not
touched. The node logs one warning naming the old genesis hash, the new one
and the new folder. A chain with any other chain ID, and a test network chain
on the built-in genesis, are left alone.

The decision is `isStaleTestNetChain` in `eth/testnet_reset.go`, and
`eth/testnet_reset_test.go` checks it and the move.

## Tests

`cmd/geth/publictestnet_test.go` starts local seed processes and a node on an
empty data directory with only local networking flags (`--datadir`,
`--port 0`, `--authrpc.port 0`, `--nat none`). The test binary, never the
shipped `geth`, replaces `TestNetBootnodes` with the local seeds, so the tests
never contact the seed hosts above.

`cmd/geth/publictestnet_mining_test.go` runs mining nodes the same way, as
"geth-test-mining", which also lowers the test network's difficulty floor to
64 through a function only test builds have (release builds always use the
floor above). The genesis is unchanged, and blocks carry real RandomX seals
that every node checks. `TestPublicTestNetMiningNodeSnapSyncsLongChain` has
two seeds mine 160 blocks and then starts a node with mining on, on an empty
data directory: it must commit a snap sync pivot, seal nothing before that,
reach the seeds' chain and get a block of its own into it.
`TestPublicTestNetMiningNodesStartTogether` starts three such nodes together
at genesis: they must build one chain with blocks from more than one of them,
each must leave snap sync, and they must keep going.
