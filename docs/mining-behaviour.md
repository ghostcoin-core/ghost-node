# Mining behaviour

Measurements of how nodes behave under mining conditions that a single
two-node run does not reach: deep reorganisations, a network split with
uneven hashrate, a peer flooding a node with bad headers, and a fresh node
syncing a chain while checking every RandomX seal. They are recorded here
before any launch date and should be taken again when consensus, fork
choice, sync or peer handling changes.

## How the tests run

The tests are in `eth/mining_behaviour_test.go`:

```sh
go test ./eth/ -run '^TestMining(DeepReorg|SplitHeal|HeaderFlood|FullSealSync)$' -count=1 -timeout 20m -v
```

With `-v` each test logs its measurements on lines starting `result:`.
Under `-short`, `TestMiningFullSealSync` is skipped; the others always run.

Every node runs in the test process: a `core.BlockChain` with its own
in-memory database, its own RandomX engine, the eth protocol handler, and a
p2p server with a quantum-safe identity listening on loopback, discovery
off. Blocks are built, sealed with RandomX and imported by the node that
mines them, and reach other nodes only over the eth protocol through the
full-sync downloader. A test runs the sync a node's chain syncer would start
once a peer has a heavier head, so the outcome does not depend on gossip
timing. A split is a disconnection of the p2p link; a heal is a new
connection, dialled from the other side.

### The chain

| | |
|---|---|
| Genesis and EVM | `params/ghost.InternalNetGenesis()`, chain ID 6777971, with its difficulty set to 16 |
| Consensus | `params/ghost.InternalNetParams()` with the RandomX test engine's values: 10-second blocks, start and minimum difficulty 16, 30 s future drift; half-life 3,600 s and rewards as the internal network |
| RandomX keys | key interval 8 blocks, key delay 4, as the RandomX package's tests: a new key every 8 blocks, so a test chain crosses many keys and the 256 MiB light caches are rebuilt often |
| Blocks | empty, ten seconds apart, so the ASERT difficulty stays at 16 and the heavier chain is the longer one |
| Sealing | 4 RandomX threads a mining node |

At the internal network's own difficulty of 1 every RandomX hash seals a
block, so a seal check can never fail there. Difficulty 16 keeps sealing
to a few dozen hashes while a wrong nonce fails the check fifteen times in
sixteen.

## Results

Measured on 2026-10-23 on a 16-CPU arm64 Linux machine with 47 GiB of
memory, all four tests in one `go test` process (100 s in total). Memory is
the Go heap in use and the resident set of the whole test process at the
end of the step; the resident set includes the RandomX caches (up to three
of 256 MiB each, outside the Go heap) and every node of the tests that ran
before.

| Test | What happens | Time | Memory |
|---|---|---|---|
| `TestMiningDeepReorg` | 4 nodes; 6-block common prefix; partitions of 2 mine 24 and 40 blocks apart; rejoin | mining apart 37.8 s; rejoin and 24-block reorg 2.9 s; test 42 s | Go heap 47 MiB, RSS 934 MiB |
| `TestMiningSplitHeal` | 3 nodes; 4-block prefix; majority of 2 with 3/4 of the hashrate, minority of 1 with 1/4; 10 rounds of 3 and 1 blocks; heal; 4 more blocks | split 14.6 s; heal and 10-block reorg 0.9 s; test 19 s | Go heap 36 MiB, RSS 918 MiB |
| `TestMiningHeaderFlood` | flood peers against a node with an 8-block chain and one honest peer | test 2.6 s | see below |
| `TestMiningFullSealSync` | one node mines 160 blocks (20 RandomX keys); a fresh node syncs them | mining 30.1 s (188 ms a block); sync with every seal checked 6.0 s (38 ms a block); test 36 s | Go heap 44 MiB before the sync, 60 MiB after; RSS 956 MiB |

### Deep reorg

After the rejoin every node is on the heavier partition's head, holds the
state of that head, and computes the same coin tree and data tree roots,
which match the head's header. Every coinbase's balance on every node is
the sum of the rewards of the canonical blocks it mined: the lighter
partition's first miner keeps only the rewards of the common prefix and the
second, which mined only on the lost branch, has none. The lost branch
leaves the canonical chain exactly at the end of the common prefix.

### Split and heal with uneven hashrate

The hashrate is modelled by the number of blocks each partition finds per
round (three to one), so the result does not depend on the machine's speed.
When the network heals the minority node drops its 10-block branch for the
majority's chain and the majority's heads do not move. The minority's
prefix rewards survive, its split-time rewards are gone, and the blocks it
mines after the heal extend the majority's chain and reach both majority
nodes.

### Header flood

Each flood comes from a minimal in-process eth/68 peer that completes the
status handshake with a total difficulty of one and then writes the same
messages as fast as the connection takes them, until the node drops it.
The bounds are constants in the test:

| Bound | Value |
|---|---|
| Drop, from the first flood message | within 10 s |
| Go heap growth during the flood (peak) | at most 256 MiB |
| Go heap left after the flood (after a collection) | at most 32 MiB |
| Every `eth_blockNumber` call during and 250 ms after the flood | within 1 s |

`eth_blockNumber` is served by the node's own RPC API over its chain, called
every 10 ms in process. The node must also keep its head and its honest
peer, and afterwards sync a new block from that peer.

| Flood | Messages written before the drop | Time to drop | Peak heap growth | Heap left | Slowest `eth_blockNumber` |
|---|---|---|---|---|---|
| Unsolicited `BlockHeaders` responses of 1,024 low-work headers (difficulty 1) | 3 | 2.5 ms | 0.1 MiB | 1.0 MiB | 0.2 ms |
| `NewBlock` on the head with difficulty 1 instead of 16 | 52 | 0.3 ms | 0.0 MiB | 0.0 MiB | 0.1 ms |
| `NewBlock` on the head with every field right but a nonce that fails RandomX | 4,179 | 28 ms | 5.8 MiB | 0.0 MiB | 0.1 ms |

The node drops an unsolicited response at once, as no request matches it.
A block below the required difficulty fails the header check before any
RandomX hash. A block with a bad seal costs one RandomX hash in the block
fetcher before the peer is dropped; the messages counted are those the
connection buffered and the node discarded meanwhile. The fetcher queues at
most 64 blocks a peer, which bounds the heap.

### Full-seal sync

The fresh node's engine records every header whose RandomX seal it checked
and accepted; the test requires a record for each of the 160 canonical
blocks, so a sync that skipped or sampled seal checks would fail. The same
engine refuses the head with other nonces as an invalid proof of work while
accepting them without the seal check, so the check is a real one. Mining
costs more than verifying because a seal takes about 16 RandomX hashes and
a check one; both rebuild a 256 MiB cache at every new key.

## Findings

None of the four tests found a bug in consensus, fork choice, sync or peer
handling.
