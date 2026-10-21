# The devp2p command

The devp2p command line tool is a utility for low-level peer-to-peer debugging and
protocol development purposes. It can do many things.

### ENR Decoding

Use `devp2p enrdump <base64>` to verify and display an Ethereum Node Record.

### Node Key Management

The `devp2p key ...` command family deals with node key files.

Run `devp2p key generate mynode.key` to create a new node key in the `mynode.key` file.

Run `devp2p key to-enode mynode.key -ip 127.0.0.1 -tcp 30303` to create an enode:// URL
corresponding to the given node key and address information.

### Node Set Utilities

There are several commands for working with JSON node set files.

Run `devp2p nodeset info <nodes.json>` to display statistics of a node set.

Run `devp2p nodeset filter <nodes.json> <filter flags...>` to write a new, filtered node
set to standard output. The following filters are supported:

- `-limit <N>` limits the output set to N entries, taking the top N nodes by score
- `-ip <CIDR>` filters nodes by IP subnet
- `-min-age <duration>` filters nodes by 'first seen' time
- `-les-server` filters nodes by LES server support
- `-snap` filters nodes by snap protocol support

For example, given a node set in `nodes.json`, you could create a filtered set containing
up to 20 eth mainnet nodes which also support snap sync using this command:

    devp2p nodeset filter nodes.json -snap -limit 20
