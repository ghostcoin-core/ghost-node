#!/bin/sh
# The faucet's signer: the Ghost node's own geth, run apart from the node with
# no peers, no HTTP and no chain of its own, answering only on its IPC socket
# (mode 0600 in this user's directory). It holds the mining account unlocked so
# the faucet can sign test GHOST transfers without unlocking the public node.
set -eu
node_dir="$HOME/.ghost-node"
here="$HOME/.ghost-faucet/signer"
umask 077
mkdir -p "$here"
etherbase=$(sed -n 's/^Etherbase = "\(0x[0-9a-fA-F]\{40\}\)"$/\1/p' "$node_dir/config.toml")
[ -n "$etherbase" ] || { echo "ghost-faucet-signer: no Etherbase in $node_dir/config.toml" >&2; exit 1; }
exec "$node_dir/bin/geth" \
  --config "$HOME/.ghost-faucet/signer.toml" \
  --datadir "$here/data" \
  --keystore "$node_dir/data/keystore" \
  --ipcpath "$here/signer.ipc" \
  --nodiscover --maxpeers 0 --authrpc.port 0 --nat none \
  --verbosity 2 \
  --unlock "$etherbase" --password "$node_dir/password"
