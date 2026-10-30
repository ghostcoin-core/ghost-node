# The Ghost public test network faucet

The faucet gives test GHOST on the public test network (chain 6777972) to
anyone who asks: `POST {"address": "0x…"}` and the node's mining account sends
10 test GHOST there, at most once a minute per address and 30 times a minute in
all. It answers once the transfer is in a block. The Ghost Wallet's "Get test
GHOST" button calls it at `https://<host>/ghost-faucet`.

It runs beside a Ghost test network node, as two systemd user services:

- `ghost-faucet.service` runs `faucet.js` with Node.js, on 127.0.0.1 only
  (port 8548, or `FAUCET_PORT`). It checks that the node and the signer are on
  the public test network at start and before every transfer, and refuses to
  send on any other chain.
- `ghost-faucet-signer.service` runs `signer.sh`: the node's own geth, apart
  from the node, with no peers, no HTTP and no chain (`signer.toml`), answering
  only on its IPC socket. It signs the faucet's transfers, so the public node
  keeps no unlocked account. It reads the node's keystore and password by path
  when it starts; nothing here copies them.

Tailscale Funnel publishes the faucet at the path `/ghost-faucet`.

## Install

On a Linux computer that runs a Ghost test network node (installed in
`~/.ghost-node` by the one-line installer), with Node.js and Tailscale logged
in with Funnel allowed, from a checkout of this repository:

```sh
sh install/faucet/install-faucet.sh
```

It copies the faucet into `~/.ghost-faucet`, writes the two units into
`~/.config/systemd/user`, enables and starts them, and runs
`sudo tailscale funnel --bg --set-path /ghost-faucet http://127.0.0.1:8548`.
Set `FAUCET_PORT` to run the faucet on another port. It refuses, installing
nothing, when the node's `config.toml` or `bin/geth` is missing. Running it
again is safe, and is how a faucet is updated: it copies the files again and
restarts both services.

For the services to keep running after logout and start at boot, the user
needs lingering on: `sudo loginctl enable-linger "$USER"` (the node's own
installer turns it on for a public node).

## Tests

```sh
node --test install/faucet/
```

`go test ./install/ -run TestFaucet` runs these and tests the install script.
