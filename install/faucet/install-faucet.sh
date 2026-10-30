#!/bin/sh
# Installs the Ghost public test network faucet beside this computer's Ghost
# node, from a checkout:
#
#   sh install/faucet/install-faucet.sh   # env: FAUCET_PORT (8548)
#
# It copies the faucet's code and config into ~/.ghost-faucet, writes its two
# systemd user units (ghost-faucet-signer.service and ghost-faucet.service),
# starts them, and publishes the faucet at https://<this computer's Tailscale
# name>/ghost-faucet with Tailscale Funnel. It needs the test network node the
# one-line installer sets up in ~/.ghost-node, and refuses without it. It never
# creates, copies, moves or prints a key, keystore or password file: the signer
# reads the node's own by path when it starts. Running it again is safe.
set -eu

say() {
	echo "ghost-faucet: $*"
}

die() {
	echo "ghost-faucet: $*" >&2
	exit 1
}

case "$0" in
*/*) src=${0%/*} ;;
*) src=. ;;
esac
node_dir="$HOME/.ghost-node"
faucet_dir="$HOME/.ghost-faucet"
unit_dir="$HOME/.config/systemd/user"
port=${FAUCET_PORT:-8548}

case "$port" in
'' | *[!0-9]*) die "FAUCET_PORT must be a port number, not '$port'; refusing to install. Nothing was installed." ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] ||
	die "FAUCET_PORT must be a port number from 1 to 65535, not $port; refusing to install. Nothing was installed."
for file in faucet.js signer.sh signer.toml ghost-faucet.service ghost-faucet-signer.service; do
	[ -f "$src/$file" ] || die "$src/$file is missing; run this script from a checkout of the Ghost node. Nothing was installed."
done
[ -f "$node_dir/config.toml" ] ||
	die "no Ghost node here: $node_dir/config.toml is missing. The faucet needs a running test network node; install the node first, then run this again. Nothing was installed."
[ -x "$node_dir/bin/geth" ] ||
	die "no Ghost node here: $node_dir/bin/geth is missing. The faucet needs a running test network node; install the node first, then run this again. Nothing was installed."
node=$(command -v node) ||
	die "Node.js (node) is not installed; the faucet runs on it. Install it, then run this again. Nothing was installed."
case "$node" in
/*) ;;
*) die "node must be a program on the PATH, not '$node'. Nothing was installed." ;;
esac
command -v systemctl >/dev/null 2>&1 ||
	die "systemctl is not here; the faucet runs as systemd user services. Nothing was installed."
command -v sudo >/dev/null 2>&1 ||
	die "sudo is not here; publishing the faucet with Tailscale Funnel needs it. Nothing was installed."
command -v tailscale >/dev/null 2>&1 ||
	die "Tailscale is not installed; the faucet is published with Tailscale Funnel. Nothing was installed."

# Each file is written beside its place and moved there, so a faucet that is
# running never reads a half-written one.
put() {
	mode=$1
	from=$2
	to=$3
	cp "$from" "$to.new"
	chmod "$mode" "$to.new"
	mv -f "$to.new" "$to"
}

mkdir -p "$faucet_dir" "$unit_dir"
chmod 700 "$faucet_dir"
put 644 "$src/faucet.js" "$faucet_dir/faucet.js"
put 755 "$src/signer.sh" "$faucet_dir/signer.sh"
put 644 "$src/signer.toml" "$faucet_dir/signer.toml"
say "copied the faucet into $faucet_dir"

put 644 "$src/ghost-faucet-signer.service" "$unit_dir/ghost-faucet-signer.service"
sed -e "s|^ExecStart=/usr/bin/node |ExecStart=$node |" \
	-e "s|^Environment=FAUCET_PORT=.*|Environment=FAUCET_PORT=$port|" \
	"$src/ghost-faucet.service" >"$unit_dir/ghost-faucet.service.new"
chmod 644 "$unit_dir/ghost-faucet.service.new"
mv -f "$unit_dir/ghost-faucet.service.new" "$unit_dir/ghost-faucet.service"
say "wrote ghost-faucet-signer.service and ghost-faucet.service in $unit_dir"

systemctl --user daemon-reload || die "'systemctl --user daemon-reload' failed. Running this again is safe."
for unit in ghost-faucet-signer.service ghost-faucet.service; do
	systemctl --user enable --now "$unit" || die "'systemctl --user enable --now $unit' failed. Running this again is safe."
done
# On a re-run the units are running already: restart them on the files just
# copied.
for unit in ghost-faucet-signer.service ghost-faucet.service; do
	systemctl --user restart "$unit" || die "'systemctl --user restart $unit' failed. Running this again is safe."
done
say "started ghost-faucet-signer.service and ghost-faucet.service"

sudo tailscale funnel --bg --set-path /ghost-faucet "http://127.0.0.1:$port" ||
	die "'sudo tailscale funnel --bg --set-path /ghost-faucet http://127.0.0.1:$port' failed; is Tailscale logged in with Funnel allowed? Running this again is safe."
say "the faucet is published at https://<this computer's Tailscale name>/ghost-faucet"
