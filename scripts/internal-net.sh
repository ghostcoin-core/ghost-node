#!/usr/bin/env bash
#
# Runs the internal test network: two geth processes on this machine, one
# mining with RandomX, the other syncing from it.
#
#   scripts/internal-net.sh [blocks]
#
# With a number, it mines until both nodes are at least that many blocks high;
# without one, until interrupted (Ctrl-C). It then stops mining, waits for the
# nodes to agree, prints both heads and exits 0 when they are equal.
#
# GETH selects the geth binary (default build/bin/geth). Everything else, the
# ports, data directories, peering, the miner account and mining, is chosen
# here, in a temporary directory removed on exit.
#
# The miner account's key is a fixed test key, the number 6777971, never a
# launch key. The internal network is a test network only; see
# docs/internal-network.md.

set -euo pipefail

blocks="${1:-0}"
GETH="${GETH:-build/bin/geth}"

die() {
	echo "internal-net: $*" >&2
	exit 1
}

case "$blocks" in
'' | *[!0-9]*) die "usage: $0 [blocks]" ;;
esac
blocks=$((10#$blocks))
[ -x "$GETH" ] || die "$GETH is not an executable geth; build one with 'make geth' or set GETH"

networkid=6777971
dir="$(mktemp -d "${TMPDIR:-/tmp}/ghost-internal-net.XXXXXX")"
pids=()

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ "$status" -ne 0 ]; then
		for n in 1 2; do
			if [ -f "$dir/node$n.log" ]; then
				echo "--- last lines of node $n's log ---" >&2
				tail -n 20 "$dir/node$n.log" >&2 || true
			fi
		done
	fi
	for pid in "${pids[@]+"${pids[@]}"}"; do
		kill "$pid" 2>/dev/null || true
	done
	for pid in "${pids[@]+"${pids[@]}"}"; do
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$dir"
	exit "$status"
}
trap cleanup EXIT

# The genesis of the internal network, params/ghost InternalNetGenesis(). A
# test in cmd/geth keeps the two equal.
cat >"$dir/genesis.json" <<'GENESIS'
{
  "config": {
    "networkId": 6777971,
    "chainId": 6777971,
    "eip2FBlock": 0,
    "eip7FBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip160Block": 0,
    "eip161FBlock": 0,
    "eip170FBlock": 0,
    "eip100FBlock": 0,
    "eip140FBlock": 0,
    "eip198FBlock": 0,
    "eip211FBlock": 0,
    "eip212FBlock": 0,
    "eip213FBlock": 0,
    "eip214FBlock": 0,
    "eip658FBlock": 0,
    "eip145FBlock": 0,
    "eip1014FBlock": 0,
    "eip1052FBlock": 0,
    "eip1283FBlock": 0,
    "petersburgBlock": 0,
    "eip152FBlock": 0,
    "eip1108FBlock": 0,
    "eip1344FBlock": 0,
    "eip1884FBlock": 0,
    "eip2028FBlock": 0,
    "eip2200FBlock": 0,
    "eip2565FBlock": 0,
    "eip2718FBlock": 0,
    "eip2929FBlock": 0,
    "eip2930FBlock": 0,
    "eip1559FBlock": 0,
    "eip3198FBlock": 0,
    "eip3529FBlock": 0,
    "eip3541FBlock": 0,
    "eip3651FBlock": 0,
    "eip3855FBlock": 0,
    "eip3860FBlock": 0,
    "eip6049FBlock": 0,
    "eip1153FBlock": 0,
    "eip5656FBlock": 0,
    "eip6780FBlock": 0,
    "disposalBlock": 0,
    "ethash": {}
  },
  "timestamp": "0x6abda280",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x1",
  "baseFeePerGas": "0x3b9aca00",
  "alloc": {}
}
GENESIS

# The miner's fixed test key, and the password of its keystore file.
printf '%064x\n' 6777971 >"$dir/miner.key"
echo "internal-net-test-only" >"$dir/password"

for n in 1 2; do
	"$GETH" --datadir "$dir/node$n" init "$dir/genesis.json" >"$dir/node$n.log" 2>&1 ||
		die "geth init failed for node $n"
done
imported="$("$GETH" --datadir "$dir/node1" --lightkdf account import --password "$dir/password" "$dir/miner.key" 2>>"$dir/node1.log")" ||
	die "importing the miner key failed"
miner="0x$(printf '%s\n' "$imported" | sed -n 's/^Address: {\([0-9a-fA-F]*\)}$/\1/p')"
[ "${#miner}" -eq 42 ] || die "could not read the miner address from: $imported"

ipc() { echo "$dir/node$1/geth.ipc"; }

# attach runs a console expression on node $1.
attach() {
	"$GETH" attach --exec "$2" "$(ipc "$1")" 2>/dev/null
}

alive() {
	for pid in "${pids[@]}"; do
		kill -0 "$pid" 2>/dev/null || die "a geth process has stopped"
	done
}

# Job control gives each node its own process group, so Ctrl-C reaches only
# this script, which then stops the network in order.
set -m
common=(--networkid "$networkid" --syncmode full --port 0 --authrpc.port 0 --nat none --nodiscover --verbosity 3)
"$GETH" --datadir "$dir/node1" "${common[@]}" \
	--mine --miner.threads 1 --miner.etherbase "$miner" \
	--unlock "$miner" --password "$dir/password" >>"$dir/node1.log" 2>&1 &
pids+=("$!")
"$GETH" --datadir "$dir/node2" "${common[@]}" >>"$dir/node2.log" 2>&1 &
pids+=("$!")
set +m

for n in 1 2; do
	for _ in $(seq 1 120); do
		[ -S "$(ipc "$n")" ] && attach "$n" 'eth.blockNumber' >/dev/null && break
		alive
		sleep 0.5
	done
	attach "$n" 'eth.blockNumber' >/dev/null || die "node $n did not open its IPC endpoint"
done

enode="$(attach 1 'admin.nodeInfo.enode' | tr -d '"')"
[ "$(attach 2 "admin.addPeer('$enode')")" = "true" ] || die "node 2 could not add node 1 as a peer"

echo "internal-net: data in $dir"
echo "internal-net: node 1 mines to $miner; attach with: $GETH attach $(ipc 1)"
if [ "$blocks" -gt 0 ]; then
	echo "internal-net: mining until both nodes reach block $blocks"
else
	echo "internal-net: mining until interrupted (Ctrl-C)"
fi

interrupted=0
trap 'interrupted=1' INT TERM
while [ "$interrupted" -eq 0 ]; do
	alive
	h1="$(attach 1 'eth.blockNumber' || echo 0)"
	h2="$(attach 2 'eth.blockNumber' || echo 0)"
	echo "internal-net: node 1 at block $h1, node 2 at block $h2"
	if [ "$blocks" -gt 0 ] && [ "$h1" -ge "$blocks" ] && [ "$h2" -ge "$blocks" ]; then
		break
	fi
	sleep 1 || true
done
trap - INT TERM

attach 1 'miner.stop()' >/dev/null || die "could not stop mining on node 1"

# head_of prints "number hash" of node $1's head block.
head_of() {
	attach "$1" 'var b = eth.getBlock("latest"); b.number + " " + b.hash' | tr -d '"'
}

# Once mining has stopped node 1's head stays put; wait for node 2 to reach it.
previous="" head1="" head2=""
for _ in $(seq 1 120); do
	alive
	head1="$(head_of 1 || true)"
	head2="$(head_of 2 || true)"
	if [ -n "$head1" ] && [ "$head1" = "$previous" ] && [ "$head1" = "$head2" ]; then
		break
	fi
	previous="$head1"
	sleep 1
done

echo "node 1 head: $head1"
echo "node 2 head: $head2"
if [ -z "$head1" ] || [ "$head1" != "$head2" ]; then
	die "the heads differ"
fi
echo "internal-net: both nodes agree"
