#!/bin/sh
#
# Installs a Ghost node for the current user and starts it mining. It asks
# nothing: paste the one line from the README,
#
#	curl -fsSL https://get.ghostcoin.com | sh
#
# and when it finishes the node is installed, on the network, syncing and
# mining, and it prints the mining address and how to check on the node.
#
# The script downloads the release archive for this computer and its
# signature, and verifies the signature against the release key pinned below
# before it unpacks or runs anything. The check is done by ghost-verify, a
# small static program (install/verify) downloaded from the same release and
# run only when its SHA-256 matches the one pinned below for this computer. On
# any doubt about a download, a hash, the signature or the archive it stops
# with nothing installed and says why.
#
# It then installs the node in ~/.ghost-node, writes the node's config with a
# newly generated mining address (or GHOST_MINE_TO's, below), and starts the node as a user service with
# mining on, which also starts it at boot: a systemd user unit on Linux, a
# launchd agent on macOS. The node joins the network built into it, the public
# test network; an archive that still holds a genesis.json gets that chain
# initialised first. The config opens the node's HTTP RPC on 127.0.0.1 only,
# for the Ghost web apps.
#
# It also installs ~/.ghost-node/update, which is this script run with
# --update, and runs it daily (a systemd user timer, or a launchd agent with a
# StartInterval) unless GHOST_NO_UPDATE=1 is set at install time. An update
# first downloads the install.sh of the newest release, from newest_url below,
# and its signature, install.sh.sig, and checks that signature against the
# release key with this script's own pinned ghost-verify. Only then does it
# run that install.sh with --update, which passes the same checks as an
# install with the newest release's own pins, replaces the geth executable
# atomically, keeps the previous one until the node has restarted, and keeps
# the config and the mining address. A refused update changes nothing and
# leaves the running node alone. Run again, the installer installs its release
# again and keeps the config and the mining address.
#
# This copy in the repository downloads from the latest release. The copy a
# release publishes is pinned to its own release: install/pin-verifier-hashes.sh
# writes in that release's ghost-verify hashes and replaces release_url's
# latest/download URL with the release's own download URL, so the script never
# fetches a ghost-verify it does not pin. newest_url stays latest/download:
# it is only where an update finds the newest release's signed install.sh.
#
# It needs only sh, curl, tar, gzip, uname, sha256sum or shasum and the usual
# POSIX tools that stock macOS and Linux have; no OpenSSL of any version.
#
# The release archive is ghost-node-<os>-<arch>.tar.gz, with os linux or darwin
# and arch amd64 or arm64. It holds the geth executable. The signature,
# <archive>.sig, is the raw 64-byte ed25519 signature of the archive's bytes.
# The checker is ghost-verify-<os>-<arch>, next to the archive.
#
# GHOST_RELEASE_URL sets where the release is downloaded from, over https
# only, and GHOST_INSTALL_CA_FILE names a certificate file to trust for that
# server; GHOST_LATEST_URL, over https only and trusted the same way, sets
# where an update looks for the newest release's install.sh; GHOST_HTTP_PORT
# moves the node's HTTP RPC off 8545. The tests use them for a local release
# server. When another program already listens on 127.0.0.1 at that port, the
# installer stops with nothing installed and says so; the installed node
# itself holding it, as on an update, is fine.
#
# GHOST_MINE_TO mines straight to a wallet address of your own, such as the
# Ghost pop-up wallet's, instead of a newly generated mining key:
#
#	curl -fsSL https://get.ghostcoin.com | GHOST_MINE_TO=0x... sh
#
# (on Windows, in PowerShell: $env:GHOST_MINE_TO='0x...'; irm https://get.ghostcoin.com/win | iex)
#
# It must be 0x followed by exactly 40 hex characters; anything else is
# refused with nothing installed. The config's Etherbase is then that address,
# and no mining key or password file is made. Set on a re-run or an update, it
# rewrites Etherbase to the address it names and restarts the node; unset, the
# config keeps the Etherbase it has.
#
# The node mines with --miner.threads, on half this computer's logical cores,
# rounded down and at least 1, so the computer stays cool and quiet.
# GHOST_MINE_THREADS chooses the number of cores instead:
#
#	curl -fsSL https://get.ghostcoin.com | GHOST_MINE_THREADS=2 sh
#
# (on Windows, in PowerShell: $env:GHOST_MINE_THREADS='2'; irm https://get.ghostcoin.com/win | iex)
#
# It must be a whole number from 1 to 9999; anything else is refused with
# nothing installed. The number is kept in ~/.ghost-node/miner-threads, and a
# re-run or an update keeps it unless GHOST_MINE_THREADS is set again; a node
# installed before the installer knew of it gets the default on its next
# update. Its closing lines say how many cores the node mines on.
#
# The release archive also holds ghost-dash, the Ghost Node Dashboard: a
# small program that shows the node, its mining and its rewards in the
# browser, on 127.0.0.1 only. The installer installs it as
# ~/.ghost-node/bin/ghost-dash and runs it as a service of its own, which also
# starts at boot: the systemd user unit ghost-dashboard.service on Linux, the
# launchd agent com.ghostcoin.dashboard on macOS. It serves on port 8580;
# GHOST_DASH_PORT chooses another, and a re-run or an update keeps the port it
# was installed with unless GHOST_DASH_PORT is set again. When another program
# already listens on 127.0.0.1 at that port, the installer stops with nothing
# installed and says so; the installed dashboard holding it is fine. The
# dashboard signs a browser in with the key in ~/.ghost-node/dashboard-key, 32
# random bytes in hex, made on the first install and kept by re-runs and
# updates. Its link is
#
#	http://127.0.0.1:8580/open?key=<the key>
#
# which the closing lines print. On a first install they also open it in the
# browser: with open on macOS, and on Linux with xdg-open when there is a
# desktop session (DISPLAY or WAYLAND_DISPLAY); re-runs and updates only
# print it. ~/.ghost-node/dashboard, a small script that runs ghost-dash open,
# opens it again any time. An update replaces ghost-dash with the copy in the
# newest release's archive, so the release signature covers it too, and
# restarts its service. GHOST_NO_DASHBOARD=1 leaves the dashboard out; set on a
# re-run, it takes out one installed before and keeps its key.
#
# When ~/.ghost-node/mining-paused exists, which the dashboard's pause control
# writes, the node's service starts it without --mine, so the node syncs but
# does not mine, and a pause holds across re-runs, updates and the restarts
# they make. An update finds when the file came or went and rewrites and
# restarts the node's service to match.
#
# The whole installer is the text of installer_source, which the last lines
# run. So a download cut short runs nothing, and the installer can write
# itself out as the update script.

installer_source() {
	cat <<'GHOST_INSTALLER'
# The release key: the public half of the key that signs every release. The
# same key is the .pub file next to this script; a test keeps the two equal.
release_key() {
	cat <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA/5nNW/CysxPVl+S5p5VJxi2ywNlEl3HQ1/BzHSAQZ3A=
-----END PUBLIC KEY-----
KEY
}

# The SHA-256 of the release's ghost-verify-<os>-<arch> files. The release
# fills them in, and pins release_url below to itself; until then they are all
# zeros, the placeholder, and the installer refuses to install rather than run
# an unpinned checker.
verifier_hashes() {
	cat <<'HASHES'
linux-amd64 0000000000000000000000000000000000000000000000000000000000000000
linux-arm64 0000000000000000000000000000000000000000000000000000000000000000
darwin-amd64 0000000000000000000000000000000000000000000000000000000000000000
darwin-arm64 0000000000000000000000000000000000000000000000000000000000000000
HASHES
}

placeholder_hash=0000000000000000000000000000000000000000000000000000000000000000
release_url=${GHOST_RELEASE_URL:-https://github.com/ghostcoin-core/ghost-node/releases/latest/download}
newest_url=${GHOST_LATEST_URL:-https://github.com/ghostcoin-core/ghost-node/releases/latest/download}
ca_file=${GHOST_INSTALL_CA_FILE:-}
http_port=${GHOST_HTTP_PORT:-8545}
service=ghost-node
update_service=ghost-node-update
label=com.ghostcoin.node
update_label=com.ghostcoin.node.update
dash_service=ghost-dashboard
dash_label=com.ghostcoin.dashboard
dash_default_port=8580

say() {
	printf 'ghost-node: %s\n' "$*"
}

die() {
	printf 'ghost-node: %s\n' "$*" >&2
	exit 1
}

# refuse stops before anything is installed or changed, saying why.
refuse() {
	if [ "$mode" = update ]; then
		die "$*; refusing to update. Nothing was changed, and the running node was left alone."
	fi
	die "$*; refusing to install. Nothing was installed."
}

need() {
	for tool in "$@"; do
		command -v "$tool" >/dev/null 2>&1 || die "this installer needs $tool, which is not on the PATH"
	done
}

# platform sets os and arch to this computer's release names.
platform() {
	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "there is no Ghost node release for $(uname -s); releases are for Linux and macOS" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "there is no Ghost node release for $(uname -m) processors; releases are for amd64 and arm64" ;;
	esac
}

# sha256 prints the SHA-256 of the file $1, with sha256sum or, on a Mac,
# shasum.
sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		s_out=$(sha256sum "$1") || return 1
	else
		s_out=$(shasum -a 256 "$1") || return 1
	fi
	s_out=${s_out%% *}
	case "$s_out" in
	*[!0-9a-f]* | '') return 1 ;;
	esac
	[ "${#s_out}" = 64 ] || return 1
	printf '%s\n' "$s_out"
}

# fetch downloads the https URL $1 to the file $2 with curl, which checks the
# server's certificate against the system's (or GHOST_INSTALL_CA_FILE's) and
# its name, and follows redirects to https URLs only.
fetch() {
	case "$1" in
	https://*) ;;
	*) refuse "will not download $1, which is not an https URL" ;;
	esac
	f_url=$1
	set -- -fsSL --proto =https --proto-redir =https --tlsv1.2 --max-redirs 8 \
		--connect-timeout 30 --retry 3 --user-agent ghost-node-installer --output "$2"
	if [ -n "$ca_file" ]; then
		set -- "$@" --cacert "$ca_file"
	fi
	curl "$@" "$f_url" 2>"$work/curl.log" ||
		refuse "could not download $f_url: $(tail -n 2 "$work/curl.log" | tr '\n' ' ')"
}

# get_verifier downloads this computer's ghost-verify and sets verifier to it,
# once its hash is the one pinned above.
get_verifier() {
	v_name="ghost-verify-$os-$arch"
	v_pinned=$(verifier_hashes | sed -n "s/^$os-$arch \([0-9a-f]\{64\}\)\$/\1/p")
	case "$v_pinned" in
	'') refuse "this installer pins no hash for $v_name" ;;
	"$placeholder_hash") refuse "this installer has no hash of $v_name pinned yet, only the placeholder, so it cannot check a release" ;;
	esac
	fetch "$release_url/$v_name" "$work/$v_name"
	v_hash=$(sha256 "$work/$v_name") || refuse "could not compute the SHA-256 of $v_name"
	[ "$v_hash" = "$v_pinned" ] ||
		refuse "the downloaded $v_name has the SHA-256 $v_hash, not the $v_pinned pinned in this installer"
	chmod 700 "$work/$v_name"
	verifier="$work/$v_name"
}

# verify refuses the archive $1 unless $1.sig is the release key's signature
# of its bytes.
verify() {
	release_key >"$work/release.pub"
	[ "$(wc -c <"$1.sig" | tr -d ' ')" = 64 ] ||
		refuse "the signature of $(basename "$1") is not a 64-byte ed25519 signature"
	v_status=0
	"$verifier" "$work/release.pub" "$1" "$1.sig" >"$work/verify.log" 2>&1 </dev/null || v_status=$?
	case "$v_status" in
	0) ;;
	1) refuse "the signature of $(basename "$1") does not match the release key" ;;
	*) refuse "the signature of $(basename "$1") could not be checked: $(tail -n 2 "$work/verify.log" | tr '\n' ' ')" ;;
	esac
}

# run_newest downloads the newest release's install.sh and runs it with
# --update once its signature is the release key's, so that the update moves
# to the newest release and checks it with that release's own pins. The
# newest install.sh, told by GHOST_NEWEST_INSTALLER=1 that it is the newest,
# updates from its own release instead of looking further. This script exits
# with its status.
run_newest() {
	newest_url=${newest_url%/}
	case "$newest_url" in
	https://*) ;;
	*) refuse "GHOST_LATEST_URL must be an https URL, not $newest_url" ;;
	esac
	fetch "$newest_url/install.sh" "$work/install.sh"
	fetch "$newest_url/install.sh.sig" "$work/install.sh.sig"
	verify "$work/install.sh"
	say "the newest release's install.sh is signed by the release key"
	n_status=0
	GHOST_NEWEST_INSTALLER=1 sh "$work/install.sh" --update </dev/null || n_status=$?
	exit "$n_status"
}

# unpack unpacks the verified archive $1 into $work/release.
unpack() {
	tar -tzf "$1" >"$work/members" 2>"$work/tar.log" || refuse "the release archive cannot be read"
	while IFS= read -r member; do
		case "$member" in
		/* | ../* | */../* | *..) refuse "the release archive holds an unexpected entry: $member" ;;
		esac
	done <"$work/members"
	mkdir "$work/release"
	tar -xzf "$1" -C "$work/release" 2>"$work/tar.log" || refuse "the release archive cannot be unpacked"
	if [ ! -f "$work/release/geth" ] || [ -L "$work/release/geth" ]; then
		refuse "the release archive holds no geth executable"
	fi
	chmod 700 "$work/release/geth"
	"$work/release/geth" version >/dev/null 2>&1 </dev/null || refuse "the downloaded geth does not run on this computer"
	# A release from before the dashboard has no ghost-dash.
	has_dash=0
	if [ -e "$work/release/ghost-dash" ] || [ -L "$work/release/ghost-dash" ]; then
		if [ ! -f "$work/release/ghost-dash" ] || [ -L "$work/release/ghost-dash" ]; then
			refuse "the release archive's ghost-dash is not a regular file"
		fi
		chmod 700 "$work/release/ghost-dash"
		has_dash=1
	fi
}

# toml_string prints $1 as the inside of a TOML basic string.
toml_string() {
	printf '%s' "$1" | sed 's/[\\"]/\\&/g'
}

# config_address prints the mining address of the config.
config_address() {
	sed -n 's/^Etherbase = "\(0x[0-9a-fA-F]*\)"$/\1/p' "$config" | head -n 1
}

# set_etherbase rewrites the config's Etherbase to GHOST_MINE_TO's address,
# keeping the rest of the config.
set_etherbase() {
	if grep -q '^Etherbase = ' "$config"; then
		sed "s/^Etherbase = .*\$/Etherbase = \"$mine_to\"/" "$config" >"$config.new" ||
			die "could not rewrite the mining address of $config"
	else
		{
			cat "$config"
			printf '\n[Eth.Miner]\nEtherbase = "%s"\n' "$mine_to"
		} >"$config.new" || die "could not rewrite the mining address of $config"
	fi
	mv -f "$config.new" "$config"
	say "the config $config now mines to $mine_to"
}

# configure writes the config with GHOST_MINE_TO's address or a new mining
# address, unless there is one; an existing config gets GHOST_MINE_TO's
# address when it is set.
configure() {
	if [ -f "$config" ]; then
		if [ -n "$mine_to" ]; then
			set_etherbase
		else
			say "keeping the existing config $config"
		fi
		return 0
	fi
	if [ -n "$mine_to" ]; then
		address=$mine_to
		cat >"$config.new" <<EOF
# The Ghost node's config, written by install.sh. The node mines to Etherbase,
# the wallet address GHOST_MINE_TO named, whose key is not on this computer.
# Its HTTP RPC listens on this computer only, for the Ghost web apps.

EOF
	else
		password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
		[ "${#password}" = 64 ] || die "could not make a password for the mining key"
		printf '%s\n' "$password" >"$base/password" || die "could not write the password of the mining key"
		created=$("$geth" --datadir "$data" account new --password "$base/password" 2>"$work/account.log" </dev/null) ||
			die "could not create the mining key: $(tail -n 3 "$work/account.log" | tr '\n' ' ')"
		address=$(printf '%s\n' "$created" | sed -n 's/^Public address of the key: *\(0x[0-9a-fA-F]\{40\}\)$/\1/p')
		[ -n "$address" ] || die "could not read the new mining address from: $created"
		cat >"$config.new" <<EOF
# The Ghost node's config, written by install.sh. The node mines to Etherbase,
# whose key is in the keystore of DataDir, locked with the password in
# $(toml_string "$base/password"). Its HTTP RPC listens on this computer only,
# for the Ghost web apps.

EOF
	fi
	cat >>"$config.new" <<EOF
[Eth.Miner]
Etherbase = "$address"

[Node]
DataDir = "$(toml_string "$data")"
HTTPHost = "127.0.0.1"
HTTPPort = $http_port
HTTPModules = ["eth", "net", "web3"]
HTTPCors = ["https://ghost-webapp-alpha.vercel.app", "https://ghost-wallet-nine.vercel.app"]
EOF
	mv -f "$config.new" "$config"
}

# cpu_count prints the number of this computer's logical cores, or nothing
# when it cannot tell.
cpu_count() {
	c_count=
	if [ "$os" = darwin ]; then
		c_count=$(sysctl -n hw.logicalcpu 2>/dev/null </dev/null) || c_count=
	fi
	[ -n "$c_count" ] || c_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null </dev/null) || c_count=
	[ -n "$c_count" ] || c_count=$(nproc 2>/dev/null </dev/null) || c_count=
	case "$c_count" in
	'' | 0* | *[!0-9]*) return 0 ;;
	esac
	printf '%s\n' "$c_count"
}

# choose_threads sets threads to the number of cores the node mines on:
# GHOST_MINE_THREADS's, else the number the node was installed with, else half
# this computer's logical cores, rounded down and at least 1. It sets
# threads_changed to 1 when that is not the number kept in threads_file.
choose_threads() {
	cores=$(cpu_count)
	t_kept=
	if [ -f "$threads_file" ]; then
		t_kept=$(head -n 1 "$threads_file")
		case "$t_kept" in
		'' | 0* | *[!0-9]* | ?????*) t_kept= ;;
		esac
	fi
	if [ -n "$mine_threads" ]; then
		threads=$mine_threads
	elif [ -n "$t_kept" ]; then
		threads=$t_kept
	elif [ -n "$cores" ]; then
		threads=$((cores / 2))
		[ "$threads" -ge 1 ] || threads=1
	else
		threads=1
	fi
	threads_changed=0
	[ "$threads" = "$t_kept" ] || threads_changed=1
}

# keep_threads writes the number of cores the node mines on to threads_file.
keep_threads() {
	printf '%s\n' "$threads" >"$threads_file.new" || die "could not write $threads_file"
	mv -f "$threads_file.new" "$threads_file"
}

# threads_summary prints how many cores the node mines on.
threads_summary() {
	if [ -n "$cores" ]; then
		printf '%s of the %s logical CPU cores of this computer' "$threads" "$cores"
	elif [ "$threads" = 1 ]; then
		printf '1 CPU core'
	else
		printf '%s CPU cores' "$threads"
	fi
}

# port_busy succeeds when a program listens on 127.0.0.1:$1. It asks nc, then
# lsof, then makes a connection with curl, which fails with status 7 only when
# nothing listens.
port_busy() {
	if command -v nc >/dev/null 2>&1 && nc -z -w 2 127.0.0.1 "$1" >/dev/null 2>&1; then
		return 0
	fi
	if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then
		return 0
	fi
	p_status=0
	curl -s -o /dev/null --noproxy '*' --connect-timeout 2 --max-time 3 "http://127.0.0.1:$1/" >/dev/null 2>&1 </dev/null ||
		p_status=$?
	[ "$p_status" != 7 ]
}

# own_node_on_port succeeds when the program on 127.0.0.1:$1 is the installed
# node: its HTTP RPC answers eth_coinbase with the Etherbase of the config it
# was started with.
own_node_on_port() {
	[ -f "$config" ] || return 1
	o_want=$(config_address | tr 'A-F' 'a-f')
	[ -n "$o_want" ] || return 1
	o_out=$(curl -s --noproxy '*' --connect-timeout 2 --max-time 5 -H 'Content-Type: application/json' \
		--data '{"jsonrpc":"2.0","id":1,"method":"eth_coinbase","params":[]}' "http://127.0.0.1:$1/" 2>/dev/null </dev/null) ||
		return 1
	o_got=$(printf '%s\n' "$o_out" | sed -n 's/.*"result" *: *"\(0x[0-9a-fA-F]\{40\}\)".*/\1/p' | head -n 1 | tr 'A-F' 'a-f')
	[ -n "$o_got" ] && [ "$o_got" = "$o_want" ]
}

# check_port refuses when another program holds the node's HTTP RPC port: the
# port of the existing config, or GHOST_HTTP_PORT's on a fresh install. The
# installed node itself may hold it, as it does when it runs during an update
# or a re-run.
check_port() {
	c_port=$http_port
	if [ -f "$config" ]; then
		c_conf=$(sed -n 's/^HTTPPort = \([0-9][0-9]*\)$/\1/p' "$config" | head -n 1)
		[ -z "$c_conf" ] || c_port=$c_conf
	fi
	port_busy "$c_port" || return 0
	own_node_on_port "$c_port" && return 0
	refuse "port $c_port on this computer is already in use by another program; stop it, or install with GHOST_HTTP_PORT=<free port>"
}

# dash_key_value prints the dashboard key, or nothing when there is none.
dash_key_value() {
	[ -f "$dash_key" ] || return 0
	tr -d ' \t\r\n' <"$dash_key"
}

# own_dash_on_port succeeds when the program on 127.0.0.1:$1 is the installed
# dashboard: its sign-in link with the dashboard's key answers 303 and sets the
# dashboard's session cookie, which only a server holding the key does.
own_dash_on_port() {
	d_key=$(dash_key_value)
	case "$d_key" in
	'' | *[!0-9a-f]*) return 1 ;;
	esac
	d_head=$(curl -s -o /dev/null -D - --noproxy '*' --connect-timeout 2 --max-time 5 \
		"http://127.0.0.1:$1/open?key=$d_key" 2>/dev/null </dev/null) || return 1
	printf '%s\n' "$d_head" | head -n 1 | grep -q ' 303' || return 1
	printf '%s\n' "$d_head" | grep -qi '^set-cookie: *ghost_dash='
}

# check_dash_port refuses, on an install or a re-run that installs the
# dashboard, when its port is the node's HTTP RPC port or another program
# holds it. The installed dashboard may hold it. check_port sets c_port.
check_dash_port() {
	[ "$mode" = install ] && [ "$with_dash" = 1 ] || return 0
	[ "$dash_port" != "$c_port" ] ||
		refuse "the dashboard's port $dash_port is the node's HTTP RPC port; install with GHOST_DASH_PORT=<another free port>"
	port_busy "$dash_port" || return 0
	own_dash_on_port "$dash_port" && return 0
	refuse "port $dash_port on this computer is already in use by another program; stop it, or install with GHOST_DASH_PORT=<free port>"
}

# initialise writes the genesis of the release's network into a new data
# directory. A release with the network built in has no genesis.json.
initialise() {
	if [ -f "$work/release/genesis.json" ] && [ ! -d "$data/geth/chaindata" ]; then
		"$geth" --datadir "$data" init "$work/release/genesis.json" >"$work/init.log" 2>&1 </dev/null ||
			die "could not initialise the chain: $(tail -n 3 "$work/init.log" | tr '\n' ' ')"
	fi
}

# write_updater writes the update script: this installer, run with --update.
write_updater() {
	{
		printf '#!/bin/sh\n'
		printf '#\n# Updates the Ghost node in this directory to the latest signed release.\n'
		printf '# install.sh wrote this file: it is the installer run with --update. It\n'
		printf '# runs the newest release'\''s install.sh once its signature checks out, and\n'
		printf '# that checks the release exactly as the installer does.\n\n'
		printf 'installer_source() {\n\tcat <<'\''GHOST_INSTALLER'\''\n'
		installer_source
		printf 'GHOST_INSTALLER\n}\n\neval "$(installer_source)"\nmain --update "$@" </dev/null\n'
	} >"$base/update.new" || die "could not write $base/update"
	chmod 700 "$base/update.new"
	mv -f "$base/update.new" "$base/update"
}

# unit_word prints $1 as one double-quoted word of a systemd unit line.
unit_word() {
	printf '"%s"' "$(printf '%s' "$1" | sed -e 's/[\\"]/\\&/g' -e 's/%/%%/g')"
}

# xml_text prints $1 escaped for an XML text node.
xml_text() {
	printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# systemd_user succeeds when this user has a systemd user session.
systemd_user() {
	command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1
}

# stop_background stops a node this script started without a service.
stop_background() {
	stop_pidfile "$base/node.pid" "$geth"
}

# stop_pidfile stops the process whose ID the file $1 holds, when it runs the
# program $2, and removes the file.
stop_pidfile() {
	[ -f "$1" ] || return 0
	pid=$(cat "$1")
	rm -f "$1"
	case "$pid" in
	'' | *[!0-9]*) return 0 ;;
	esac
	case "$(ps -p "$pid" -o args= 2>/dev/null)" in
	*"$2"*) ;;
	*) return 0 ;;
	esac
	kill "$pid" 2>/dev/null || return 0
	tries=0
	while kill -0 "$pid" 2>/dev/null && [ "$tries" -lt 60 ]; do
		sleep 1
		tries=$((tries + 1))
	done
}

start_background() {
	set -- --config "$config"
	[ -e "$paused" ] || set -- "$@" --mine
	nohup "$geth" "$@" --miner.threads "$threads" >>"$base/node.log" 2>&1 </dev/null &
	echo "$!" >"$base/node.pid"
}

# mine_flag prints the node's --mine argument, with a space before it, or
# nothing while mining is paused.
mine_flag() {
	[ -e "$paused" ] || printf ' --mine'
}

# service_mining_changed succeeds when the node's service mines and mining is
# paused, or the other way round.
service_mining_changed() {
	case "$os" in
	linux)
		m_file="$unit_dir/$service.service"
		m_pat=' --mine '
		;;
	darwin)
		m_file="$agents/$label.plist"
		m_pat='<string>--mine</string>'
		;;
	esac
	[ -f "$m_file" ] || return 1
	m_want=1
	[ ! -e "$paused" ] || m_want=0
	m_have=0
	! grep -qF -- "$m_pat" "$m_file" || m_have=1
	[ "$m_have" != "$m_want" ]
}

# node_unit prints the node's systemd user unit.
node_unit() {
	cat <<EOF
[Unit]
Description=Ghost node
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=$(unit_word "$geth") --config $(unit_word "$config")$(mine_flag) --miner.threads $threads
Restart=on-failure
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
EOF
}

start_linux() {
	if systemd_user; then
		mkdir -p "$unit_dir"
		node_unit >"$unit_dir/$service.service"
		if [ "$auto_update" = 1 ]; then
			cat >"$unit_dir/$update_service.service" <<EOF
[Unit]
Description=Ghost node update to the latest signed release

[Service]
Type=oneshot
ExecStart=$(unit_word "$base/update")
Nice=10
EOF
			cat >"$unit_dir/$update_service.timer" <<EOF
[Unit]
Description=Daily Ghost node update

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
		elif [ -f "$unit_dir/$update_service.timer" ]; then
			systemctl --user disable --now "$update_service.timer" >/dev/null 2>&1 || :
			rm -f "$unit_dir/$update_service.timer" "$unit_dir/$update_service.service"
		fi
		stop_background
		systemctl --user daemon-reload || die "systemctl --user daemon-reload failed"
		systemctl --user enable "$service.service" >/dev/null 2>&1 || die "could not enable the $service user service"
		systemctl --user restart "$service.service" || die "could not start the $service user service"
		if [ "$auto_update" = 1 ]; then
			systemctl --user enable --now "$update_service.timer" >/dev/null 2>&1 ||
				die "could not enable the $update_service timer"
			update_hint="daily, by the $update_service.timer user timer"
		fi
		# Lingering keeps the node running after logout and starts it at boot.
		if command -v loginctl >/dev/null 2>&1; then
			loginctl enable-linger --no-ask-password >/dev/null 2>&1 ||
				say "note: the node stops when you log out; 'loginctl enable-linger' keeps it running"
		fi
		status_hint="systemctl --user status $service"
		log_hint="journalctl --user -u $service"
		stop_hint="systemctl --user stop $service"
	else
		say "systemd user services are not available here, so the node runs in the background without one; it does not start again after a reboot until this installer runs again"
		stop_background
		start_background
		if [ "$auto_update" = 1 ]; then
			say "without systemd user services updates are not scheduled; run $base/update to update"
		fi
		status_hint="ps -p \$(cat $base/node.pid)"
		log_hint="tail -f $base/node.log"
		stop_hint="kill \$(cat $base/node.pid)"
	fi
}

# plist_head prints the start of a launchd agent's plist, up to its program
# arguments.
plist_head() {
	cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$1</string>
	<key>ProgramArguments</key>
	<array>
EOF
}

# reload_agent (re)loads the launchd agent $1 from the plist $2, and fails
# when launchd does not load it. It enables the agent first: launchd refuses to
# bootstrap a disabled one, and stopping the node with launchctl disable leaves
# it disabled.
reload_agent() {
	launchctl bootout "$domain/$1" >/dev/null 2>&1 || :
	launchctl enable "$domain/$1" >/dev/null 2>&1 || :
	# bootout returns before the old agent is gone; bootstrap until it loads.
	tries=0
	until launchctl bootstrap "$domain" "$2" 2>"$work/launchctl.log"; do
		tries=$((tries + 1))
		[ "$tries" -lt 10 ] || return 1
		sleep 1
	done
}

# load_agent (re)loads the launchd agent $1 from the plist $2, or stops saying
# why launchd did not load it.
load_agent() {
	reload_agent "$1" "$2" && return 0
	l_disabled=$(launchctl print-disabled "$domain" 2>/dev/null | grep -F "\"$1\"" | sed 's/^[[:space:]]*//' | tr '\n' ' ')
	die "could not start the launchd agent $1: $(cat "$work/launchctl.log").${l_disabled:+ launchd lists it as: ${l_disabled% }.} Run 'launchctl enable $domain/$1', then run this installer again."
}

# node_plist prints the node's launchd agent.
node_plist() {
	plist_head "$label"
	cat <<EOF
		<string>$(xml_text "$geth")</string>
		<string>--config</string>
		<string>$(xml_text "$config")</string>
EOF
	[ -e "$paused" ] || printf '\t\t<string>--mine</string>\n'
	cat <<EOF
		<string>--miner.threads</string>
		<string>$threads</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>$(xml_text "$base/node.log")</string>
	<key>StandardErrorPath</key>
	<string>$(xml_text "$base/node.log")</string>
</dict>
</plist>
EOF
}

start_darwin() {
	mkdir -p "$agents"
	plist="$agents/$label.plist"
	update_plist="$agents/$update_label.plist"
	node_plist >"$plist"
	load_agent "$label" "$plist"
	if [ "$auto_update" = 1 ]; then
		{
			plist_head "$update_label"
			cat <<EOF
		<string>$(xml_text "$base/update")</string>
	</array>
	<key>StartInterval</key>
	<integer>86400</integer>
	<key>RunAtLoad</key>
	<false/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>$(xml_text "$base/update.log")</string>
	<key>StandardErrorPath</key>
	<string>$(xml_text "$base/update.log")</string>
</dict>
</plist>
EOF
		} >"$update_plist"
		load_agent "$update_label" "$update_plist"
		update_hint="daily, by the launchd agent $update_label"
	elif [ -f "$update_plist" ]; then
		launchctl bootout "$domain/$update_label" >/dev/null 2>&1 || :
		rm -f "$update_plist"
	fi
	status_hint="launchctl print $domain/$label"
	log_hint="tail -f $base/node.log"
	stop_hint="launchctl bootout $domain/$label"
}

# refresh_service rewrites the installed node's systemd unit or launchd agent
# to mine on $threads cores, for restart_node to start it so. A node started
# without a service gets them when start_background starts it again.
refresh_service() {
	case "$os" in
	linux)
		[ -f "$unit_dir/$service.service" ] || return 0
		node_unit >"$unit_dir/$service.service.new" || die "could not rewrite the $service user service"
		mv -f "$unit_dir/$service.service.new" "$unit_dir/$service.service"
		;;
	darwin)
		[ -f "$agents/$label.plist" ] || return 0
		node_plist >"$agents/$label.plist.new" || die "could not rewrite the launchd agent $label"
		mv -f "$agents/$label.plist.new" "$agents/$label.plist"
		;;
	esac
	service_rewritten=1
}

# restart_node restarts the installed node, however it was started. After
# refresh_service it has the service manager read the node's service again.
restart_node() {
	case "$os" in
	linux)
		if [ -f "$unit_dir/$service.service" ] && systemd_user; then
			if [ "$service_rewritten" = 1 ]; then
				systemctl --user daemon-reload || return 1
			fi
			systemctl --user restart "$service.service"
		else
			stop_background
			start_background
		fi
		;;
	darwin)
		if [ "$service_rewritten" = 1 ]; then
			reload_agent "$label" "$agents/$label.plist"
			return
		fi
		launchctl kickstart -k "$domain/$label" >/dev/null 2>&1 || {
			launchctl enable "$domain/$label" >/dev/null 2>&1 || :
			launchctl bootstrap "$domain" "$agents/$label.plist" >/dev/null 2>&1
		}
		;;
	esac
}

# sh_word prints $1 as one single-quoted word of a shell script.
sh_word() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# kept_dash_port prints the port the installed dashboard was installed with,
# from its open script, or nothing.
kept_dash_port() {
	[ -f "$dash_script" ] || return 0
	sed -n 's/^exec .* --port \([0-9][0-9]*\) "\$@"$/\1/p' "$dash_script" | head -n 1
}

# make_dash_key writes the dashboard key unless there is one, and sets
# dash_new to 1 when it made it: the dashboard's first install.
make_dash_key() {
	dash_new=0
	[ -z "$(dash_key_value)" ] || return 0
	k_value=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
	[ "${#k_value}" = 64 ] || die "could not make a key for the dashboard"
	printf '%s\n' "$k_value" >"$dash_key.new" || die "could not write $dash_key"
	chmod 600 "$dash_key.new"
	mv -f "$dash_key.new" "$dash_key"
	dash_new=1
}

# write_dash_script writes the script that opens the dashboard signed in.
write_dash_script() {
	{
		printf '#!/bin/sh\n#\n'
		printf '# Opens the Ghost Node Dashboard in the browser, signed in: it prints the\n'
		printf '# dashboard'\''s link and opens it. install.sh wrote this file.\n\n'
		printf 'exec %s open --node-dir %s --port %s "$@"\n' "$(sh_word "$dash")" "$(sh_word "$base")" "$dash_port"
	} >"$dash_script.new" || die "could not write $dash_script"
	chmod 700 "$dash_script.new"
	mv -f "$dash_script.new" "$dash_script"
}

# dash_unit prints the dashboard's systemd user unit.
dash_unit() {
	cat <<EOF
[Unit]
Description=Ghost Node Dashboard

[Service]
ExecStart=$(unit_word "$dash") --node-dir $(unit_word "$base") --port $dash_port
Restart=on-failure
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
EOF
}

# dash_plist prints the dashboard's launchd agent.
dash_plist() {
	plist_head "$dash_label"
	cat <<EOF
		<string>$(xml_text "$dash")</string>
		<string>--node-dir</string>
		<string>$(xml_text "$base")</string>
		<string>--port</string>
		<string>$dash_port</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>$(xml_text "$base/dashboard.log")</string>
	<key>StandardErrorPath</key>
	<string>$(xml_text "$base/dashboard.log")</string>
</dict>
</plist>
EOF
}

start_dash_background() {
	nohup "$dash" --node-dir "$base" --port "$dash_port" >>"$base/dashboard.log" 2>&1 </dev/null &
	echo "$!" >"$base/dashboard.pid"
}

# start_dashboard writes the dashboard's service and (re)starts it, as the
# node's is: a systemd user unit, a launchd agent, or without systemd user
# services a process in the background.
start_dashboard() {
	case "$os" in
	linux)
		if systemd_user; then
			mkdir -p "$unit_dir"
			dash_unit >"$unit_dir/$dash_service.service"
			stop_pidfile "$base/dashboard.pid" "$dash"
			systemctl --user daemon-reload || die "systemctl --user daemon-reload failed"
			systemctl --user enable "$dash_service.service" >/dev/null 2>&1 ||
				die "could not enable the $dash_service user service"
			systemctl --user restart "$dash_service.service" || die "could not start the $dash_service user service"
		else
			stop_pidfile "$base/dashboard.pid" "$dash"
			start_dash_background
		fi
		;;
	darwin)
		mkdir -p "$agents"
		dash_plist >"$agents/$dash_label.plist"
		load_agent "$dash_label" "$agents/$dash_label.plist"
		;;
	esac
}

# restart_dashboard restarts the installed dashboard, however it was started.
restart_dashboard() {
	case "$os" in
	linux)
		if [ -f "$unit_dir/$dash_service.service" ] && systemd_user; then
			systemctl --user restart "$dash_service.service"
		else
			stop_pidfile "$base/dashboard.pid" "$dash"
			start_dash_background
		fi
		;;
	darwin)
		launchctl kickstart -k "$domain/$dash_label" >/dev/null 2>&1 || {
			launchctl enable "$domain/$dash_label" >/dev/null 2>&1 || :
			launchctl bootstrap "$domain" "$agents/$dash_label.plist" >/dev/null 2>&1
		}
		;;
	esac
}

# remove_dashboard takes out a dashboard installed before, for
# GHOST_NO_DASHBOARD=1, and keeps its key.
remove_dashboard() {
	r_had=0
	case "$os" in
	linux)
		if [ -f "$unit_dir/$dash_service.service" ]; then
			systemctl --user disable --now "$dash_service.service" >/dev/null 2>&1 || :
			rm -f "$unit_dir/$dash_service.service"
			r_had=1
		fi
		;;
	darwin)
		if [ -f "$agents/$dash_label.plist" ]; then
			launchctl bootout "$domain/$dash_label" >/dev/null 2>&1 || :
			rm -f "$agents/$dash_label.plist"
			r_had=1
		fi
		;;
	esac
	if [ -f "$base/dashboard.pid" ]; then
		stop_pidfile "$base/dashboard.pid" "$dash"
		r_had=1
	fi
	if [ -f "$dash" ] || [ -f "$dash_script" ]; then
		rm -f "$dash" "$dash_script"
		r_had=1
	fi
	[ "$r_had" = 0 ] || say "took out the dashboard installed before, as GHOST_NO_DASHBOARD=1 asks; its key $dash_key is kept"
}

# install_dashboard installs the release's ghost-dash with its key, its open
# script and its service, and starts it; or with GHOST_NO_DASHBOARD=1 takes
# out one installed before.
install_dashboard() {
	if [ "$with_dash" != 1 ]; then
		remove_dashboard
		return 0
	fi
	if [ "$has_dash" != 1 ]; then
		say "this release has no dashboard, so none is installed"
		return 0
	fi
	cp "$work/release/ghost-dash" "$dash.new" || die "could not copy ghost-dash"
	chmod 700 "$dash.new"
	mv -f "$dash.new" "$dash"
	make_dash_key
	write_dash_script
	start_dashboard
	dash_on=1
}

# update_dashboard replaces the installed ghost-dash with the release's copy
# and restarts it. A node installed without the dashboard is left without.
update_dashboard() {
	[ -f "$dash" ] || return 0
	dash_on=1
	[ "$has_dash" = 1 ] || return 0
	o_hash=$(sha256 "$dash") || die "could not compute the SHA-256 of $dash"
	n_hash=$(sha256 "$work/release/ghost-dash") || die "could not compute the SHA-256 of the new ghost-dash"
	[ "$o_hash" != "$n_hash" ] || return 0
	cp "$work/release/ghost-dash" "$dash.new" || {
		rm -f "$dash.new"
		die "could not copy the new ghost-dash"
	}
	chmod 700 "$dash.new"
	mv -f "$dash.new" "$dash"
	if restart_dashboard; then
		say "updated the dashboard to the latest release and restarted it"
	else
		say "note: updated the dashboard, but it did not restart; it runs the new copy when it next starts"
	fi
}

# dash_link prints the link that opens the dashboard signed in.
dash_link() {
	printf 'http://127.0.0.1:%s/open?key=%s' "$dash_port" "$(dash_key_value)"
}

# open_dashboard opens the dashboard's link in the browser once it listens:
# with open on a Mac, and with xdg-open on Linux when there is a desktop
# session.
open_dashboard() {
	tries=0
	until port_busy "$dash_port"; do
		tries=$((tries + 1))
		[ "$tries" -lt 10 ] || break
		sleep 1
	done
	case "$os" in
	darwin)
		if command -v open >/dev/null 2>&1 && open "$(dash_link)" >/dev/null 2>&1 </dev/null; then
			say "opened the dashboard in the browser"
		else
			say "could not open the browser; open the dashboard's link above"
		fi
		;;
	linux)
		if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || ! command -v xdg-open >/dev/null 2>&1; then
			say "there is no desktop session here, so the browser was not opened; open the dashboard's link above in a browser on this computer"
			return 0
		fi
		# xdg-open can wait for the browser it starts; the installer does not.
		nohup xdg-open "$(dash_link)" >/dev/null 2>&1 </dev/null &
		say "opened the dashboard in the browser"
		;;
	esac
}

# dashboard_summary prints the dashboard's link, and on its first install
# opens it.
dashboard_summary() {
	if [ "$dash_on" != 1 ]; then
		[ "$with_dash" = 1 ] || [ "$mode" = update ] || say "the dashboard is left out, as GHOST_NO_DASHBOARD=1 asks"
		return 0
	fi
	say "the Ghost Node Dashboard runs at http://127.0.0.1:$dash_port; this link opens it signed in: $(dash_link)"
	say "open it again with: $dash_script"
	if [ "$mode" = install ] && [ "$dash_new" = 1 ]; then
		open_dashboard
	fi
}

# mark_start notes the time before the node is (re)started.
mark_start() {
	touch "$work/started"
	# A socket made in the same second must still count as newer.
	sleep 1
}

# wait_started waits for the node started after mark_start to open its IPC
# endpoint.
wait_started() {
	tries=0
	until [ -S "$data/geth.ipc" ] && [ -n "$(find "$data/geth.ipc" -newer "$work/started" 2>/dev/null)" ]; do
		tries=$((tries + 1))
		[ "$tries" -le 120 ] || return 1
		sleep 1
	done
}

# update installs the verified release in $work/release over the installed
# node and restarts it, keeping the previous geth until the new one runs.
update() {
	o_hash=$(sha256 "$geth") || die "could not compute the SHA-256 of $geth"
	n_hash=$(sha256 "$work/release/geth") || die "could not compute the SHA-256 of the new geth"
	if [ "$o_hash" = "$n_hash" ]; then
		say "the node is up to date"
		return 0
	fi
	cp -p "$geth" "$geth.previous" || {
		rm -f "$geth.previous"
		die "could not keep the previous geth; nothing was changed"
	}
	cp "$work/release/geth" "$geth.new" || {
		rm -f "$geth.new" "$geth.previous"
		die "could not copy the new geth; nothing was changed"
	}
	chmod 700 "$geth.new"
	mv -f "$geth.new" "$geth"
	mark_start
	if restart_node && wait_started; then
		restarted=1
		rm -f "$geth.previous"
		say "updated the node to the latest release and restarted it"
		return 0
	fi
	mv -f "$geth.previous" "$geth"
	mark_start
	restart_node || :
	die "the updated node did not start, so the previous geth was put back and restarted"
}

main() {
	mode=install
	case "$*" in
	'') ;;
	--update) mode=update ;;
	*) die "usage: install.sh [--update]" ;;
	esac
	LC_ALL=C
	export LC_ALL
	umask 077
	[ -n "${HOME:-}" ] && [ -d "$HOME" ] || die "HOME is not set to a directory"
	platform
	need sh uname curl tar gzip sed tr head tail wc mktemp grep od cp mv rm mkdir chmod touch find sleep id basename
	command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 ||
		die "this installer needs sha256sum or shasum, and neither is on the PATH"
	case "$http_port" in
	'' | *[!0-9]* | 0*) die "GHOST_HTTP_PORT is not a port number: $http_port" ;;
	esac
	[ "$http_port" -le 65535 ] || die "GHOST_HTTP_PORT is not a port number: $http_port"
	mine_to=${GHOST_MINE_TO:-}
	if [ -n "$mine_to" ]; then
		m_hex=${mine_to#0x}
		case "$mine_to" in
		0x*) ;;
		*) m_hex=bad ;;
		esac
		case "$m_hex" in
		*[!0-9a-fA-F]*) m_hex=bad ;;
		esac
		[ "${#m_hex}" = 40 ] ||
			refuse "GHOST_MINE_TO must be a wallet address, 0x followed by exactly 40 hex characters, not '$mine_to'"
	fi
	mine_threads=${GHOST_MINE_THREADS:-}
	case "$mine_threads" in
	'') ;;
	0* | *[!0-9]* | ?????*)
		refuse "GHOST_MINE_THREADS must be the number of CPU cores to mine on, a whole number from 1 to 9999, not '$mine_threads'"
		;;
	esac
	release_url=${release_url%/}
	case "$release_url" in
	https://*) ;;
	*) die "GHOST_RELEASE_URL must be an https URL, not $release_url" ;;
	esac
	auto_update=1
	[ "${GHOST_NO_UPDATE:-}" != 1 ] || auto_update=0
	with_dash=1
	[ "${GHOST_NO_DASHBOARD:-}" != 1 ] || with_dash=0
	base="$HOME/.ghost-node"
	data="$base/data"
	config="$base/config.toml"
	geth="$base/bin/geth"
	threads_file="$base/miner-threads"
	paused="$base/mining-paused"
	dash="$base/bin/ghost-dash"
	dash_key="$base/dashboard-key"
	dash_script="$base/dashboard"
	dash_port=${GHOST_DASH_PORT:-}
	if [ -n "$dash_port" ]; then
		case "$dash_port" in
		*[!0-9]* | 0*) refuse "GHOST_DASH_PORT must be a port number, not '$dash_port'" ;;
		esac
		[ "${#dash_port}" -le 5 ] && [ "$dash_port" -le 65535 ] ||
			refuse "GHOST_DASH_PORT must be a port number, not '$dash_port'"
	else
		dash_port=$(kept_dash_port)
		[ -n "$dash_port" ] || dash_port=$dash_default_port
	fi
	dash_on=0
	dash_new=0
	has_dash=0
	service_rewritten=0
	unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
	agents="$HOME/Library/LaunchAgents"
	domain="gui/$(id -u)"
	update_hint=
	restarted=0
	if [ "$mode" = update ] && { [ ! -x "$geth" ] || [ ! -f "$config" ]; }; then
		die "there is no Ghost node installed in $base to update; install one with: curl -fsSL https://get.ghostcoin.com | sh"
	fi
	check_port
	check_dash_port

	work=$(mktemp -d "${TMPDIR:-/tmp}/ghost-node-install.XXXXXX") || die "could not make a temporary directory"
	trap 'rm -rf "$work"' EXIT
	trap 'exit 1' HUP INT TERM

	get_verifier
	if [ "$mode" = update ] && [ "${GHOST_NEWEST_INSTALLER:-}" != 1 ]; then
		run_newest
	fi
	asset="ghost-node-$os-$arch.tar.gz"
	say "downloading $asset"
	fetch "$release_url/$asset" "$work/$asset"
	fetch "$release_url/$asset.sig" "$work/$asset.sig"
	verify "$work/$asset"
	say "the release signature is valid"
	unpack "$work/$asset"

	choose_threads
	if [ "$mode" = update ]; then
		rewritten=0
		if [ -n "$mine_to" ] && [ "$(config_address)" != "$mine_to" ]; then
			set_etherbase
			rewritten=1
		fi
		if [ "$threads_changed" = 1 ] || service_mining_changed; then
			refresh_service
			keep_threads
			rewritten=1
		fi
		update
		if [ "$rewritten" = 1 ] && [ "$restarted" != 1 ]; then
			mark_start
			{ restart_node && wait_started; } ||
				die "the node did not start again to mine to $(config_address) on $(threads_summary); see its log"
			say "restarted the node to mine to $(config_address) on $(threads_summary)"
		fi
		update_dashboard
		say "mining to: $(config_address)"
		say "mining on $(threads_summary)"
		paused_summary
		dashboard_summary
		return 0
	fi

	mkdir -p "$base/bin" "$data"
	cp "$work/release/geth" "$geth.new"
	chmod 700 "$geth.new"
	mv -f "$geth.new" "$geth"
	write_updater
	configure
	keep_threads
	initialise

	mark_start
	case "$os" in
	linux) start_linux ;;
	darwin) start_darwin ;;
	esac
	wait_started || die "the node did not start; see its log ($log_hint)"
	install_dashboard

	address=$(sed -n 's/^Etherbase = "\(0x[0-9a-fA-F]*\)"$/\1/p' "$config")
	if [ -e "$paused" ]; then
		say "the node is installed in $base, running and syncing"
	else
		say "the node is installed in $base, running, syncing and mining"
	fi
	say "mining to: $address"
	say "mining on $(threads_summary); to change that, run the install line again with GHOST_MINE_THREADS set to the number of cores, such as: curl -fsSL https://get.ghostcoin.com | GHOST_MINE_THREADS=2 sh"
	say "check its status with: $status_hint"
	say "follow its log with: $log_hint"
	say "ask it for the chain head with: $geth attach --exec eth.blockNumber $data/geth.ipc"
	say "the Ghost web apps reach it at http://127.0.0.1:$http_port"
	if [ -n "$update_hint" ]; then
		say "signed updates are installed $update_hint; to update now run: $base/update"
	else
		say "automatic updates are off; to update run: $base/update"
	fi
	say "stop it with: $stop_hint"
	paused_summary
	dashboard_summary
}

# paused_summary says when mining is paused.
paused_summary() {
	[ -e "$paused" ] || return 0
	say "mining is paused: $paused is there, so the node runs without --mine; resume it from the dashboard, or delete that file and run $base/update"
}
GHOST_INSTALLER
}

eval "$(installer_source)"
main "$@" </dev/null
