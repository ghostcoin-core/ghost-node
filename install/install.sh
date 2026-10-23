#!/bin/sh
#
# Installs a Ghost node for the current user and starts it mining. It asks
# nothing: paste the one line from the README.
#
# The script downloads the release archive for this computer and its
# signature, and verifies the signature against the release key pinned below
# before it unpacks or runs anything; on any mismatch it stops with nothing
# installed. It then installs the node in ~/.ghost-node, writes the node's
# config with a newly generated mining address, and starts the node as a user
# service with mining on: a systemd user unit on Linux, a launchd agent on
# macOS. Run again, it installs the new release and keeps the config and the
# mining address.
#
# It needs sh, tar, gzip and OpenSSL 3 or later, which does both the download
# (over TLS, checking the server's certificate and name) and the verification.
#
# The release archive is ghost-node-<os>-<arch>.tar.gz, with os linux or darwin
# and arch amd64 or arm64. It holds the geth executable and, while the node has
# no network built in, the genesis.json of the network the release runs. The
# signature, <archive>.sig, is the raw 64-byte ed25519 signature of the
# archive's bytes.
#
# GHOST_RELEASE_URL sets where the release is downloaded from, and
# GHOST_INSTALL_CA_FILE names a certificate file to trust for that server; the
# tests use both for a local release server.

# The release key. This is a test key whose private half nobody holds, so
# until the real key replaces it this script accepts no release. The same key
# is the .pub file next to this script; a test keeps the two equal.
release_key() {
	cat <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAaXYrmAQBL2GOex7Gk5uAi/2q/0DxRZwTbYyVPGQVHfE=
-----END PUBLIC KEY-----
KEY
}

release_url=${GHOST_RELEASE_URL:-https://github.com/ghostcoin-core/ghost-node/releases/latest/download}
ca_file=${GHOST_INSTALL_CA_FILE:-}
service=ghost-node
label=com.ghostcoin.node

say() {
	printf 'ghost-node: %s\n' "$*"
}

die() {
	printf 'ghost-node: %s\n' "$*" >&2
	exit 1
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

# find_openssl sets openssl to an OpenSSL of version 3 or later. Older
# versions and LibreSSL cannot verify a raw ed25519 signature.
find_openssl() {
	for candidate in openssl3 openssl; do
		if command -v "$candidate" >/dev/null 2>&1; then
			case "$("$candidate" version 2>/dev/null)" in
			"OpenSSL "[3-9].*)
				openssl=$candidate
				return 0
				;;
			esac
		fi
	done
	die "this installer needs OpenSSL 3 or later as openssl on the PATH, to download and verify the release"
}

# header_value prints the value of the header line $1.
header_value() {
	value=${1#*:}
	printf '%s' "${value#"${value%%[! ]*}"}"
}

# fetch downloads the https URL $1 to the file $2, following redirects. It
# speaks HTTP/1.0 through openssl s_client, which checks the server's
# certificate against the system's (or GHOST_INSTALL_CA_FILE's) and its name.
fetch() {
	f_url=$1
	f_out=$2
	f_hops=0
	cr=$(printf '\r')
	while :; do
		case "$f_url" in
		https://*) ;;
		*) die "refusing to download $f_url: only https is used" ;;
		esac
		case "$f_url" in
		*[[:space:][:cntrl:]]*) die "refusing to download a URL with spaces or control characters" ;;
		esac
		f_rest=${f_url#https://}
		f_hostport=${f_rest%%/*}
		f_path=${f_rest#"$f_hostport"}
		[ -n "$f_path" ] || f_path=/
		case "$f_hostport" in
		*:*)
			f_host=${f_hostport%:*}
			f_port=${f_hostport##*:}
			;;
		*)
			f_host=$f_hostport
			f_port=443
			;;
		esac
		case "$f_host" in
		'' | *[!A-Za-z0-9.-]*) die "refusing to download from the host $f_host" ;;
		esac
		case "$f_port" in
		'' | *[!0-9]*) die "refusing to download from the port $f_port" ;;
		esac
		# A host name is checked against the certificate's names, an address
		# against its addresses.
		case "$f_host" in
		*[!0-9.]*) f_check="-servername $f_host -verify_hostname $f_host" ;;
		*) f_check="-verify_ip $f_host" ;;
		esac
		set --
		if [ -n "$ca_file" ]; then
			set -- -CAfile "$ca_file"
		fi
		# The exit status says little: a server may close without a TLS
		# close notice. The status line and the length below decide, and
		# the signature decides what the bytes are worth.
		# shellcheck disable=SC2086
		printf 'GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: ghost-node-installer\r\nAccept: */*\r\nConnection: close\r\n\r\n' "$f_path" "$f_hostport" |
			"$openssl" s_client -quiet -verify 9 -verify_return_error $f_check "$@" -connect "$f_host:$f_port" \
				>"$work/response" 2>"$work/tls.log" || :

		f_status=
		f_location=
		f_length=
		f_size=0
		f_first=1
		while IFS= read -r line; do
			f_size=$((f_size + ${#line} + 1))
			line=${line%"$cr"}
			if [ "$f_first" = 1 ]; then
				f_status=$line
				f_first=0
				continue
			fi
			[ -n "$line" ] || break
			case "$(printf '%s' "${line%%:*}" | tr 'A-Z' 'a-z')" in
			location) f_location=$(header_value "$line") ;;
			content-length) f_length=$(header_value "$line") ;;
			esac
		done <"$work/response"

		case "$f_status" in
		HTTP/*) ;;
		*) die "could not download $f_url: $(tail -n 3 "$work/tls.log" | tr '\n' ' ')" ;;
		esac
		f_code=${f_status#* }
		f_code=${f_code%% *}
		case "$f_code" in
		200) break ;;
		301 | 302 | 303 | 307 | 308)
			f_hops=$((f_hops + 1))
			[ "$f_hops" -le 8 ] || die "too many redirects downloading $f_url"
			case "$f_location" in
			https://*) f_url=$f_location ;;
			/*) f_url="https://$f_hostport$f_location" ;;
			*) die "downloading $f_url redirected to an unexpected place: $f_location" ;;
			esac
			;;
		*) die "downloading $f_url failed: $f_status" ;;
		esac
	done

	if [ -n "$f_length" ]; then
		case "$f_length" in
		*[!0-9]*) die "downloading $f_url gave a bad length: $f_length" ;;
		esac
		tail -c "+$((f_size + 1))" "$work/response" | head -c "$f_length" >"$f_out"
		[ "$(wc -c <"$f_out" | tr -d ' ')" = "$f_length" ] || die "the download of $f_url was cut short"
	else
		tail -c "+$((f_size + 1))" "$work/response" >"$f_out"
	fi
	rm -f "$work/response"
}

# verify refuses the archive $1 unless $1.sig is the release key's signature
# of its bytes.
verify() {
	release_key >"$work/release.pub"
	[ "$(wc -c <"$1.sig" | tr -d ' ')" = 64 ] ||
		die "the signature of $(basename "$1") is not a 64-byte ed25519 signature; refusing to install. Nothing was installed."
	if ! "$openssl" pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin -in "$1" -sigfile "$1.sig" >"$work/verify.log" 2>&1 ||
		! grep -q 'Signature Verified Successfully' "$work/verify.log"; then
		die "the signature of $(basename "$1") does not match the release key; refusing to install. Nothing was installed."
	fi
}

# unpack unpacks the verified archive $1 into $work/release.
unpack() {
	tar -tzf "$1" >"$work/members" || die "the release archive cannot be read"
	while IFS= read -r member; do
		case "$member" in
		/* | ../* | */../* | *..) die "the release archive holds an unexpected entry: $member" ;;
		esac
	done <"$work/members"
	mkdir "$work/release"
	tar -xzf "$1" -C "$work/release" || die "the release archive cannot be unpacked"
	if [ ! -f "$work/release/geth" ] || [ -L "$work/release/geth" ]; then
		die "the release archive holds no geth executable"
	fi
	chmod 700 "$work/release/geth"
	"$work/release/geth" version >/dev/null 2>&1 </dev/null || die "the downloaded geth does not run on this computer"
}

# toml_string prints $1 as the inside of a TOML basic string.
toml_string() {
	printf '%s' "$1" | sed 's/[\\"]/\\&/g'
}

# configure writes the config with a new mining address, unless there is one.
configure() {
	if [ -f "$config" ]; then
		say "keeping the existing config $config"
		return 0
	fi
	"$openssl" rand -hex 32 >"$base/password" || die "could not make a password for the mining key"
	created=$("$geth" --datadir "$data" account new --password "$base/password" 2>"$work/account.log" </dev/null) ||
		die "could not create the mining key: $(tail -n 3 "$work/account.log" | tr '\n' ' ')"
	address=$(printf '%s\n' "$created" | sed -n 's/^Public address of the key: *\(0x[0-9a-fA-F]\{40\}\)$/\1/p')
	[ -n "$address" ] || die "could not read the new mining address from: $created"
	cat >"$config.new" <<EOF
# The Ghost node's config, written by install.sh. The node mines to Etherbase,
# whose key is in the keystore of DataDir, locked with the password in
# $(toml_string "$base/password").

[Eth.Miner]
Etherbase = "$address"

[Node]
DataDir = "$(toml_string "$data")"
EOF
	mv -f "$config.new" "$config"
}

# initialise writes the genesis of the release's network into a new data
# directory. A release with the network built in has no genesis.json.
initialise() {
	if [ -f "$work/release/genesis.json" ] && [ ! -d "$data/geth/chaindata" ]; then
		"$geth" --datadir "$data" init "$work/release/genesis.json" >"$work/init.log" 2>&1 </dev/null ||
			die "could not initialise the chain: $(tail -n 3 "$work/init.log" | tr '\n' ' ')"
	fi
}

# unit_word prints $1 as one double-quoted word of a systemd unit line.
unit_word() {
	printf '"%s"' "$(printf '%s' "$1" | sed -e 's/[\\"]/\\&/g' -e 's/%/%%/g')"
}

# xml_text prints $1 escaped for an XML text node.
xml_text() {
	printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# stop_background stops a node this script started without a service.
stop_background() {
	[ -f "$base/node.pid" ] || return 0
	pid=$(cat "$base/node.pid")
	rm -f "$base/node.pid"
	case "$pid" in
	'' | *[!0-9]*) return 0 ;;
	esac
	case "$(ps -p "$pid" -o args= 2>/dev/null)" in
	*"$geth"*) ;;
	*) return 0 ;;
	esac
	kill "$pid" 2>/dev/null || return 0
	tries=0
	while kill -0 "$pid" 2>/dev/null && [ "$tries" -lt 60 ]; do
		sleep 1
		tries=$((tries + 1))
	done
}

start_linux() {
	if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
		unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
		mkdir -p "$unit_dir"
		cat >"$unit_dir/$service.service" <<EOF
[Unit]
Description=Ghost node
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=$(unit_word "$geth") --config $(unit_word "$config") --mine
Restart=on-failure
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
EOF
		stop_background
		systemctl --user daemon-reload || die "systemctl --user daemon-reload failed"
		systemctl --user enable "$service.service" >/dev/null 2>&1 || die "could not enable the $service user service"
		systemctl --user restart "$service.service" || die "could not start the $service user service"
		# Lingering keeps the node running after logout and starts it at boot.
		if command -v loginctl >/dev/null 2>&1; then
			loginctl enable-linger --no-ask-password >/dev/null 2>&1 ||
				say "note: the node stops when you log out; 'loginctl enable-linger' keeps it running"
		fi
		stop_hint="systemctl --user stop $service"
	else
		say "systemd user services are not available here, so the node runs in the background without one; it does not start again after a reboot until this installer runs again"
		stop_background
		nohup "$geth" --config "$config" --mine >>"$base/node.log" 2>&1 </dev/null &
		echo "$!" >"$base/node.pid"
		stop_hint="kill \$(cat $base/node.pid)"
	fi
}

start_darwin() {
	agents="$HOME/Library/LaunchAgents"
	plist="$agents/$label.plist"
	mkdir -p "$agents"
	cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>$(xml_text "$geth")</string>
		<string>--config</string>
		<string>$(xml_text "$config")</string>
		<string>--mine</string>
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
	domain="gui/$(id -u)"
	launchctl bootout "$domain/$label" >/dev/null 2>&1 || :
	# bootout returns before the old agent is gone; bootstrap until it loads.
	tries=0
	until launchctl bootstrap "$domain" "$plist" 2>"$work/launchctl.log"; do
		tries=$((tries + 1))
		[ "$tries" -lt 10 ] || die "could not start the launchd agent: $(cat "$work/launchctl.log")"
		sleep 1
	done
	launchctl enable "$domain/$label" >/dev/null 2>&1 || :
	stop_hint="launchctl bootout $domain/$label"
}

# wait_started waits for the node's IPC endpoint.
wait_started() {
	tries=0
	until [ -S "$data/geth.ipc" ]; do
		tries=$((tries + 1))
		if [ "$tries" -gt 120 ]; then
			die "the node did not start; see its log ($log_hint)"
		fi
		sleep 1
	done
}

main() {
	LC_ALL=C
	export LC_ALL
	umask 077
	[ -n "${HOME:-}" ] && [ -d "$HOME" ] || die "HOME is not set to a directory"
	platform
	need uname tar gzip sed tr head tail wc mktemp grep
	find_openssl
	release_url=${release_url%/}
	base="$HOME/.ghost-node"
	data="$base/data"
	config="$base/config.toml"
	geth="$base/bin/geth"

	work=$(mktemp -d "${TMPDIR:-/tmp}/ghost-node-install.XXXXXX") || die "could not make a temporary directory"
	trap 'rm -rf "$work"' EXIT
	trap 'exit 1' HUP INT TERM

	asset="ghost-node-$os-$arch.tar.gz"
	say "downloading $asset"
	fetch "$release_url/$asset" "$work/$asset"
	fetch "$release_url/$asset.sig" "$work/$asset.sig"
	verify "$work/$asset"
	say "the release signature is valid"
	unpack "$work/$asset"

	mkdir -p "$base/bin" "$data"
	cp "$work/release/geth" "$geth.new"
	chmod 700 "$geth.new"
	mv -f "$geth.new" "$geth"
	configure
	initialise

	case "$os" in
	linux)
		log_hint="journalctl --user -u $service"
		start_linux
		[ -f "$base/node.pid" ] && log_hint="$base/node.log"
		;;
	darwin)
		log_hint="$base/node.log"
		start_darwin
		;;
	esac
	wait_started

	address=$(sed -n 's/^Etherbase = "\(0x[0-9a-fA-F]*\)"$/\1/p' "$config")
	say "the node is installed in $base, running, and mining to $address"
	say "watch it with: $geth attach $data/geth.ipc"
	say "stop it with: $stop_hint"
}

main "$@"
