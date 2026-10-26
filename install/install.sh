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
# newly generated mining address, and starts the node as a user service with
# mining on, which also starts it at boot: a systemd user unit on Linux, a
# launchd agent on macOS. The node joins the network built into it, the public
# test network; an archive that still holds a genesis.json gets that chain
# initialised first. The config opens the node's HTTP RPC on 127.0.0.1 only,
# for the Ghost web apps.
#
# It also installs ~/.ghost-node/update, which is this script run with
# --update, and runs it daily (a systemd user timer, or a launchd agent with a
# StartInterval) unless GHOST_NO_UPDATE=1 is set at install time. An update
# passes the same checks as an install, replaces the geth executable
# atomically, keeps the previous one until the node has restarted, and keeps
# the config and the mining address. A refused update changes nothing and
# leaves the running node alone. Run again, the installer installs the latest
# release and keeps the config and the mining address.
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
# server; GHOST_HTTP_PORT moves the node's HTTP RPC off 8545. The tests use
# them for a local release server.
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
# fills them in; until then they are all zeros, the placeholder, and the
# installer refuses to install rather than run an unpinned checker.
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
ca_file=${GHOST_INSTALL_CA_FILE:-}
http_port=${GHOST_HTTP_PORT:-8545}
service=ghost-node
update_service=ghost-node-update
label=com.ghostcoin.node
update_label=com.ghostcoin.node.update

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
		printf '# install.sh wrote this file: it is the installer run with --update, and it\n'
		printf '# checks each release exactly as the installer does.\n\n'
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

start_background() {
	nohup "$geth" --config "$config" --mine >>"$base/node.log" 2>&1 </dev/null &
	echo "$!" >"$base/node.pid"
}

start_linux() {
	if systemd_user; then
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

# load_agent (re)loads the launchd agent $1 from the plist $2.
load_agent() {
	launchctl bootout "$domain/$1" >/dev/null 2>&1 || :
	# bootout returns before the old agent is gone; bootstrap until it loads.
	tries=0
	until launchctl bootstrap "$domain" "$2" 2>"$work/launchctl.log"; do
		tries=$((tries + 1))
		[ "$tries" -lt 10 ] || die "could not start the launchd agent $1: $(cat "$work/launchctl.log")"
		sleep 1
	done
	launchctl enable "$domain/$1" >/dev/null 2>&1 || :
}

start_darwin() {
	mkdir -p "$agents"
	plist="$agents/$label.plist"
	update_plist="$agents/$update_label.plist"
	{
		plist_head "$label"
		cat <<EOF
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
	} >"$plist"
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

# restart_node restarts the installed node, however it was started.
restart_node() {
	case "$os" in
	linux)
		if [ -f "$unit_dir/$service.service" ] && systemd_user; then
			systemctl --user restart "$service.service"
		else
			stop_background
			start_background
		fi
		;;
	darwin)
		launchctl kickstart -k "$domain/$label" >/dev/null 2>&1 ||
			launchctl bootstrap "$domain" "$agents/$label.plist" >/dev/null 2>&1
		;;
	esac
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
	need uname curl tar gzip sed tr head tail wc mktemp grep od cp mv rm mkdir chmod touch find sleep id basename
	command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 ||
		die "this installer needs sha256sum or shasum, and neither is on the PATH"
	case "$http_port" in
	'' | *[!0-9]* | 0*) die "GHOST_HTTP_PORT is not a port number: $http_port" ;;
	esac
	[ "$http_port" -le 65535 ] || die "GHOST_HTTP_PORT is not a port number: $http_port"
	release_url=${release_url%/}
	case "$release_url" in
	https://*) ;;
	*) die "GHOST_RELEASE_URL must be an https URL, not $release_url" ;;
	esac
	auto_update=1
	[ "${GHOST_NO_UPDATE:-}" != 1 ] || auto_update=0
	base="$HOME/.ghost-node"
	data="$base/data"
	config="$base/config.toml"
	geth="$base/bin/geth"
	unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
	agents="$HOME/Library/LaunchAgents"
	domain="gui/$(id -u)"
	update_hint=
	if [ "$mode" = update ] && { [ ! -x "$geth" ] || [ ! -f "$config" ]; }; then
		die "there is no Ghost node installed in $base to update; install one with: curl -fsSL https://get.ghostcoin.com | sh"
	fi

	work=$(mktemp -d "${TMPDIR:-/tmp}/ghost-node-install.XXXXXX") || die "could not make a temporary directory"
	trap 'rm -rf "$work"' EXIT
	trap 'exit 1' HUP INT TERM

	get_verifier
	asset="ghost-node-$os-$arch.tar.gz"
	say "downloading $asset"
	fetch "$release_url/$asset" "$work/$asset"
	fetch "$release_url/$asset.sig" "$work/$asset.sig"
	verify "$work/$asset"
	say "the release signature is valid"
	unpack "$work/$asset"

	if [ "$mode" = update ]; then
		update
		return 0
	fi

	mkdir -p "$base/bin" "$data"
	cp "$work/release/geth" "$geth.new"
	chmod 700 "$geth.new"
	mv -f "$geth.new" "$geth"
	write_updater
	configure
	initialise

	mark_start
	case "$os" in
	linux) start_linux ;;
	darwin) start_darwin ;;
	esac
	wait_started || die "the node did not start; see its log ($log_hint)"

	address=$(sed -n 's/^Etherbase = "\(0x[0-9a-fA-F]*\)"$/\1/p' "$config")
	say "the node is installed in $base, running, syncing and mining"
	say "your mining address: $address"
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
}
GHOST_INSTALLER
}

eval "$(installer_source)"
main "$@" </dev/null
