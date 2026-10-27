#!/bin/sh
#
# Pins the release's ghost-verify hashes in a copy of install.sh:
#
#	pin-verifier-hashes.sh <install.sh> <dir>
#
# install.sh in the repository pins the all-zero placeholder as the SHA-256 of
# each ghost-verify-<os>-<arch>, and refuses to install while it does. The
# release runs this on its own copy of install.sh before signing it, with dir
# holding the ghost-verify-<os>-<arch> files it publishes: it replaces the one
# placeholder line of each of linux and darwin on amd64 and arm64 in
# verifier_hashes() with that file's real SHA-256, in place.
#
# It fails, leaving the script as it was, when a file is missing or empty,
# when the script does not hold exactly one placeholder line for a platform,
# or when any placeholder line is left afterwards.
#
# In GitHub Actions (GITHUB_ACTIONS=true) it also pins the release the
# installers download from: the published install.sh pins this release's
# ghost-verify hashes, so it must not follow releases/latest to the next
# release, whose ghost-verify has other hashes. It computes the release tag as
# the publish step does, build-$GITHUB_RUN_NUMBER- and the first 12 characters
# of $GITHUB_SHA, and replaces the default releases/latest/download URL with
# releases/download/<tag> in the script and in dir's install.ps1 and
# install.cmd. GHOST_RELEASE_URL still overrides it. It fails, changing none
# of the files, when either variable is missing or malformed or when a file
# does not hold the default URL exactly once. Outside GitHub Actions the URL
# is left alone.

set -eu
LC_ALL=C
export LC_ALL

zero=0000000000000000000000000000000000000000000000000000000000000000
platforms='linux-amd64 linux-arm64 darwin-amd64 darwin-arm64'
latest_url=https://github.com/ghostcoin-core/ghost-node/releases/latest/download
latest_pattern='https://github\.com/ghostcoin-core/ghost-node/releases/latest/download'

fail() {
	printf 'pin-verifier-hashes: %s\n' "$*" >&2
	exit 1
}

[ "$#" = 2 ] || fail "usage: pin-verifier-hashes.sh <install.sh> <dir>"
script=$1
dir=$2
[ -f "$script" ] || fail "$script is not a file"
[ -d "$dir" ] || fail "$dir is not a directory"

pin_url=false
if [ "${GITHUB_ACTIONS:-}" = true ]; then
	pin_url=true
	run=${GITHUB_RUN_NUMBER:-}
	sha=${GITHUB_SHA:-}
	case "$run" in
	'' | *[!0-9]* | 0*) fail "GITHUB_RUN_NUMBER is not a positive integer: '$run'" ;;
	esac
	case "$sha" in
	'' | *[!0-9a-fA-F]*) fail "GITHUB_SHA is not a hex commit hash: '$sha'" ;;
	esac
	[ "${#sha}" -ge 12 ] || fail "GITHUB_SHA is shorter than 12 characters: '$sha'"
	tag=build-$run-$(printf '%s\n' "$sha" | cut -c1-12)
	release_url=https://github.com/ghostcoin-core/ghost-node/releases/download/$tag
	for name in install.ps1 install.cmd; do
		[ -f "$dir/$name" ] || fail "there is no $name in $dir"
	done
fi

# sha256 prints the SHA-256 of the file $1, with sha256sum or, on a Mac,
# shasum.
sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		s_out=$(sha256sum "$1") || return 1
	else
		s_out=$(shasum -a 256 "$1") || return 1
	fi
	printf '%s\n' "${s_out%% *}"
}

tmp=$(mktemp "${TMPDIR:-/tmp}/pin-verifier-hashes.XXXXXX")
trap 'rm -f "$tmp" "$tmp.new" "$tmp.ps1" "$tmp.cmd"' EXIT
cat "$script" >"$tmp"

for platform in $platforms; do
	file="$dir/ghost-verify-$platform"
	[ -f "$file" ] && [ -s "$file" ] || fail "there is no ghost-verify-$platform in $dir, or it is empty"
	hash=$(sha256 "$file") || fail "could not compute the SHA-256 of $file"
	case "$hash" in
	*[!0-9a-f]* | '' | "$zero") fail "$file has no usable SHA-256: $hash" ;;
	esac
	[ "${#hash}" = 64 ] || fail "$file has no usable SHA-256: $hash"
	count=$(grep -c "^$platform $zero\$" "$tmp" || :)
	[ "$count" = 1 ] || fail "$script has $count placeholder lines for ghost-verify-$platform, not one"
	sed "s/^$platform $zero\$/$platform $hash/" "$tmp" >"$tmp.new"
	cat "$tmp.new" >"$tmp"
	count=$(grep -c "^$platform $hash\$" "$tmp" || :)
	[ "$count" = 1 ] || fail "could not pin the hash of ghost-verify-$platform in $script"
done

# Only the installer's placeholder_hash constant may still hold the zeros.
if grep -Eq "^[a-z0-9]+-[a-z0-9]+[[:space:]]+$zero\$" "$tmp"; then
	fail "$script still pins the placeholder for: $(grep -E "^[a-z0-9]+-[a-z0-9]+[[:space:]]+$zero\$" "$tmp" | cut -d' ' -f1 | tr '\n' ' ')"
fi
count=$(grep -c "$zero" "$tmp" || :)
[ "$count" = 1 ] || fail "$script holds the placeholder $count times after pinning, not only in placeholder_hash"

# occurrences prints how many times the text $1 is in the file $2.
occurrences() {
	grep -oF "$1" "$2" | wc -l | tr -d ' '
}

# pin_release_url writes the file $1 to $2 with the default URL replaced by
# this release's, which file $3 must hold exactly once.
pin_release_url() {
	count=$(occurrences "$latest_url" "$1")
	[ "$count" = 1 ] || fail "$3 holds the default release URL $latest_url $count times, not once"
	sed "s|$latest_pattern|$release_url|" "$1" >"$2"
	[ "$(occurrences "$latest_url" "$2")" = 0 ] && [ "$(occurrences "$release_url" "$2")" = 1 ] ||
		fail "could not pin the release URL in $3"
}

if [ "$pin_url" = true ]; then
	pin_release_url "$tmp" "$tmp.new" "$script"
	cat "$tmp.new" >"$tmp"
	pin_release_url "$dir/install.ps1" "$tmp.ps1" "$dir/install.ps1"
	pin_release_url "$dir/install.cmd" "$tmp.cmd" "$dir/install.cmd"
fi

cat "$tmp" >"$script"
printf 'pin-verifier-hashes: pinned the ghost-verify hashes of %s in %s\n' "$platforms" "$script"
if [ "$pin_url" = true ]; then
	cat "$tmp.ps1" >"$dir/install.ps1"
	cat "$tmp.cmd" >"$dir/install.cmd"
	printf 'pin-verifier-hashes: pinned the release URL %s in %s, %s and %s\n' "$release_url" "$script" "$dir/install.ps1" "$dir/install.cmd"
fi
