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
# release, whose ghost-verify has other hashes. A release is cut from a pushed
# tag vMAJOR.MINOR.PATCH (GITHUB_REF_TYPE=tag, GITHUB_REF_NAME the tag), each
# part a number from 0 to 999 without leading zeros, and not v0.0.0. The
# script replaces the default releases/latest/download URL with
# releases/download/<tag> in the script's release_url and in dir's
# install.ps1 and install.cmd. GHOST_RELEASE_URL still overrides it. The
# script's newest_url keeps the default URL: its updater looks there for the
# newest release's signed install.sh. It also replaces the script's one
# release_build=0 line with the tag's build number, MAJOR*1000000 +
# MINOR*1000 + PATCH, which the updater compares so that it never installs an
# older release. It fails, changing none of the files, when the run is not for
# such a tag, when dir lacks a ghost-node-<os>-<arch>.tar.gz archive or the
# script does not hold exactly one placeholder line for it (each is pinned to
# the archive's SHA-256, so the signed script names its own release's
# archives), when install.ps1 or install.cmd does not hold the default URL
# exactly once, when the script does not hold it exactly twice, once as
# release_url's and once as newest_url's default, or when the script does not
# hold exactly one release_build=0 line. Outside GitHub Actions the URL and
# the build number are left alone.

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
	[ "${GITHUB_REF_TYPE:-}" = tag ] || fail "this run is not for a pushed tag (GITHUB_REF_TYPE is '${GITHUB_REF_TYPE:-}'); releases are cut from vMAJOR.MINOR.PATCH tags"
	tag=${GITHUB_REF_NAME:-}
	part='(0|[1-9][0-9]{0,2})'
	case "$tag" in
	*[!v0-9.]*) tag_ok=false ;;
	*) tag_ok=true ;;
	esac
	[ "$tag_ok" = true ] && printf '%s\n' "$tag" | grep -Eqx "v$part\.$part\.$part" ||
		fail "the tag '$tag' is not vMAJOR.MINOR.PATCH with each part a number from 0 to 999"
	build=$(printf '%s\n' "$tag" | awk -F. '{ sub(/^v/, "", $1); print $1 * 1000000 + $2 * 1000 + $3 }')
	[ "$build" -gt 0 ] || fail "the tag '$tag' gives build number $build; the first release is v0.0.1 or later"
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

# In GitHub Actions, pin the release's archives too: the signed install.sh
# then names the one archive of each platform it installs.
if [ "$pin_url" = true ]; then
	for platform in $platforms; do
		name=ghost-node-$platform.tar.gz
		file="$dir/$name"
		[ -f "$file" ] && [ -s "$file" ] || fail "there is no $name in $dir, or it is empty"
		hash=$(sha256 "$file") || fail "could not compute the SHA-256 of $file"
		case "$hash" in
		*[!0-9a-f]* | '' | "$zero") fail "$file has no usable SHA-256: $hash" ;;
		esac
		[ "${#hash}" = 64 ] || fail "$file has no usable SHA-256: $hash"
		count=$(grep -cF "$name $zero" "$tmp" || :)
		[ "$count" = 1 ] && [ "$(grep -cx "ghost-node-$platform\.tar\.gz $zero" "$tmp" || :)" = 1 ] ||
			fail "$script has $count placeholder lines for $name, not one"
		sed "s/^ghost-node-$platform\.tar\.gz $zero\$/$name $hash/" "$tmp" >"$tmp.new"
		cat "$tmp.new" >"$tmp"
		[ "$(grep -cx "ghost-node-$platform\.tar\.gz $hash" "$tmp" || :)" = 1 ] ||
			fail "could not pin the hash of $name in $script"
	done
	archives_left=0
else
	archives_left=$(echo $platforms | wc -w | tr -d ' ')
	[ "$(grep -cE "^ghost-node-[a-z0-9]+-[a-z0-9]+\.tar\.gz $zero\$" "$tmp" || :)" = "$archives_left" ] ||
		fail "$script does not hold one archive placeholder line for each of $platforms"
fi

# Only the installer's placeholder_hash constant, and outside GitHub Actions
# the archive placeholders, may still hold the zeros.
if grep -Eq "^[a-z0-9]+-[a-z0-9]+[[:space:]]+$zero\$" "$tmp"; then
	fail "$script still pins the placeholder for: $(grep -E "^[a-z0-9]+-[a-z0-9]+[[:space:]]+$zero\$" "$tmp" | cut -d' ' -f1 | tr '\n' ' ')"
fi
count=$(grep -c "$zero" "$tmp" || :)
[ "$count" = $((archives_left + 1)) ] || fail "$script holds the placeholder $count times after pinning, not only in placeholder_hash"

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

# pin_script_url writes the script $1 to $2 with release_url's default
# replaced by this release's URL, keeping newest_url's. It refuses a script $3
# that does not set each of the two to the default URL on exactly one line,
# or holds the default URL anywhere else.
pin_script_url() {
	release_line="release_url=\${GHOST_RELEASE_URL:-$latest_url}"
	newest_line="newest_url=\${GHOST_LATEST_URL:-$latest_url}"
	count=$(grep -cxF "$release_line" "$1" || :)
	[ "$count" = 1 ] || fail "$3 sets release_url to the default release URL $latest_url on $count lines, not one"
	count=$(grep -cxF "$newest_line" "$1" || :)
	[ "$count" = 1 ] || fail "$3 sets newest_url to the default release URL $latest_url on $count lines, not one"
	count=$(occurrences "$latest_url" "$1")
	[ "$count" = 2 ] || fail "$3 holds the default release URL $latest_url $count times, not twice"
	sed "/^release_url=/s|$latest_pattern|$release_url|" "$1" >"$2"
	[ "$(grep -cxF "release_url=\${GHOST_RELEASE_URL:-$release_url}" "$2" || :)" = 1 ] &&
		[ "$(grep -cxF "$newest_line" "$2" || :)" = 1 ] &&
		[ "$(occurrences "$latest_url" "$2")" = 1 ] && [ "$(occurrences "$release_url" "$2")" = 1 ] ||
		fail "could not pin the release URL in $3"
}

# pin_build writes the script $1 to $2 with its one release_build=0 line
# holding this release's build number. It refuses a script $3 that does not
# hold exactly one release_build line, and that line release_build=0.
pin_build() {
	count=$(grep -c '^release_build=' "$1" || :)
	[ "$count" = 1 ] || fail "$3 has $count release_build lines, not one"
	count=$(grep -cx 'release_build=0' "$1" || :)
	[ "$count" = 1 ] || fail "$3 does not set release_build=0, the placeholder"
	sed "s/^release_build=0\$/release_build=$build/" "$1" >"$2"
	[ "$(grep -cx "release_build=$build" "$2" || :)" = 1 ] || fail "could not pin the build number in $3"
}

if [ "$pin_url" = true ]; then
	pin_script_url "$tmp" "$tmp.new" "$script"
	cat "$tmp.new" >"$tmp"
	pin_build "$tmp" "$tmp.new" "$script"
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
	printf 'pin-verifier-hashes: pinned build number %s of %s in %s\n' "$build" "$tag" "$script"
fi
