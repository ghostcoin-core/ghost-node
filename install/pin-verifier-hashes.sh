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

set -eu
LC_ALL=C
export LC_ALL

zero=0000000000000000000000000000000000000000000000000000000000000000
platforms='linux-amd64 linux-arm64 darwin-amd64 darwin-arm64'

fail() {
	printf 'pin-verifier-hashes: %s\n' "$*" >&2
	exit 1
}

[ "$#" = 2 ] || fail "usage: pin-verifier-hashes.sh <install.sh> <dir>"
script=$1
dir=$2
[ -f "$script" ] || fail "$script is not a file"
[ -d "$dir" ] || fail "$dir is not a directory"

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
trap 'rm -f "$tmp" "$tmp.new"' EXIT
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

cat "$tmp" >"$script"
printf 'pin-verifier-hashes: pinned the ghost-verify hashes of %s in %s\n' "$platforms" "$script"
