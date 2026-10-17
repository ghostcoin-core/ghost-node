#!/usr/bin/env bash
# Builds geth twice from the committed tree, in two different directories with
# separate Go build caches, and fails if the two executables differ.
#
# Usage: build/check-reproducible.sh [output-file]
# The sha256 of the executable is printed, and also written to output-file
# when one is given, so that builds on different machines can be compared.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
cleanup() {
	for dir in "$work"/a "$work"/second-build-dir; do
		git -C "$root" worktree remove --force "$dir" >/dev/null 2>&1 || true
	done
	rm -rf "$work"
}
trap cleanup EXIT

# Go on Windows needs a native path for GOCACHE, not a Git Bash one.
cache_root="$work"
if command -v cygpath >/dev/null 2>&1; then
	cache_root="$(cygpath -m "$work")"
fi

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

exe=geth
case "$(go env GOOS)" in windows) exe=geth.exe ;; esac

hashes=()
for name in a second-build-dir; do
	dir="$work/$name"
	git -C "$root" worktree add --detach --quiet "$dir" HEAD
	(
		cd "$dir"
		GOCACHE="$cache_root/cache-$name" GOFLAGS='' go run build/ci.go install ./cmd/geth >"$work/build-$name.log" 2>&1 ||
			{ cat "$work/build-$name.log"; exit 1; }
	)
	hashes+=("$(sha256 "$dir/build/bin/$exe")")
done

echo "$(go env GOOS)/$(go env GOARCH) $exe ${hashes[0]}"
if [ "${hashes[0]}" != "${hashes[1]}" ]; then
	echo "not reproducible: second build gave ${hashes[1]}" >&2
	exit 1
fi
if [ $# -ge 1 ]; then
	echo "${hashes[0]}" >"$1"
fi
