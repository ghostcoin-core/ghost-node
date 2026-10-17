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

exe=geth
case "$(go env GOOS)" in windows) exe=geth.exe ;; esac

hashes=()
for name in a second-build-dir; do
	dir="$work/$name"
	git -C "$root" worktree add --detach --quiet "$dir" HEAD
	(
		cd "$dir"
		GOCACHE="$work/cache-$name" GOFLAGS= go run build/ci.go install ./cmd/geth >"$work/build-$name.log" 2>&1 ||
			{ cat "$work/build-$name.log"; exit 1; }
	)
	hashes+=("$(sha256sum "$dir/build/bin/$exe" | cut -d' ' -f1)")
done

echo "$(go env GOOS)/$(go env GOARCH) $exe ${hashes[0]}"
if [ "${hashes[0]}" != "${hashes[1]}" ]; then
	echo "not reproducible: second build gave ${hashes[1]}" >&2
	exit 1
fi
if [ $# -ge 1 ]; then
	echo "${hashes[0]}" >"$1"
fi
