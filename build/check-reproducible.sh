#!/usr/bin/env bash
# Builds geth twice from the committed tree, in two different directories with
# separate Go build caches, and fails if the two executables differ. It does
# the same for ghost-dash, the Ghost Node Dashboard the release archives carry
# next to geth: built twice from the ghost-node-dashboard commit pinned in
# build/dashboard-commit, with CGO_ENABLED=0 and -trimpath as the release
# builds it. GHOST_DASH_REPO sets where that commit is fetched from.
#
# Usage: build/check-reproducible.sh [output-file [dashboard-output-file]]
# The sha256 of each executable is printed, and also written to output-file
# (geth's) and dashboard-output-file (ghost-dash's) when they are given, so
# that builds on different machines can be compared.
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
dash_exe=ghost-dash
case "$(go env GOOS)" in windows)
	exe=geth.exe
	dash_exe=ghost-dash.exe
	;;
esac

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

dash_owner=ghostcoin-core
dash_repo="${GHOST_DASH_REPO:-https://github.com/$dash_owner/ghost-node-dashboard.git}"
dash_commit="$(tr -d '[:space:]' <"$root/build/dashboard-commit")"
if ! [[ $dash_commit =~ ^[0-9a-f]{40}$ ]]; then
	echo "build/dashboard-commit must hold the full 40-character SHA of a ghost-node-dashboard commit" >&2
	exit 1
fi
src="$work/dash-src"
git init --quiet "$src"
git -C "$src" fetch --quiet --depth 1 "$dash_repo" "$dash_commit"
git -C "$src" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$src" rev-parse HEAD)" = "$dash_commit"

dash_hashes=()
for name in dash-a dash-second-build-dir; do
	dir="$work/$name"
	git -C "$src" worktree add --detach --quiet "$dir" HEAD
	(
		cd "$dir"
		CGO_ENABLED=0 GOCACHE="$cache_root/cache-$name" GOFLAGS='' \
			go build -trimpath -ldflags=-buildid= -o out/ ./... >"$work/build-$name.log" 2>&1 ||
			{ cat "$work/build-$name.log"; exit 1; }
	)
	dash_hashes+=("$(sha256 "$dir/out/$dash_exe")")
done

echo "$(go env GOOS)/$(go env GOARCH) $dash_exe ${dash_hashes[0]} (dashboard commit $dash_commit)"
if [ "${dash_hashes[0]}" != "${dash_hashes[1]}" ]; then
	echo "not reproducible: second build of $dash_exe gave ${dash_hashes[1]}" >&2
	exit 1
fi

if [ $# -ge 1 ]; then
	echo "${hashes[0]}" >"$1"
fi
if [ $# -ge 2 ]; then
	echo "${dash_hashes[0]}" >"$2"
fi
