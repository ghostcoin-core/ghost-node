#!/usr/bin/env bash
# Runs the checks of CI's test jobs on any host. CI calls this script for each
# job, so the package sets and test commands live here and nowhere else.
#
# Usage:
#   build/ci-gate.sh                    run every stage
#   build/ci-gate.sh typecheck          gofmt, go mod tidy, go vet, release and link checks
#   build/ci-gate.sh build              build every command and run the real-proof tests
#   build/ci-gate.sh unit [shard]       one unit test shard, or all of them
#   build/ci-gate.sh fixtures [part]    one part of the Ethereum test fixtures, or all of them
#   build/ci-gate.sh --list             print the stage names and run nothing
#   build/ci-gate.sh --check-shards     fail unless the unit shards cover every package once
#
# When several shards run, GATE_JOBS (default 4) of them run at once, each
# with its output kept aside; the last 100 lines of a failed shard are printed.
set -euo pipefail

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(git rev-parse --show-toplevel)"

mod=github.com/ethereum/go-ethereum
unit_shards=(consensus core core-sub eth eth-sub cmd p2p rest)
fixture_parts=(state blockchain other)

# Every package the unit shards test: all of them except the fixture runner.
unit_packages() {
	local all pkg
	all="$(go list ./...)"
	for pkg in $all; do
		if [ "$pkg" != "$mod/tests" ]; then
			echo "$pkg"
		fi
	done
}

in_shard() {
	local shard=$1 pkg=$2
	case "$shard" in
	consensus) [[ $pkg == "$mod/consensus" || $pkg == "$mod/consensus/"* ]] ;;
	core) [[ $pkg == "$mod/core" ]] ;;
	core-sub) [[ $pkg == "$mod/core/"* ]] ;;
	eth) [[ $pkg == "$mod/eth" || $pkg == "$mod/eth/fetcher" ]] ;;
	eth-sub) [[ $pkg == "$mod/eth/"* && $pkg != "$mod/eth/fetcher" ]] ;;
	cmd) [[ $pkg == "$mod/cmd" || $pkg == "$mod/cmd/"* ]] ;;
	p2p) [[ $pkg == "$mod/p2p" || $pkg == "$mod/p2p/"* ]] ;;
	rest) ! [[ $pkg =~ ^$mod/(consensus|core|eth|cmd|p2p)(/|$) ]] ;;
	*) return 2 ;;
	esac
}

# Prints the packages of one shard, chosen from the packages given after it.
shard_packages() {
	local shard=$1 pkg
	shift
	for pkg in "$@"; do
		if in_shard "$shard" "$pkg"; then
			echo "$pkg"
		fi
	done
}

known() {
	local name=$1 item
	shift
	for item in "$@"; do
		if [ "$item" = "$name" ]; then
			return 0
		fi
	done
	return 1
}

stage_typecheck() {
	local gofmt unformatted deps
	echo "--- gofmt"
	# The gofmt of the go in use, which need not be on the PATH.
	gofmt="$(go env GOROOT)/bin/gofmt"
	unformatted="$(git ls-files -z '*.go' | xargs -0 "$gofmt" -l)"
	if [ -n "$unformatted" ]; then
		echo "These files need gofmt:"
		echo "$unformatted"
		exit 1
	fi
	echo "--- go mod tidy"
	go mod tidy -diff
	echo "--- go vet"
	go vet -tags integrationtests ./...
	echo "--- Release builds have no fake seals"
	go test -tags ghostrelease -run '^TestRelease' ./consensus/ethash
	echo "--- No proof-of-stake code in the node"
	# The beacon wrapper is kept only for upstream tests and the evm test
	# runner; the node itself must not link it.
	deps="$(go list -deps ./cmd/geth)"
	if echo "$deps" | grep -x -E "$mod/(consensus/beacon|eth/catalyst|beacon/.*)"; then
		echo "geth links proof-of-stake code"
		exit 1
	fi
}

stage_build() {
	local kind
	echo "--- Build every command"
	go run build/ci.go install
	echo "--- Real-proof verifier tests"
	CGO_ENABLED=1 go test -tags ghostproofs -count=1 -v -run '^(TestGhostVerifierKnownAnswer|TestRealProofRevealRoundTrip)$' ./core/ghostpriv/
	CGO_ENABLED=1 go test -tags ghostproofs -count=1 -v -run '^(TestRealProofRevealPoolAndBlock|TestRealProofTamperedRevealRejected)$' ./core/txpool/ghostpool/
	echo "--- The Linux release is one self-contained file"
	kind="$(file build/bin/geth)"
	echo "$kind"
	if [[ $kind != *"statically linked"* ]]; then
		echo "build/bin/geth is not statically linked"
		exit 1
	fi
}

stage_unit() {
	local shard=$1 all pkgs
	all="$(unit_packages)"
	pkgs="$(shard_packages "$shard" $all)"
	if [ -z "$pkgs" ]; then
		echo "unit shard $shard has no packages"
		exit 1
	fi
	# One package at a time, as upstream's CI does: several upstream tests
	# are timing-sensitive and fail when packages run in parallel on a small
	# runner.
	go test -p 1 -tags integrationtests -timeout 20m $pkgs
}

stage_fixtures() {
	local part=$1
	if [ ! -d tests/testdata ] || [ -z "$(ls -A tests/testdata)" ]; then
		git submodule update --init --depth 1 tests/testdata
	fi
	case "$part" in
	state) go test -timeout 20m -run '^TestState$' ./tests ;;
	blockchain) go test -timeout 20m -run '^TestBlockchain$' ./tests ;;
	other) go test -timeout 20m -skip '^(TestState|TestBlockchain)$' ./tests ;;
	esac
}

check_shards() {
	local all shard pkgs covered="" missing extra
	all="$(unit_packages | sort)"
	for shard in "${unit_shards[@]}"; do
		pkgs="$(shard_packages "$shard" $all)"
		if [ -z "$pkgs" ]; then
			echo "unit shard $shard has no packages"
			exit 1
		fi
		echo "$shard: $(echo "$pkgs" | wc -l | tr -d ' ') packages"
		covered="$covered$pkgs"$'\n'
	done
	covered="$(echo "$covered" | grep -v -x '' | sort)"
	if [ "$covered" != "$all" ]; then
		missing="$(comm -23 <(echo "$all") <(echo "$covered" | sort -u))"
		extra="$(echo "$covered" | uniq -d)"
		if [ -n "$missing" ]; then
			echo "Packages in no unit shard:"
			echo "$missing"
		fi
		if [ -n "$extra" ]; then
			echo "Packages in more than one unit shard:"
			echo "$extra"
		fi
		exit 1
	fi
	echo "Every package except $mod/tests is in exactly one unit shard."
}

list_stages() {
	local name
	echo typecheck
	echo build
	for name in "${unit_shards[@]}"; do
		echo "unit $name"
	done
	for name in "${fixture_parts[@]}"; do
		echo "fixtures $name"
	done
}

# Runs one stage in its own process, so that it stops at its first error, and
# writes its result next to its output.
run_buffered() {
	local stage=$1 dir=$2 file start
	file="$dir/${stage// /-}"
	start=$SECONDS
	if bash "$self" $stage >"$file.log" 2>&1; then
		echo "ok   $stage ($((SECONDS - start))s)"
		echo ok >"$file.result"
	else
		echo "FAIL $stage ($((SECONDS - start))s), last 100 lines:"
		tail -n 100 "$file.log"
		echo fail >"$file.result"
	fi
}

# Runs the given stages, GATE_JOBS at a time, and fails if any of them failed.
run_pool() {
	local jobs=${GATE_JOBS:-4} dir stage failed=""
	if ! [[ $jobs =~ ^[1-9][0-9]*$ ]]; then
		echo "GATE_JOBS must be a positive number, not $jobs"
		exit 2
	fi
	dir="$(mktemp -d)"
	# Expanded now: dir is local, and gone when the trap runs.
	trap "rm -rf '$dir'" EXIT
	for stage in "$@"; do
		while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do
			sleep 1
		done
		run_buffered "$stage" "$dir" &
	done
	wait
	for stage in "$@"; do
		if [ "$(cat "$dir/${stage// /-}.result" 2>/dev/null)" != ok ]; then
			failed="$failed  $stage"$'\n'
		fi
	done
	if [ -n "$failed" ]; then
		echo "Failed stages:"
		printf '%s' "$failed"
		return 1
	fi
	return 0
}

run_all() {
	local stage shards=() failed=""
	for stage in typecheck build; do
		echo "=== $stage"
		if ! bash "$self" "$stage"; then
			failed="$failed  $stage"$'\n'
		fi
	done
	for stage in "${unit_shards[@]}"; do
		shards+=("unit $stage")
	done
	for stage in "${fixture_parts[@]}"; do
		shards+=("fixtures $stage")
	done
	echo "=== unit and fixtures, ${GATE_JOBS:-4} at a time"
	if ! run_pool "${shards[@]}"; then
		failed="$failed  unit or fixtures"$'\n'
	fi
	if [ -n "$failed" ]; then
		echo "The gate failed:"
		printf '%s' "$failed"
		exit 1
	fi
	echo "The gate passed."
}

usage() {
	echo "usage: $0 [--list | --check-shards | typecheck | build | unit [shard] | fixtures [part]]" >&2
	exit 2
}

if [ $# -eq 0 ]; then
	run_all
	exit 0
fi

case "$1" in
--list)
	[ $# -eq 1 ] || usage
	list_stages
	;;
--check-shards)
	[ $# -eq 1 ] || usage
	check_shards
	;;
typecheck)
	[ $# -eq 1 ] || usage
	stage_typecheck
	;;
build)
	[ $# -eq 1 ] || usage
	stage_build
	;;
unit)
	if [ $# -eq 1 ]; then
		set --
		for shard in "${unit_shards[@]}"; do
			set -- "$@" "unit $shard"
		done
		run_pool "$@"
		exit
	fi
	[ $# -eq 2 ] || usage
	if ! known "$2" "${unit_shards[@]}"; then
		echo "unknown unit shard $2; the shards are: ${unit_shards[*]}" >&2
		exit 2
	fi
	stage_unit "$2"
	;;
fixtures)
	if [ $# -eq 1 ]; then
		set --
		for part in "${fixture_parts[@]}"; do
			set -- "$@" "fixtures $part"
		done
		run_pool "$@"
		exit
	fi
	[ $# -eq 2 ] || usage
	if ! known "$2" "${fixture_parts[@]}"; then
		echo "unknown fixtures part $2; the parts are: ${fixture_parts[*]}" >&2
		exit 2
	fi
	stage_fixtures "$2"
	;;
*)
	usage
	;;
esac
