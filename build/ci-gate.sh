#!/usr/bin/env bash
# Runs the checks of CI's test jobs on any host. CI calls this script for each
# job, so the package sets and test commands live here and nowhere else.
#
# Usage:
#   build/ci-gate.sh                    the merge gate: every stage, or only the
#                                       checks of what the change touches (below)
#   build/ci-gate.sh --full             run every stage
#   build/ci-gate.sh --plan             print what the merge gate would run, run nothing
#   build/ci-gate.sh typecheck         gofmt, go mod tidy, go vet, release and link checks
#   build/ci-gate.sh build              build every command and run the real-proof tests
#   build/ci-gate.sh unit [shard]       one unit test shard, or all of them
#   build/ci-gate.sh fixtures [part]    one part of the Ethereum test fixtures, or all of them
#   build/ci-gate.sh --list             print the stage names and run nothing
#   build/ci-gate.sh --check-shards     fail unless the unit shards cover every package once
#   build/ci-gate.sh --prepare-fixtures fill the fixture test submodules and run nothing
#
# When several shards run, GATE_JOBS (default 4) of them run at once, each
# with its output kept aside; the last 100 lines of a failed shard are printed.
#
# The merge gate compares the work tree, untracked files included, with the
# merge base of HEAD and GATE_BASE (default origin/main, else main). When every
# changed file is in the install directory or is documentation (docs, *.md),
# it runs only:
#   gofmt of the changed Go files and go mod tidy, when Go files changed;
#   bash -n or sh -n of the changed shell scripts;
#   go vet and go test of the install directory's packages, when it changed;
#   go vet and go test of the packages whose Go files name a changed document,
#   or that sit in its directory; in the Ethereum fixture runner (tests), only
#   the tests of the test files that name it.
# With no base, nothing changed, any other changed path, or a document the
# fixture runner may read outside its own tests, every stage runs as --full.
# CI's jobs name their stage and are not scoped.
set -euo pipefail

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(git rev-parse --show-toplevel)"

mod=github.com/ethereum/go-ethereum
unit_shards=(consensus core core-sub eth eth-sub cmd p2p rest)
fixture_parts=(state blockchain other)
# The submodules the fixture tests read.
fixture_submodules=(tests/testdata tests/evm-benchmarks)

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
	echo "--- Release builds have no checkpoint override"
	# With cgo: the package links core, whose EVMC bindings need it, and a
	# release build of core links the proof verifier's library, built first.
	go run build/ci.go ghostverifier
	LIBRARY_PATH=build/cache/ghostverifier/release CGO_ENABLED=1 go test -tags ghostrelease -run '^TestReleaseHasNoCheckpointOverride$' ./eth/ethconfig
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
	local shard=$1 all pkgs home
	all="$(unit_packages)"
	pkgs="$(shard_packages "$shard" $all)"
	if [ -z "$pkgs" ]; then
		echo "unit shard $shard has no packages"
		exit 1
	fi
	# One package at a time, as upstream's CI does: several upstream tests
	# are timing-sensitive and fail when packages run in parallel on a small
	# runner.
	# The expected outputs of the float tests (metrics/influxdb among them)
	# were made on amd64, where Go does not fuse multiply and add. Other
	# architectures fuse them and round differently, so turn fusing off there;
	# GOCOMPILEDEBUG is part of the build cache key.
	if [ "$(go env GOARCH)" != amd64 ] && [ -z "${GOCOMPILEDEBUG:-}" ]; then
		export GOCOMPILEDEBUG=fmahash=qn
	fi
	# Some tests (internal/flags) expect ~ to expand to the account's home
	# from the user database, as it does on CI. Sandboxes may set HOME to
	# another directory; use the account's home then, keeping the Go caches
	# where they are.
	if command -v getent >/dev/null; then
		home="$(getent passwd "$(id -u)" | cut -d: -f6)"
		if [ -n "$home" ] && [ "$home" != "${HOME:-}" ] && [ -d "$home" ] && [ -w "$home" ]; then
			GOCACHE="$(go env GOCACHE)"
			GOMODCACHE="$(go env GOMODCACHE)"
			GOPATH="$(go env GOPATH)"
			export GOCACHE GOMODCACHE GOPATH HOME="$home"
		fi
	fi
	go test -p 1 -tags integrationtests -timeout 20m $pkgs
}

is_empty() {
	[ ! -d "$1" ] || [ -z "$(ls -A "$1")" ]
}

# Fills the submodule $2 of the repository $1 when it is empty, then every
# submodule nested in it (tests/testdata holds LegacyTests): a shallow fetch
# first, then the read-only copy $3 for hosts that cannot fetch.
fill_submodule() {
	local repo=$1 sub=$2 copy=$3 path nested
	path="$sub"
	if [ "$repo" != . ]; then
		path="$repo/$sub"
	fi
	if is_empty "$path"; then
		if git -C "$repo" submodule update --init --depth 1 "$sub" && ! is_empty "$path"; then
			:
		elif ! is_empty "$copy"; then
			echo "Could not fetch $path; copying it from $copy"
			mkdir -p "$path"
			cp -R "$copy/." "$path/"
		else
			echo "$path is empty: it could not be fetched, and there is no copy in $copy."
			echo "Run 'git submodule update --init --recursive --depth 1 ${fixture_submodules[*]}', or set GATE_FIXTURES_DIR to a directory holding a copy of it."
			exit 1
		fi
	fi
	if [ -f "$path/.gitmodules" ]; then
		while read -r _ nested; do
			fill_submodule "$path" "$nested" "$copy/$nested"
		done < <(git config -f "$path/.gitmodules" --get-regexp '^submodule\..*\.path$' || true)
	fi
}

# Fills every submodule the fixture tests read (tests/testdata and
# tests/evm-benchmarks, with the submodules nested in them) when it is empty.
# Hosts that cannot fetch read a read-only copy (GATE_FIXTURES_DIR, laid out as
# <dir>/testdata and <dir>/evm-benchmarks) instead.
prepare_fixtures() {
	local host=${GATE_FIXTURES_DIR:-/usr/local/share/fixtures-ghost-node}
	local path
	for path in "${fixture_submodules[@]}"; do
		fill_submodule . "$path" "$host/$(basename "$path")"
	done
}

stage_fixtures() {
	local part=$1
	prepare_fixtures
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
	# Once, before the parallel fixture parts would each fetch it at once.
	echo "=== fixture data"
	if ! bash "$self" --prepare-fixtures; then
		failed="$failed  fixture data"$'\n'
	fi
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

installer=install
# The Ethereum fixture runner, whose fixtures run only in the full gate.
fixture_dir=tests

scope=full
scope_reason=""
scope_base=""
changed=()
scoped_packages=()
fixture_tests=()

# Prints the scope of the repository path $1: installer, docs or full.
scope_of() {
	case "$1" in
	"$installer"/*) echo installer ;;
	docs/* | *.md) echo docs ;;
	*) echo full ;;
	esac
}

# Prints the commit the change is measured from.
base_commit() {
	local ref
	for ref in ${GATE_BASE:-origin/main main}; do
		if git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
			git merge-base HEAD "$ref"
			return
		fi
		if [ -n "${GATE_BASE:-}" ]; then
			echo "GATE_BASE $GATE_BASE is not a commit" >&2
		fi
	done
	return 1
}

# Prints every path that differs between the commit $1 and the work tree.
changed_files() {
	{
		git diff --name-only --no-renames --ignore-submodules=dirty "$1" --
		git ls-files --others --exclude-standard
	} | sort -u
}

add_scoped_package() {
	if ! known "$1" "${scoped_packages[@]+"${scoped_packages[@]}"}"; then
		scoped_packages+=("$1")
	fi
}

# Adds the tests of the fixture runner's test file $1. Fails when $1 is not a
# test file: what it does with the document may reach every fixture.
add_fixture_tests() {
	local file=$1 name
	case "$file" in
	*_test.go) ;;
	*) return 1 ;;
	esac
	while IFS= read -r name; do
		name="${name#func }"
		name="${name%(}"
		if ! known "$name" "${fixture_tests[@]+"${fixture_tests[@]}"}"; then
			fixture_tests+=("$name")
		fi
	done < <(grep -o -E '^func Test[A-Za-z0-9_]*\(' "$file" || true)
}

# Adds the package in directory $1, unless it is test data.
add_dir_package() {
	local dir=$1
	case "/$dir/" in
	*/testdata/* | */vendor/*) return 0 ;;
	esac
	if [ "$dir" = . ]; then
		add_scoped_package .
	else
		add_scoped_package "./$dir"
	fi
}

# Adds the packages that may read the document $1: those whose Go files name
# it, and a package in its own directory (go:embed). Fails when the fixture
# runner may read it outside its own tests.
add_doc_packages() {
	local doc=$1 file dir
	while IFS= read -r file; do
		dir="$(dirname "$file")"
		if [ "$dir" = "$fixture_dir" ]; then
			add_fixture_tests "$file" || return 1
		else
			add_dir_package "$dir"
		fi
	done < <(git grep -l -F -e "$(basename "$doc")" -- '*.go' || true)
	dir="$(dirname "$doc")"
	if [ -n "$(git ls-files -- ":(glob)$dir/*.go")" ]; then
		if [ "$dir" = "$fixture_dir" ]; then
			return 1
		fi
		add_dir_package "$dir"
	fi
	return 0
}

# Sets scope to scoped when the change allows it, and scope_reason to why.
decide_scope() {
	local path
	if ! scope_base="$(base_commit)"; then
		scope_reason="there is no base to compare against"
		return
	fi
	while IFS= read -r path; do
		if [ -n "$path" ]; then
			changed+=("$path")
		fi
	done < <(changed_files "$scope_base")
	if [ ${#changed[@]} -eq 0 ]; then
		scope_reason="nothing differs from the base $scope_base"
		return
	fi
	for path in "${changed[@]}"; do
		case "$(scope_of "$path")" in
		installer)
			add_scoped_package "./$installer/..."
			;;
		docs)
			if ! add_doc_packages "$path"; then
				scope_reason="$path may be read by the Ethereum fixtures"
				return
			fi
			;;
		*)
			scope_reason="$path is outside the install directory and the docs"
			return
			;;
		esac
	done
	scope=scoped
	scope_reason="every changed file is in the install directory or is documentation"
}

print_plan() {
	local path
	echo "$scope"
	echo "reason: $scope_reason"
	echo "base: ${scope_base:-none}"
	for path in "${changed[@]+"${changed[@]}"}"; do
		echo "changed: $path"
	done
	if [ "$scope" = scoped ]; then
		for path in "${scoped_packages[@]+"${scoped_packages[@]}"}"; do
			echo "package: $path"
		done
		for path in "${fixture_tests[@]+"${fixture_tests[@]}"}"; do
			echo "fixture runner test: $path"
		done
	fi
}

run_scoped() {
	local path go_files=() sh_files=() gofmt unformatted names
	for path in "${changed[@]}"; do
		if [ ! -f "$path" ]; then
			continue
		fi
		case "$path" in
		*.go) go_files+=("$path") ;;
		*.sh) sh_files+=("$path") ;;
		esac
	done
	if [ ${#go_files[@]} -gt 0 ]; then
		echo "--- gofmt"
		gofmt="$(go env GOROOT)/bin/gofmt"
		unformatted="$("$gofmt" -l "${go_files[@]}")"
		if [ -n "$unformatted" ]; then
			echo "These files need gofmt:"
			echo "$unformatted"
			exit 1
		fi
		echo "--- go mod tidy"
		go mod tidy -diff
	fi
	if [ ${#sh_files[@]} -gt 0 ]; then
		echo "--- shell syntax"
		for path in "${sh_files[@]}"; do
			if head -n 1 "$path" | grep -q bash; then
				bash -n "$path"
			else
				sh -n "$path"
			fi
		done
	fi
	if [ ${#scoped_packages[@]} -eq 0 ] && [ ${#fixture_tests[@]} -eq 0 ]; then
		echo "No Go package reads the changed files."
	fi
	if [ ${#scoped_packages[@]} -gt 0 ]; then
		echo "--- go vet"
		go vet -tags integrationtests "${scoped_packages[@]}"
		echo "--- go test"
		go test -tags integrationtests -timeout 20m "${scoped_packages[@]}"
	fi
	if [ ${#fixture_tests[@]} -gt 0 ]; then
		names="$(
			IFS='|'
			echo "${fixture_tests[*]}"
		)"
		echo "--- fixture runner tests that read the changed documents"
		go test -timeout 20m -run "^($names)\$" "./$fixture_dir"
	fi
	echo "The scoped gate passed."
}

# The merge gate: every stage, unless the change allows the scoped checks.
run_merge_gate() {
	decide_scope
	echo "=== $scope gate: $scope_reason"
	if [ "$scope" = scoped ]; then
		run_scoped
	else
		run_all
	fi
}

usage() {
	echo "usage: $0 [--full | --plan | --list | --check-shards | --prepare-fixtures | typecheck | build | unit [shard] | fixtures [part]]" >&2
	exit 2
}

if [ $# -eq 0 ]; then
	run_merge_gate
	exit 0
fi

case "$1" in
--full)
	[ $# -eq 1 ] || usage
	run_all
	;;
--plan)
	[ $# -eq 1 ] || usage
	decide_scope
	print_plan
	;;
--list)
	[ $# -eq 1 ] || usage
	list_stages
	;;
--check-shards)
	[ $# -eq 1 ] || usage
	check_shards
	;;
--prepare-fixtures)
	[ $# -eq 1 ] || usage
	prepare_fixtures
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
		prepare_fixtures
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
