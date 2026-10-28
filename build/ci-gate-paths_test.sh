#!/usr/bin/env bash
# Tests the merge gate's path selection in build/ci-gate.sh: a change only in
# the install directory or the docs runs the scoped checks, any other change
# runs every stage. Each case runs the gate in a scratch repository with a fake
# go tool that records its arguments, so nothing real is built or tested.
#
# Usage: bash build/ci-gate-paths_test.sh
set -euo pipefail

gate="$(cd "$(dirname "$0")" && pwd)/ci-gate.sh"
inst=install
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

tools="$tmp/tools"
mkdir -p "$tools/bin" "$tools/goroot/bin"
golog="$tools/go.log"

# The fake go: logs each call; `go env GOROOT` names a root whose gofmt lists
# the files in FAKE_GOFMT_LIST; `go test` fails when FAKE_GO_TEST_FAIL is set;
# `go list` prints nothing, so the full gate's unit shards stop at once.
cat >"$tools/bin/go" <<EOF
#!/usr/bin/env bash
echo "go \$*" >>"$golog"
case "\$1 \${2:-}" in
"env GOROOT") echo "$tools/goroot" ;;
"env GOARCH") echo amd64 ;;
"env "*) echo "$tools/cache" ;;
"test "*) [ -z "\${FAKE_GO_TEST_FAIL:-}" ] ;;
esac
EOF
cat >"$tools/goroot/bin/gofmt" <<'EOF'
#!/usr/bin/env bash
if [ -n "${FAKE_GOFMT_LIST:-}" ]; then
	echo "$FAKE_GOFMT_LIST"
fi
EOF
chmod +x "$tools/bin/go" "$tools/goroot/bin/gofmt"

export PATH="$tools/bin:$PATH"
export GATE_BASE=main
export GATE_JOBS=8
export GATE_FIXTURES_DIR="$tmp/no-fixtures"
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
unset FAKE_GOFMT_LIST FAKE_GO_TEST_FAIL

failures=0
cases=0
repo=""
out=""
status=0

fail() {
	echo "FAIL: $current: $*"
	echo "--- gate output"
	echo "$out"
	echo "--- go calls"
	cat "$golog" 2>/dev/null || true
	failures=$((failures + 1))
}

# Makes a fresh repository with one commit on main, and a change branch.
new_repo() {
	current=$1
	cases=$((cases + 1))
	repo="$tmp/repo-$cases"
	mkdir -p "$repo/build" "$repo/$inst" "$repo/docs" "$repo/p2p" "$repo/tests" "$repo/rpc"
	cp "$gate" "$repo/build/ci-gate.sh"
	printf 'module example.com/ghost\n\ngo 1.22\n' >"$repo/go.mod"
	printf '#!/usr/bin/env bash\necho install\n' >"$repo/$inst/install.sh"
	printf 'package install\n' >"$repo/$inst/install_test.go"
	printf '# Mining\n' >"$repo/docs/mining.md"
	printf '# Fixture notes\n' >"$repo/docs/fixture-notes.md"
	printf '# Fixture runner notes\n' >"$repo/docs/runner-notes.md"
	printf '# API\n' >"$repo/docs/api.md"
	printf '# Ghost\n' >"$repo/README.md"
	printf 'package p2p\n' >"$repo/p2p/server.go"
	printf 'package tests\n\nfunc TestFixtureNotes(t *testing.T) { _ = "fixture-notes.md" }\nfunc TestOther(t *testing.T) {}\n' >"$repo/tests/notes_test.go"
	printf 'package tests\n\nvar notes = "runner-notes.md"\n' >"$repo/tests/init.go"
	printf 'package rpc\n\nvar doc = "api.md"\n' >"$repo/rpc/docs.go"
	git -C "$repo" init -q -b main
	git -C "$repo" add -A
	git -C "$repo" commit -q -m base
	git -C "$repo" checkout -q -b change
	: >"$golog"
}

commit_change() {
	git -C "$repo" add -A
	git -C "$repo" commit -q -m change
}

# Runs the gate with the arguments given; sets out and status.
run_gate() {
	status=0
	out="$(cd "$repo" && bash build/ci-gate.sh "$@" 2>&1)" || status=$?
}

expect_plan() {
	local want=$1 got
	run_gate --plan
	# The first line of the plan; warnings on stderr may come before it.
	got="$(echo "$out" | grep -x -E 'full|scoped' | head -n 1 || true)"
	if [ "$status" -ne 0 ]; then
		fail "--plan exited $status"
	elif [ "$got" != "$want" ]; then
		fail "plan is ${got:-missing}, want $want"
	fi
}

expect_out() {
	if ! echo "$out" | grep -q -F -x -e "$1"; then
		fail "output has no line: $1"
	fi
}

expect_go() {
	if ! grep -q -F -x -e "go $1" "$golog"; then
		fail "go was not called as: go $1"
	fi
}

expect_no_go() {
	if grep -q -F -e "go $1" "$golog"; then
		fail "go was called as: go $1"
	fi
}

# The full gate ran: its first stage, the whole-repository vet, the build.
expect_full_run() {
	if ! echo "$out" | grep -q -F -e "=== full gate:"; then
		fail "the merge gate did not choose the full gate"
	fi
	expect_out "=== typecheck"
	expect_out "=== build"
	expect_go "vet -tags integrationtests ./..."
	expect_go "run build/ci.go install"
	if echo "$out" | grep -q -F -e "The scoped gate passed."; then
		fail "the scoped gate ran"
	fi
}

expect_scoped_run() {
	if [ "$status" -ne 0 ]; then
		fail "the scoped gate exited $status"
	fi
	expect_out "The scoped gate passed."
	expect_no_go "vet -tags integrationtests ./..."
	expect_no_go "run build/ci.go"
	if echo "$out" | grep -q -F -e "=== typecheck"; then
		fail "the full gate ran"
	fi
}

# --- Changes the scoped gate covers

new_repo "an install script change"
printf '#!/usr/bin/env bash\necho install again\n' >"$repo/$inst/install.sh"
commit_change
expect_plan scoped
expect_out "package: ./$inst/..."
expect_out "changed: $inst/install.sh"
run_gate
expect_scoped_run
expect_go "vet -tags integrationtests ./$inst/..."
expect_go "test -tags integrationtests -timeout 20m ./$inst/..."
expect_out "--- shell syntax"
expect_no_go "mod tidy -diff"

new_repo "an install script and its Go test"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
printf 'package install\n\n// changed\n' >"$repo/$inst/install_test.go"
commit_change
expect_plan scoped
run_gate
expect_scoped_run
expect_go "mod tidy -diff"
expect_go "test -tags integrationtests -timeout 20m ./$inst/..."

new_repo "an uncommitted install change"
printf '#!/usr/bin/env bash\necho work tree\n' >"$repo/$inst/install.sh"
expect_plan scoped
expect_out "changed: $inst/install.sh"

new_repo "a new untracked file in the install directory"
printf 'notes\n' >"$repo/$inst/NOTES.txt"
expect_plan scoped

new_repo "a doc no Go file reads"
printf '# Mining, changed\n' >"$repo/docs/mining.md"
printf '# Ghost, changed\n' >"$repo/README.md"
commit_change
expect_plan scoped
run_gate
expect_scoped_run
expect_out "No Go package reads the changed files."
expect_no_go "test"

new_repo "a doc a Go package reads"
printf '# API, changed\n' >"$repo/docs/api.md"
commit_change
expect_plan scoped
expect_out "package: ./rpc"
run_gate
expect_scoped_run
expect_go "test -tags integrationtests -timeout 20m ./rpc"

new_repo "a doc a fixture runner test reads"
printf '# Fixture notes, changed\n' >"$repo/docs/fixture-notes.md"
commit_change
expect_plan scoped
expect_out "fixture runner test: TestFixtureNotes"
run_gate
expect_scoped_run
expect_go "test -timeout 20m -run ^(TestFixtureNotes|TestOther)\$ ./tests"
expect_no_go "-run ^TestState\$"

new_repo "an install change and a doc"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
printf '# Mining, changed\n' >"$repo/docs/mining.md"
commit_change
expect_plan scoped

# --- The scoped gate fails what it checks

new_repo "an install script with a syntax error"
printf '#!/usr/bin/env bash\nif then fi (\n' >"$repo/$inst/install.sh"
commit_change
run_gate
if [ "$status" -eq 0 ]; then
	fail "the gate passed a script that does not parse"
fi
expect_no_go "test"

new_repo "a failing install test"
printf 'package install\n\n// changed\n' >"$repo/$inst/install_test.go"
commit_change
FAKE_GO_TEST_FAIL=1 run_gate
if [ "$status" -eq 0 ]; then
	fail "the gate passed a failing go test"
fi

new_repo "an unformatted install Go file"
printf 'package install\n\n// changed\n' >"$repo/$inst/install_test.go"
commit_change
FAKE_GOFMT_LIST="$inst/install_test.go" run_gate
if [ "$status" -eq 0 ]; then
	fail "the gate passed a file gofmt lists"
fi
expect_out "These files need gofmt:"

# --- Changes that run the full gate

new_repo "an install change and a node change"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
printf 'package p2p\n\n// changed\n' >"$repo/p2p/server.go"
commit_change
expect_plan full
expect_out "reason: p2p/server.go is outside the install directory and the docs"
run_gate
expect_full_run
if [ "$status" -eq 0 ]; then
	fail "the full gate passed with a fake go and no fixtures"
fi

new_repo "a node change only"
printf 'package p2p\n\n// changed\n' >"$repo/p2p/server.go"
commit_change
expect_plan full
run_gate
expect_full_run

new_repo "a go.mod change"
printf 'module example.com/ghost\n\ngo 1.23\n' >"$repo/go.mod"
commit_change
expect_plan full

new_repo "a build script change"
printf '\n# changed\n' >>"$repo/build/ci-gate.sh"
commit_change
expect_plan full

new_repo "a file next to the install directory"
mkdir -p "$repo/installer-tools"
printf 'x\n' >"$repo/installer-tools/x.sh"
printf 'x\n' >"$repo/${inst}.sh"
commit_change
expect_plan full

new_repo "an untracked file outside the scoped paths"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
commit_change
printf 'x\n' >"$repo/p2p/new.go"
expect_plan full

new_repo "a deleted node file"
git -C "$repo" rm -q p2p/server.go
commit_change
expect_plan full

new_repo "a doc the fixture runner reads outside its tests"
printf '# Fixture runner notes, changed\n' >"$repo/docs/runner-notes.md"
commit_change
expect_plan full
expect_out "reason: docs/runner-notes.md may be read by the Ethereum fixtures"

new_repo "a doc in the fixture runner's directory"
printf '# Notes\n' >"$repo/tests/NOTES.md"
commit_change
expect_plan full

new_repo "nothing changed"
expect_plan full
expect_out "reason: nothing differs from the base $(git -C "$repo" rev-parse main)"

new_repo "no base"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
commit_change
GATE_BASE=no-such-branch expect_plan full
expect_out "reason: there is no base to compare against"

new_repo "a branch behind main"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
commit_change
git -C "$repo" checkout -q main
printf 'package p2p\n\n// on main\n' >"$repo/p2p/server.go"
git -C "$repo" commit -q -a -m "main moved"
git -C "$repo" checkout -q change
expect_plan scoped

# --- Named stages and --full are not scoped

new_repo "--full on an install change"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
commit_change
run_gate --full
expect_out "=== typecheck"
expect_go "vet -tags integrationtests ./..."

new_repo "the typecheck stage on an install change"
printf '#!/usr/bin/env bash\necho changed\n' >"$repo/$inst/install.sh"
commit_change
run_gate typecheck
expect_go "vet -tags integrationtests ./..."

echo "$cases cases, $failures failures"
if [ "$failures" -ne 0 ]; then
	exit 1
fi
