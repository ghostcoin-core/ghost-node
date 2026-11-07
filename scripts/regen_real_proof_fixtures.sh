#!/usr/bin/env bash
# Regenerates the committed real-proof fixtures whose recorded request no
# longer matches the chain the tests build, for example after a change to the
# Ghost header layout moves the genesis hash.
#
# For each fixture it first runs the tagged test that reads it. A fixture
# that passes is kept as it is. A fixture that fails because it was made for
# another chain (or, for the action fixtures, another action) is made again:
#
#  1. the test writes its proof request, with
#     GHOST_REAL_PROOF_REQUEST=<file> CGO_ENABLED=1 go test -tags ghostproofs
#     -run '^<Test>$' <pkg>;
#  2. the pinned verifier crate's example proves it, offline:
#     cargo run --release --locked --offline --example <example>
#     (the data lifecycle fixture with --features unsettled-points-test);
#  3. the output is compressed with gzip -n -9 into the package's testdata,
#     so the same proof gives the same bytes;
#  4. the test runs again and must pass.
#
# Any other failure stops the script with the test's output. Run it from
# anywhere; it works in the repository root.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

crate=ghostverifier
out=build
lib="$out/cache/$crate/release/lib$crate.a"

# The tagged tests link the static library the gate builds; build it when
# this checkout does not have it yet.
if [[ ! -f "$lib" ]]; then
	echo "building lib$crate.a"
	go run "./$out/ci.go" "$crate"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# name|package|test|example|cargo features
fixtures=(
	"real_reveal|core/txpool/ghostpool|TestRealProofRevealPoolAndBlock|revealfixture|"
	"pool_action|core/txpool/ghostpool|TestRealProofPolicyActionAdmission|actionfixture|"
	"real_data_lifecycle|core/txpool/ghostpool|TestRealProofDataLifecycle|datalifecyclefixture|unsettled-points-test"
	"know_action|core/ghostpriv|TestRealProofPolicyAction|actionfixture|"
)

# tagged_test runs one tagged test of a package, with the rest of the
# arguments as extra environment.
tagged_test() {
	local pkg=$1 test=$2
	shift 2
	env "$@" CGO_ENABLED=1 go test -tags ghostproofs -count=1 -run "^${test}\$" "./$pkg/"
}

regenerated=0
for entry in "${fixtures[@]}"; do
	IFS='|' read -r name pkg test example features <<<"$entry"
	dest="$pkg/testdata/$name.bin.gz"
	log="$tmp/$name.log"

	if tagged_test "$pkg" "$test" >"$log" 2>&1; then
		echo "$dest: up to date"
		continue
	fi
	if ! grep -q -e 'made for another chain' -e 'is not for this action' "$log"; then
		cat "$log"
		echo "$dest: $test fails for another reason than a stale fixture" >&2
		exit 1
	fi
	echo "$dest: made for another chain, regenerating"

	req="$tmp/$name.req"
	tagged_test "$pkg" "$test" "GHOST_REAL_PROOF_REQUEST=$req"
	if [[ ! -s "$req" ]]; then
		echo "$dest: $test wrote no request to $req" >&2
		exit 1
	fi

	cargo_args=(run --release --locked --offline --manifest-path "$crate/Cargo.toml")
	if [[ -n "$features" ]]; then
		cargo_args+=(--features "$features")
	fi
	cargo "${cargo_args[@]}" --example "$example" -- "$req" "$tmp/$name.bin"

	gzip -n -9 -c "$tmp/$name.bin" >"$tmp/$name.bin.gz"
	mv "$tmp/$name.bin.gz" "$dest"

	if ! tagged_test "$pkg" "$test" >"$log" 2>&1; then
		cat "$log"
		echo "$dest: $test still fails with the regenerated fixture" >&2
		exit 1
	fi
	echo "$dest: regenerated and verified"
	regenerated=$((regenerated + 1))
done
echo "regenerated $regenerated of ${#fixtures[@]} fixtures"
