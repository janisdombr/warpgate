#!/usr/bin/env bash
# Builds one arm's test binary from an exact commit and records what was built.
#
# usage: build-arm.sh LABEL SHA PACKAGE TARGET_NAME PACKAGE_DIR TEST_NAME \
#                     FINGERPRINT_FILE FINGERPRINT_REGEX EXPECTED_COUNT
#
# The arm is a detached worktree at SHA, never the checkout the workflow runs
# from, so an arm is the named tree and nothing else. The executable path comes
# from cargo's --message-format=json; a guessed deps/<name>-<hash> path can pick
# up a stale binary from the other arm. The fingerprint is a grep count of the
# line that tells the arms apart, printed and checked, because a label says
# which arm was meant and only the source says which was built.
#
# Writes $ARMS_DIR/LABEL/arm.env, sourced by run-interleaved.sh.
set -euo pipefail

label=$1 sha=$2 package=$3 target_name=$4 package_dir=$5 test_name=$6
fp_file=$7 fp_regex=$8 fp_expected=$9

: "${ARMS_DIR:?}"
: "${GITHUB_WORKSPACE:?}"
arm="$ARMS_DIR/$label"
src="$arm/src"
mkdir -p "$arm"

fail() { echo "::error::arm $label: $*"; exit 1; }

git -C "$GITHUB_WORKSPACE" worktree add --detach "$src" "$sha" > "$arm/worktree.log" 2>&1 \
  || { cat "$arm/worktree.log"; fail "cannot check out $sha"; }
actual=$(git -C "$src" rev-parse HEAD)
[ "$actual" = "$sha" ] || fail "checked out $actual, expected $sha"
[ -z "$(git -C "$src" status --porcelain --untracked-files=no)" ] || fail "worktree is not clean"

# One toolchain for both arms, or the comparison includes a compiler change.
cmp -s "$src/rust-toolchain.toml" "$GITHUB_WORKSPACE/rust-toolchain.toml" \
  || fail "rust-toolchain.toml differs from the workflow's"

fp_count=$(grep -cE -- "$fp_regex" "$src/$fp_file" || true)
echo "arm $label: source $actual; fingerprint grep -cE '$fp_regex' $fp_file = $fp_count (expected $fp_expected)"
[ "$fp_count" = "$fp_expected" ] || fail "fingerprint $fp_count != $fp_expected: this is not the tree the arm names"

set +e
(cd "$src" && cargo test -p "$package" --lib --no-run --locked --message-format=json) \
  > "$arm/build.json" 2> "$arm/build.log"
status=$?
set -e
[ "$status" -eq 0 ] || { tail -50 "$arm/build.log"; fail "build exited $status"; }

jq -r --arg n "$target_name" '
  select(.reason == "compiler-artifact"
         and .target.name == $n
         and .profile.test == true
         and (.target.kind | index("lib")))
  | .executable // empty' "$arm/build.json" > "$arm/executables.txt"
[ "$(wc -l < "$arm/executables.txt")" -eq 1 ] \
  || { cat "$arm/executables.txt"; fail "expected exactly one test executable for $target_name"; }
exe=$(cat "$arm/executables.txt")

cp "$exe" "$arm/test-bin"
exe_sha=$(sha256sum "$exe" | cut -d' ' -f1)
bin_sha=$(sha256sum "$arm/test-bin" | cut -d' ' -f1)
[ "$exe_sha" = "$bin_sha" ] || fail "copy of $exe does not match it"

listed=$("$arm/test-bin" --list --format terse 2>/dev/null | grep -cFx "$test_name: test" || true)
[ "$listed" = 1 ] || fail "test $test_name is listed $listed times in the binary, expected 1"

cat > "$arm/arm.env" <<EOF
ARM_LABEL=$label
ARM_SHA=$actual
ARM_BIN=$arm/test-bin
ARM_BIN_SHA256=$bin_sha
ARM_CWD=$src/$package_dir
ARM_CARGO_EXECUTABLE=$exe
ARM_FINGERPRINT_COUNT=$fp_count
EOF
echo "arm $label: binary sha256 $bin_sha (from $exe)"
