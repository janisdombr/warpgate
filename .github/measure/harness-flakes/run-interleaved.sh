#!/usr/bin/env bash
# Runs one test in two arms, alternating batches, one process per trial.
#
# Environment:
#   MEASUREMENT  M1 | M3
#   CONDITION    idle | stressed   (stressed requires STRESS_PID of a live stress-ng)
#   N_PER_ARM    predeclared trial count per arm; never raised after a look
#   BATCH        trials per batch (50)
#   TEST_NAME    the exact libtest name, identical in both arms
#   ARM_A ARM_B  paths to arm.env files written by build-arm.sh; A is the baseline
#   DEFECT_CLASS the one predeclared class that counts as `fail`
#   OUT_DIR      rows, batch records and failure logs go here
#
# Every trial is an independent invocation of the arm's test binary, so each
# pays process start, runtime and TLS initialisation the way a CI job does. The
# rate is therefore a per-invocation rate, not an in-process loop rate.
#
# Even batches run A then B, odd batches B then A, so neither arm always runs
# second on a runner that drifts; the order is recorded in every row.
#
# Only DEFECT_CLASS is a `fail`. Any other non-pass (a watchdog kill, zero tests
# matched, a binary that changed, an unexpected panic) is `invalid`: kept with
# its class, never a failure of the arm, and report.py refuses the comparison.
#
# Exits non-zero if the stressor is not alive before and after every batch of a
# stressed cell, if a binary's hash changes (after writing an `invalid` row for
# it), or if an arm does not end with exactly N_PER_ARM trial rows.
set -euo pipefail

: "${MEASUREMENT:?}" "${CONDITION:?}" "${N_PER_ARM:?}" "${BATCH:?}" "${TEST_NAME:?}"
: "${ARM_A:?}" "${ARM_B:?}" "${DEFECT_CLASS:?}" "${OUT_DIR:?}"

fail() { echo "::error::$MEASUREMENT/$CONDITION: $*"; exit 1; }

[ $((N_PER_ARM % BATCH)) -eq 0 ] || fail "N_PER_ARM=$N_PER_ARM is not a multiple of BATCH=$BATCH"
if [ "$CONDITION" = stressed ]; then
  : "${STRESS_PID:?a stressed cell needs STRESS_PID}"
fi

mkdir -p "$OUT_DIR/failures"
rows="$OUT_DIR/rows-$MEASUREMENT-$CONDITION.csv"
batches="$OUT_DIR/batches-$MEASUREMENT-$CONDITION.csv"
echo "measurement,condition,arm,source_sha,binary_sha256,batch,batch_order,slot,trial_in_arm,trial_global,started_utc,duration_ms,exit_code,outcome,class,detail,panic_at,stress_pid" > "$rows"
echo "measurement,condition,arm,batch,batch_order,slot,stress_pid,alive_before,alive_after,workers_before,workers_after,loadavg_before,loadavg_after,binary_sha256_verified" > "$batches"

declare -A LABEL SHA BIN BIN_SHA CWD
for key in A B; do
  if [ "$key" = A ]; then env_file=$ARM_A; else env_file=$ARM_B; fi
  # shellcheck disable=SC1090
  source "$env_file"
  LABEL[$key]=$ARM_LABEL SHA[$key]=$ARM_SHA BIN[$key]=$ARM_BIN BIN_SHA[$key]=$ARM_BIN_SHA256 CWD[$key]=$ARM_CWD
  echo "arm $key = ${LABEL[$key]}: source ${SHA[$key]}, binary sha256 ${BIN_SHA[$key]}, fingerprint count $ARM_FINGERPRINT_COUNT"
done

stress_ok() {
  [ "$CONDITION" = stressed ] || { echo na; return; }
  # A dead stress-ng stays a zombie until the step shell reaps it, and a
  # zombie still answers `kill -0`; its state has to be read.
  if kill -0 "$STRESS_PID" 2> /dev/null \
    && grep -q '^stress-ng' "/proc/$STRESS_PID/comm" 2> /dev/null \
    && [ "$(sed 's/.*) //' "/proc/$STRESS_PID/stat" 2> /dev/null | cut -d' ' -f1)" != Z ]; then
    echo yes
  else
    echo no
  fi
}
workers() {
  [ "$CONDITION" = stressed ] || { echo na; return; }
  # pgrep exits 1 when it finds no workers, which under pipefail would end
  # the caller silently instead of letting it report the dead stressor.
  { pgrep -P "$STRESS_PID" 2> /dev/null || true; } | wc -l
}

# By the assertion that fired, read from the arms' sources: C0 and C1 share the
# hold-drain message, C0 and C2 the size-refusal one. The transport symptom
# under a size-refusal panic is `detail`, not the class.
classify() {
  local code=$1 log=$2
  if [ "$code" -eq 124 ] || [ "$code" -eq 137 ]; then echo process_watchdog
  elif grep -qE '^running 0 tests|^test result: ok\. 0 passed' "$log"; then echo zero_tests_matched
  elif grep -q 'every event sent during the hold must have been taken off the channel' "$log"; then echo events_left_on_channel
  elif grep -q 'expected the body to be refused on size' "$log"; then echo not_refused_on_size
  elif grep -q 'the hold does not resolve, so the pump should still be waiting' "$log"; then echo hold_resolved_early
  elif grep -q 'the hold never resolves, so only the viewer' "$log"; then echo hold_ended_without_disconnect
  elif grep -q 'the pump stopped draining before it reached the disconnect' "$log"; then echo in_test_watchdog
  elif grep -q 'stub failed before the crossing chunk' "$log"; then echo stub_failed_before_crossing
  elif grep -q 'did not deliver the body up to the limit' "$log"; then echo stub_short_before_crossing
  elif grep -q 'the stub never finished answering' "$log"; then echo stub_hung
  elif grep -q 'no signing request was made' "$log"; then echo no_signing_request
  else echo other
  fi
}
detail() {
  local log=$1
  if grep -q 'IncompleteMessage' "$log"; then echo incomplete_message
  elif grep -qE 'IncompleteBody|UnexpectedEof' "$log"; then echo body_ended_early
  fi
}

global=0
declare -A done_in_arm=([A]=0 [B]=0)
tmp=$(mktemp)
batches_per_arm=$((N_PER_ARM / BATCH))

invalid=0
# The row a trial writes, and the row a binary mismatch writes before failing.
row() {
  echo "$MEASUREMENT,$CONDITION,${LABEL[$key]},${SHA[$key]},$1,$b,$order,$slot,$2,$global,$3,$4,$5,$6,$7,$8,$9,${STRESS_PID:-}" >> "$rows"
}
check_binary() {
  local now_sha
  now_sha=$(sha256sum "${BIN[$key]}" | cut -d' ' -f1)
  if [ "$now_sha" != "${BIN_SHA[$key]}" ]; then
    row "$now_sha" "${done_in_arm[$key]}" "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "" "" invalid binary_mismatch "$1" ""
    fail "binary of ${LABEL[$key]} changed $1 batch $b: $now_sha"
  fi
}

for ((b = 0; b < batches_per_arm; b++)); do
  if ((b % 2 == 0)); then keys=(A B) order=AB; else keys=(B A) order=BA; fi
  slot=0
  for key in "${keys[@]}"; do
    slot=$((slot + 1))
    alive_before=$(stress_ok)
    workers_before=$(workers)
    load_before=$(cut -d' ' -f1-3 /proc/loadavg)
    [ "$alive_before" != no ] || fail "stress-ng $STRESS_PID is gone before batch $b of arm ${LABEL[$key]}"

    check_binary before

    for ((t = 0; t < BATCH; t++)); do
      global=$((global + 1))
      done_in_arm[$key]=$((${done_in_arm[$key]} + 1))
      started=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
      t0=$(date +%s%N)
      set +e
      (cd "${CWD[$key]}" && timeout --kill-after=10 300 "${BIN[$key]}" --exact "$TEST_NAME" --test-threads=1) > "$tmp" 2>&1
      code=$?
      set -e
      t1=$(date +%s%N)
      duration_ms=$(((t1 - t0) / 1000000))
      # Exit 0 alone also fits a filter that matched nothing.
      if [ "$code" -eq 0 ] && grep -q '^test result: ok\. 1 passed' "$tmp"; then
        outcome=pass class=pass why= panic_at=
      else
        class=$(classify "$code" "$tmp")
        why=$(detail "$tmp")
        if [ "$class" = "$DEFECT_CLASS" ]; then
          outcome=fail
        else
          outcome=invalid invalid=$((invalid + 1))
        fi
        # A watchdog kill has no panic line; grep's exit 1 must not end the run.
        panic_at=$({ grep -oE 'panicked at [^ ]+' "$tmp" || true; } | head -1 | sed 's/panicked at //; s/:$//' | tr -d ',')
        cp "$tmp" "$OUT_DIR/failures/$MEASUREMENT-$CONDITION-${LABEL[$key]}-$global-$outcome.log"
      fi
      row "${BIN_SHA[$key]}" "${done_in_arm[$key]}" "$started" "$duration_ms" "$code" "$outcome" "$class" "$why" "$panic_at"
    done

    check_binary after

    alive_after=$(stress_ok)
    workers_after=$(workers)
    load_after=$(cut -d' ' -f1-3 /proc/loadavg)
    echo "$MEASUREMENT,$CONDITION,${LABEL[$key]},$b,$order,$slot,${STRESS_PID:-},$alive_before,$alive_after,$workers_before,$workers_after,$load_before,$load_after,yes" >> "$batches"
    [ "$alive_after" != no ] || fail "stress-ng $STRESS_PID died during batch $b of arm ${LABEL[$key]}"
    if [ "$CONDITION" = stressed ] && [ "$workers_after" -eq 0 ]; then
      fail "stress-ng $STRESS_PID has no workers after batch $b of arm ${LABEL[$key]}"
    fi
    echo "$MEASUREMENT/$CONDITION batch $b ($order) ${LABEL[$key]}: load $load_after, stress $alive_after ($workers_after workers)"
  done
done
rm -f "$tmp"

# Column 14 is `outcome`.
for key in A B; do
  count=$(awk -F, -v a="${LABEL[$key]}" 'NR > 1 && $3 == a' "$rows" | wc -l)
  failures=$(awk -F, -v a="${LABEL[$key]}" 'NR > 1 && $3 == a && $14 == "fail"' "$rows" | wc -l)
  bad=$(awk -F, -v a="${LABEL[$key]}" 'NR > 1 && $3 == a && $14 == "invalid"' "$rows" | wc -l)
  echo "$MEASUREMENT/$CONDITION ${LABEL[$key]}: $count rows, $failures $DEFECT_CLASS failures, $bad invalid"
  [ "$count" -eq "$N_PER_ARM" ] || fail "${LABEL[$key]} produced $count rows, predeclared $N_PER_ARM"
done
# The cell still finishes, so a later cell is not lost to one bad trial; the
# report is what refuses it.
[ "$invalid" -eq 0 ] || echo "::warning::$MEASUREMENT/$CONDITION: $invalid invalid trials; the report will refuse this comparison"
