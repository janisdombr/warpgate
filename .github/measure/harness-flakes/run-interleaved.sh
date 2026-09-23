#!/usr/bin/env bash
# Runs one test in two arms, alternating batches, one process per trial.
#
# Environment:
#   MEASUREMENT  M1 | M3
#   CONDITION    idle | stressed   (stressed requires STRESS_PID of a live stress-ng)
#   N_PER_ARM    predeclared trial count per arm; never raised after a look
#   BATCH        trials per batch (50)
#   TEST_NAME    the exact libtest name, identical in both arms
#   ARM_A ARM_B  paths to arm.env files written by build-arm.sh; A runs first
#   OUT_DIR      rows, batch records and failure logs go here
#
# Every trial is an independent invocation of the arm's test binary, so each
# pays process start, runtime and TLS initialisation the way a CI job does. The
# rate is therefore a per-invocation rate, not an in-process loop rate.
#
# Exits non-zero if the stressor is not alive before and after every batch of a
# stressed cell, if a binary's hash changes, or if an arm does not end with
# exactly N_PER_ARM rows.
set -euo pipefail

: "${MEASUREMENT:?}" "${CONDITION:?}" "${N_PER_ARM:?}" "${BATCH:?}" "${TEST_NAME:?}"
: "${ARM_A:?}" "${ARM_B:?}" "${OUT_DIR:?}"

fail() { echo "::error::$MEASUREMENT/$CONDITION: $*"; exit 1; }

[ $((N_PER_ARM % BATCH)) -eq 0 ] || fail "N_PER_ARM=$N_PER_ARM is not a multiple of BATCH=$BATCH"
if [ "$CONDITION" = stressed ]; then
  : "${STRESS_PID:?a stressed cell needs STRESS_PID}"
fi

mkdir -p "$OUT_DIR/failures"
rows="$OUT_DIR/rows-$MEASUREMENT-$CONDITION.csv"
batches="$OUT_DIR/batches-$MEASUREMENT-$CONDITION.csv"
echo "measurement,condition,arm,source_sha,binary_sha256,batch,trial_in_arm,trial_global,started_utc,duration_ms,exit_code,outcome,class,panic_at,stress_pid" > "$rows"
echo "measurement,condition,arm,batch,stress_pid,alive_before,alive_after,workers_before,workers_after,loadavg_before,loadavg_after,binary_sha256_verified" > "$batches"

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

classify() {
  local code=$1 log=$2
  if [ "$code" -eq 124 ] || [ "$code" -eq 137 ]; then echo process_watchdog
  elif grep -q 'IncompleteMessage' "$log"; then echo incomplete_message
  elif grep -q 'stub failed before the crossing chunk' "$log"; then echo stub_failed_before_crossing
  elif grep -q 'did not deliver the body up to the limit' "$log"; then echo stub_short_before_crossing
  elif grep -qE 'IncompleteBody|UnexpectedEof' "$log"; then echo body_ended_early
  elif grep -q 'every event sent during the hold must have been taken off the channel' "$log"; then echo events_left_on_channel
  elif grep -q 'the hold does not resolve, so the pump should still be waiting' "$log"; then echo hold_resolved_early
  elif grep -q 'the pump stopped draining before it reached the disconnect' "$log"; then echo in_test_watchdog
  elif grep -q 'expected the body to be refused on size' "$log"; then echo not_refused_on_size
  else echo other
  fi
}

global=0
declare -A done_in_arm=([A]=0 [B]=0)
tmp=$(mktemp)
batches_per_arm=$((N_PER_ARM / BATCH))

for ((b = 0; b < batches_per_arm; b++)); do
  for key in A B; do
    alive_before=$(stress_ok)
    workers_before=$(workers)
    load_before=$(cut -d' ' -f1-3 /proc/loadavg)
    [ "$alive_before" != no ] || fail "stress-ng $STRESS_PID is gone before batch $b of arm ${LABEL[$key]}"

    now_sha=$(sha256sum "${BIN[$key]}" | cut -d' ' -f1)
    [ "$now_sha" = "${BIN_SHA[$key]}" ] || fail "binary of ${LABEL[$key]} changed: $now_sha"

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
        outcome=pass class=pass panic_at=
      else
        outcome=fail
        class=$(classify "$code" "$tmp")
        # A watchdog kill has no panic line; grep's exit 1 must not end the run.
        panic_at=$({ grep -oE 'panicked at [^ ]+' "$tmp" || true; } | head -1 | sed 's/panicked at //; s/:$//' | tr -d ',')
        cp "$tmp" "$OUT_DIR/failures/$MEASUREMENT-$CONDITION-${LABEL[$key]}-$global.log"
      fi
      echo "$MEASUREMENT,$CONDITION,${LABEL[$key]},${SHA[$key]},${BIN_SHA[$key]},$b,${done_in_arm[$key]},$global,$started,$duration_ms,$code,$outcome,$class,$panic_at,${STRESS_PID:-}" >> "$rows"
    done

    alive_after=$(stress_ok)
    workers_after=$(workers)
    load_after=$(cut -d' ' -f1-3 /proc/loadavg)
    echo "$MEASUREMENT,$CONDITION,${LABEL[$key]},$b,${STRESS_PID:-},$alive_before,$alive_after,$workers_before,$workers_after,$load_before,$load_after,yes" >> "$batches"
    [ "$alive_after" != no ] || fail "stress-ng $STRESS_PID died during batch $b of arm ${LABEL[$key]}"
    if [ "$CONDITION" = stressed ] && [ "$workers_after" -eq 0 ]; then
      fail "stress-ng $STRESS_PID has no workers after batch $b of arm ${LABEL[$key]}"
    fi
    echo "$MEASUREMENT/$CONDITION batch $b ${LABEL[$key]}: load $load_after, stress $alive_after ($workers_after workers)"
  done
done
rm -f "$tmp"

for key in A B; do
  count=$(awk -F, -v a="${LABEL[$key]}" 'NR > 1 && $3 == a' "$rows" | wc -l)
  failures=$(awk -F, -v a="${LABEL[$key]}" 'NR > 1 && $3 == a && $12 == "fail"' "$rows" | wc -l)
  echo "$MEASUREMENT/$CONDITION ${LABEL[$key]}: $count rows, $failures failures"
  [ "$count" -eq "$N_PER_ARM" ] || fail "${LABEL[$key]} produced $count rows, predeclared $N_PER_ARM"
done
