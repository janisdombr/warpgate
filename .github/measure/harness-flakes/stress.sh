# Sourced, not executed: the EXIT trap has to belong to the step's own shell so
# the stressor dies with the step, and so does every check against it.
#
# The one stress recipe for every stressed cell. The timeout is longer than any
# job's timeout-minutes, so stress-ng cannot end on its own while trials run —
# if it is gone, something killed it, and the cell fails rather than letting its
# tail be measured idle under a "stressed" label.

STRESS_TIMEOUT=3h
STRESS_METHOD=matrixprod

stress_start() {
  local out=$1
  STRESS_ARGS=(--cpu "$(nproc)" --cpu-method "$STRESS_METHOD" --timeout "$STRESS_TIMEOUT" --metrics-brief)
  stress-ng "${STRESS_ARGS[@]}" > "$out/stress-ng.log" 2>&1 &
  STRESS_PID=$!
  export STRESS_PID
  trap stress_stop EXIT
  # Workers are forked after the parent starts; give them time to be running
  # before the first trial counts as stressed.
  sleep 5
  if ! stress_alive; then
    echo "::error::stress-ng (pid $STRESS_PID) is not running after start"
    cat "$out/stress-ng.log"
    exit 1
  fi
  {
    echo "stress_version=$(stress-ng --version 2>&1 | head -1)"
    echo "stress_args=${STRESS_ARGS[*]}"
    echo "stress_pid=$STRESS_PID"
    echo "stress_workers_at_start=$(stress_workers)"
    echo "nproc=$(nproc)"
    echo "loadavg_at_start=$(cat /proc/loadavg)"
  } | tee "$out/stress.meta"
}

stress_alive() {
  [ -n "${STRESS_PID:-}" ] || return 1
  kill -0 "$STRESS_PID" 2> /dev/null || return 1
  # Guards against a recycled PID that belongs to something else.
  case "$(cat "/proc/$STRESS_PID/comm" 2> /dev/null)" in
    stress-ng*) ;;
    *) return 1 ;;
  esac
  # The step shell is its parent and does not reap it until the trap runs, so
  # a stress-ng that died mid-cell is a zombie — and `kill -0` and `comm` both
  # still answer for a zombie.
  [ "$(sed 's/.*) //' "/proc/$STRESS_PID/stat" 2> /dev/null | cut -d' ' -f1)" != Z ]
}

stress_workers() {
  # pgrep exits 1 when it finds no workers, which under pipefail would end
  # the caller silently instead of letting it report the dead stressor.
  { pgrep -P "$STRESS_PID" 2> /dev/null || true; } | wc -l
}

stress_stop() {
  if [ -n "${STRESS_PID:-}" ]; then
    kill -TERM "$STRESS_PID" 2> /dev/null || true
    wait "$STRESS_PID" 2> /dev/null || true
  fi
}
