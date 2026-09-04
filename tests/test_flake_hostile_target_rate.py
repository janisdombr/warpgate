"""Throwaway CI harness. Not a regression test — a measuring instrument.

https://github.com/warp-tech/warpgate/issues/2520: a target that sends garbage
right after its SSH banner is detected and closed by the gateway inside the
same second (the gateway's own log and audit line say so), and every so often
the connecting `ssh` client is never released and is still there when the
harness kills it. Locally on macOS this reproduces about 2 times in 400 full
runs of the equivalent test; it has reproduced once in fork CI. There is no
observed "slow but eventually passing" case — a run either finishes within a
couple of seconds of the target going hostile, or it does not finish until
killed.

This module exists to put a denominator on that rate, on Linux CI, and to keep
evidence for every hang it catches: the client's own `-vvv` trace, the
gateway's log for that one attempt, and the TCP socket state at the moment the
harness gave up on it (`ss -tnp`).

Fork-only. Deliberately not shaped as something to send upstream:
- It never asserts, even when a hang is caught. A pytest failure here would
  abort the loop and throw away the very denominator this file exists to
  produce; `test_delay_sweep.py` on `tooling/delay-sweep` established the same
  "count and keep going" shape for the same investigation, and this reuses it.
- Every iteration starts and fully tears down its own `warpgate` process. That
  is slower than reusing one gateway across attempts, but it is exactly the
  shape the 2/400 macOS baseline and `test_upstream_hostile_target.py` (the
  validated upstream, no-certificate-feature reproduction this file's target
  setup is copied from) were both measured with. Reusing a gateway across
  thousands of connections would be a second, unvalidated methodology
  answering a different question.
- The target is an ordinary `SshTargetPublicKeyAuth` target against a raw
  socket standing in for a compromised host, not a certificate one — issue
  #2520 is reproducible on unpatched upstream with no certificate feature
  involved, so nothing here depends on anything unmerged.

Reading the result: each iteration prints a `RESULT shard=... iter=...` line,
and the run ends with one `RESULT shard=... SUMMARY iterations=... hangs=...
rate=...` line — that line, from every shard, is the number. Per-hang evidence
and every shard's `summary.json` land under `ARTIFACT_DIR`
(`hostile-rate-artifacts/shard-<id>/` by default), which the workflow uploads
as a build artifact regardless of whether any hangs were caught.
"""

import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .hostile_ssh_server import HostileSSHServer
from .util import wait_port

# The one mode this hunts. The suite it is drawn from covers several ways a
# target can misbehave; only this one is the flake under investigation.
MODE = "garbage_after_banner"

# Restricting the inbound client to password auth keeps this independent of
# the SSH-certificate feature: what is under test is the Warpgate-to-target
# leg, and the client's own login method is not part of that.
COMMON_ARGS = ["-i", "/dev/null", "-o", "PreferredAuthentications=password"]

ITERATIONS = int(os.getenv("ITERATIONS", "300"))
SHARD_ID = os.getenv("SHARD_ID", "local")
ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", "hostile-rate-artifacts")) / f"shard-{SHARD_ID}"


def _user_and_target(url, port):
    """A fresh role/user/target against a fresh gateway. Copied from
    `test_upstream_hostile_target.py` (`tooling/upstream-hang-probe`), the
    validated shape that reproduces #2520 without the certificate feature."""
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
        api.create_public_key_credential(
            user.id,
            sdk.NewPublicKeyCredential(
                label="Public Key",
                openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
            ),
        )
        api.add_user_role(user.id, role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="127.0.0.1",
                        port=port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, role.id)
    return user, target


def _socket_state():
    """`ss -tnp` at the moment a hang was declared — cheap, and it is the only
    way to tell "the client is stuck waiting on a TCP connection that is still
    open" apart from "the connection is already gone and something else is
    holding the client". Best-effort: absence of `ss` must not break the loop."""
    if shutil.which("ss") is None:
        return "(ss not found on PATH)"
    try:
        r = subprocess.run(["ss", "-tnp"], capture_output=True, timeout=5)
        return (r.stdout + r.stderr).decode(errors="replace")
    except Exception as e:  # noqa: BLE001 - evidence collection must not itself hang the loop
        return f"(ss failed: {e!r})"


def _stop_wg(process):
    """Fully tear down one iteration's gateway before starting the next one.
    Left running, 300 warpgates would exhaust the runner's fds/ports long
    before the loop finished."""
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=5)
        return
    except Exception:  # noqa: BLE001
        pass
    try:
        process.kill()
        process.wait(timeout=5)
    except Exception:  # noqa: BLE001
        pass


def test_hostile_target_rate(processes: ProcessManager, ctx, timeout):
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    server = HostileSSHServer(MODE)
    server.start()

    hangs = 0
    all_results = []
    started_at = time.time()

    try:
        for i in range(1, ITERATIONS + 1):
            log_path = ctx.tmpdir / f"wg-{SHARD_ID}-{i}.log"
            elapsed = None
            code = None
            hung = False
            ss_output = None
            out = err = b""

            with log_path.open("w") as log:
                wg = processes.start_wg(stdout=log, stderr=log)
                # Matches test_upstream_hostile_target.py exactly: only the
                # HTTP port is waited on before the connection attempt. Adding
                # an SSH-port wait here would change the timing this is trying
                # to measure, not just make the harness tidier.
                wait_port(wg.http_port, recv=False)

                url = f"https://localhost:{wg.http_port}"
                user, target = _user_and_target(url, server.port)

                client = processes.start_ssh_client(
                    f"{user.username}:{target.name}@localhost",
                    "-vvv",
                    "-p",
                    str(wg.ssh_port),
                    *COMMON_ARGS,
                    "ls /bin/sh",
                    password="123",
                    stderr=subprocess.PIPE,
                )

                t0 = time.monotonic()
                try:
                    out, err = client.communicate(timeout=timeout)
                    elapsed = time.monotonic() - t0
                    code = client.returncode
                except subprocess.TimeoutExpired:
                    hung = True
                    elapsed = time.monotonic() - t0
                    # Before killing anything: this is the one chance to see
                    # whether the client's socket to the gateway is still
                    # open.
                    ss_output = _socket_state()
                    client.kill()
                    try:
                        out, err = client.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        out, err = b"", b"(still blocked after SIGKILL)"
                    code = client.returncode

                _stop_wg(wg.process)

            if hung:
                hangs += 1
                iter_dir = ARTIFACT_DIR / f"iter-{i:04d}"
                iter_dir.mkdir(parents=True, exist_ok=True)
                (iter_dir / "client_stdout.txt").write_bytes(out or b"")
                (iter_dir / "client_stderr_vvv.txt").write_bytes(err or b"")
                (iter_dir / "ss_tnp_at_timeout.txt").write_text(ss_output or "")
                try:
                    (iter_dir / "gateway_log.txt").write_text(
                        log_path.read_text(errors="replace")
                    )
                except OSError as e:
                    (iter_dir / "gateway_log.txt").write_text(f"(could not read log: {e!r})")
                (iter_dir / "meta.json").write_text(
                    json.dumps(
                        {
                            "shard": SHARD_ID,
                            "iteration": i,
                            "mode": MODE,
                            "timeout_s": timeout,
                            "elapsed_s": elapsed,
                            "returncode_after_kill": code,
                        },
                        indent=2,
                    )
                )

            all_results.append({"iteration": i, "hung": hung, "elapsed_s": round(elapsed, 3)})
            print(f"RESULT shard={SHARD_ID} iter={i} hung={hung} elapsed={elapsed:.2f}s", flush=True)
    finally:
        server.stop()

    finished_at = time.time()
    rate = hangs / ITERATIONS if ITERATIONS else 0.0
    summary = {
        "shard": SHARD_ID,
        "mode": MODE,
        "iterations": ITERATIONS,
        "hangs": hangs,
        "rate": rate,
        "timeout_s": timeout,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": finished_at - started_at,
    }
    (ARTIFACT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    (ARTIFACT_DIR / "all_iterations.jsonl").write_text(
        "\n".join(json.dumps(r) for r in all_results) + "\n"
    )
    print(
        f"RESULT shard={SHARD_ID} SUMMARY iterations={ITERATIONS} hangs={hangs} "
        f"rate={rate:.4%} duration={summary['duration_s']:.0f}s",
        flush=True,
    )

    # Deliberately no assertion. A hang here is the thing being measured, not
    # a test failure to report; see the module docstring. A harness bug that
    # makes every iteration error out before a client is even started would
    # not show up as a hang at all — it would show up as `hangs == 0` with no
    # per-iteration evidence directories and a suspiciously short duration, in
    # a run where the local baseline says some hangs are expected. That is a
    # bug in this file, not a repro, and is why the RESULT lines are printed
    # per iteration rather than only at the end: a run that errored out on
    # iteration 3 stops producing RESULT lines at iteration 3.
