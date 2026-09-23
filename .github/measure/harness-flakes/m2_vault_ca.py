"""M2: how long the SSH engine's `config/ca` call takes on a fresh server.

Each trial starts a new container through the contract fixture's own
`RealVault.start()`, so the container, TLS setup and the calls made before
`config/ca` are the fixture's and not a copy. Two things are overridden: the
readiness wait, to time it separately and at a finer poll, and `_configure`,
which stops after the timed `config/ca` call instead of building the role and
AppRole the tests need.

The measurement ceiling is 120 s, twice the fixture's new 60 s budget, and it
is a wall-clock ceiling on the whole call. urllib's `timeout` bounds each socket
operation, not the call, so connect, TLS, headers and body could each take up to
it and the sum still come back `ok`; a SIGALRM interval timer bounds the sum. A
call that reaches the ceiling by any route is right-censored: the row says
`censored`, `censor_reason` says which route, and the duration is a lower bound,
never a completion time.

Cells: {vault, openbao} x {default, ed25519}. `default` sends no key_type, as
the fixture does; `ed25519` is a control that asks for an Ed25519 CA. The key
the server actually generated is read back and recorded for every trial, so the
default's type and size are observed, not assumed.

    python3 m2_vault_ca.py --print-images
    python3 m2_vault_ca.py --self-test-wall-deadline
    python3 m2_vault_ca.py --shard K --shards 4 --per-cell 25 \
        --vault-ref REF --openbao-ref REF --source-sha SHA --out rows.csv
"""

import argparse
import ast
import csv
import datetime
import hashlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FIXTURE = REPO / "tests" / "vault_server.py"

CEILING_S = 120.0
# Never above the wall ceiling, so a socket timeout cannot outlast it.
SOCKET_TIMEOUT_S = CEILING_S
HEALTH_CEILING_S = 120.0
HEALTH_POLL_S = 0.1

CELLS = [
    ("vault", "default"),
    ("vault", "ed25519"),
    ("openbao", "default"),
    ("openbao", "ed25519"),
]
PAYLOAD = {
    "default": {"generate_signing_key": True},
    "ed25519": {"generate_signing_key": True, "key_type": "ssh-ed25519"},
}

FIELDS = [
    "measurement", "shard", "round", "position", "engine", "key_cell",
    "image_ref", "image_id", "source_sha", "fixture_sha256", "started_utc",
    "launch_s", "health_ready_s", "health_censored", "server_version",
    "config_ca_s", "config_ca_status", "censor_reason", "ceiling_s", "ca_key_type", "ca_key_bits",
    "error",
]


def fixture_images() -> dict:
    """The image tags the fixture pins, read from its source rather than retyped."""
    tree = ast.parse(FIXTURE.read_text())
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ("VAULT_IMAGE", "OPENBAO_IMAGE"):
                found[target.id] = ast.literal_eval(node.value)
    if set(found) != {"VAULT_IMAGE", "OPENBAO_IMAGE"}:
        raise SystemExit(f"cannot find the pinned images in {FIXTURE}: {found}")
    return found


def is_timeout(error: BaseException) -> bool:
    if isinstance(error, TimeoutError):
        return True
    return isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError)


def one_line(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}".replace("\n", " ").replace(",", ";")[:300]


class HealthTimeout(Exception):
    pass


class WallDeadline(BaseException):
    """Raised from SIGALRM. A BaseException, so neither urllib (which rewraps
    OSError) nor a broad `except Exception` in the fixture can swallow it."""


def _on_alarm(signum, frame):
    raise WallDeadline


def timed_call(call, ceiling_s: float) -> tuple[str, str, float, BaseException | None]:
    """Runs `call` under a hard wall deadline; returns (status, censor_reason,
    elapsed_s, error). Status is `ok`, `censored` or `error`.

    The timer is one-shot, so if it fires inside the inner `finally` before the
    disarm it is already spent; the handler is restored on every path.
    """
    previous = signal.signal(signal.SIGALRM, _on_alarm)
    fired = False
    error = None
    t0 = time.monotonic()
    try:
        try:
            signal.setitimer(signal.ITIMER_REAL, ceiling_s)
            call()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    except WallDeadline:
        fired = True
    except Exception as caught:
        error = caught
    finally:
        signal.signal(signal.SIGALRM, previous)
    elapsed = time.monotonic() - t0

    if fired:
        return "censored", "wall_deadline", elapsed, None
    if error is not None and is_timeout(error):
        return "censored", "socket_timeout", elapsed, error
    # At or past the ceiling is never a completion time, whatever ended it.
    if elapsed >= ceiling_s:
        return "censored", "elapsed_at_ceiling", elapsed, error
    if error is not None:
        return "error", "", elapsed, error
    return "ok", "", elapsed, None


def measured_vault_class():
    sys.path.insert(0, str(REPO))
    from tests.vault_server import AUDIT_PATH, MOUNT, RealVault

    class MeasuredVault(RealVault):
        def __init__(self, image, config_dir, key_cell, row):
            super().__init__(image=image, config_dir=config_dir)
            self.key_cell = key_cell
            self.row = row
            self.t_start = time.monotonic()

        def _wait_until_up(self, timeout=HEALTH_CEILING_S):
            # `docker run -d` has just returned: everything before this point is
            # image check, TLS generation and container creation.
            t0 = time.monotonic()
            self.row["launch_s"] = round(t0 - self.t_start, 3)
            deadline = t0 + timeout
            while True:
                try:
                    health = self._api("GET", "sys/health", token=None)
                except Exception:
                    if time.monotonic() >= deadline:
                        self.row["health_ready_s"] = round(time.monotonic() - t0, 3)
                        self.row["health_censored"] = True
                        raise HealthTimeout(f"not ready within {timeout} s")
                    time.sleep(HEALTH_POLL_S)
                    continue
                self.row["health_ready_s"] = round(time.monotonic() - t0, 3)
                self.row["health_censored"] = False
                self.row["server_version"] = str(health.get("version", ""))
                return

        def _configure(self):
            # The fixture's calls ahead of `config/ca`, in its order, so the
            # timed call meets the server in the state the fixture leaves it.
            if not self.is_openbao:
                self._api(
                    "PUT",
                    "sys/audit/file",
                    {
                        "type": "file",
                        "options": {"file_path": AUDIT_PATH, "log_raw": "true"},
                    },
                )
            self._api("POST", "sys/mounts/" + MOUNT, {"type": "ssh"})

            self.row["ceiling_s"] = CEILING_S
            status, reason, elapsed, error = timed_call(
                lambda: self._api(
                    "POST", f"{MOUNT}/config/ca", PAYLOAD[self.key_cell], timeout=SOCKET_TIMEOUT_S
                ),
                CEILING_S,
            )
            self.row["config_ca_s"] = round(elapsed, 3)
            self.row["config_ca_status"] = status
            self.row["censor_reason"] = reason
            if status == "error":
                self.row["error"] = "config/ca: " + one_line(error)
            if status != "ok":
                return

            key = self.ca_public_key
            self.row["ca_key_type"] = key.split(" ", 1)[0]
            with tempfile.NamedTemporaryFile("w", suffix=".pub") as f:
                f.write(key + "\n")
                f.flush()
                listed = subprocess.run(
                    ["ssh-keygen", "-l", "-f", f.name], capture_output=True, text=True, check=False
                )
            self.row["ca_key_bits"] = listed.stdout.split(" ", 1)[0] if listed.returncode == 0 else ""

    return MeasuredVault


def image_id(ref: str) -> str:
    out = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", ref],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        raise SystemExit(f"{ref} is not present locally; pull it by digest before timing: {out.stderr}")
    return out.stdout.strip()


def self_test_wall_deadline() -> int:
    """Proves the ceiling holds against servers that never finish answering,
    with the ceiling lowered to 2 s. Local sockets only; no Docker."""
    ceiling = 2.0

    def serve(behaviour):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        held = []

        def run():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                held.append(conn)
                behaviour(conn)

        threading.Thread(target=run, daemon=True).start()
        return listener, f"http://127.0.0.1:{listener.getsockname()[1]}/v1/ssh/config/ca"

    def silent(conn):
        pass

    def trickle(conn):
        # One header byte every 0.5 s: no single socket read ever waits long
        # enough to time out, so only the wall deadline can end the call.
        def run():
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\n")
                while True:
                    time.sleep(0.5)
                    conn.sendall(b"X")
            except OSError:
                return

        threading.Thread(target=run, daemon=True).start()

    def answers(conn):
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        conn.close()

    cases = [
        ("silent server, socket timeout = ceiling", silent, ceiling, "censored"),
        ("silent server, socket timeout 30 s > ceiling", silent, 30.0, "censored"),
        ("trickling server, socket timeout = ceiling", trickle, ceiling, "censored"),
        ("answering server", answers, ceiling, "ok"),
    ]
    failed = 0
    for name, behaviour, socket_timeout, want in cases:
        listener, url = serve(behaviour)
        request = urllib.request.Request(url, method="POST", data=b"{}")

        def call():
            with urllib.request.urlopen(request, timeout=socket_timeout) as response:
                response.read()

        status, reason, elapsed, error = timed_call(call, ceiling)
        listener.close()
        disarmed = signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        restored = signal.getsignal(signal.SIGALRM) is signal.SIG_DFL
        within = elapsed < ceiling + 1.0
        good = status == want and disarmed and restored and within
        failed += not good
        print(
            f"{'PASS' if good else 'FAIL'}: {name}: status={status} reason={reason or '-'} "
            f"elapsed={elapsed:.3f}s ceiling={ceiling}s timer_disarmed={disarmed} "
            f"handler_restored={restored} error={one_line(error) if error else '-'}",
            flush=True,
        )
    print(f"self-test: {len(cases) - failed}/{len(cases)} passed")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-images", action="store_true")
    parser.add_argument("--self-test-wall-deadline", action="store_true")
    parser.add_argument("--shard", type=int)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--per-cell", type=int)
    parser.add_argument("--vault-ref")
    parser.add_argument("--openbao-ref")
    parser.add_argument("--source-sha")
    parser.add_argument("--out")
    args = parser.parse_args()

    if args.self_test_wall_deadline:
        return self_test_wall_deadline()

    if args.print_images:
        images = fixture_images()
        print(f"vault={images['VAULT_IMAGE']}")
        print(f"openbao={images['OPENBAO_IMAGE']}")
        return 0

    for ref in (args.vault_ref, args.openbao_ref):
        if "@sha256:" not in ref:
            raise SystemExit(f"{ref} is not a digest reference; every trial runs by digest")
    refs = {"vault": args.vault_ref, "openbao": args.openbao_ref}
    ids = {engine: image_id(ref) for engine, ref in refs.items()}
    fixture_sha = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    print(f"fixture {FIXTURE} sha256 {fixture_sha}")
    for engine in refs:
        print(f"{engine}: {refs[engine]} -> {ids[engine]}")

    MeasuredVault = measured_vault_class()
    counts = {cell: 0 for cell in CELLS}

    with open(args.out, "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()
        for rnd in range(args.per_cell):
            # Rotated per round and per shard, so no cell always runs first
            # after a container teardown, and the shards do not move in step.
            shift = (rnd + args.shard) % len(CELLS)
            order = CELLS[shift:] + CELLS[:shift]
            for position, (engine, key_cell) in enumerate(order):
                row = {field: "" for field in FIELDS}
                row.update(
                    measurement="M2", shard=args.shard, round=rnd, position=position,
                    engine=engine, key_cell=key_cell, image_ref=refs[engine],
                    image_id=ids[engine], source_sha=args.source_sha,
                    fixture_sha256=fixture_sha,
                    started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                )
                with tempfile.TemporaryDirectory(prefix="m2-bao-config-") as config_dir:
                    server = MeasuredVault(refs[engine], Path(config_dir), key_cell, row)
                    try:
                        server.start()
                    except HealthTimeout as error:
                        row["config_ca_status"] = "error"
                        row["error"] = "health: " + one_line(error)
                    except Exception as error:
                        row["config_ca_status"] = row["config_ca_status"] or "error"
                        row["error"] = row["error"] or ("setup: " + one_line(error))
                    finally:
                        server.stop()
                writer.writerow(row)
                out.flush()
                counts[(engine, key_cell)] += 1
                print(
                    f"shard {args.shard} round {rnd} {engine}/{key_cell}: "
                    f"health {row['health_ready_s']} s, config/ca {row['config_ca_s']} s "
                    f"[{row['config_ca_status']}{' ' + row['censor_reason'] if row['censor_reason'] else ''}] {row['ca_key_type']} {row['ca_key_bits']} {row['error']}",
                    flush=True,
                )

    wrong = {f"{e}/{k}": n for (e, k), n in counts.items() if n != args.per_cell}
    if wrong:
        print(f"::error::row counts differ from the predeclared {args.per_cell}: {wrong}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
