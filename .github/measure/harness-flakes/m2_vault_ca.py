"""M2: how long the SSH engine's `config/ca` call takes on a fresh server.

Each trial starts a new container through the contract fixture's own
`RealVault.start()`, so the container, TLS setup and the calls made before
`config/ca` are the fixture's and not a copy. Two things are overridden: the
readiness wait, to time it separately and at a finer poll, and `_configure`,
which stops after the timed `config/ca` call instead of building the role and
AppRole the tests need.

The measurement ceiling is 120 s, twice the fixture's new 60 s budget. A call
that reaches it is right-censored: the row says `censored` and its duration is a
lower bound, never a completion time.

Cells: {vault, openbao} x {default, ed25519}. `default` sends no key_type, as
the fixture does; `ed25519` is a control that asks for an Ed25519 CA. The key
the server actually generated is read back and recorded for every trial, so the
default's type and size are observed, not assumed.

    python3 m2_vault_ca.py --print-images
    python3 m2_vault_ca.py --shard K --shards 4 --per-cell 25 \
        --vault-ref REF --openbao-ref REF --source-sha SHA --out rows.csv
"""

import argparse
import ast
import csv
import datetime
import hashlib
import subprocess
import sys
import tempfile
import time
import urllib.error
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FIXTURE = REPO / "tests" / "vault_server.py"

CEILING_S = 120.0
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
    "config_ca_s", "config_ca_status", "ceiling_s", "ca_key_type", "ca_key_bits",
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
            t0 = time.monotonic()
            try:
                self._api("POST", f"{MOUNT}/config/ca", PAYLOAD[self.key_cell], timeout=CEILING_S)
            except Exception as error:
                self.row["config_ca_s"] = round(time.monotonic() - t0, 3)
                if is_timeout(error):
                    self.row["config_ca_status"] = "censored"
                    return
                self.row["config_ca_status"] = "error"
                self.row["error"] = "config/ca: " + one_line(error)
                return
            self.row["config_ca_s"] = round(time.monotonic() - t0, 3)
            self.row["config_ca_status"] = "ok"

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-images", action="store_true")
    parser.add_argument("--shard", type=int)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--per-cell", type=int)
    parser.add_argument("--vault-ref")
    parser.add_argument("--openbao-ref")
    parser.add_argument("--source-sha")
    parser.add_argument("--out")
    args = parser.parse_args()

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
                    f"[{row['config_ca_status']}] {row['ca_key_type']} {row['ca_key_bits']} {row['error']}",
                    flush=True,
                )

    wrong = {f"{e}/{k}": n for (e, k), n in counts.items() if n != args.per_cell}
    if wrong:
        print(f"::error::row counts differ from the predeclared {args.per_cell}: {wrong}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
