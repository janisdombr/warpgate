"""Throwaway harness. Not a regression test — a measuring instrument.

The question: when a client stops reading long enough for its SSH channel
window to run out, and *then* its target dies, how long does the gateway keep
the client's connection?

Why that question has an interesting answer, from russh 0.63.2's own source
(`src/server/session.rs`, the crate version in `Cargo.lock`):

    msg = self.receiver.recv(), if !self.kex.active() && !self.common.has_any_pending_data()

`Handle::data`, `Handle::close`, `Handle::eof` and `Handle::disconnect` all go
through that one bounded `sender` (`event_buffer_size`, 100 in
`warpgate-protocol-ssh/src/server/mod.rs`), and Warpgate funnels every one of
them through a single FIFO in `server/channel_writer.rs`. So once a channel
holds data the client's window could not take, russh stops draining its own
message queue, the queue fills with target output, and nothing Warpgate wants
to say afterwards can get past it.

What this harness measured is worse than that, and the difference matters to
anyone proposing a fix. Run it with `WG_INACTIVITY=15s` and russh's own
inactivity timeout becomes 25s (`ssh.inactivity_timeout + 10s`). That timer
lives on an arm of the `select!` above which pending data does *not* disable,
so if the loop were sitting in the `select!` it would fire. It does not — not
at 25s, not at 120s. The only other place the loop awaits is the
`packet_writer.flush_into(&mut stream_write).await` in the batch drain just
above the `select!`: a plain socket write to a client whose receive window is
zero. Nothing times that out, so the loop never returns to the `select!` and
no timer in it is ever armed. The connection is held until the process ends.

Back-pressure reaches all the way to the target: with the client stopped, the
gateway does not process the target's disconnection either — the session event
loop is parked in `EventIntake::next` waiting for an outbound data slot, and
`Event::Client` is on the budgeted side of that intake. So `disconnect_server`
is not reached by the target dying at all; it is reached, five minutes later,
by Warpgate's own session inactivity timeout, and by then its 5s
`DISCONNECT_FLUSH_TIMEOUT` expires against the same wedged queue.

This file does not assert anything about *why*. It measures one number per
iteration — seconds from the target dying to the gateway letting go of the
client's TCP connection — and prints it. The mechanism above is what makes the
number worth measuring; the number is what decides whether a fix works.

Shape borrowed from `test_flake_hostile_target_rate.py`: every iteration is
self-contained (its own gateway, its own log, its own evidence directory), and
every iteration prints a RESULT line as it finishes, so a harness that dies on
iteration 3 is visibly a harness that died on iteration 3 rather than a clean
run with a small denominator. Unlike that file this one *does* assert at the
end, because it is a reproduction and a reproduction that cannot go red is
worth nothing.

Three things it refuses to infer:

- That the client stopped reading. `_conn_rows` reads the kernel's own numbers
  out of `netstat -anv -p tcp`: the iteration only counts as stalled once the
  client socket's Recv-Q has reached its high-water mark (`rhiwat`) and the
  gateway's Send-Q is non-empty. Both snapshots are kept as evidence.
- That the gateway let go. `_gateway_holds_socket` asks `lsof` whether the
  warpgate process still has an open fd for that connection. A FIN the client
  never acknowledges, or a socket orphaned in the kernel, is not the gateway
  releasing anything, and a state-based check would call both of those a
  release. It also does not accept a log line as a release: russh runs its own
  session loop on a task spawned inside `run_stream`, whose real handle
  `russh_util::runtime::spawn` throws away, so "we dropped the protocol task"
  and "the socket is gone" are not the same claim.
- That the threshold is meaningful. `test_control_reading_client` runs the same
  target death against a client that keeps reading. If that one does not come
  in far under the threshold, the threshold is measuring the harness.

The target dies by having its TCP connection to the gateway torn down under
it — a relay in front of the sshd container, closed with SO_LINGER 0 so the
gateway gets an RST. Same thing `hostile_ssh_server.py` does to a connection,
and unlike `docker kill` it is instant and lets one container serve every
iteration. `TARGET_KILL=docker` swaps in a real `docker kill` of the container
for a run that needs to answer "but is the relay the reason?".
"""

import json
import os
import select
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .util import alloc_port, wait_port

ITERATIONS = int(os.getenv("ITERATIONS", "3"))
# How long to watch for the gateway to let go before giving up on it. Kept
# below russh's own `inactivity_timeout + 10s` by default so a run does not
# silently turn into a 5-minute wait; raise it to find out what the gateway
# does eventually rather than whether it does anything soon.
OBSERVE_S = float(os.getenv("OBSERVE_S", "60"))
# The discriminating line. A healthy teardown is under a second (see
# `test_control_reading_client`); russh's inactivity timeout is 5m10s with
# Warpgate's defaults. Anything in between is unambiguous.
THRESHOLD_S = float(os.getenv("THRESHOLD_S", "30"))
# Bytes to read off the client's stdout before stopping it. Only proves output
# is flowing; the stall itself is confirmed from the socket queues.
FLOW_BYTES = int(os.getenv("FLOW_BYTES", "65536"))
# How long to wait for the socket queues to back up after SIGSTOP.
BACKLOG_WAIT_S = float(os.getenv("BACKLOG_WAIT_S", "30"))
# Consecutive half-second samples the gateway's byte counter must not move for
# before the transfer counts as wedged rather than merely slow.
STALL_QUIET_SAMPLES = int(os.getenv("STALL_QUIET_SAMPLES", "4"))
# After SIGCONT, how long to give the client to exit on its own.
CONT_WAIT_S = float(os.getenv("CONT_WAIT_S", "60"))
TARGET_KILL = os.getenv("TARGET_KILL", "relay")
# Overrides `ssh.inactivity_timeout`. russh gets that plus 10s
# (`server/mod.rs`), and its inactivity arm is the one arm of the run loop's
# `select!` that pending data does not disable — so a short value here turns
# "does the gateway ever let go, and because of what" into a question a
# 60-second run can answer.
WG_INACTIVITY = os.getenv("WG_INACTIVITY", "")
SHARD_ID = os.getenv("SHARD_ID", "local")
ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", "stall-artifacts")) / f"shard-{SHARD_ID}"

# 33 bytes a line, so the window fills in far fewer write syscalls than `yes`
# on its own would need.
STREAM_COMMAND = "yes 0123456789abcdef0123456789abcdef"

CLIENT_ARGS = [
    "-o",
    "IdentityFile=ssh-keys/id_ed25519",
    "-o",
    "PreferredAuthentications=publickey",
]


def _hard_close(sock):
    """RST, not FIN: a host that has gone away does not close politely, and a
    FIN would let the gateway's client leg finish its own shutdown handshake,
    which is a different event from the one being staged."""
    try:
        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
        )
    except OSError:
        pass
    # `shutdown` first: it is what wakes another thread blocked in `sendall`
    # on this socket, which `close` alone does not reliably do.
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class TargetRelay:
    """A plain TCP relay standing in front of the real sshd, so the target can
    be made to vanish at an exact moment without restarting a container."""

    def __init__(self, upstream_port: int):
        self.upstream_port = upstream_port
        self.port = alloc_port()
        self.connections = 0
        self._socks: list[socket.socket] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", self.port))
        self._server.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                downstream, _ = self._server.accept()
            except OSError:
                return
            self.connections += 1
            try:
                upstream = socket.create_connection(
                    ("127.0.0.1", self.upstream_port), timeout=10
                )
                upstream.settimeout(None)
            except OSError:
                _hard_close(downstream)
                continue
            with self._lock:
                self._socks += [downstream, upstream]
            for a, b in ((downstream, upstream), (upstream, downstream)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    def _pump(self, a: socket.socket, b: socket.socket):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                # Blocks once the gateway stops reading. That is the correct
                # behaviour for a relay and matches what a real target's own
                # TCP stack does to `yes`.
                b.sendall(data)
        except OSError:
            pass

    def kill(self):
        """The target dies."""
        with self._lock:
            socks, self._socks = self._socks, []
        for s in socks:
            _hard_close(s)

    def stop(self):
        self._stop.set()
        self.kill()
        try:
            self._server.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


def _netstat_rows():
    """`netstat -anv -p tcp` parsed into dicts. macOS gives Recv-Q, Send-Q and
    the socket buffer high-water marks in the same line, which is the whole
    reason this is read rather than `lsof`."""
    try:
        r = subprocess.run(
            ["netstat", "-anv", "-p", "tcp"], capture_output=True, timeout=15
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows = []
    for line in r.stdout.decode(errors="replace").splitlines():
        f = line.split()
        if len(f) < 10 or not f[0].startswith("tcp"):
            continue
        try:
            rows.append(
                {
                    "line": line,
                    "local": f[3],
                    "foreign": f[4],
                    "state": f[5],
                    "recvq": int(f[1]),
                    "sendq": int(f[2]),
                    "rxbytes": int(f[6]),
                    "txbytes": int(f[7]),
                    "rhiwat": int(f[8]),
                    "shiwat": int(f[9]),
                }
            )
        except ValueError:
            continue
    return rows


def _conn_rows(wg_port: int, client_port: int):
    """The two ends of one loopback connection: (gateway side, client side)."""
    gw_local = f"127.0.0.1.{wg_port}"
    cl_local = f"127.0.0.1.{client_port}"
    gateway = client = None
    for row in _netstat_rows():
        if row["local"] == gw_local and row["foreign"] == cl_local:
            gateway = row
        elif row["local"] == cl_local and row["foreign"] == gw_local:
            client = row
    return gateway, client


def _client_port(pid: int, wg_port: int, deadline: float):
    """The client's local port, read from its own open sockets. Needed to name
    the one connection this iteration is about; every other test in the suite
    can get away with not knowing it because none of them watch a socket."""
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(
                ["lsof", "-nP", "-a", "-p", str(pid), "-iTCP"],
                capture_output=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            time.sleep(0.2)
            continue
        for line in r.stdout.decode(errors="replace").splitlines():
            if f"->127.0.0.1:{wg_port}" not in line or "ESTABLISHED" not in line:
                continue
            for field in line.split():
                if "->" in field:
                    return int(field.split("->")[0].rsplit(":", 1)[1])
        time.sleep(0.2)
    return None


def _gateway_holds_socket(wg_pid: int, client_port: int) -> bool:
    """Whether the gateway process still has an open fd for the connection.

    Not a TCP state check. The gateway cannot deliver a FIN to a client whose
    receive window is zero, and a socket the kernel keeps around after the fd
    is gone is not the gateway holding anything — a state-based check would
    score both of those wrong, in opposite directions."""
    try:
        r = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(wg_pid), "-iTCP"],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        # Unknown is not "released": treating a slow lsof as a release would
        # turn a red run green.
        return True
    marker = f":{client_port}"
    for line in r.stdout.decode(errors="replace").splitlines():
        for field in line.split():
            if "->" in field and field.endswith(marker):
                return True
    return False


# Lines the gateway prints on its way through a teardown, in the order it
# reaches them. Timestamped against the moment the target died, these say
# whether the gateway even noticed — "the client was not released" is
# consistent with a teardown that could not be delivered *and* with a teardown
# that never started, and those are different defects.
LOG_MARKERS = {
    "target_disconnect_seen": "event=State(Disconnected)",
    "session_loop_ended": "No more events",
    "session_closed": "Closed session",
    "inactivity": "Closing the session due to inactivity",
    "protocol_task_dropped": "dropping it to release the client",
    "protocol_handler_dropped": "server::russh_handler: Dropped",
}


def _log_marker_times(log_path: Path, t_kill_wall: float, relay_port: int):
    """First appearance of each marker, in seconds relative to the target's
    death. Warpgate's log stamps to the second, so these are ±1s — enough to
    separate "a few seconds" from "not at all".

    Scanned only from the line where the gateway dials this iteration's
    target. `wait_port` opens and drops a TCP connection to the SSH port
    before the real client ever runs, and warpgate logs that probe as a full
    session — "Closed session", "No more events" and the handler drop all
    appear once for it. Scored from the top of the file those matched the
    probe and came out *before* the target died, which is how the mistake
    announced itself."""
    import datetime

    found = {}
    try:
        text = log_path.read_text(errors="replace")
    except OSError:
        return found
    lines = text.splitlines()
    anchor = 0
    for i, line in enumerate(lines):
        if f"Connecting address=127.0.0.1:{relay_port}" in line:
            anchor = i
    for line in lines[anchor:]:
        head = line[:19]
        try:
            when = datetime.datetime.strptime(head, "%d.%m.%Y %H:%M:%S").timestamp()
        except ValueError:
            continue
        for name, needle in LOG_MARKERS.items():
            if name not in found and needle in line:
                found[name] = round(when - t_kill_wall, 1)
    return found


def _drain_some(fd: int, want: int, deadline: float) -> int:
    """Read up to `want` bytes so the iteration can say output was flowing.
    Stops there: the pipe filling up is part of what stops the client reading."""
    got = 0
    while got < want and time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if not r:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        got += len(chunk)
    return got


def _user_and_target(url: str, port: int):
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
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


def _stop_wg(process):
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        return
    except Exception:  # noqa: BLE001
        pass
    try:
        process.kill()
        process.wait(timeout=10)
    except Exception:  # noqa: BLE001
        pass


def _docker_id_for_port(port: int):
    try:
        r = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"publish={port}"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    ids = r.stdout.decode().split()
    return ids[0] if ids else None


def _run_iteration(
    processes: ProcessManager,
    ctx,
    wg_c_ed25519_pubkey,
    sshd_port: int,
    index: int,
    stop_client: bool,
    artifacts: Path,
):
    """One full attempt. Returns a dict; raises only on harness faults."""
    artifacts.mkdir(parents=True, exist_ok=True)
    log_path = ctx.tmpdir / f"wg-stall-{SHARD_ID}-{index}.log"
    record = {
        "iteration": index,
        "stop_client": stop_client,
        "kill_mode": TARGET_KILL,
        "flow_bytes": 0,
        "stalled": False,
        "release_s": None,
        "observed_s": None,
        "client_returncode": None,
        "client_exit_after_cont_s": None,
    }

    t_start = time.monotonic()
    relay = TargetRelay(sshd_port)
    relay.start()
    client = None
    resumed = False

    with log_path.open("w") as log:
        wg = processes.start_wg(
            stdout=log,
            stderr=log,
            config_patch=(
                {"ssh": {"inactivity_timeout": WG_INACTIVITY}} if WG_INACTIVITY else None
            ),
            env={"RUST_LOG": os.getenv("WG_RUST_LOG", "audit=info,warpgate=debug")},
        )
        try:
            wait_port(wg.http_port, for_process=wg.process, recv=False)
            wait_port(wg.ssh_port, for_process=wg.process)

            url = f"https://localhost:{wg.http_port}"
            record["relay_port"] = relay.port
            user, target = _user_and_target(url, relay.port)

            client = processes.start_ssh_client(
                f"{user.username}:{target.name}@127.0.0.1",
                "-p",
                str(wg.ssh_port),
                *CLIENT_ARGS,
                STREAM_COMMAND,
                stderr=subprocess.PIPE,
            )

            deadline = time.monotonic() + 60
            record["flow_bytes"] = _drain_some(
                client.stdout.fileno(), FLOW_BYTES, deadline
            )
            if record["flow_bytes"] < FLOW_BYTES:
                record["error"] = "target output never started"
                return record

            client_port = _client_port(client.pid, wg.ssh_port, time.monotonic() + 30)
            if client_port is None:
                record["error"] = "could not identify the client's socket"
                return record
            record["client_port"] = client_port

            drain_thread = None
            if stop_client:
                client.send_signal(signal.SIGSTOP)
            else:
                # The control: a client that never stops reading. Its window is
                # never exhausted, so the gateway is never in the state under
                # investigation.
                def drain():
                    try:
                        while os.read(client.stdout.fileno(), 262144):
                            pass
                    except OSError:
                        pass

                drain_thread = threading.Thread(target=drain, daemon=True)
                drain_thread.start()

            # Wait for the kernel to confirm the backlog, rather than assuming
            # a sleep was long enough. Three conditions, all read out of
            # `netstat`, none of them inferred:
            #   - the client's receive buffer is at its high-water mark, so the
            #     process really has stopped reading;
            #   - the gateway has data it cannot hand over (Send-Q non-empty);
            #   - the gateway's byte counter has stopped moving for
            #     `STALL_QUIET_SAMPLES` samples, so this is a wedged transfer
            #     and not a slow one.
            samples = []
            backlog_deadline = time.monotonic() + (
                BACKLOG_WAIT_S if stop_client else 3.0
            )
            gateway_row = client_row = None
            quiet = 0
            last_tx = None
            while time.monotonic() < backlog_deadline:
                gateway_row, client_row = _conn_rows(wg.ssh_port, client_port)
                if not gateway_row or not client_row:
                    time.sleep(0.5)
                    continue
                samples.append(
                    {
                        "t": round(time.monotonic() - t_start, 2),
                        "client_recvq": client_row["recvq"],
                        "client_rhiwat": client_row["rhiwat"],
                        "gateway_sendq": gateway_row["sendq"],
                        "gateway_txbytes": gateway_row["txbytes"],
                    }
                )
                quiet = quiet + 1 if gateway_row["txbytes"] == last_tx else 0
                last_tx = gateway_row["txbytes"]
                if (
                    client_row["recvq"] >= 0.9 * client_row["rhiwat"]
                    and gateway_row["sendq"] > 0
                    and quiet >= STALL_QUIET_SAMPLES
                ):
                    record["stalled"] = True
                    break
                time.sleep(0.5)

            record["stall_samples"] = samples[-12:]
            record["gateway_socket"] = gateway_row["line"] if gateway_row else None
            record["client_socket"] = client_row["line"] if client_row else None
            (artifacts / "netstat_before_kill.txt").write_text(
                "\n".join(
                    filter(
                        None,
                        [
                            record["gateway_socket"],
                            record["client_socket"],
                        ],
                    )
                )
                + "\n"
            )
            (artifacts / "stall_samples.json").write_text(json.dumps(samples, indent=2))
            if stop_client and not record["stalled"]:
                record["error"] = "client never stopped reading"
                return record

            relay_before = relay.connections
            t_kill = time.monotonic()
            record["t_kill_wall"] = time.time()
            if TARGET_KILL == "docker":
                container = _docker_id_for_port(sshd_port)
                record["container"] = container
                if container:
                    subprocess.run(
                        ["docker", "kill", container], capture_output=True, timeout=60
                    )
                relay.kill()
            else:
                relay.kill()
            record["relay_connections"] = relay_before

            observe_deadline = t_kill + OBSERVE_S
            while time.monotonic() < observe_deadline:
                if not _gateway_holds_socket(wg.process.pid, client_port):
                    record["release_s"] = time.monotonic() - t_kill
                    break
                time.sleep(0.25)
            record["observed_s"] = time.monotonic() - t_kill

            gateway_row, client_row = _conn_rows(wg.ssh_port, client_port)
            (artifacts / "netstat_after_observe.txt").write_text(
                "\n".join(
                    filter(
                        None,
                        [
                            gateway_row["line"] if gateway_row else None,
                            client_row["line"] if client_row else None,
                        ],
                    )
                )
                + "\n"
            )

            if stop_client:
                client.send_signal(signal.SIGCONT)
                resumed = True
            t_cont = time.monotonic()
            try:
                out, err = client.communicate(timeout=CONT_WAIT_S)
                record["client_exit_after_cont_s"] = time.monotonic() - t_cont
                record["client_returncode"] = client.returncode
            except subprocess.TimeoutExpired:
                out, err = b"", b"(client still running)"
                record["client_returncode"] = None
            (artifacts / "client_stderr.txt").write_bytes(err or b"")
            record["client_stderr_tail"] = (err or b"").decode(errors="replace")[-2000:]
            return record
        finally:
            if client is not None and client.poll() is None:
                if not resumed:
                    try:
                        client.send_signal(signal.SIGCONT)
                    except OSError:
                        pass
                client.kill()
                try:
                    client.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    pass
            relay.stop()
            _stop_wg(wg.process)

    return record


def _finish(artifacts: Path, log_path: Path, record: dict):
    """Keep the gateway's log for the iteration and read the teardown markers
    out of it. Done here, after the gateway has been stopped, so the log is
    complete."""
    try:
        (artifacts / "gateway_log.txt").write_text(log_path.read_text(errors="replace"))
    except OSError as e:  # noqa: BLE001
        (artifacts / "gateway_log.txt").write_text(f"(could not read log: {e!r})")
    if record.get("t_kill_wall") and record.get("relay_port"):
        record["log_markers_s"] = _log_marker_times(
            log_path, record["t_kill_wall"], record["relay_port"]
        )


def test_stalled_client_release_after_target_death(
    processes: ProcessManager, ctx, wg_c_ed25519_pubkey
):
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    sshd_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(sshd_port)

    results = []
    for i in range(1, ITERATIONS + 1):
        artifacts = ARTIFACT_DIR / f"iter-{i:03d}"
        record = _run_iteration(
            processes, ctx, wg_c_ed25519_pubkey, sshd_port, i, True, artifacts
        )
        _finish(artifacts, ctx.tmpdir / f"wg-stall-{SHARD_ID}-{i}.log", record)
        (artifacts / "meta.json").write_text(json.dumps(record, indent=2))
        results.append(record)
        print(
            f"RESULT shard={SHARD_ID} iter={i} stalled={record['stalled']} "
            f"release_s={record['release_s']} observed_s={record['observed_s']:.1f} "
            f"rc={record['client_returncode']} "
            f"markers={record.get('log_markers_s')} error={record.get('error')}",
            flush=True,
        )

    released = [r for r in results if r["release_s"] is not None]
    within = [r for r in released if r["release_s"] <= THRESHOLD_S]
    summary = {
        "shard": SHARD_ID,
        "iterations": ITERATIONS,
        "kill_mode": TARGET_KILL,
        "inactivity_timeout": WG_INACTIVITY or "(default)",
        "threshold_s": THRESHOLD_S,
        "observe_s": OBSERVE_S,
        "stalled": sum(1 for r in results if r["stalled"]),
        "released": len(released),
        "released_within_threshold": len(within),
        "release_times_s": [r["release_s"] for r in results],
        "results": results,
    }
    (ARTIFACT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"RESULT shard={SHARD_ID} SUMMARY {json.dumps(summary['release_times_s'])}", flush=True)

    harness_errors = [r for r in results if r.get("error")]
    assert not harness_errors, (
        "the scenario did not reach the state it measures: "
        f"{[r['error'] for r in harness_errors]}"
    )
    assert len(within) == ITERATIONS, (
        f"{ITERATIONS - len(within)}/{ITERATIONS} stalled sessions were still held by "
        f"the gateway {THRESHOLD_S}s after the target died "
        f"(release times: {summary['release_times_s']}, `None` = still held at "
        f"{OBSERVE_S}s)"
    )


def test_control_reading_client(processes: ProcessManager, ctx, wg_c_ed25519_pubkey):
    """The same target death against a client that keeps reading.

    Without this the threshold is unfalsifiable: a 30s bound that nothing ever
    meets says nothing about the stalled case."""
    artifacts = ARTIFACT_DIR / "control"
    sshd_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(sshd_port)
    record = _run_iteration(
        processes, ctx, wg_c_ed25519_pubkey, sshd_port, 900, False, artifacts
    )
    _finish(artifacts, ctx.tmpdir / f"wg-stall-{SHARD_ID}-900.log", record)
    (artifacts / "meta.json").write_text(json.dumps(record, indent=2))
    print(
        f"RESULT shard={SHARD_ID} CONTROL release_s={record['release_s']} "
        f"observed_s={record['observed_s']:.1f} rc={record['client_returncode']} "
        f"markers={record.get('log_markers_s')} error={record.get('error')}",
        flush=True,
    )
    assert not record.get("error"), record.get("error")
    assert record["release_s"] is not None and record["release_s"] <= THRESHOLD_S, (
        "a reading client was not released either, so the threshold measures the "
        f"harness rather than the stall (release_s={record['release_s']})"
    )
