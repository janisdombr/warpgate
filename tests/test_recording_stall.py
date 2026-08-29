"""How far does a recorded session get before it stalls?

`test_terminal_recording_index` streams ~1.3 MB through a recorded PTY and
fails intermittently on the client timeout — about a quarter of runs on this
project's own main. The assertions after it never run, so all the failure says
is "the client did not finish".

This asks the narrower question: when it does not finish, how much of the
output arrived? A transfer that stops at a repeatable offset points at the
recorder's write path; one that stops anywhere points at scheduling.
"""

import subprocess
import time

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port

LINES = 200000


def test_a_recorded_session_streams_to_the_end(
    processes: ProcessManager, timeout, wg_c_ed25519_pubkey
):
    wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
    wait_port(wg.http_port, recv=False)
    with admin_client(f"https://localhost:{wg.http_port}") as api:
        api.update_parameters(sdk.ParameterUpdate(recordings_enable=True))

    user, target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)

    started = time.monotonic()
    client = processes.start_ssh_client(
        f"{user.username}:{target.name}@localhost",
        "-p", str(wg.ssh_port), "-tt", *common_args,
        f"seq 1 {LINES}", password="123",
    )
    try:
        out, _ = client.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        client.kill()
        out, _ = client.communicate(timeout=10)
        got = len(exc.output or out or b"")
        last = (exc.output or out or b"").splitlines()[-1:] or [b""]
        print(
            f"STALL after {time.monotonic()-started:.1f}s: {got} bytes arrived, "
            f"last line {last[0][:40]!r} of {LINES}"
        )
        raise
    print(f"OK {len(out)} bytes in {time.monotonic()-started:.1f}s")
