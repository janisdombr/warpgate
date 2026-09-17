from pathlib import Path
import os
import subprocess
import tempfile
import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .approval_util import wait_for_pending_approval
from .util import wait_port


class Test:
    def test_probe_many_channels(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # An automation client (Ansible with forks, a mux'd batch job) opens
        # its sessions as fast as the transport allows, all of them landing
        # while the gate is still held. Every one of them must complete once
        # the approval lands — the session loop may not wedge on the count.
        url, user, target = _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg)
        with tempfile.TemporaryDirectory() as tmp:
            control_path = os.path.join(tmp, "mux")
            master = _connect_held(
                processes,
                shared_wg,
                user,
                target,
                "sleep 60",
                options=["-o", "ControlMaster=yes", "-o", f"ControlPath={control_path}"],
            )
            _wait_for_control_socket(control_path, master)
            # Under the target sshd's default MaxSessions the exact per-channel
            # success is capped, so this asserts the node-level property: the
            # burst must not take the whole node down. The PR's reentrant
            # per-channel wait recurses one stack frame deeper per queued open
            # and overflows the worker stack around the sixth.
            clients = [
                processes.start(
                    [
                        "ssh",
                        "-o",
                        f"ControlPath={control_path}",
                        "-o",
                        "ControlMaster=no",
                        f"{user.username}#{target.name}@localhost",
                        "true",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                for _ in range(int(os.environ.get("PROBE_CHANNELS", "16")))
            ]

            # The whole point is that the opens pile up *while* the gate is
            # held: approving too early lets each one resolve on its own and
            # the deferred queue never grows. Nothing observable says "all N
            # are queued", so the probe waits a fixed settle time and the
            # gateway's own PROBE lines report how many actually queued.
            time.sleep(float(os.environ.get("PROBE_SETTLE", "8")))
            with admin_client(url) as api:
                approval = wait_for_pending_approval(api, target.name, user.username)
                api.approve_session(
                    approval.id,
                    sdk.ApproveSessionRequest(scope=sdk.ApprovalScope.ONCE, target=approval.target),
                )

            for c in clients:
                c.wait(timeout=timeout)
            master.terminate()

            # The node has to still be serving after the burst.
            with admin_client(url) as api:
                api.get_session_approvals()



def _held_ssh_target(processes, wg_c_ed25519_pubkey, shared_wg, require_approval=True):
    """A public-key user and an SSH target, gated by JIT admin approval by default."""
    ssh_port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(ssh_port)

    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        # Public key rather than password: sshpass retries on its own, which
        # shows up as spurious failed-login attempts under a loaded suite.
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
                require_approval=require_approval,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        allow_insecure_algos=False,
                        host="localhost",
                        port=ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, role.id)
    return url, user, target


def _connect_held(processes, shared_wg, user, target, *command, options=()):
    """Start ssh; it authenticates, then waits for the approval."""
    return processes.start_ssh_client(
        "-p",
        str(shared_wg.ssh_port),
        "-o",
        "IdentityFile=ssh-keys/id_ed25519",
        *options,
        f"{user.username}#{target.name}@localhost",
        *command,
        stderr=subprocess.PIPE,
    )


def _wait_for_control_socket(path, client, deadline=15):
    for _ in range(deadline * 10):
        if os.path.exists(path):
            return
        assert client.poll() is None, "the client exited before multiplexing"
        time.sleep(0.1)
    raise AssertionError("the multiplexing master never opened its control socket")


def _assert_request_disappears(url, user, target):
    """The request must clear on its own — no admin decision, and well inside
    the approval window."""
    with admin_client(url) as api:
        for _ in range(40):
            pending = [
                a
                for a in api.get_session_approvals()
                if a.target == target.name and a.username == user.username
            ]
            if not pending:
                return
            time.sleep(0.25)
    raise AssertionError("approval request outlived the session")
