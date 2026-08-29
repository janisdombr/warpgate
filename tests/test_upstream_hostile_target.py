"""The hostile-target suite, on upstream, without the certificate feature.

This is the shape that reproduces: the same `hostile_ssh_server`, the same set
of modes, the same one-target-per-mode parametrisation as the branch's own
suite. The single difference is the target — an ordinary public-key SSH target
here, where the branch uses a certificate one — so nothing in this file depends
on anything unmerged.

A simplified probe was tried first and reproduced once in sixty iterations,
which is too rare to conclude anything from. The branch's suite reproduces on
the first. If the difference is the shape rather than the branch, this file
finds it; if upstream stays clean across the same modes, that is finally worth
something.
"""

import subprocess
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .hostile_ssh_server import MODES, HostileSSHServer
from .test_ssh_proto import common_args
from .util import wait_port


def _user_and_target(url, port):
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
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


@pytest.mark.parametrize("mode", sorted(set(MODES) - {"silent_after_banner"}))
def test_a_hostile_target_cannot_hang_or_crash_the_gateway(
    mode, processes: ProcessManager, timeout
):
    wg = processes.start_wg()
    wait_port(wg.http_port, recv=False)
    url = f"https://localhost:{wg.http_port}"

    server = HostileSSHServer(mode)
    server.start()
    try:
        user, target = _user_and_target(url, server.port)
        client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            *common_args,
            "ls /bin/sh",
            password="123",
        )
        try:
            client.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            client.kill()
            raise
    finally:
        server.stop()
