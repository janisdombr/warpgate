"""Is the hang a race that a delay can pin down?

The gateway ends a session by closing the client's channels. Whether there are
any depends on whether the client's channel request has been answered by the
time the target's handshake fails. If that is the whole of it, holding the bad
banner back by a controlled amount should move the race to one side and make
the outcome the same every time.

Each case runs the same target ten times. A delay that hangs ten out of ten is
a deterministic reproduction, which is worth more than six hundred attempts at
one percent.
"""

import socket
import subprocess
import threading
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import common_args
from .util import alloc_port, wait_port


class DelayedBadBanner:
    def __init__(self, delay: float):
        self.delay = delay
        self.port = alloc_port()
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            try:
                if self.delay:
                    self._stop.wait(self.delay)
                client.sendall(b"SSH-2.0-warpgate-probe\r\n")
                client.sendall(bytes(range(256)) * 64)
            except OSError:
                pass
            finally:
                client.close()

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def _user_and_target(url, port):
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
                        kind="Ssh", host="127.0.0.1", port=port, username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(target.id, role.id)
    return user, target


@pytest.mark.parametrize("delay", [0.0, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0])
def test_how_often_does_this_delay_hang(delay, processes: ProcessManager):
    wg = processes.start_wg()
    wait_port(wg.http_port, recv=False)
    url = f"https://localhost:{wg.http_port}"

    server = DelayedBadBanner(delay)
    try:
        user, target = _user_and_target(url, server.port)
        hangs = 0
        for _ in range(10):
            client = processes.start_ssh_client(
                f"{user.username}:{target.name}@localhost",
                "-p", str(wg.ssh_port), *common_args, "ls /bin/sh", password="123",
            )
            try:
                client.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                hangs += 1
                client.kill()
                client.communicate(timeout=10)
        print(f"RESULT delay={delay:>4} hangs={hangs}/10")
    finally:
        server.stop()
