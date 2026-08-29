"""Does a target that never completes its banner release the connecting user?

Written on the feature branch, but with a public-key target: the certificate
path is deliberately not taken, so a hang here would belong to the branch as
a whole and not to certificate issuance. Twenty iterations of this passed on
upstream, so if it hangs here the difference is something this branch adds.

"""

import socket
import subprocess
import threading
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import common_args
from .util import alloc_port, wait_port


class NeverEndingBanner:
    """Accepts, then sends a version line it never terminates."""

    def __init__(self):
        self.port = alloc_port()
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            try:
                while not self._stop.is_set():
                    client.sendall(b"SSH-2.0-" + b"A" * 1024)
                    self._stop.wait(0.05)
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


def test_a_target_that_never_finishes_its_banner_releases_the_client(
    processes: ProcessManager, wg_c_ed25519_pubkey
):
    wg = processes.start_wg()
    wait_port(wg.http_port, recv=False)

    server = NeverEndingBanner()
    server.start()
    try:
        url = f"https://localhost:{wg.http_port}"
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
                            port=server.port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        client = processes.start_ssh_client(
            f"{user.username}:{target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            # No tracing flag. The control: twenty iterations without one
            # reproduced on the sixteenth, and eighty with -v or -vvv
            # reproduced none. Either the tracing is a participant in the race
            # or that first hit was luck, and only a run in the original shape
            # tells them apart.
            *common_args,
            "ls /bin/sh",
            password="123",
        )
        # Forty seconds is past the gateway's own thirty-second handshake bound
        # with room to spare, so a client still running here is not waiting on
        # that bound — it is waiting on nothing.
        try:
            client.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            client.kill()
            out, err = client.communicate(timeout=10)
            print("---- ssh stdout ----")
            print(out.decode(errors="replace")[-3000:])
            print("---- ssh stderr (last 120 lines) ----")
            print("\n".join(err.decode(errors="replace").splitlines()[-120:]))
            raise
    finally:
        server.stop()
