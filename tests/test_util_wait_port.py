"""What `wait_port` tells the caller when the wait does not succeed.

Every case here failed silently before: the caller was told the port was up.
On 2026-09-13 that turned `minio/minio` disappearing from Docker Hub into
`Port 1903 is not up` after a 60s timeout, with `docker: pull access denied`
visible only in pytest's captured stderr.
"""

import socket
import subprocess
import threading
import time

import pytest

from .util import alloc_port, wait_port


def test_a_child_that_exits_is_named_rather_than_timed_out():
    """The case the `for_process` argument exists for.

    It raised inside a `try` whose `except` caught `TimeoutExpired`, so the
    exception was swallowed, the wait thread died, and the caller was told the
    port had come up."""
    port = alloc_port()
    child = subprocess.Popen(["sh", "-c", "exit 3"])
    started = time.monotonic()
    with pytest.raises(Exception) as caught:
        wait_port(port, for_process=child, timeout=30)
    # Asserted, or this passes just as well on a plain timeout.
    assert time.monotonic() - started < 10, "waited for the timeout instead"
    assert "exited with code 3" in str(caught.value), caught.value


def test_a_port_that_never_opens_still_times_out():
    port = alloc_port()
    with pytest.raises(Exception, match=f"Port {port} is not up"):
        wait_port(port, timeout=1)


def test_an_open_port_that_closes_on_us_reaches_the_caller():
    """`recv=True` raises a plain `Exception`, which is not a `socket.error`,
    so it escaped the retry loop and killed the wait thread.

    The peer has to accept and close: a peer that accepts and stays silent
    makes `recv` time out, and `socket.timeout` IS a `socket.error`, so that
    one is retried rather than reported -- which is the intended behaviour and
    is why this test closes instead of holding."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_and_close():
        conn, _ = server.accept()
        conn.close()

    threading.Thread(target=accept_and_close, daemon=True).start()
    try:
        with pytest.raises(Exception, match="not responding"):
            wait_port(port, timeout=10)
    finally:
        server.close()


def test_a_port_that_is_up_is_still_reported_as_up():
    """The control. Without it the three above pass on a `wait_port` that
    always raises."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        wait_port(port, recv=False, timeout=10)
    finally:
        server.close()
