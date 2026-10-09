"""Client IP resolution behind two reverse proxies.

Chain modelled: client -> P1 (e.g. a CDN) -> P2 (nginx) -> Warpgate. P1 sends
`X-Forwarded-For: <client>`, P2 appends P1's address, so Warpgate receives
`X-Forwarded-For: <client>, <P1>`. These tests record what Warpgate does with
that header when `trust_x_forwarded_headers` is on; they pass on current main.
"""

import time
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

CLIENT_IP = "198.51.100.7"
OTHER_CLIENT_IP = "192.0.2.66"
FIRST_PROXY_IP = "203.0.113.10"

ONE_PROXY = CLIENT_IP
TWO_PROXIES = f"{CLIENT_IP}, {FIRST_PROXY_IP}"


def _login(url: str, username: str, password: str, forwarded_for: str) -> requests.Response:
    session = requests.Session()
    session.verify = False
    session.headers["X-Forwarded-For"] = forwarded_for
    return session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": username, "password": password},
    )


def _create_user(api, password: str, allowed_ip_ranges=None):
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password=password))
    if allowed_ip_ranges is not None:
        api.update_user(
            user.id,
            sdk.UserDataRequest(username=user.username, allowed_ip_ranges=allowed_ip_ranges),
        )
    return user


@pytest.fixture
def proxied_wg(processes: ProcessManager):
    wg = processes.start_wg(config_patch={"http": {"trust_x_forwarded_headers": True}})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    yield wg


def test_two_proxy_chain_rejects_a_user_restricted_to_their_own_client_ip(
    proxied_wg: WarpgateProcess,
):
    url = f"https://localhost:{proxied_wg.http_port}"
    with admin_client(url) as api:
        user = _create_user(api, "123", allowed_ip_ranges=[f"{CLIENT_IP}/32"])

    one_proxy = _login(url, user.username, "123", ONE_PROXY)
    assert one_proxy.status_code == 201, one_proxy.text

    # Same client, same credentials; only the proxy depth differs.
    two_proxies = _login(url, user.username, "123", TWO_PROXIES)
    assert two_proxies.status_code == 401, two_proxies.text
    assert two_proxies.json()["state"] == "IpRejected"


def test_two_proxy_chain_ip_block_lands_on_the_first_proxy_and_locks_out_other_clients(
    processes: ProcessManager,
):
    wg = processes.start_wg(config_patch={"http": {"trust_x_forwarded_headers": True}})
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    url = f"https://localhost:{wg.http_port}"

    ip_max = 3
    with admin_client(url) as api:
        api.update_parameters(
            sdk.ParameterUpdate(
                login_protection_enabled=True,
                lp_ip_max_attempts=ip_max,
                lp_ip_time_window_seconds=600,
                lp_ip_base_block_duration_seconds=120,
                lp_ip_block_duration_multiplier=2.0,
                lp_ip_max_block_duration_seconds=3600,
                lp_ip_cooldown_reset_seconds=3600,
                # High enough that only the IP block can explain a rejection.
                lp_user_max_attempts=100,
                lp_user_time_window_seconds=600,
                lp_user_auto_unlock=True,
                lp_user_lockout_duration_seconds=120,
            )
        )
        attacker_target = _create_user(api, "attacker-does-not-know-this")
        victim = _create_user(api, "victim-password")
        assert api.list_blocked_ips() == []

    # The victim can log in through the two-proxy chain before any block exists.
    before = _login(url, victim.username, "victim-password", TWO_PROXIES)
    assert before.status_code == 201, before.text

    attacker_chain = f"{OTHER_CLIENT_IP}, {FIRST_PROXY_IP}"
    for i in range(ip_max):
        resp = _login(url, attacker_target.username, f"wrong-{i}", attacker_chain)
        assert resp.status_code // 100 != 2, resp.text
        assert resp.json().get("state") != "IpBlocked", resp.text

    time.sleep(0.2)

    with admin_client(url) as api:
        blocked = [b.ip_address for b in api.list_blocked_ips()]
    assert blocked == [FIRST_PROXY_IP]

    # A different client with correct credentials, behind the same first proxy.
    via_two = _login(url, victim.username, "victim-password", TWO_PROXIES)
    assert via_two.status_code // 100 != 2, via_two.text
    assert via_two.json().get("state") == "IpBlocked", via_two.text

    # The same victim seen through one proxy is not blocked: the block is keyed
    # by the proxy address, not by either client.
    via_one = _login(url, victim.username, "victim-password", ONE_PROXY)
    assert via_one.status_code == 201, via_one.text

    # The attacker's own address was never the block key.
    via_attacker_direct = _login(url, victim.username, "victim-password", OTHER_CLIENT_IP)
    assert via_attacker_direct.status_code == 201, via_attacker_direct.text
