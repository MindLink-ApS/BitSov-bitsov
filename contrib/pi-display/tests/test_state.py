import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import bitsov_display as bd

DOWN = bd.Probe(None)
NOT_FOUND = bd.Probe(404)
LOCKED = bd.probe_from_body(
    200,
    json.dumps(
        {
            "state": "locked",
            "node_id": "ab" * 32,
            "fingerprint": "cd" * 16,
            "locked_since": 1,
            "attempts_left": 20,
            "hosted_by": "Rasmus's Pi",
        }
    ).encode(),
)
LIVEZ_JSON = bd.probe_from_body(200, b'{"status":"ok","uptime_secs":93784,"version":2}')
LIVEZ_BOOTSTRAP = bd.probe_from_body(200, b"ok")
HEALTH = bd.probe_from_body(
    200,
    json.dumps(
        {
            "hosted_by": None,
            "status": "ok",
            "connected_peers": 3,
            "e2ee_sessions": 2,
            "pending_deliveries": 1,
            "lightning_available": True,
            "lightning_payment_capable": False,
            "uptime_secs": 600,
            "version": 2,
            "lightning_backend": "ldk",
            "chain_backend": "esplora",
            "block_height": 900_123,
            "lightning_balance_msat": 123_456_789,
        }
    ).encode(),
)
HEALTH_LIVE = {"block_height": 900_123, "peers": 3, "lightning": bd.Lightning.RECEIVE_ONLY}


def test_probe_keeps_only_allow_listed_fields():
    assert LOCKED.fields == {"state": "locked", "hosted_by": "Rasmus's Pi"}
    assert HEALTH.fields == {
        "uptime_secs": 600,
        "hosted_by": None,
        "block_height": 900_123,
        "connected_peers": 3,
        "lightning_available": True,
        "lightning_payment_capable": False,
    }
    assert "123456789" not in repr(HEALTH)


@pytest.mark.parametrize(
    "available, capable, expected",
    [
        (True, True, bd.Lightning.READY),
        (True, False, bd.Lightning.RECEIVE_ONLY),
        (False, False, bd.Lightning.DOWN),
        (None, True, None),
        ("yes", True, None),
    ],
)
def test_lightning_readiness(available, capable, expected):
    body = json.dumps({"lightning_available": available, "lightning_payment_capable": capable}).encode()
    status = bd.map_state(NOT_FOUND, NOT_FOUND, bd.probe_from_body(200, body))
    assert status.lightning is expected


@pytest.mark.parametrize(
    "lock, livez, health, expected",
    [
        (DOWN, None, None, bd.NodeStatus(bd.NodeState.OFFLINE)),
        (DOWN, DOWN, DOWN, bd.NodeStatus(bd.NodeState.OFFLINE)),
        (LOCKED, None, None, bd.NodeStatus(bd.NodeState.LOCKED, hosted_by="Rasmus's Pi")),
        (NOT_FOUND, LIVEZ_JSON, None, bd.NodeStatus(bd.NodeState.RUNNING, 93784)),
        (NOT_FOUND, NOT_FOUND, HEALTH, bd.NodeStatus(bd.NodeState.RUNNING, 600, **HEALTH_LIVE)),
        (NOT_FOUND, LIVEZ_JSON, HEALTH, bd.NodeStatus(bd.NodeState.RUNNING, 93784, **HEALTH_LIVE)),
        (NOT_FOUND, NOT_FOUND, NOT_FOUND, bd.NodeStatus(bd.NodeState.RUNNING)),
        (NOT_FOUND, LIVEZ_BOOTSTRAP, None, bd.NodeStatus(bd.NodeState.SETUP)),
        (bd.Probe(500), bd.Probe(500), bd.Probe(500), bd.NodeStatus(bd.NodeState.RUNNING)),
        (NOT_FOUND, bd.probe_from_body(200, b'{"uptime_secs":0}'), None, bd.NodeStatus(bd.NodeState.RUNNING, 0)),
        (
            NOT_FOUND,
            bd.probe_from_body(200, b'{"uptime_secs":-3}'),
            HEALTH,
            bd.NodeStatus(bd.NodeState.RUNNING, 600, **HEALTH_LIVE),
        ),
    ],
)
def test_map_state(lock, livez, health, expected):
    assert bd.map_state(lock, livez, health) == expected


def _fake(answers):
    calls = []

    def get(path):
        calls.append(path)
        return answers.get(path, NOT_FOUND)

    return get, calls


def test_probe_node_offline_makes_one_call():
    get, calls = _fake({"/api/v1/node/lock": DOWN})
    assert bd.probe_node(get).state is bd.NodeState.OFFLINE
    assert calls == ["/api/v1/node/lock"]


def test_probe_node_locked_makes_one_call():
    get, calls = _fake({"/api/v1/node/lock": LOCKED})
    assert bd.probe_node(get).state is bd.NodeState.LOCKED
    assert calls == ["/api/v1/node/lock"]


def test_probe_node_live_without_operator_probes_reads_health_uptime():
    get, calls = _fake({"/api/v1/health": HEALTH})
    assert bd.probe_node(get) == bd.NodeStatus(bd.NodeState.RUNNING, 600, **HEALTH_LIVE)
    assert calls == ["/api/v1/node/lock", "/livez", "/api/v1/health"]


def test_probe_node_live_with_operator_probes_still_reads_public_health():
    get, calls = _fake({"/livez": LIVEZ_JSON, "/api/v1/health": HEALTH})
    status = bd.probe_node(get)
    assert status.uptime_secs == 93784 and status.block_height == 900_123
    assert calls == ["/api/v1/node/lock", "/livez", "/api/v1/health"]


def test_probe_node_bootstrap_skips_health():
    get, calls = _fake({"/livez": LIVEZ_BOOTSTRAP})
    assert bd.probe_node(get).state is bd.NodeState.SETUP
    assert calls == ["/api/v1/node/lock", "/livez"]


@pytest.mark.parametrize(
    "secs, text",
    [(0, "0s"), (59, "59s"), (60, "1m"), (3_660, "1h 1m"), (93_784, "1d 2h"), (10 * 86_400, "10d 0h")],
)
def test_format_uptime(secs, text):
    assert bd.format_uptime(secs) == text


def test_state_badge():
    snap = lambda status: bd.Snapshot(bd.NodeSettings(), status, bd.MachineStats(), "pi", 3141)  # noqa: E731
    assert bd.state_badge(snap(bd.NodeStatus(bd.NodeState.LOCKED))) == ("LOCKED", "unlock from your Mac")
    assert bd.state_badge(snap(bd.NodeStatus(bd.NodeState.RUNNING, 3_660))) == ("RUNNING", "up 1h 1m")
    assert bd.state_badge(snap(bd.NodeStatus(bd.NodeState.SETUP)))[0] == "NOT SET UP"
    assert bd.state_badge(snap(bd.NodeStatus(bd.NodeState.OFFLINE)))[0] == "OFFLINE"


class _LockedHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/api/v1/node/lock":
            body = LOCKED_BODY
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


LOCKED_BODY = b'{"state":"locked","node_id":"x","fingerprint":"y","hosted_by":null}'


def test_loopback_get_against_real_server_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.1:9")
    monkeypatch.setenv("http_proxy", "http://203.0.113.1:9")
    server = HTTPServer(("127.0.0.1", 0), _LockedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        status = bd.probe_node(lambda path: bd.loopback_get(port, path))
        assert status.state is bd.NodeState.LOCKED
    finally:
        server.shutdown()
        server.server_close()


def test_loopback_get_reports_closed_port_as_unreachable():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert bd.loopback_get(port, "/livez", timeout=0.5) == DOWN
    status = bd.probe_node(lambda path: bd.loopback_get(port, path, timeout=0.5))
    assert status.state is bd.NodeState.OFFLINE


def test_loopback_get_refuses_non_paths():
    with pytest.raises(ValueError):
        bd.loopback_get(3141, "http://example.com/")
