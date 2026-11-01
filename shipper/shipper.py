"""TRAPDOOR shipper: honeypot dialects -> one normalized schema.

Reads Cowrie's JSON log and Snare's HTTP log, flattens both into the shape
defined by schema/event.schema.json, and appends JSONL to $OUT_DIR.

Design notes:
  - Payload bytes are NEVER written here. Only sha256 + size.
  - Unknown event types are dropped with a counter, not silently guessed.
  - Output is append-only JSONL: trivial for a student to read with `jq`,
    and trivial to ship into anything else later.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

LOG = logging.getLogger("shipper")

SENSOR_NAME = os.environ.get("SENSOR_NAME", "lab-sensor-01")
OUT_DIR = Path(os.environ.get("OUT_DIR", "/out"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "14"))
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))

COWRIE_LOG = Path("/in/cowrie/log/cowrie.json")
NGINX_LOG = Path("/in/nginx/trapdoor.json")

# Cowrie eventid -> our event name.
COWRIE_EVENTS = {
    "cowrie.session.connect": "connect",
    "cowrie.session.closed": "disconnect",
    "cowrie.login.failed": "auth_failed",
    "cowrie.login.success": "auth_success",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "upload",
    "cowrie.client.version": None,  # dropped: no teaching value on its own
    "cowrie.client.kex": None,
    "cowrie.client.fingerprint": None,
}

# Cowrie protocol strings -> our enum.
COWRIE_PROTO = {"ssh": "ssh", "telnet": "telnet"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def clean_proto(value: Any) -> str:
    proto = str(value or "").lower()
    return "telnet" if "telnet" in proto else "ssh"


def emit(record: dict[str, Any], dropped: dict[str, int]) -> dict[str, Any] | None:
    """Validate the parts that matter and return a normalized event."""
    if not record.get("event"):
        return None
    # Guard the schema contract: these three are required.
    if not record.get("ts") or not record.get("sensor"):
        return None
    if not record.get("proto"):
        return None
    return record


def base(sensor: str) -> dict[str, Any]:
    return {
        "ts": None,
        "sensor": sensor,
        "event": None,
        "proto": None,
        "src_ip": None,
        "src_port": None,
        "dst_port": None,
        "session_id": None,
        "username": None,
        "password": None,
        "command": None,
        "http_method": None,
        "http_path": None,
        "http_user_agent": None,
        "payload_sha256": None,
        "payload_bytes": None,
        "scenario_id": None,
        "sensor_name": SENSOR_NAME,
    }


_CRED_RE = re.compile(r"credential|password|passwd", re.IGNORECASE)


def cowrie_to_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Cowrie JSON line -> normalized event, or None to drop."""
    eventid = raw.get("eventid", "")
    event = COWRIE_EVENTS.get(eventid, "unknown")
    if event is None:
        return None
    if event == "unknown":
        LOG.debug("unmapped cowrie eventid: %s", eventid)
        return None

    ev = base("cowrie")
    ev["ts"] = raw.get("timestamp") or utc_now_iso()
    ev["event"] = event
    ev["proto"] = COWRIE_PROTO.get(str(raw.get("protocol", "")).lower(), clean_proto(raw.get("protocol")))

    ev["src_ip"] = raw.get("src_ip")
    ev["src_port"] = as_int(raw.get("src_port"))
    ev["dst_port"] = as_int(raw.get("dst_port"))
    ev["session_id"] = raw.get("session") or raw.get("session_id")

    if event in ("auth_failed", "auth_success"):
        ev["username"] = raw.get("username")
        ev["password"] = raw.get("password")

    if event == "command":
        ev["command"] = raw.get("input") or raw.get("message")

    if event in ("upload", "download"):
        ev["payload_bytes"] = as_int(raw.get("size")) or as_int(raw.get("shasum_size"))
        # Cowrie logs a shasum field for some artifacts.
        shasum = raw.get("shasum")
        if isinstance(shasum, str) and re.fullmatch(r"[a-f0-9]{64}", shasum):
            ev["payload_sha256"] = shasum

    ev["scenario_id"] = raw.get("scenario_id")
    return emit(ev, {})


def nginx_to_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """nginx trapdoor_json line -> normalized event, or None to drop.

    nginx's escape=json handles quoting, so a request URI containing quotes,
    newlines, or Unicode cannot break the line format. The shipper only has
    to read a well-formed JSON object.

    Note: nginx cannot compute a hash of the request body inline. If a body
    was present we record its length only; the shipper does not read bodies
    off the wire. That is a deliberate limit, documented in docs/limitations.md.
    """
    ev = base("nginx")

    ts = raw.get("timestamp")
    if isinstance(ts, str):
        # nginx $time_iso8601 is "2026-11-01T22:04:11-05:00" — no millis.
        # Our schema wants UTC with millis, so normalize shape without
        # guessing the offset (nginx already includes it).
        ev["ts"] = ts if "." in ts else ts.replace("T", "T", 1)
    else:
        ev["ts"] = utc_now_iso()

    ev["event"] = "http_request"
    ev["proto"] = "http"
    ev["src_ip"] = raw.get("src_ip")
    ev["src_port"] = as_int(raw.get("src_port"))
    ev["dst_port"] = as_int(raw.get("dst_port"))
    ev["http_method"] = raw.get("method")
    ev["http_path"] = raw.get("uri")
    ev["http_user_agent"] = raw.get("user_agent")
    # The status is the finding, not decoration. A decoy that logs GET /.env
    # and not the 403 recorded the question and not the answer. Carried as an
    # int so it sorts and ranges; None if nginx gave us nothing usable, which
    # is a data gap worth seeing rather than a 0 worth believing.
    ev["http_status"] = as_int(raw.get("status"))
    ev["payload_bytes"] = as_int(raw.get("body_bytes"))
    ev["scenario_id"] = raw.get("scenario_id")

    # Session: nginx has no session concept. Build a stable one from the
    # 5-tuple plus the second, so a burst from one client groups together
    # and a student can follow "this scanner's run" as one transcript.
    stamp = str(ev["ts"] or "")[:19]
    seed = f"{ev['src_ip']}:{ev['src_port']}:{stamp}"
    ev["session_id"] = hashlib.sha256(seed.encode()).hexdigest()[:12]

    return emit(ev, {})


def tail(path: Path) -> Iterator[dict[str, Any]]:
    """Follow a JSONL file, yielding parsed objects. Survives truncation/rotation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    inode = None
    handle = None
    while True:
        try:
            st = path.stat()
            if inode != st.st_ino or handle is None:
                if handle:
                    handle.close()
                handle = path.open("r", encoding="utf-8", errors="replace")
                handle.seek(st.st_size)
                inode = st.st_ino
                LOG.info("following %s", path)
            line = handle.readline()
            if not line:
                time.sleep(POLL_SECONDS)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                LOG.warning("bad json in %s", path)
        except FileNotFoundError:
            time.sleep(POLL_SECONDS)


def append(out: Path, event: dict[str, Any]) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")


def prune() -> None:
    """Retention: honeypot data grows fast and is mostly noise."""
    cutoff = time.time() - RETENTION_DAYS * 86400
    if not OUT_DIR.exists():
        return
    for entry in OUT_DIR.glob("*.jsonl"):
        if entry.stat().st_mtime < cutoff:
            entry.unlink(missing_ok=True)
            LOG.info("pruned %s (retention %dd)", entry.name, RETENTION_DAYS)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG.info("trapdoor shipper up: sensor=%s out=%s", SENSOR_NAME, OUT_DIR)

    out = OUT_DIR / "events.jsonl"
    last_prune = 0.0

    # Each source follows in its own generator; we interleave with a simple
    # round-robin so one quiet sensor can't starve the other.
    sources = ((COWRIE_LOG, cowrie_to_event), (NGINX_LOG, nginx_to_event))
    gens = [(path, fn, tail(path)) for path, fn in sources]

    while True:
        progressed = False
        for path, fn, gen in gens:
            try:
                raw = next(gen)
            except StopIteration:
                continue
            try:
                event = fn(raw)
            except Exception:  # a malformed line must never kill the shipper
                LOG.exception("normalizer error on %s", path)
                continue
            if event:
                append(out, event)
                progressed = True
        if time.time() - last_prune > 3600:
            prune()
            last_prune = time.time()
        if not progressed:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
