#!/usr/bin/env python3
"""Render one session from out/events.jsonl as a transcript.

Feeds the "show me eight lines" question. The output is deterministic for a
given input file and is printed by `make sessions SESSION=<id>`.

  python3 scripts/render_session.py <events.jsonl> <session_id>
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path, session = argv[1], argv[2]
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("session_id") == session:
                rows.append(ev)
    rows.sort(key=lambda e: e["ts"])

    print(f"{'ts':<24} {'event':<14} {'proto':<5} detail")
    for ev in rows:
        detail = ev.get("command") or ev.get("http_path") or ""
        if ev.get("event") in ("auth_failed", "auth_success"):
            detail = f"{ev.get('username')}:{ev.get('password')}"
        if ev.get("payload_sha256"):
            detail = f"{detail} sha256={ev['payload_sha256'][:12]}…"
        print(f"{ev['ts']:<24} {ev['event']:<14} {ev.get('proto', ''):<5} {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
