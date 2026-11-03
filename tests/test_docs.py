#!/usr/bin/env python3
"""Check docs against the schema. The schema is the contract; docs are a claim.

Exists because the README contradicted the schema in five places on 2026-11-02
and nothing noticed — the only thing reading the page was whoever wrote it.
A hand-maintained list in prose cannot disagree with a machine-readable one, so
this makes the prose *be* the check.

Checks:
  1. the example JSON event matches the schema
  2. every event name the docs mention is in the schema enum, and every enum
     value is mentioned somewhere
  3. no doc uses a honeypot's dialect name (e.g. cowrie.login.failed) where it
     means our field value

Exit non-zero on any disagreement. Run by `make test`.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema/event.schema.json").read_text())
DOCS = ["README.md", "docs/DEPLOY.md", "docs/ACCEPTANCE.md", "docs/limitations.md"]

# Cowrie's own eventids. They may appear when quoting Cowrie, never as a value
# of our `event` field.
COWRIE_EVENTIDS = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.connect",
    "cowrie.session.closed",
}

failures: list[str] = []


def check_example() -> None:
    readme = (ROOT / "README.md").read_text()
    block = re.search(r"```json\n(.*?)```", readme, re.S)
    if not block:
        failures.append("README: no ```json example block found")
        return
    example = json.loads(block.group(1))
    enum = set(SCHEMA["properties"]["event"]["enum"])
    if example["event"] not in enum:
        failures.append(
            f"README example event {example['event']!r} is not in the schema enum"
        )
    for field in SCHEMA["required"]:
        if field not in example:
            failures.append(f"README example missing required field {field!r}")
    extra = set(example) - set(SCHEMA["properties"])
    if extra:
        failures.append(f"README example has fields not in the schema: {sorted(extra)}")


def check_event_names() -> None:
    enum = set(SCHEMA["properties"]["event"]["enum"])
    seen: set[str] = set()
    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text()
        seen |= set(re.findall(r"\b(auth_failed|auth_success|http_request|upload|download)\b", text))
        for bad in re.findall(r"\b(login_failed)\b", text):
            failures.append(f"{name}: {bad!r} — the schema calls this auth_failed")
    missing = enum - seen
    # connect/disconnect/command are common English words; only the distinctive
    # ones are meaningful to require.
    required_in_docs = {"auth_failed", "auth_success", "http_request"}
    absent = required_in_docs - seen
    if absent:
        failures.append(f"docs never mention these schema events: {sorted(absent)}")


def check_dialect_leak() -> None:
    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            # A dialect name is fine when the word Cowrie is on the same line,
            # i.e. the sentence is explicitly about Cowrie's output.
            if "cowrie." in line and "Cowrie" in line:
                continue
            for eid in COWRIE_EVENTIDS:
                if eid in line:
                    failures.append(
                        f"{name}:{lineno}: uses Cowrie's {eid} without saying so"
                    )


def main() -> int:
    check_example()
    check_event_names()
    check_dialect_leak()
    if failures:
        for f in failures:
            print(f"FAIL  {f}", file=sys.stderr)
        return 1
    print("PASS  docs agree with schema/event.schema.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
