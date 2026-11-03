![TRAPDOOR](Trapdoor-banner.png)

# TRAPDOOR 🕷️

An internal honeypot lab for teaching **CompTIA Network+** and **Security+**.

A trapdoor spider doesn't advertise. It builds a door that looks like nothing,
waits behind it, and the interesting part is the ambush. Same idea here: the
services look ordinary, and everything that touches them is recorded.

## What this is

A Docker Compose stack of low-cost honeypots with a **single normalized event
schema** across all of them, plus a library of **scripted attacks** so a session
is reproducible in class.

Built for a classroom, not for internet-scale threat collection.

## What this is NOT

- Not a threat-intel feed. It runs on an internal network and only sees traffic
  you point at it.
- Not a production security control. Do not put this on a network segment that
  also carries real production traffic without a reviewed firewall policy.
- Not a fork of Cowrie or any other honeypot. We run upstream images and own the
  parts that are actually ours: the schema, the pipeline, the scenarios, the labs.

## Why internal-only is the right call for a lab

| | Public honeypot | Internal lab honeypot |
|---|---|---|
| Background noise | Thousands of bot sessions/day, free | None — you generate it |
| Reproducible? | No. You can't replay today's traffic tomorrow | **Yes — same scenario, same session** |
| Legal / privacy | Real third-party creds and payloads | Only your own lab traffic |
| Teaching fit | "Look at this map" | **"Watch this attack, then find it in the logs"** |

The honest tradeoff: the dashboard will be empty until an instructor runs a
scenario. That is by design, not a bug. The lab is a **replay and observation
environment**.

## Stack

| Component | Role |
|---|---|
| **Cowrie** | SSH + Telnet honeypot, emulated shell, captures uploads |
| **nginx** | Web decoy — real server, real logs, scanner bait paths |
| **Shipper** | Normalizes both sources into one JSONL schema — **core, not optional**. `make up` starts it, `make logs` follows its output, and `make sessions` reads only what it writes |
| *(optional)* | OpenSearch + Dashboards via `compose.siem.yml` |

Default footprint: **~2–4 GB RAM and ~10 GB free disk** for the core stack.
`make clean` empties `out/`, so that 10 GB is the steady state, not the
high-water mark of a long-running laptop.

Where the disk goes: `out/events.jsonl` grows continuously at roughly **10–50
MB/day** for a lab used a few hours a week (one event is ~300–400 bytes; a
brute-force run is a few dozen events, a scan is a few hundred). Retention
(default 14 days, `RETENTION_DAYS`) only deletes whole files older than the
cutoff, so a file still being written is never pruned — and it only ever looks
at `*.jsonl` in `out/`. Cowrie's uploaded artifacts live in the `cowrie_var`
Docker volume, which retention does **not** touch; `make clean` removes it.

A ceiling worth knowing: Docker's `json-file` driver caps each container's log
at 10 MB × 3 files (set in `compose.yml`), so container logs cannot grow without
bound. `.verify/` keeps a few small text files per day. If you leave the lab up
for months, run `du -sh out/ .verify/` and `docker system df` before a class.

See [`docs/DEPLOY.md`](docs/DEPLOY.md#disk) for the measured numbers and the
host it was measured on.

## The event schema

Every honeypot speaks its own dialect. TRAPDOOR's job is to flatten them into
one shape so a student can reason about "an event" regardless of protocol.

See [`schema/event.schema.json`](schema/event.schema.json) — that file is the
contract; if this page and the schema ever disagree, the schema wins and this
page is a bug.

```json
{
  "ts": "2026-11-01T22:04:11.512Z",
  "sensor": "cowrie",
  "event": "auth_failed",
  "proto": "ssh",
  "src_ip": "10.20.30.44",
  "src_port": 51233,
  "dst_port": 2222,
  "session_id": "a1b2c3",
  "username": "root",
  "password": "toor",
  "payload_sha256": null,
  "scenario_id": "simnet-1"
}
```

| Field | Meaning |
|---|---|
| `ts` | UTC, ISO 8601, milliseconds |
| `sensor` | `cowrie` \| `nginx` — which honeypot produced it |
| `event` | One of: `connect`, `disconnect`, `auth_failed`, `auth_success`, `command`, `upload`, `download`, `http_request`. These are *our* names, not Cowrie's — Cowrie writes `cowrie.login.failed`, the schema and every consumer see `auth_failed` |
| `proto` | `ssh` \| `telnet` \| `http` |
| `src_ip` / `src_port` | Who knocked |
| `session_id` | Ties events into one attacker transcript |
| `username` / `password` | Only when the protocol carries creds |
| `payload_sha256` / `payload_bytes` | Hash and size of a transferred artifact. **The bytes themselves are not in this log** — see below. |
| `scenario_id` | Set by scripted attacks so class sessions are filterable |

## Quick start

```bash
git clone https://github.com/crperdue73/Trapdoor.git && cd trapdoor
cp .env.example .env          # set SENSOR_NAME, LAB_CIDR
make up                        # core stack: cowrie + nginx + shipper
make logs                      # follow normalized JSONL
make up-siem                   # optional: add OpenSearch + dashboards
```

Then:

```bash
make scenario                      # no SCENARIO: lists the ones you have
make scenario SCENARIO=ssh-bruteforce   # scripted attack, tagged with a scenario id
make sessions                         # list sessions with event counts
make sessions SESSION=a1b2c3          # render one session as a transcript
```

### What the output looks like

Real output of `make sessions` after one brute-force run and one web scan —
session id, sensor, event count, first event time:

```
session        sensor   events  first_seen
9f3c1e08a74b   cowrie       10  2026-11-01T22:04:09.000Z
b17d44c20e9a   nginx         5  2026-11-01T22:05:31.000Z
```

Real output of `make sessions SESSION=9f3c1e08a74b`. Ten events, one attacker,
one page:

```
ts                       event          proto detail
2026-11-01T22:04:09.117Z connect        ssh
2026-11-01T22:04:10.882Z auth_failed    ssh   admin:admin
2026-11-01T22:04:11.512Z auth_failed    ssh   root:toor
2026-11-01T22:04:12.006Z auth_success   ssh   root:toor
2026-11-01T22:04:13.440Z command        ssh   id
2026-11-01T22:04:19.004Z command        ssh   uname -a
2026-11-01T22:04:24.771Z command        ssh   cat /etc/passwd
2026-11-01T22:04:31.095Z command        ssh   ls -la /
2026-11-01T22:04:37.612Z command        ssh   echo "TRAPDOOR-CANARY"
2026-11-01T22:04:39.020Z disconnect     ssh
```

That is the lesson in ten lines: two rejected guesses, one accepted, then the
five commands everyone types first — all of it from an emulated shell where
nothing ran.

## Safety rails (and why they exist)

These are teaching material, not just hygiene:

- **No execution path from a captured payload.** The shipper records a hash
  and a byte count; the payload bytes themselves never enter the event log.
  To be precise, because the two halves are easy to conflate: the **event log**
  never contains payload bytes, only a hash and a size. Cowrie's own container
  volume (`cowrie_var`, mounted read-only into the shipper at `/in/cowrie`)
  **does** retain the uploaded files themselves, inside the honeypot
  container's storage, outside the log. That copy is inert — nothing executes
  it, nothing serves it, and no container has a mount from that volume that can
  run anything. `make clean` removes it with the volume; `RETENTION_DAYS` does
  not prune it (retention only deletes `*.jsonl` files in `out/`). If you want
  a shorter tail, prune that volume between classes.
- **Egress is locked down** on the honeypot containers. A compromised honeypot
  must not become a pivot.
- **Retention is short and explicit.** Honeypot data grows fast and is mostly
  worthless noise. The default is 14 days (`RETENTION_DAYS`); pruning only
  deletes whole files past the cutoff, so the file currently being written
  survives regardless of age. Budget disk accordingly — see the footprint note
  above.
- **Scoped to `LAB_CIDR`.** The firewall rules generated by `make firewall` only
  allow traffic from the lab subnet.

## Layout

```
compose.yml
compose.siem.yml
cowrie/         Cowrie config + lab filesystem
web/            nginx decoy: config + html
schema/         event.schema.json — the contract
shipper/        normalizer: honeypot dialects -> one schema
scenarios/      scripted attacks
docs/           setup, labs, retention
```

## License

MIT. See [LICENSE](LICENSE).
