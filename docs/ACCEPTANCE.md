# TRAPDOOR — acceptance claims

Every claim is written as a **testable statement about the box**, not a
description of what an attacker does. "An unauthenticated GET to `/` returns
200" can be checked by anyone with curl. "A student attempts to log in" cannot.

This file is the acceptance list. It is split into two halves on purpose:

- **Part 1 — proven.** Demonstrated on the live host, with the artifact that
  demonstrated it named.
- **Part 2 — not proven.** Named gaps, including the one that matters most:
  `scripts/firewall.sh --apply` **has never executed on a host with root.**

A claim moves from Part 2 to Part 1 only when someone ran the thing and kept
the output. Writing it down differently does not move it.

Run order: `scripts/verify.sh` first (it checks the platform), then the
scenarios (they check the behaviour). Both exit non-zero on an unmet claim.

**A check that cannot run is `NOT RUN` and fails the run. It is not a pass.**
A check that cannot run has proven nothing. This sentence exists because the
containment proof in this repo was unparsable for two days while the commit
message said containment was proved.

---

## Part 1 — proven on the live host

Host `192.168.111.45`. Evidence directory `out/` and `.verify/`.

### A. Platform — `scripts/verify.sh`

| # | Claim | Evidence |
|---|-------|----------|
| A1 | The decoy ports are bound to `LAB_BIND_IP`, not `0.0.0.0` | `ss -tlnp` shows `192.168.111.45:2222`, `:2223`, `:8080` |
| A2 | Nothing else opened a listener while the stack started | before/after `ss -tlnp` diff is empty |
| A3 | No published port is on a wildcard address | wildcard grep returns nothing for our ports |
| A4 | The web decoy is up and answering | `GET /` → 200 |
| A5 | The bait is present and deliberately forbidden | `GET /.env` → 403 |
| A6 | SSH is being emulated | banner matches `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2` |
| A7 | The pipeline normalizes events | `out/events.jsonl` parses, sensors = `cowrie` + `nginx` |
| A8 | All three services run | `docker compose ps` lists cowrie, web, shipper |
| A9 | The honeypot cannot reach the LAN | from inside cowrie, a request to `192.168.0.1` fails |

**A1 and A9 are the two that matter.** A1 because a wrong bind is silent and
fatal — Docker publishes wide and no host firewall rule saves it, since Docker
writes its own rules ahead of ours. A9 because a network policy you have not
tested is a network policy you do not have.

### B. SSH brute-force — `scenarios/ssh-bruteforce.sh`

| # | Claim | Evidence |
|---|-------|----------|
| B1 | An unauthenticated TCP connect to `:2222` returns an SSH banner | `nc` shows `SSH-2.0-...` |
| B2 | A rejected credential is logged with its username | `cowrie.login.failed` with `username` populated |
| B3 | An accepted credential is logged | `cowrie.login.success` for `root` |
| B4 | Commands typed in the shell are logged individually | `cowrie.command.input` × 5 (`id`, `uname`, `cat`, `ls`, `echo`) |
| B5 | No command typed reaches the host | `scripts/containment-check.sh` exits 0 |
| B6 | The run is identical each time | same event order, same usernames, same count |

**B5 is the one that matters.** It is the difference between a decoy and a
vulnerable server.

`scripts/containment-check.sh` generates a **fresh canary per run**, types it
into the decoy shell in a way that would leave traces in `/root`, `/tmp` and
the shell history if it actually executed, then searches the host for it.
Contained = the canary is in the log and nowhere else.

**The canary is never transmitted to anyone, including reviewers.** A fixed or
shared canary can be planted — by a helpful colleague, by a future maintainer,
or by the person who wrote the check. Evidence handed to someone should be
evidence they could not have contaminated. If you need to describe the test to
another person, describe the method and the search path, not the string.

### C. Web scanner — `scenarios/web-scan.sh`

| # | Claim | Evidence |
|---|-------|----------|
| C1 | The decoy is an ordinary web server | `GET /` → 200 |
| C2 | Secret paths exist but are forbidden | `GET /.env` → 403, not 404 |
| C3 | VCS paths are forbidden | `GET /.git/config` → 403 |
| C4 | Cloud credential paths are forbidden | `GET /.aws/credentials` → 403 |
| C5 | CMS paths are forbidden | `GET /wp-login.php` → 403 |
| C6 | A genuinely absent path is 404 | random path → 404 |
| C7 | Requests are logged with path and status | `sensor == "nginx"` in `out/events.jsonl`, `http_status` populated |
| C8 | Request bodies are not stored | `payload_sha256` is null for nginx events |

C2–C5 matter most. 403 rather than 404 because a scanner that sees "exists but
forbidden" keeps probing and generates a transcript; a scanner that sees 404
moves on and generates nothing. That is the whole design of the bait list.

C8 is an honest limitation, not a feature. See `docs/limitations.md`.

### D. What the boundary actually is

Measured on `.45`, 2026-11-02, and the reason `scripts/firewall.sh` prints
instead of acting by default:

| # | Claim | Evidence |
|---|-------|----------|
| D1 | Off-box traffic to a published port reaches `FORWARD`/`DOCKER-USER`, never `INPUT` | `DOCKER-USER` counters moved 12 pkts / 2230 bytes on one request from `.43` |
| D2 | An `INPUT DROP` on `:8080` closes loopback and not the lab | `.45` → 200 while `127.0.0.1` → 000, with the DROP installed |
| D3 | `! -s 192.168.0.0/16` matches nothing on this farm | every farm host is inside the /16 |
| D4 | iptables rejects two `--source` options in one rule | `multiple --source options not allowed` |

D3 is the honest one: with `LAB_CIDR` at the farm /16, the firewall rule shape
this script emits would be present, reachable, correct, and do nothing. The
decoy is open to the whole /16, and the only reason it is not open to the
internet is that the farm is triple-NATed.

---

## Part 2 — NOT proven

These are stated so nobody reads Part 1 as more than it is. Each one has a
line saying what would close it.

### ⚠️ G1 — `firewall.sh --apply` has never run on a host with root

**The single largest gap in this repo.** Everything in `firewall.sh` from the
`== applying ==` banner to the final `applied and verified.` is a claim about
a code path nobody has executed. It parses (`bash -n` clean, `set -euo
pipefail`), and parsing is not running.

Specifically unproven:

- that `iptables-save > /root/iptables-backup-*.rules` succeeds and the
  rollback file is readable when it matters
- that the `iptables -D DOCKER-USER` teardown loop converges instead of
  mangling the chain on a re-run
- that the bridge enumeration returns both `docker0` and `br-*` on the real
  host and refuses cleanly when it returns neither
- that the post-apply probes (HTTP 200, health path, SSH banner) pass while
  the DROP is actually in the chain
- **that it is idempotent** — run twice, same chain, no duplicates

**To close:** on `.45`, as root, in this order — `scripts/firewall.sh` (read
the printed output first), `scripts/firewall.sh --apply`, `scripts/verify.sh`,
then `--apply` a second time and diff `iptables -S DOCKER-USER` between runs.
Record the backup filename and the full output in `out/`.

**A specific warning for whoever runs it:** `verify.sh` check 6 is the
unreachability probe for A9. An `OK` there with **no** accompanying
`REFUSED`/`UNREACHABLE` line means the probe broke, not that containment
holds. Read the line, not the verdict.

### ⚠️ G2 — the containment proof's own history

`firewall.sh` carried two defects (a stray `fi`, and `$BRIDGES` used three
times with its declaration deleted) that made the containment proof
**unparsable from the commit that claimed containment** until `14c67d8`. The
claim was true-looking and uncheckable for two days.

**To close:** a lint step in `make check` that `bash -n`s every script, so a
syntax break cannot ship again. The lesson is not "test more" — it is that a
thing which cannot be parsed cannot disagree with you.

### G3 — not claimed: the deployment is secure

It is a teaching target. The host is a normal farm member; its exposure is a
farm policy question, not a TRAPDOOR one. See D3.

### G4 — not claimed: attacks are detected in real time

There is no alerting. Events are collected, not chased.

### G5 — not claimed: the decoy is unbreakable

Cowrie is medium-interaction. A determined attacker can escape an emulated
shell's *believability*. They cannot escape into the host through it — that is
a different guarantee, and it is what A9 tests.

### G6 — not claimed: results are forensically sound

Timestamps are Cowrie's, HTTP sessions are approximated, and there is no chain
of custody.

---

## Why this list is split in two

The risk is rarely where the worry is pointed. C7 is the worked example: my
instinct said the bait regex in `default.conf` was the fragile part. I ran all
ten paths through it — all ten match. The regex was fine. The actual gap was
in the hand-built normalizer event that silently omitted `http_status`,
because nothing in it could be incomplete *against* anything.

Three bugs, all the same shape: a heredoc comment that ate `${LAB_BIND_IP}`; a
`verify.sh` that printed "SOME CHECKS FAILED" and exited 0; an event dict with
no schema to fail against. None was a coding error. Each was built so that
**nothing downstream could check it**, and each read as working because the
only thing looking at it was the person who wrote it.

Then the README contradicted the schema in five places (fixed in `f8025d1`),
and fixing those found three more: a broken `make sessions` index, a
brute-force walkthrough selecting Cowrie's `.event_type` instead of ours
(a column of nulls after a successful attack), and a push that needed a
rebase.

**Standing rules that come out of this:**

1. A deployment is not verified until something has **tried to break it and
   failed.**
2. If the README and the schema disagree, **the schema wins** and the README
   is a bug.
3. The thing that reports is not the thing that runs.
4. A claim in Part 2 does not become true by being written well.

This is why the list exists. Not to be right — to move the argument from
memory to a file that can disagree with me.
