# TRAPDOOR — acceptance claims

Every scenario is written as a **testable claim about the box**, not a
description of what an attacker does. "An unauthenticated GET to `/` returns
200" can be checked by anyone with curl. "A student attempts to log in" cannot.

This file is the acceptance list. When every claim below is demonstrated with
evidence, the deployment is real. Until then it is code in a git repository.

Run order: `scripts/verify.sh` first (it checks the platform), then the
scenarios (they check the behaviour). Both exit non-zero on an unmet claim.

---

## A. Platform claims — `scripts/verify.sh`

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

A check that cannot run is reported as `NOT RUN` and fails the run. It is not
a pass. A check that cannot run has proven nothing.

---

## B. SSH brute-force claims — `scenarios/ssh-bruteforce.sh`

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

It is checked by `scripts/containment-check.sh`, which generates a **fresh
canary per run**, types it into the decoy shell in a way that would leave
traces in `/root`, `/tmp` and the shell history if it actually executed, then
searches the host for it. Contained = the canary is in the log and nowhere else.

**The canary is never transmitted to anyone, including reviewers.** A fixed or
shared canary can be planted — by a helpful colleague, by a future maintainer,
or by the person who wrote the check. Evidence handed to someone should be
evidence they could not have contaminated. If you need to describe the test to
another person, describe the method and the search path, not the string.

---

## C. Web scanner claims — `scenarios/web-scan.sh`

| # | Claim | Evidence |
|---|-------|----------|
| C1 | The decoy is an ordinary web server | `GET /` → 200 |
| C2 | Secret paths exist but are forbidden | `GET /.env` → 403, not 404 |
| C3 | VCS paths are forbidden | `GET /.git/config` → 403 |
| C4 | Cloud credential paths are forbidden | `GET /.aws/credentials` → 403 |
| C5 | CMS paths are forbidden | `GET /wp-login.php` → 403 |
| C6 | A genuinely absent path is 404 | random path → 404 |
| C7 | Requests are logged with path and status | `sensor == "nginx"` in `out/events.jsonl` |
| C8 | Request bodies are not stored | `payload_sha256` is null for nginx events |

**C2–C5 matter most.** 403 rather than 404 because a scanner that sees "exists
but forbidden" keeps probing and generates a transcript; a scanner that sees
404 moves on and generates nothing. That is the whole design of the bait list.

C8 is an honest limitation, not a feature. See `docs/limitations.md`.

---

## D. What is deliberately NOT claimed

### The risk is rarely where the worry is pointed

C7 is the worked example and it is worth keeping. My instinct said the bait
regex in `default.conf` was the fragile part — a regex is where path-matching
bugs live, and I could picture it matching wrong. I ran all ten paths through
it instead of nodding at it: all ten match. The regex was fine.

The actual gap was in the part I had written from the design and never read
back from the output: the hand-built normalizer event silently omitted
`http_status`. Nothing about the code looked wrong. It looked *incomplete* in a
way that is invisible unless you compare the field list against the claim.

Two lessons, and the second is the one that costs:

1. A regex you have read is not a regex you have tested.
2. The failure was not in the risky-looking code. It was in the code nobody
   thought was risky, which is where it always is.

### The real pattern, named by Vera

Three bugs tonight, all mine, all the same shape:

- a heredoc comment that ate `${LAB_BIND_IP}` out of the printed rule
- `verify.sh` printing "SOME CHECKS FAILED" and exiting 0
- a hand-built event dict with no declared schema to be incomplete against

None of them was a coding error. Each was a thing built so that **nothing
downstream could check it**, and each read as working because the only thing
looking at it was the person who wrote it. A comment cannot fail to render the
variable it consumed. A dict with no schema cannot omit a field. An always-zero
exit cannot contradict a printed failure.

The lesson is not "test more." It is: **build things that can disagree with
you.** The acceptance list is not discipline. It is a device for being wrong
out loud, on purpose, before a classroom finds out instead.

This is why the list exists. Not to be right — to move the argument from
memory to a file that can disagree with me.

---

Stated here so nobody reads this list as more than it is:

- **Not claimed: the deployment is secure.** It is a teaching target. The host
  it runs on is a normal farm member and its exposure is a farm policy
  question, not a TRAPDOOR one.
- **Not claimed: attacks are detected in real time.** There is no alerting.
  Events are collected, not chased.
- **Not claimed: the decoy is unbreakable.** Cowrie is medium-interaction. A
  determined attacker can escape an emulated shell's *believability*. They
  cannot escape into the host through it — that is a different guarantee, and
  it is the one A9 tests.
- **Not claimed: results are forensically sound.** Timestamps are Cowrie's,
  sessions for HTTP are approximated, and there is no chain of custody.
