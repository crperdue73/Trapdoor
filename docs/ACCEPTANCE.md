# TRAPDOOR — acceptance claims

Every claim is written as a **testable statement about the box**, not a
description of what an attacker does. "An unauthenticated GET to `/` returns
200" can be checked by anyone with curl. "A student attempts to log in" cannot.

This file is the acceptance list. It is split into two halves on purpose:

- **Part 1 — proven.** Demonstrated on the live host, with the artifact that
  demonstrated it named.
- **Part 2 — not proven.** Named gaps.

A claim moves from Part 2 to Part 1 only when someone ran the thing and kept
the output. Writing it down differently does not move it.

**Every Part 1 row carries the date it was last observed.** A proof is a
statement about a box at a time, not a property of the box forever. Rows marked
*re-observed 2026-11-07* were checked from off-box on that date and the output
is quoted below; rows with an earlier date rest on the artifact recorded then
and have not been re-run since. If you are reading this months later, do not
assume a row is still true — the date is there so you can tell.

What was re-observed on 2026-11-07, from this host (`.10`, off-box, read-only):

```
GET /                 -> 200      GET /nope-xyz       -> 404
GET /.env             -> 403      GET /.git/config    -> 403
GET /.aws/credentials -> 403      GET /.wp-login.php  -> 403
nc .45 2222           -> SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
```

That is C1–C6 and A6, five days after they were first written,
against a box nobody had re-probed in between. It is also the extent of what
can be checked without root and without the stack's event log: A1–A3, A8, and
everything that reads `out/events.jsonl` were **not** re-observed, because
`out/` on this checkout is empty except `out/g1/` and there is no `.env` here.

Run order: `scripts/verify.sh` first (it checks the platform), then the
scenarios (they check the behaviour). Both exit non-zero on an unmet claim.

**A check that cannot run is `NOT RUN` and fails the run. It is not a pass.**
A check that cannot run has proven nothing. This sentence exists because the
containment proof in this repo was unparsable for two days while the commit
message said containment was proved.

---

## Evidence is not in the repository

`.gitignore` excludes `out/` and `.verify/`:

```
.env
out/
*.jsonl
*.log
.verify/
```

So every row below whose evidence names a file under `out/` or `.verify/` is
citing something **on the host**, not something a reader of this repo can open.
The claim can still be true; it cannot be independently checked from a clone.
That is a deliberate trade (log files and a `.env` hold lab data and a token),
and it has a cost that this file should state rather than bury:

- the reader has to trust the person who ran it, or re-run it themselves
- a row's evidence can vanish with the host and nothing will notice
- "the output is in `out/g1/`" is a claim about a directory, and on this
  checkout **that directory exists and is empty** (see G1a)

Where a result matters enough to be argued about, quote the output in this
file and quote it in full. A named path is a pointer to evidence; a quoted
transcript is evidence.

---

## Part 1 — proven on the live host

Host `192.168.111.45`. Evidence directory `out/` and `.verify/`.

### A. Platform — `scripts/verify.sh`

Observed **2026-11-02** from the live host, except A4/A5/A6 re-observed
**2026-11-07** from `.10` (off-box). A1–A3, A7, A8 were not re-observed on
2026-11-07: they need the stack and its event log, and `out/` is empty here.

| # | Claim | Evidence |
|---|-------|----------|
| A1 | The decoy ports are bound to `LAB_BIND_IP`, not `0.0.0.0` | `ss -tlnp` shows `192.168.111.45:2222`, `:2223`, `:8080` (2026-11-02) |
| A2 | Nothing else opened a listener while the stack started | before/after `ss -tlnp` diff is empty (2026-11-02) |
| A3 | No published port is on a wildcard address | wildcard grep returns nothing for our ports (2026-11-02) |
| A4 | The web decoy is up and answering | `GET /` → 200 — **re-observed 2026-11-07** |
| A5 | The bait is present and deliberately forbidden | `GET /.env` → 403 — **re-observed 2026-11-07** |
| A6 | SSH is being emulated | banner matches `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2` — **re-observed 2026-11-07** |
| A7 | The pipeline normalizes events | `out/events.jsonl` parses, sensors = `cowrie` + `nginx` (2026-11-02) |
| A8 | All three services run | `docker compose ps` lists cowrie, web, shipper (2026-11-02) |
| A9 | The honeypot cannot reach the LAN | from inside cowrie, a request to `192.168.0.1` fails (2026-11-02) |

**A1 and A9 are the two that matter.** A1 because a wrong bind is silent and
fatal — Docker publishes wide and no host firewall rule saves it, since Docker
writes its own rules ahead of ours. A9 because a network policy you have not
tested is a network policy you do not have.

A1 has a second life outside this table: `.env.example` ships
`LAB_BIND_IP=0.0.0.0` with the comment "Default 0.0.0.0 is convenient; in a
real lab set this to the LXC's lab-facing address". Copying the example and
stopping there reproduces exactly the failure A1 exists to catch. The row
proves the *host* was configured correctly on 2026-11-02. It proves nothing
about the next person who copies the example.

### B. SSH brute-force — `scenarios/ssh-bruteforce.sh`

| # | Claim | Evidence |
|---|-------|----------|
| B1 | An unauthenticated TCP connect to `:2222` returns an SSH banner | `nc` shows `SSH-2.0-...` |
| B2 | A rejected credential is logged with its username | `event: auth_failed` with `username` populated (Cowrie logs it natively as `cowrie.login.failed`) |
| B3 | An accepted credential is logged | `event: auth_success` for `root` (Cowrie logs it natively as `cowrie.login.success`) |
| B4 | Commands typed in the shell are logged individually | `event: command` × 5 in order (`id`, `uname`, `cat`, `ls`, `echo`) |
| B5 | No command typed reaches the host | `scripts/containment-check.sh` exits 0 |
| B6 | The run is identical each time | same event order, same usernames, same count |

B2–B6 rest on runs made **before 2026-11-07**; they need the stack and its
event log, and neither is on this checkout. Only B1 is reproducible off-box
without root, and A6 covers the same measurement.

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

C1–C6 **re-observed 2026-11-07** by direct off-box probe; C7–C8 on 2026-11-02
from the event log (not re-observed — no `out/events.jsonl` on this checkout).

| # | Claim | Evidence |
|---|-------|----------|
| C1 | The decoy is an ordinary web server | `GET /` → 200 — re-observed 2026-11-07 |
| C2 | Secret paths exist but are forbidden | `GET /.env` → 403, not 404 — re-observed 2026-11-07 |
| C3 | VCS paths are forbidden | `GET /.git/config` → 403 — re-observed 2026-11-07 |
| C4 | Cloud credential paths are forbidden | `GET /.aws/credentials` → 403 — re-observed 2026-11-07 |
| C5 | CMS paths are forbidden | `GET /wp-login.php` → 403 — re-observed 2026-11-07 |
| C6 | A genuinely absent path is 404 | random path → 404 — re-observed 2026-11-07 |
| C7 | Requests are logged with path and status | `sensor == "nginx"` in `out/events.jsonl`, `http_status` populated (2026-11-02) |
| C8 | Request bodies are not stored | `payload_sha256` is null for nginx events (2026-11-02) |

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

### E. Acceptance rows that are checked by `make test`, not by a host

`make test` runs three things: `tests/test_shipper.py` (17 normalization
cases), `tests/test_docs.py` (docs agree with `schema/event.schema.json`), and
`tests/test_syntax.sh` (every `.sh` parses). Verified on this checkout,
2026-11-12:

```
$ make test
...
17 passed, 0 failed
PASS  docs agree with schema/event.schema.json
PASS  8 shell scripts parse (parsing is not running)
exit 0
```

What that buys: the normalizer's behaviour on 17 known inputs, the absence of
drift between docs and schema, and the absence of syntax breaks. What it does
not buy: anything about a running stack. This row is here so nobody reads a
green `make test` as a deployment verdict. It is a pre-push check.

---

## Part 2 — NOT proven

These are stated so nobody reads Part 1 as more than it is. Each one has a
line saying what would close it.

### G1a - `firewall.sh --apply`: green on a bench 2026-11-18; DROP semantics measured, insert path argued

**Status as of 2026-11-18 20:4xZ: `verify.sh` exits 0 end to end on a clean
bench, and still stops at check 8 on 192.168.111.45 because that host has no
declaration written. The verdict moved from FAIL to "proven on a bench,
unproven in deployment." Read the 2026-11-18 note below before the 2026-11-17
one, because the 11-17 verdict was measuring the network rather than the
deployment and that is now understood.**

**Status as of 2026-11-17 16:14Z, kept for the record: the run gap was closed. `--apply` has now
executed on a host with root, twice, idempotently, and the transcript is in the
repository at `docs/g1-transcript-20261117.txt` (not gitignored). The row stayed
in Part 2 for a different and narrower reason: `scripts/verify.sh` exited 1 on
that host, and check 8 was the failure. Do not read the 11-17 run as deployed
either; it was a run with a failing check, not a green one.**

**What the 2026-11-17 run proved**, on `test-trapdoor` (192.168.111.45),
kernel 6.17.2-2-pve, as root:

- `firewall.sh` (no flags) exits 0 and prints its report.
- `firewall.sh --apply` exits 0. DOCKER-USER is built with 20 TRAPDOOR rules
  plus the trailing RETURN.
- A second `--apply` leaves `iptables -S DOCKER-USER` **byte-identical**
  (`diff` clean, 22 lines both runs). Idempotent, measured, not asserted.
- The rules match **container destinations after DNAT** (172.22.0.2:2222,
  :2223, :80 and 172.22.0.3:8081), not host ports, which is what the script's
  comment claims and what the 2026-11-06 investigation established.
- Check 6 holds: `cowrie cannot reach the LAN (connection refused, internal
  network holding)`. Named refusal, not a bare OK, so the probe ran.
- 20790 events parsed, 4 containers up, every event line valid JSON.

**Update 2026-11-18, bench verdict from an independent reviewer (dept:jim).**
This row's status changed twice today and both changes are narrower than they
look.

The 2026-11-17 failure above was check 8 asserting a property of the NETWORK
(a console narrower than the whole /16) rather than a property of the
DEPLOYMENT. On this farm there is one network: the entire IT department is on
a single /16 and there is no student VLAN to narrow to, which Robbie confirmed
on 2026-11-18. A check that fails the only configuration that exists is the
same lie as one that cannot fail. Check 8 now asserts a DECLARED scope: an
undeclared console fails, a console that has drifted WIDER than its declaration
fails, and an honest declaration of a /16 passes.

With that change, a reviewer on a clean Debian 13.7 bench (192.168.111.49),
fresh clone, base install, DEPLOY.md Steps 1 through 5 as written:

- `firewall.sh --apply` exits 0. 20 TRAPDOOR-scope rules in the bench's own
  DOCKER-USER: ACCEPT the declared scope, ACCEPT the three local bridges, then
  an unconditional DROP for the port. Inserted above Docker's bare RETURN so
  they are reachable. Convergent on re-run, not additive.
- `verify.sh` **exits 0, full green.** This is the first end-to-end green this
  project has recorded.
- Check 8 caught a real operator error during that run, unforced: the reviewer
  declared `CONSOLE_NETWORK_DECLARED` as an instructor /24 while `ADMIN_CIDR`
  was /16, and the check failed the drift in the correct words. He had edited
  the declaration expecting it to narrow the rule; the rule comes from
  `ADMIN_CIDR` at `firewall.sh:421-422`.

**The console DROP rule has never dropped a packet in DOCKER-USER.** Reaching
it needs a source outside the declared scope, and this farm is one /16 with no
second subnet (Robbie, 2026-11-18: "there IS NO other subnet. i only have this
/16"). So the box that would have settled it cannot be provided on this
network, and that reason is not going to lift.

**But the rule's semantics are now measured, separately, and that is new.**
On a scratch chain, an identical ACCEPT-one-source-then-DROP-the-port shape was
built by hand and probed from both sides of the boundary:

    source 127.0.0.1 (accepted) -> CONNECTED
    source 127.0.0.2 (not accepted) -> TIMED OUT, no response
    iptables -L DROPTEST -n -v
    1  4 pkts  ACCEPT tcp -- * * 127.0.0.1  0.0.0.0/0 dport 18081
    2  2 pkts  DROP   tcp -- * * 0.0.0.0/0  0.0.0.0/0 dport 18081

Reproduced independently on this box before the wording was written into this
file, with the same two results and a DROP counter of 2. The timeout rather than
a refusal is the load-bearing detail: a reject would also stop the connection,
so the behaviour alone cannot distinguish DROP from REJECT. The counter can.
**The counter is the evidence; the behaviour is only a verdict.**

**What is proven:** a rule of this exact shape, ACCEPT one source then DROP the
port unconditionally, silently discards a packet from a source it does not
accept, and does so as a drop rather than a reject.

**What is still NOT proven:** that this script's instance of it is reachable
where the script puts it. The scratch chain was built by hand. The insert path,
the position above Docker's bare RETURN, and the DNAT'd destination matching
were not exercised by that test; they remain argued from the rule listing, and
argued is not measured. Do not upgrade one to the other.

**On the guard that made this necessary.** `firewall.sh:180` refuses an
`ADMIN_CIDR` narrower than the host's own network. That refusal exists because
of 2026-11-12, when a /24 test inside a /16 farm reported "boundary proven" from
both directions and both directions were wrong, since both were taken from
inside the same /24. The refusal is correct and the reviewer did not work around
it: no `.env` change, no declaration, chain and alias removed afterwards. Note
what it costs, though. It is now the only thing standing between this project
and a genuine in-deployment drop test, and it is protecting against a FALSE
proof, not against a real one. An explicit override for a self-contained
loopback test is conceivable and deliberately not proposed here.

So the remaining gap is not a defect and not a missing artifact. It is a
deployment that has been proven on a bench and never on a host where the
firewall has something to protect: a named host, root, and a live teammate.
That decision belongs to Robbie and is recorded here as unproven rather than
as pending, so that the next reader does not go prove it on a live network in
order to tick a box in this file.

**What the 2026-11-17 run did NOT prove, in its own words and kept for the
record.**

Check 8 **FAILS**: `console is scoped to the farm /16: every host can read
every student's attack traffic`. The console on 8081 replays what students
typed. Scoped to a /16 that contains every agent host and management interface
on the farm, that means any host on the farm can read any other student's
session. That is a privacy defect in the deployment, not a documentation gap,
and it is why the verdict line still reads "do not call this deployed."

Closing it needs a decision, not a script fix: narrow the console scope to the
student VLAN. `LAB_CIDR` is also still the whole farm (`192.168.0.0/16`), which
the script's own report says "is not a boundary."

**Three measurement traps hit during this run, recorded because each one
produced a confident wrong answer:**

1. *Localhost cannot test DOCKER-USER.* Traffic sourced on .45 to its own
   external IP resolves to `local ... dev lo` and traverses INPUT, never
   FORWARD. Probing from the box itself showed a **delta of 0 packets** and
   looked exactly like a dead chain. The same probes fired from a different
   host (192.168.111.43) moved the counter by **1178 packets**. `verify.sh`
   check 7 warns "TRAPDOOR rules present but not one has matched a packet" when
   run on the host, which is this artifact, not a fault. A check that cannot
   reach the chain must not report on it.
2. *`$?` after a pipe is the exit of the last command.* Reading
   `bash scripts/verify.sh | tail` gave `exit=0` under a failing run. The
   script's real exit was 1. The exit code is correct; the reading was wrong.
3. *An empty evidence directory reads like lost evidence.* This row was open
   for eleven days partly because `out/g1/` is gitignored, so a real run left
   no artifact a reader could open. The transcript now lives under `docs/` for
   that reason.

**Superseded for history — the original 2026-11-06 evidence gap.**

**Open gap: the 2026-11-06 `--apply` run cannot be re-verified from this
checkout (`out/g1/` is empty). One defect claim inside this row is DISPROVED,
not open — see the status line below.**

Who is allowed to answer the two questions this row is waiting on (which host,
who has root) is written down in `docs/AUTHORITY.md`. It was never written down
before 2026-11-12, which is why this row stalled on an authority instead of on
technical work.

**Claimed closed 2026-11-06 on `test-trapdoor`, as root.** Kept in Part 2
because the artifact this file cites for it cannot be produced from the
repository, and on this checkout it cannot be produced at all.

What the closing run reported, per the commit and this file as originally
written: the backup was written and readable, the teardown loop converged, the
bridge enumeration returned `172.17.0.1 172.22.0.1 172.23.0.1`, the post-apply
probes passed with the DROP in the chain, and a second `--apply` diffed clean
against the first.

What a reader can check from here today:

```
$ ls -la out/g1/
total 8
drwxr-xr-x 2 root root 4096 Nov  6 07:43 .
drwxr-xr-x 3 root root 4096 Nov  6 07:43 ..
```

Empty. `out/` is gitignored, so the evidence was never in the repo to begin
with, and the copy on this checkout has nothing in it. **An empty directory
reads exactly like a directory whose evidence was lost.** It does not read like
a proof.

That does not make the run false. It makes the run **unverifiable from here**,
and it means this row is resting on a commit message. `docs/limitations.md`
spends its length on why a commit message is not a statement about the file.
The same rule applies to a commit message about a directory.

**How to close it again, durably:** on a host with root, run

```bash
bash scripts/firewall.sh            # read the printed report first
bash scripts/firewall.sh --apply
bash scripts/verify.sh
iptables -S DOCKER-USER > /tmp/apply-1.rules
bash scripts/firewall.sh --apply
iptables -S DOCKER-USER > /tmp/apply-2.rules
diff /tmp/apply-1.rules /tmp/apply-2.rules && echo IDEMPOTENT
```

then paste the whole transcript into this file, or into a `docs/g1-*` file that
is not gitignored. Closing it a second time with another empty `out/` directory
would close nothing.

**A defect claim in this row that I made and then disproved (2026-11-12).**
**Status: DISPROVED (2026-11-12). Not a live defect. Do not cite this as a bug.**

The claim, kept verbatim as history rather than as a finding:

While writing this row I asserted that `scripts/firewall.sh` could not print its
report on a tree with no `.env`, because the line

```bash
[[ -f .env ]] && source .env
```

sits above the `if ! $APPLY` and, under `set -euo pipefail`, an unmatched
`[[ ]]` would exit the script. **I tested that and it is false.**

The claim is disproved on the same box in one command, and the reason is worth
knowing because it fools people who reason about `set -e` from memory:

```
$ bash -c 'set -euo pipefail; [[ -f nope ]] && echo yes; echo "reached"'
reached
rc=0                     <- the && does NOT trigger set -e mid-script

$ bash -c 'set -euo pipefail; [[ -f nope ]] && echo yes'
rc=1                     <- it does when it is the LAST statement
```

`set -e` does not act on the left side of `&&` or `||`, and the compound's
non-zero status only matters if that compound is the script's final statement.
In `firewall.sh` it is not; execution falls through to the report.

The end-to-end check, run in a scratch directory containing only `scripts/`
and no `.env`, with an empty environment:

```
$ env -i PATH=/usr/bin:/bin bash scripts/firewall.sh >out.txt 2>err.txt; echo rc=$?
rc=0          stdout: 60 lines (the full report)      stderr: empty
```

The report printed and the script exited 0. So the dry-run workflow
`docs/DEPLOY.md` depends on works on a fresh clone, and this row's job is to
say that plainly rather than leave a wrong defect report in the file.

**What this cost and why it is written down:** the wrong version was in this
file for one edit. It was caught by running the script instead of reading it,
which is rule 3 in this file turned on the person writing the file. Nine wrong
claims in `docs/limitations.md` now include a tenth, and this is the tenth: I
reasoned about `set -e` from memory, wrote it as a proven property, and quoted
a test I had not run. The quoted one-liner as originally written would in fact
have printed `reached` with `rc=0`, which is the opposite of what I needed it
to show.

**The still-open part of G1a is only this:** the 2026-11-06 run cannot be
re-verified from this checkout, and `out/g1/` is empty. That is the whole gap.
Nothing else in this row is a known defect.

Two other defects known from the closing run are documented in
`docs/g1-findings-2026-11-06.md` (both inside the unquoted heredoc that produces
the report), and the first `verify.sh` after applying printed
`no TRAPDOOR rules applied` because check 7 grepped the ruleset for a string no
rule contained.

**The original gap, kept because the shape is the lesson:** everything in
`firewall.sh` from the `== applying ==` banner to `applied and verified.` was a
claim about a code path nobody had executed. It parsed (`bash -n` clean,
`set -euo pipefail`), and parsing is not running. The unproven items were: the
`iptables-save` backup existing and being readable when needed; the
`iptables -D DOCKER-USER` teardown converging on a re-run; the bridge
enumeration returning both `docker0` and `br-*`; the post-apply probes passing
with the DROP actually in the chain; and idempotence.

**Note what closing it did not buy.** The code path works. On the day it was
closed, the rule it wrote still did not reach the traffic, which was G1b,
resolved via G1c. Apply succeeding and apply enforcing are different claims,
and this file treats them as different claims now.

**A specific warning for whoever runs it:** `verify.sh` check 6 is the
unreachability probe for A9. An `OK` there with **no** accompanying
`REFUSED`/`UNREACHABLE` line means the probe broke, not that containment
holds. Read the line, not the verdict.

### ✅ G1c — a TRAPDOOR rule has denied a packet

Closed 2026-11-06 on `.45`. The negative test that everything above was
missing:

```
iptables -I DOCKER-USER 1 -s 192.168.111.43 -p tcp -d 172.22.0.2 --dport 80 -j DROP
```

From `.43`: request returns `000`, counter **7**. From `.45`: `200`.
Selective denial, measured both directions.

Getting there took four defects, each of which made the previous fix look
correct: the heredoc, check 7's grep, the wrong destination field, and
`-A` appending below Docker's own `RETURN`. Two of the four were answered by
the same observation: **a rule that is present is not a rule that matches.**

This row is quoted rather than pointed at, which is why it stays in Part 1. It
is also a hand-inserted rule, not a rule emitted by `firewall.sh`, which is
exactly why G1a stays open above.

### ⚠️ G1b — DOCKER-USER was not in the decoy's packet path on `.45` (RESOLVED)

Kept because the wrong diagnosis is the useful part. I concluded twice that
traffic never reached the host, and both times the evidence was bad: I watched
`INPUT` counters (wrong chain), and I read "no counter moved" as "no traffic"
when the rules were simply unreachable.

The one test that settled it was stopping the decoy container: the port went
`000`. Traffic *had* been reaching the container the whole time. That test
took thirty seconds and I ran it last.

The catch-all `RETURN` gaining 12 pkts while the `DROP` above it stayed at 0
was real, and it was Docker's own traffic, not the decoy's. The header comment
cited it as proof of the wrong thing.

### ✅ G2 — a syntax break can no longer ship

**Closed 2026-11-07**, and re-run on this checkout **2026-11-12** (section E).
`make test` runs `tests/test_syntax.sh`, which `bash -n`s every `.sh` in the
tree and exits non-zero on any that fails.

Proven both ways, in the order that matters. First that it is green on the real
tree, then that it goes red on the real defect:

```
$ make test                      # clean tree
PASS  8 shell scripts parse (parsing is not running)   -> exit 0

$ sed -i '... append a stray fi ...' scripts/firewall.sh
$ make test                      # the 14c67d8 defect, reintroduced
FAIL  ./scripts/firewall.sh
      ./scripts/firewall.sh: line 89: syntax error near unexpected token `fi'
                                                     -> exit 1
```

The script is restored by checksum afterward (`f9556889…`), not by memory.

**The history, kept because the shape is the lesson.** `firewall.sh` carried
two defects, a stray `fi` and `$BRIDGES` used three times with its declaration
deleted, and between them the containment proof was unparsable. It was fixed in
`14c67d8`, and the fix commit says so plainly.

**Correction, 2026-11-07:** the claim that this lasted "from the commit that
claimed containment" is not supported by the repository. I re-parsed every
version of every `.sh` at all 58 commits (`git show <c>:<path> | bash -n`).
Every committed version of `firewall.sh` parses. The break existed in a
**working-tree state that was never committed**, so no commit message and no
acceptance row ever rested on an unparsable script. What was true is narrower
and still bad: the author of the fix could not parse the file in front of her,
she found that by hand, and nothing in `make test` would have said so.

Not claiming the stronger version matters. An acceptance file that overstates
its own history has stopped being evidence, and this row was doing exactly
what the rest of the file warns about.

**What this does not prove:** that any script is correct, or that it will work
when run. `make test` parses all eight scripts and runs one of them only
indirectly (the shipper tests import its parser). `firewall.sh --apply`,
`verify.sh`, and both scenarios are parsed and unexecuted by `make test`.
Parsing is not running.

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

### G7 — closed 2026-11-12: a fresh clone can print the firewall report

**Claimed as a gap, then tested, and it is not a gap.** The report prints on a
tree with no `.env` and exits 0 (transcript in G1a). This row is kept as a
closed row because it was published for one edit as a defect that had not been
tested, and because the test that closed it is two lines and belongs somewhere
that runs it.

**Still not claimed:** that a fresh clone can be *deployed* by following
`docs/DEPLOY.md` end to end. That needs a host with root and a `.env`, and
steps 1–5 were written from the deployment that exists, not re-walked from a
clone. Nobody has done the walkthrough.

---

## Why this list is split in two

The risk is rarely where the worry is pointed. C7 is the worked example: my
instinct said the bait regex in `default.conf` was the fragile part. I ran all
ten paths through it, all ten match. The regex was fine. The actual gap was
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
5. **Evidence that cannot be re-read is not evidence.** A pointer to an empty
   directory, or to a path outside the repo, is a claim about a claim.

This file was rewritten on 2026-11-12 for exactly rule 5: what was labelled
proven was, in one place, labelled from memory of a run rather than from an
artifact anyone can open. In the course of that rewrite I wrote a tenth wrong
claim into the file, asserting a `set -e` defect I had not tested, and then
reproduced the opposite result in one command. Both changes are recorded in
G1a rather than quietly reverted. Nothing about the box changed that day. The
listing of what is proven did.

This is why the list exists. Not to be right — to move the argument from
memory to a file that can disagree with me.
