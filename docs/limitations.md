# Limitations

Writing these down as they are found, not at the end when it looks tidy.
A limitation discovered during a class and not in the docs is a bug report.

## Telemetry

**HTTP request bodies are not hashed.**
nginx cannot compute a hash of the request body inline (there is no `sha256`
variable for the body). We record `payload_bytes` for HTTP requests and no
hash. SSH file transfers through Cowrie *are* hashed.

Consequence for teaching: you can show students a hash for an SSH-uploaded
payload, but not for a POSTed webshell. If that gap matters, the options are
(a) a tiny sidecar that reads nginx's body buffer, or (b) switch the web
component to something that logs bodies itself. Neither is built.

**No HTTP response body capture.**
We log status and bytes sent, not the response. A student cannot see what the
decoy actually replied to an exploit attempt.

## Sessions

**nginx has no session concept.**
Session ids are derived from `src_ip:src_port:second`. This groups a burst from
one client and splits on a new source port, which is an approximation. A real
HTTP session (cookie-based) is not reconstructed.

## Detection

**No scoring, no alerting.**
TRAPDOOR records. It does not decide what is interesting. That is deliberate —
deciding is the student's exercise — but it does mean nobody gets paged.

**Bait paths are a fixed list.**
`.env`, `.git`, `wp-login.php` and friends. A scanner using a path we did not
enumerate produces a plain 404 with no flag. The list is in
`web/conf.d/default.conf` and is meant to be extended per lesson.

## Operations

**Retention is file-age pruning.**
Not index-aware, not incremental. Fine at lab volume, wrong at scale.

**No egress from the honeypots.**
`internal: true` on the bridge network. This is a safety rail, but it also
means the decoy cannot fetch anything — no live updates, no external calls.
If a future scenario needs the honeypot to reach out (to simulate C2 traffic,
for example), that network policy has to change deliberately and per-scenario.

**The shipper has no schema validation at runtime.**
It builds events that match `schema/event.schema.json` and the tests assert
it, but nothing validates every emitted event against the JSON Schema on the
way out. A malformed field would be written and discovered later.

## Lab-specific

**No organic traffic.**
An internal honeypot is silent until someone attacks it. The dashboard is
empty until an instructor runs a scenario. This is by design, not a defect —
see the table in README.md.

## Network topology, and the mistake I made with it

Three facts that are easy to state and were expensive to learn:

**A container on a non-internal network has a route out.** Full stop. There
is no setting that publishes a port inbound-only. A multi-homed container
takes its default route from the interface Docker attaches with the lower
metric, and the non-internal one usually wins. Cowrie sat on `labnet` for
three deployments with a route to the LAN because publishing its SSH port
required it.

**Therefore the reply "publishing a port does not open an egress path" is
false**, and it was false in this repo's own commit history for a night. What
is true is that the *container doing the publishing* gets a route. So the
only containers that may hold published ports are ones that accept no input.

**The web decoy publishes everything now.** nginx holds 8080 for HTTP and
forwards 2222/2223 to cowrie with a `stream {}` block over the internal
network. nginx is a static server that takes no instructions from the
network, so routing to it is harmless. Cowrie, which hands out a shell, is on
`internal: true` and nothing else, and its own ports are `expose`d, not
published.

Verified by measurement, not by reading the compose file:

    docker exec trapdoor-cowrie python3 -c 'socket.create_connection(("192.168.0.1",80))'
    -> OSError [Errno 101] Network is unreachable
    -> 1.1.1.1:443  Network is unreachable
    -> DNS          gaierror

## The egress check certified containment while being unable to run

For one night, `verify.sh` step 6 ran `docker compose exec -T cowrie sh -c …`.
The cowrie image has no `sh`. The exec failed, exited non-zero, and the check
read that as "could not reach the LAN" and printed OK.

That is worth writing down as a pattern, because the comment four lines above
it said *"a check that cannot run is not a check that passed"* — and the bug
was still there. Writing the principle is not the same as applying it. The
fix distinguishes three outcomes: CONNECTED (fail), REFUSED/UNREACHABLE
(pass), and NOT RUN (skip, sets FAIL). It never collapses them.

## The same shape a third time: a check that printed the good answer

Found on 2026-11-02 by running `verify.sh` on a host where the stack was down.
Steps 1, 2, 3, 5 and 6 all behaved — they FAILed, or refused a verdict with
NOT RUN. Step 4 printed:

    OK   all 0
    0 declared ports are published and listening

for a stack with zero running containers.

The cause was `grep -c … || echo 0`. `grep -c` prints `0` when it matches
nothing **and exits 1**, so the fallback appended a second line to the
variable. Every `[[ "${declared:-0}" -eq 0 ]]` after that died with
`syntax error in expression`, bash had nowhere to report it but stderr,
nothing was reading stderr, and the arithmetic tests failing meant control
fell through to the success branch. Bare `0` is truthy in bash, so "no ports
declared at all" became "all 0 declared ports are published".

Three instances of one shape now, all mine:

1. A `FORWARD` rule whose `|| true` ate a failed variable
2. The egress probe that read a failed `exec` as containment holding
3. This one, where there was no `|| true` to blame at all

The lesson is not "don't use `|| echo 0`". It is that **a check is a program,
and its error handling has to be as deliberate as its logic.** Verify scripts
are the worst place to be sloppy, because their failure mode is not a crash —
it is a green line.

Fixed by computing `docker compose config` once, failing closed with a NOT RUN
verdict when it produces nothing, and relying on `${var:-0}` only for the
genuinely-empty case. Verified both directions on the live box: on a stopped
stack it now reports `NOT RUN — 3 ports declared, NONE listening`, and on a
running stack it reports `OK — all 3 declared ports are published and
listening`. The negative test mattered more than the positive one.

---

# Proposal — retention that can actually delete, and an exemption with a number on it

**Status: proposed, not implemented.** Written 2026-11-03 for review before
`shipper/shipper.py` is touched. Nothing below describes code that exists yet.
Everything above this line does.

## The finding this comes from

`shipper.prune()` unlinks whole `*.jsonl` files in `OUT_DIR` whose mtime is
older than `RETENTION_DAYS`. `out/events.jsonl` is appended to continuously, so
its mtime is always now, so retention can never delete it. The file that grows
is the only file retention cannot see.

This was found by writing the disk footprint sentence down and then testing it.
The README had implied retention kept a runaway event log in check. It does not.
Every other claim in this repo has a check behind it; this one had a paragraph.

Two separate gaps fall out of that:

1. **The event log needs rotation**, so `prune()` has whole files to act on.
2. **`cowrie_var` was exempt by omission** — `prune()` globs `*.jsonl` and has
   never known the volume exists. An omission that reads like a policy is worse
   than either decision.

---

## Decision 1 — rotate the event log, on size, inside the shipper

**Rotation on a size boundary (`ROTATE_MB`, default 50), performed by the
shipper itself. Not by `logrotate`, not on a timer, not by day.**

The reasoning, in the order it matters:

- **Retention is already shaped for this.** `prune()` deletes whole files. The
  fix is to give it files, not to teach it partial deletes. A prune that
  rewrites the live file has to read and rewrite the whole thing on the same box
  the lab runs on, corrupts the only copy of the events if it dies mid-write,
  and cannot be explained to a student. A student can look at
  `events-2026-11-03T142211Z.jsonl` and know what it is.
- **Size, not time.** A class day is exactly when the file grows. A day
  boundary fires at an arbitrary moment and will eventually fire mid-scenario,
  splitting one session's transcript across two files for no reason. 50 MB is
  roughly a month of ordinary lab use, so rotation is rare and unremarkable.
- **Inside the shipper, because the shipper owns the offset table.** This is the
  part that makes it safe. `tail()` stores resume positions in the module-level
  `_OFFSETS` dict keyed by path and detects a swapped file via `st_ino`.
  Any *external* rotator renaming files under a running shipper produces the
  exact failure below, on a timer, with nobody watching. Rotation and the offset
  reset must be the same operation or they will eventually disagree.

### The failure mode rotation introduces, stated up front

`tail()` reopens on a new inode at the old byte offset. The guard
`if start > st.st_size: start = 0` means **no data is lost** — but it also means
the new file is re-read from byte zero and its first events are written a second
time. For a class that sees a session count double, and the lesson they take
away is "the pipeline is broken."

So: **rotate by rename-then-create, and reset `_OFFSETS[path]` for that path in
the same function that creates the new file.** One code path owns both halves.

`copytruncate` is rejected: it truncates to zero, which hits the same
`start > st_size` branch, and it drops everything written between the copy and
the truncate.

### What has to be true before this ships

- [ ] `ROTATE_MB` (default 50) and `ROTATE_KEEP` / retention interaction:
      rotated files must be named so `prune()` sees them as old-and-whole, and
      the newest rotated file must not be pruned while `events.jsonl` is empty.
- [ ] **Test: ten events stay ten across a rotation.** Push ten events through
      the normalizer with a rotation forced in the middle (set `ROTATE_MB` tiny
      in the test), read every `out/events*.jsonl` in ts order, assert exactly
      ten events and no duplicates. This is the test Robbie asked for and it is
      the acceptance criterion for the whole change.
- [ ] A rotation is logged at INFO with the file it moved to.
- [ ] `make clean` still removes rotated files (`rm -f out/*.jsonl` already globs).

### Every reader, or the pipeline is right and the transcript is wrong

Rotation is worthless if the readers keep reading one file. Currently
hardcoded to `out/events.jsonl`:

| Reader | Where |
|---|---|
| `make events` | `Makefile` |
| `make sessions` (index and transcript) | `Makefile` |
| `render_session.py` | argv path |
| `verify.sh` | three places (pipeline check, nginx count, missing-status count) |
| `ssh-bruteforce.sh` | scenario hint block |
| `web-scan.sh` | scenario hint block, three jq calls |

All of them move to **`out/events*.jsonl` in timestamp order**. Two traps:

- Shell glob order is lexicographic, which only matches time order because the
  stamp is `YYYYmmddTHHMMSSZ` — so the rotated names must be sortable that way,
  or the glob has to be sorted explicitly. `events.jsonl` sorts *before*
  `events-…` lexicographically but is the *newest*; it must be concatenated
  last, not by glob.
- `render_session.py` reading only the current file is the exact failure Robbie
  named: a transcript showing three of ten events and nobody told. It needs the
  same multi-file read as the Makefile, and the test in the next section proves
  it.

### Test: the transcript survives a rotation

- [ ] Build a fixture with a session split across `events-<stamp>.jsonl` and
      `events.jsonl`, run `render_session.py`, assert the full transcript in
      order. Run the same fixture through the `make sessions` index and assert
      the session count is unchanged.
- [ ] Run the docs check (`tests/test_docs.py`) against the samples, since the
      README shows this output.

---

## Decision 2 — `cowrie_var` is exempt on purpose, and it gets a number

**Exempt from retention, deliberately, because it is not telemetry — it is the
artifact store.** Recorded here so the next person finds a decision instead of
an absence.

Why exemption is right:

- **Pruning it on a timer deletes the thing the lesson is about.** Cowrie's
  upload capture is the evidence that a payload arrived and what it was. A
  student re-reading a session days later should still be able to hash-match
  what is on disk. These files are rare by construction — only when a scenario
  uploads — so they are not the noise retention exists to bound.
- **The risk is already contained by design.** Nothing executes from that
  volume, nothing serves it, and its only mount is read-only into the shipper at
  `/in/cowrie`.

The price, stated in the same breath: **it grows until `make clean`.** An
unbounded exemption that nobody measures is how a laptop user finds out the hard
way on a Tuesday, which is the same argument that produced the disk figure in
the README.

So the exemption ships with a visible bound:

- [ ] `make health` reports the `cowrie_var` volume size in every report
      (`docker system df -v`, volume row, or a one-line `du` via a throwaway
      container). Weekly on the record beats discovered in a class.
- [ ] `docs/DEPLOY.md#disk` gains the same number and the sentence "exempt from
      retention on purpose; `make clean` is the only thing that removes it."
- [ ] `make health` reports a NOT RUN verdict, not a skip, if the volume size
      cannot be determined — same rule as every other check in this repo.

### The alternative, for Robbie to decide

**Keep the last N artifacts (say 20) instead of unbounded.** Arguments each way:

- *For:* a hard ceiling on a hostile file sitting on a disk, which is the one
  risk the volume actually carries. Pruning by count is cheap and does not need
  a size measurement to be useful.
- *Against:* it is a policy about evidence, and evidence deleted by a counter is
  evidence the instructor did not choose to delete. It also deletes in the order
  files were written, which correlates with *when* rather than *worth* — the
  interesting upload is as likely to be the 21st as the 1st.
- *My read:* exempt-plus-measured first, because it is reversible and it makes
  the number visible. If the measured number ever surprises us, keep-last-N
  becomes an obvious next step with data behind it. I would not start there.

Robbie decides from this text. Either way it goes in this file as a stated
decision with the reason, and the bound gets a number.

---

---

## The bait path is unbounded, and the declared limiter is dead code

Found 2026-11-07, jointly with June, on the live box.

`web/conf.d/default.conf` declares a rate limit on the bait path:

    location ~* ^/login {
        limit_req zone=trapdoor burst=20 nodelay;
        limit_req_status 429;
        return 401;
    }

**It has never fired.** The comment above it says the path is rate-limited so
one student running a wordlist demo cannot fill the disk in ninety seconds.
There is no rate limiting. `return` is a rewrite-phase directive and fires
before `limit_req`, which is preaccess-phase, so the bare `return 401`
short-circuits every request before the limiter is consulted. `limit_req_zone`
in `nginx.conf` allocates 10 MB of shared memory for a limiter that cannot run.

Measured, so the shape of the gap is on the record and not in a comment:

| Requests to `/login` | 429s observed |
|---|---|
| 200 sequential | 0 |
| 300 parallel (`xargs -P 20`) | 0 |

And measured, the cost of that gap. June drove 300 parallel requests and read
the log before and after:

- 300 requests → 300 new lines in `out/events.jsonl`, one-for-one, ~100 KB.
- **Approximate**, and the label matters: June and I both measured this by
  reading a file Docker was still appending to. A sample of a buffered writer
  is not a measurement of its contents. The per-request figure is the right
  order of magnitude and the projection that follows holds; the third digit
  does not exist. Re-measure quiesced before anyone quotes this with
  confidence.
- ~330 bytes per request, no ceiling of any kind.
- rockyou is 14,344,391 entries. At that rate it is **~4.7 GB from one
demo, on one path.**

The file it fills is `out/events.jsonl`, which is the file retention cannot see
(the section above). So the two defects compose: the unbounded path has no
rate limit, and the file it grows is exempt from every deletion rule the
shipper has.

**Not fixed yet, on purpose.** The fix is to move the limit so it can actually
run — nginx applies `limit_req` before `return` only if the limit is reached in
preaccess, which it is not here, so the real fix is a `limit_req` on a location
that does not short-circuit, or a `map`-driven `return` whose status the limit
can override. That is a config change with a real risk of breaking the bait
path, and it ships on a clean tree with a test that sends 200 requests and
asserts a 429 appears. Until it ships, the honest statement is: **the bait path
has no rate limit and the README must not claim one.**

---

## Everything that was supposed to be watching was itself unwatched

### The incident, stated plainly, before the mechanism: nine minutes forty-six seconds

On 2026-11-06 the drift check fired at **17:11:11**. It was right. It exit-2'd,
wrote a durable artifact naming its own branch point, and alarmed on schedule.
The timer was silenced at **17:20:57**. Nine minutes.

**Every piece of the system worked.** The checker detected real drift, reported
it correctly, persisted the evidence, and alarmed on time. What failed was the
response to a correct alarm. Somebody saw a red light and turned off the light.

That means the four-day green streak before it was not a result. It was 380
runs with nobody reading them, and the first one that mattered got read as
*"make it stop."* **You cannot unit-test the person who answers the phone.**
This is the one thing in this document that a future reader cannot fix by
patching code, which is why it goes above the mechanism rather than under it.

Four instances, found in one night (2026-11-07), all the same mechanism. Written
together because they are one bug and fixing them as four is how they come back.

| What | Configured | What it actually did |
|---|---|---|
| `limit_req` on `/login` | declared, zone allocated | never executed — `return` fires first |
| `refs/remotes/origin/main` on `.45` | a ref exists, `git status` uses it | stale at `27630b4`; box reported "1 behind" when it was 9 |
| `trapdoor-health.timer` | installed Nov 2, ran ~380 times over 4 days | **silenced 2026-11-06 17:20:57 from the assistant box (.43), 9m46s after a correct drift alert; off 29 hours** |
| the sensor itself | recording correctly all night | reported on by nothing, because the reporter was off |

June's sentence, and it belongs here in her words: **a drifted box also has a
stale view of how drifted it is.** The box's own drift report compares against
a cached ref from its last fetch, so "1 commit behind" was a floor and not a
measurement. `git fetch` before trusting any report that host produces.

The last row is the one that hurts. The sensor was never broken. June's 300
requests produced 300 entries, one-for-one, with `src_ip`, `http_path` and
`http_status`. A perfect instrument with a dead readout is not a working
instrument — it is a recording nobody will ever watch.

### Correction, 2026-11-07 22:40 — the timer was not "never enabled"

An earlier draft of this section claimed the timer had never been enabled and
that its single run on Nov 6 was a hand-start. **That was wrong, and it was
wrong because of the same defect the section describes.**

The evidence was never in the journal. Every run leaves a report in `.verify/`:

| Day | Reports | First | Last |
|---|---|---|---|
| Nov 02 | 27 | 18:52 (install) | — |
| Nov 03 | 94 | 00:00:41 | 23:54:41 |
| Nov 04 | 93 | 00:19 | 23:49 |
| Nov 05 | 95 | 00:04:41 | 23:59:11 |
| Nov 06 | 68 | 00:10:38 | **17:11:11** |
| Nov 07 | 2 | 22:13:40 | 22:13:52 |

The timer was installed with `systemctl enable --now` (`Makefile: timer-install`)
and ticked every ~15 minutes for four days. It stopped here:

    Nov 06 17:11:11  health run FAILS on drift, exit 2
    Nov 06 17:20:57.457470  Started session-c446.scope
    Nov 06 17:20:57.478132  trapdoor-health.timer: Deactivated successfully
    Nov 06 17:20:57.478455  Stopped trapdoor-health.timer
    Nov 06 17:20:57.494522  Reload requested from client PID 266175 ('systemctl')

Root logged in from `192.168.111.43` — **`dept-crperdue-tech`, the assistant
box** — 9m46s after the drift alert, disabled the timer, reloaded, and
disconnected 266 ms later. It was off for **29 hours**.

Two corrections were needed to get here, and both are worth recording because
each looked convincing:

1. **"The timer was never enabled"** — false. `is-enabled: disabled` read at
   22:1x on Nov 7 was a present-tense observation with no history behind it.
   The timer ran 380 times over four days.
2. **"`timer-install` is not idempotent, and the daemon-reload kills the
   active timer"** — false, and tested. Re-running the exact target sequence on
   a scratch unit while active leaves it active: `install` → `daemon-reload` →
   `enable --now` all preserve it. Also survived: plain `daemon-reload`,
   `enable` without `--now`, a second `enable --now`, `disable` without `--now`,
   and `stop timers.target`.

   Two independent proofs killed it: the unit files still carry their original
   `2026-11-02 18:52:26.434392148` mtime (`install -m 644` rewrites mtime, so
   the target did not run on Nov 6), and the microsecond journal shows the
   timer dead **16 ms before** the reload was requested — the reload was the
   consequence, not the cause. A log without fractional seconds makes those two
   look adjacent, and adjacency read as causality.

**The timer was stopped by an operator debugging the failure it had correctly
reported.** Nine minutes after the drift alert, the watch was silenced rather
than the drift fixed. Then the machine was left with a working watchdog that
was switched off.

**The journal showed only 51 `Finished` lines because journald had rotated.**
The `.verify/` directory held 380 reports. The smaller artifact was the one
that got believed, and it produced a theory that fit: "a unit never enabled
leaves no failure record." The record was in a directory nobody opened.

So the real failure mode is ordinary and worse than "never installed":
**a working watchdog, switched off mid-debug by someone with a reason at the
time, who then forgets.** Nobody deletes a smoke alarm. They pull the battery
because it is beeping while they look for the fire. No failure record is
written for a monitor you silenced on purpose — because it did not fail.

That is the standing argument for the external check, sharpened by the fact
that the silencer was on `.43` — the assistant box, not the target box:

> **The thing that asks "did your check run" must not be within the blast
> radius of the thing it watches.** Not outside the repo — outside the
> operator's reach. A repo-external check run from the same shell that
> disabled the timer is the same check with a longer path.

And that has an uncomfortable consequence. A check owned by whoever has root on
the target is still silenceable by them. If the same engineer can edit the
watcher and restart the watched, the watcher is a diary. **Something is only a
watchdog if someone else is looking at its readout** — which makes "report into
a channel a third party sees" a design requirement, not a nicety.

### The health check counts events by existence, not by growth

`verify.sh` section 4 reads `out/events.jsonl`, counts every line, and prints
`OK <n> events`. It never asks **when**. The count is absolute and there is no
recency test anywhere in the file:

    grep -nE "mtime|today|recent|24h|date \+|stat " scripts/verify.sh
    (no output)

Proven by construction, not argued: an `events.jsonl` containing 8 events dated
2026-10-30 with its mtime set to the epoch prints

    OK  8 events (python3 parser), sensors: cowrie=5 nginx=3
    OK  every event line is valid JSON

Two green OKs from a sensor that has been dead for eight days. **A health check
that reports green on a system which has quietly stopped emitting events is
green.** The check is asking "is there a log" when the question is "is the log
growing."

That is the timer failure one layer down, and it is the same defect shape as
everything else in this document: a number read as a fact. `8539 events` reads
like a healthy sensor. It is a statement about history. **The number that would
mean something is the delta**, and the report does not contain it.

What a reader would need, and what is not currently printed:

    wc -l out/events.jsonl   # at two points a known interval apart
    # zero delta over 24h of green ticks = a dead sensor and a lying check

### On reading logs: adjacency is not causality

Three of the wrong conclusions in this document came from a log that was
missing data. One came from a log that had *all* of it.

The reload was requested 16.390 milliseconds **after** the timer was already
dead. At whole-second resolution those two lines sit side by side, and side by
side reads as one causing the other. It produced a confident, specific,
entirely false theory about a non-idempotent install target — which survived
until it was run on a scratch unit six different ways.

> **A log without fractional seconds is a log where everything that happened
> together looks like everything that caused each other.** If a claim is
> "this line caused that line," the timestamps have to be able to tell them
> apart. At one-second resolution they cannot, and the honest sentence is
> "these are adjacent," full stop. `journalctl -o short-precise` costs
> nothing.

Two rules out of this:

1. **Before quoting a count from any log, ask what the log's own coverage is.**
   `journalctl --list-boots`, oldest file in a directory, the shipper's
   `RETENTION_DAYS`. A count is meaningless without its window. 51 and 380
   are the same data over different windows, and only one of them was true.
2. **The checker's output directory is better evidence than the supervisor's
   log.** The log can rotate; the artifacts persist. Check the thing the check
   wrote, not the record that it was invited to run.

**The fix is not in this repo, and cannot be.** Every one of these four is a
thing whose health is only knowable by asking a different process. A repo-owned
liveness check dies with the repo, which is what happened on the 6th. The
required check lives outside: an external cron or another agent's heartbeat
whose only job is to ask `.45` *did your health check run, and what did it say*,
and to alarm on silence specifically — not on a non-zero exit, which is the case
already handled.

---

## Scope and sequencing

| # | Change | Touches |
|---|---|---|
| 1 | Rotation in `shipper.py` + rotation test | `shipper/shipper.py`, `tests/` |
| 2 | Readers glob `out/events*.jsonl` + transcript-across-rotation test | `Makefile`, `scripts/render_session.py`, `scripts/verify.sh`, `scenarios/*.sh`, `tests/` |
| 3 | `cowrie_var` size in `make health` | `scripts/health-check.sh` |
| 4 | Docs: DEPLOY disk section, README footprint, this file | `docs/`, `README.md` |

Each is its own commit. 1 and 2 are not separable in practice — rotating without
updating the readers makes the transcript wrong, which is the failure mode this
whole round is about — so 2 lands with 1 or immediately after it, and neither
ships without its test.
