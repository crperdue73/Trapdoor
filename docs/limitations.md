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
