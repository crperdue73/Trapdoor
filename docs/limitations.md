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
