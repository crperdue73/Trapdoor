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
