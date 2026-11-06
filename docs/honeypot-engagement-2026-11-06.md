# Honeypot Adversarial Engagement — 2026-11-06

## The finding that outlives the engagement

Read this paragraph if you read nothing else.

Two agents with the same tools, the same intent, and the same morning spent telling each other to
**measure instead of assume** — and within thirty minutes, on the same host, both failed to do it. One
assumed a silent service was unlogged. The other queried one service's log and made a claim about the
host. Neither was careless.

Each caught the other within that same half hour. That is the part that matters: it was not more
discipline or a better tool held by one sharper observer. It was **two independent wrong readings
colliding**, in unshared directions. Alone on that host, either of us would have filed the wrong claim
as a finding and it would have survived review.

Conclusion: **"be more careful" is not a control and never will be.** The fix is checks that fail closed,
in sequence, before the first packet. Everything below — the grade, the defect list, the refutations —
is about one decoy on one afternoon and will not matter in five years.

Counterpart report: June, `aegis-vault` `5a27969` (`reports/aurora-honeypot-assessment-2026-11-06.md`).
Same numbers, same verdicts; the disagreements are the ones both reports state openly.

---

## 1. Honeypot grade

| Tier | Claim | Sensor side | Verdict |
|---|---|---|---|
| 0 | Port/version scan of 2222, 2223, 8080 | Recorded. 2222 = OpenSSH 9.2p1 banner, 2223 = *"Cowrie Honeypot telnetd"*, 8080 = nginx. `gobuster` never ran — no wordlist on Kali. | **partial** |
| 1a | `GET /` | Recorded. 17:34:50Z, 200, 1275 bytes, Chrome 131 UA. | **recorded** |
| 1b | `GET /.env` | Recorded. 17:38:20Z, 403, 548 bytes. | **recorded** |
| 1c | SSH 2222 admin/admin | *First attempt sent zero packets* (`sshpass: command not found` on Kali). Re-run 18:23:34Z recorded: connect → `auth_success admin` → command → disconnect. | **recorded (re-run)** |
| 1d | telnet 2223, silent 3s, `rc=124` | Recorded as connect + clean disconnect, **no credential attempt**. | **recorded** |
| 2 | low-and-slow | Not run. | **not run** |
| 3 | reverse shell | Not run. Halted before firing. | **not run** |
| 4 | web path enumeration | 28 requests (14 paths × 2), 403/548 bytes byte-identical across 12 baited paths, 3× 404 at 926 bytes. | **recorded** |

**Detection score: 6 of 6 events actually sent were recorded.** T1c-first-attempt is excluded from the
denominator because no packet left the attacker box — a test that never ran cannot be a miss.

### The join works
June's Tier 1c re-run carried `MARKER-T1C-20261106T182334Z`. Found in Cowrie command events,
one match, timestamp agreement to the sub-second. **Attribution is not structurally missing** —
the evidence needed to bind an action to a source is present. What is absent is an automatic join.

---

## 2. The primary finding: host ≠ service

Within the same half hour, on the same host, both agents made the identical error from opposite sides:

- **June** found a service absent from a log and concluded the *service* did not log.
- **Aurora** queried one service's log and made a claim about the *host*.

Both competent, both actively trying to be rigorous, both wrong. The defect is structural:
**nothing in either toolchain forces a step that names which service is being queried before a claim
about a host is made.** "I checked 192.168.111.4" is not a statement about anything.

This outranks the honeypot results, because the honeypot grade describes one decoy while this
describes every diagnosis anyone on this farm will make with these tools.

**Same shape as this morning's firewall defect:** I queried the host-port counter and made a claim
about enforcement, when the rules match the post-DNAT container destination. Query one thing, claim
another. Three instances in one day, all the same class.

---

---

## 3. Defects in the decoy (found by June, confirmed by me)

1. **Telnet self-outing banner — DESIGN DEFECT, not a wording defect (June's severity, adopted).**
   Port 2223 announces *"Cowrie Honeypot telnetd"*. A self-announcing decoy does not merely fail to
   catch an attentive reader; it hands them a labelled environment to practise in and tells them
   exactly what is being observed. It converts the asset into the attacker's training ground.
2. **Source attribution collapses to the proxy.** All Cowrie `src_ip` = `172.23.0.5` (the forwarding
   container). Downgraded to "not automated" — see §1. **June wrote this downgrade into her own report
   before I asked for it**; it is her correction, not my softening of her finding.
   Fix post-run: forward-preserve + shipper session reconcile.
3. **Telnet credential field — PREDICTION REFUTED, DEFECT SURVIVES.** June's original prediction was a
   10 MB unauthenticated write primitive. A 5000-byte payload was tested and **not stored** — Cowrie
   caps the field upstream (longest observed: 30 chars). Recorded as **refuted with the mechanism
   named**, not deleted. The surviving defect: 30 chars of attacker text in a `username` field, rendered
   unescaped, is a bounded-input modelling defect with an injection surface.
4. **Incomplete WordPress decoy.** `/wp-login.php` is baited but `/wp-content/` returns 404. Kept at
   full weight: it is the only defect today that **actively refutes** an attack path rather than merely
   weakening one. A facade that 404s on `/wp-content/` answers the attacker's question for them.
5. **Attacker-side arithmetic (June, self-reported, not solicited).** Her Tier 4 count was wrong by a
   factor of two, and her first T1c printed a success line without sending a packet. Same class as my
   T1b error and this morning's firewall counter: **a check that cannot fail reads exactly like a check
   that passed.** Three instances, one lesson, three separate authors in one day.
5. **`dst_port` reports `$server_port`, not the published port.** Known, deliberately **not** fixed
   mid-run so the manifest stayed stable.

## 4. Defects in my instrumentation (found by me)

1. **Shipper/event-stream misreading (mine, not the shipper's).** I reported T1b `/.env` as missing.
   It was present in both the raw nginx log and the JSONL stream. I scanned a window flooded by 27
   nmap requests, never queried the single path directly, and reported absence from a truncated view.
   *The instrument was correct; my query was wrong.*
2. **`.10` family chat has no request logging.** Verified in source: two startup `console.log`s and
   nothing else. Any request to it leaves no trace. **Real, open.**
3. **`.4` "logging gap" — REFUTED.** I grepped the portal's log for a request that went to LiteLLM.
   LiteLLM logs method, path, status, source IP and port per request, and records auth failures with a
   structured `requester_ip`. June's probe is on record: `18:23:39Z  192.168.111.42:53760  "GET / HTTP/1.1" 200`.
4. **Telnet sensor sees silence.** T1d recorded as connect + disconnect with no auth attempt — so
   "silence is only an answer if the sensor is proven to see silence" is satisfied for 2223.

---

## 5. Why the run halted

June's Tier 3 wrapper used a nested heredoc whose delimiter never matched. The script body was never
written, and the command block — including a nested `ssh` that never wrapped it — executed **on her own
workstation as root**. In doing so it sent two requests to `192.168.111.4` and `192.168.111.10`, both
on the do-not-touch list. No writes, no credentials, no payload; status codes only. Her GET to `.4` is
confirmed in LiteLLM's log.

She stopped the run and called it an incident rather than a margin note.

**The halt is not the finding. The boundary is.** A typo was a harmless non-event on the decoy and a
production event on `.4` and `.10`; the only thing separating those outcomes was a string in a script.
The environment has no network control between attacker, decoy, portal and message bus — all on one
flat `/16`. **The bug was load-bearing; the boundary finding credits the gap, not either agent.**

---

## 6. What the rebuild requires

Order matters: boundary first, proven, then scripts.

1. Decoy on a segment with **no route to production** and default-deny egress.
2. Three negative tests, **three recorded denials** — not timeouts, not absence of success:
   - decoy → production must fail (proves egress denial)
   - test host → production must fail (proves the host is not on the flat `/16`)
   - test host → **wrong port** on the decoy host must fail (separates "nothing listening" from
     "something enforcing")
3. Each denial logged, attributable, timestamped on the enforcing device. **Silence voids the test.**
   Written criterion (June, adopted verbatim): *a boundary is proven only when all three negative tests
   produce attributable, timestamped denials. Silence voids the test — it does not pass it. Two denials
   and one silence is not "mostly contained," it is unproven, and it gets re-run.*
4. Attacker scripts assert hostname and source IP in their first lines and exit 1 otherwise. No nested
   heredoc inside an `ssh` string — files `scp`'d or piped over stdin.

---

## 7. Run record

| | |
|---|---|
| Attacker | June (`agent:engineering:june`), workstation `192.168.111.42`, scripted from Kali `192.168.100.24` (`Kali-MCP`) |
| Defender | Aurora, decoy host `192.168.111.45` (LXC `test-trapdoor`) |
| Line in the sand | 17:32:00Z green-light; log baseline 1965 lines |
| Halted | 18:23:39Z — attacker-side scope breach (§5), not a defender action |
| Produced | Tier 1 4/4 recorded, Tier 4 28 requests, Tier 0 partial; Tiers 2–3 unrun |
| Counterpart | June, `aegis-vault` `5a27969` |
| Not verified | Tiers 2–3 never ran; `gobuster` never ran; boundary not built, not tested |
