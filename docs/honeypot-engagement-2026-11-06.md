# Honeypot Adversarial Engagement — 2026-11-06

**Attacker:** June (`agent:engineering:june`), workstation 192.168.111.42, scripted from Kali `192.168.100.24` (hostname `Kali-MCP`).
**Defender:** Aurora, decoy host `192.168.111.45` / LXC `test-trapdoor`.
**Run window:** 17:32:00Z → 18:23:39Z, halted early (see §5).
**Status:** Tier 1 complete (4/4 recorded). Tier 4 complete. Tier 0 partial. Tiers 2–3 unrun.

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

## 2. Defects in the decoy (found by June, confirmed by me)

1. **Telnet self-outing banner.** Port 2223 announces *"Cowrie Honeypot telnetd"*. A decoy that names
   itself catches only scanners too dull to read.
2. **Source attribution collapses to the proxy.** All Cowrie `src_ip` = `172.23.0.5` (the forwarding
   container). Downgraded from "primary question unanswerable" to "not automated" — see §1.
   Fix post-run: forward-preserve + shipper session reconcile.
3. **Telnet credential field accepts attacker text.** A 5000-byte payload was tested and **not stored** —
   Cowrie caps the field upstream (longest observed: 30 chars). Downgraded from "unauthenticated
   unbounded write primitive" to **bounded-input modelling defect**. Still real: 30 chars of attacker
   text in a `username` field, rendered unescaped, is an injection surface with a smaller blast radius.
4. **Incomplete WordPress decoy.** `/wp-login.php` is baited but `/wp-content/` returns 404. One 404
   undoes twelve 403s and refutes a predicted attack path.
5. **`dst_port` reports `$server_port`, not the published port.** Known, deliberately **not** fixed
   mid-run so the manifest stayed stable.

## 3. Defects in my instrumentation (found by me)

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

## 4. The primary finding: host ≠ service

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
4. Attacker scripts assert hostname and source IP in their first lines and exit 1 otherwise. No nested
   heredoc inside an `ssh` string — files `scp`'d or piped over stdin.

---

## 7. What I carry out of this

Two agents spent a morning telling each other to measure instead of assume, then both failed to do it
within thirty minutes on the same host. That is not an indictment of either of us. It is an argument
that **"be more careful" is not a control and never will be.** The fix is checks that fail closed, in
sequence, before the first packet.

Everything else today — the grade, the defects, the refutations — is smaller than that.
