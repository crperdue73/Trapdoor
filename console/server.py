"""TRAPDOOR console: the human view. Read-only, port 8081.

Why this exists
---------------
The stack collected events for six days and the only way to look at them was
`make sessions` on an SSH session. The decoy at :8080 is bait; it must never be
a console. The fleet portal is how agents talk, not how a person watches a lab.
So the lab had no door, and a honeypot nobody can watch teaches nothing to the
person it was built for.

Design rules, each one learned the hard way elsewhere in this repo:

  - READ ONLY. This process opens files for reading and answers GET. There is
    no POST, no admin action, no run-this-scenario button. The box it lives on
    is a honeypot; a console that can be told to do things is an interface for
    an attacker who reaches the lab network.
  - stdlib only. No pip, no build step. Same reason the shipper has no deps:
    if it needs installing, it breaks on the box nobody updated.
  - The tailer is stateless. Every request re-reads out/events.jsonl from
    inside the container, so the console cannot drift from the log, and a
    console restart loses nothing.
  - Nothing is trusted from the log. Every field is escaped on the way to HTML.
    Cowrie records whatever an attacker typed, so the log is attacker-controlled
    text and is treated as hostile.
  - Missing input is VISIBLE. When out/events.jsonl is not there, the page says
    so in one line. The shipper's first three deployments were silent because a
    missing file looked exactly like a quiet network; this page refuses to make
    that mistake twice.

Endpoints:
  GET /            dashboard (counts, recent events, sessions, health)
  GET /api/events  JSON: last N normalized events
  GET /api/stats   JSON: the same numbers the page shows
  GET /api/live    server-sent events: new lines as they land, no reload
  GET /static/*    the banner and logo, served from this process
  GET /healthz     200 always, so a container healthcheck can use it

Every number carries a timestamp. A count of the past is a diary.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

CONSOLE_NAME = "TRAPDOOR console"
OUT_DIR = Path(os.environ.get("OUT_DIR", "/out"))
EVENTS = OUT_DIR / "events.jsonl"
VERIFY_DIR = Path(os.environ.get("VERIFY_DIR", "/verify"))
BIND = os.environ.get("CONSOLE_BIND", "0.0.0.0")
PORT = int(os.environ.get("CONSOLE_PORT", "8081"))
MAX_ROWS = int(os.environ.get("CONSOLE_MAX_ROWS", "60000"))
DEFAULT_LIMIT = 200
STATIC_DIR = Path(os.environ.get("CONSOLE_STATIC", "/static"))
STREAM_POLL = float(os.environ.get("STREAM_POLL", "2"))
STREAM_KEEPALIVE = float(os.environ.get("STREAM_KEEPALIVE", "15"))


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

def read_events(limit: int = MAX_ROWS) -> tuple[list[dict], int]:
    """Return (events, total_lines).

    total_lines is read from the file honestly rather than inferred from what
    we parsed, because "how many events exist" and "how many I could parse" are
    different facts and the page must not conflate them.
    """
    if not EVENTS.is_file():
        return [], 0
    rows: list[dict] = []
    total = 0
    try:
        with EVENTS.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except OSError:
        return [], 0
    if len(rows) > limit:
        rows = rows[-limit:]
    return rows, total


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stats(events: list[dict], total: int) -> dict:
    by_event = Counter(str(e.get("event") or "?") for e in events)
    by_sensor = Counter(str(e.get("sensor") or "?") for e in events)
    by_src = Counter(str(e.get("src_ip") or "?") for e in events)
    sessions: OrderedDict[str, dict] = OrderedDict()
    for e in events:
        sid = e.get("session_id")
        if not sid:
            continue
        s = sessions.setdefault(
            str(sid),
            {"session_id": str(sid), "sensor": e.get("sensor"),
             "src_ip": e.get("src_ip"), "events": 0, "first": e.get("ts"),
             "last": e.get("ts"), "commands": []},
        )
        s["events"] += 1
        s["last"] = e.get("ts") or s["last"]
        if not s["first"]:
            s["first"] = e.get("ts")
        if e.get("event") == "command" and e.get("command"):
            s["commands"].append(str(e["command"]))
    success = [e for e in events if e.get("event") == "auth_success"]
    forbidden = [e for e in events
                 if e.get("http_status") in (401, 403)]
    return {
        "generated_at": now_iso(),
        "total_lines": total,
        "parsed_events": len(events),
        "events_file_present": EVENTS.is_file(),
        "by_event": dict(by_event.most_common()),
        "by_sensor": dict(by_sensor.most_common()),
        "top_sources": dict(by_src.most_common(10)),
        "session_count": len(sessions),
        "sessions": list(sessions.values())[-25:][::-1],
        "auth_success": len(success),
        "http_forbidden": len(forbidden),
        "first_ts": events[0].get("ts") if events else None,
        "last_ts": events[-1].get("ts") if events else None,
    }


# --------------------------------------------------------------------------
# health: the three things `make health` computes and nobody could see
# --------------------------------------------------------------------------

_HEALTH_RE = re.compile(r"^(?P<k>DRIFT|VERIFY|TIMER)[:=]\s*(?P<v>.+)$", re.IGNORECASE)


def health() -> dict:
    """Read whatever health-report.sh last wrote. Absent is reported as absent."""
    out: dict = {"source": str(VERIFY_DIR), "present": VERIFY_DIR.is_dir(),
                 "entries": []}
    if not VERIFY_DIR.is_dir():
        return out
    try:
        files = sorted(p for p in VERIFY_DIR.iterdir() if p.is_file())
    except OSError:
        return out
    for p in files[-12:]:
        try:
            st = p.stat()
        except OSError:
            continue
        out["entries"].append({
            "name": p.name,
            "modified": datetime.fromtimestamp(
                st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bytes": st.st_size,
        })
    out["entries"].reverse()
    return out


# --------------------------------------------------------------------------
# html
# --------------------------------------------------------------------------

def tail_new(offset: int) -> tuple[list[str], int]:
    """Return (new raw lines, new byte offset) from EVENTS.

    Byte-offset tailing rather than re-reading the whole file: on a busy
    honeypot events.jsonl grows by megabytes an hour and a browser holding
    a stream open must not cost a full file read every two seconds.

    A missing file is not an error. It is the state before the first event,
    and the caller is told so with an empty list rather than an exception.
    """
    try:
        size = EVENTS.stat().st_size
    except OSError:
        return [], offset
    if size < offset:
        # Truncated or rotated underneath us. Start over rather than sit on an
        # offset past the end, which would silently deliver nothing forever.
        offset = 0
    if size == offset:
        return [], offset
    try:
        with EVENTS.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except OSError:
        return [], offset
    new_offset = offset + len(chunk)
    text = chunk.decode("utf-8", "replace")
    lines = [ln for ln in text.split("\n") if ln.strip()]
    if text and not text.endswith("\n") and lines:
        # Last line is partial. Hand back only what is complete and rewind to
        # the last newline so the fragment is re-read whole next pass.
        #
        # Rewinding to "just after the last newline" is the whole trick: an
        # earlier version added one byte past it and the next read began a
        # character late, so '{"partial":' + 'true}' came back as 'rue}'.
        # A corrupt row that still parses nowhere is worse than a delay.
        lines = lines[:-1]
        cut = text.rfind("\n")
        new_offset = offset if cut < 0 else offset + len(text[:cut + 1].encode("utf-8"))
    return lines, new_offset


def esc(value) -> str:
    s = "" if value is None else str(value)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


CSS = """
:root{--bg:#0b0d12;--panel:#11151d;--panel2:#151a24;--fg:#e8ebf2;--dim:#7d869c;
--line:#1e2431;--ok:#3ddc84;--warn:#fbbf24;--bad:#ff5c5c;--accent:#5aa9ff;
--mag:#ff4d9d}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
/* The banner is 3:1. Letting it hold that ratio instead of cropping it into a
strip: object-fit:cover on a tall-capped box sliced the middle out of the art
and threw away most of the image. Capped only so it cannot eat the whole
viewport on a short laptop screen. */
.banner{display:block;width:100%;height:auto;object-fit:cover;
border-bottom:1px solid var(--line)}
@media(max-height:700px){.banner{max-height:26vh;object-fit:cover}}
.topbar{display:flex;align-items:center;gap:14px;padding:14px 24px;
border-bottom:1px solid var(--line);background:linear-gradient(180deg,#10141c,#0b0d12);
position:sticky;top:0;z-index:20}
.topbar img.mark{width:34px;height:34px;border-radius:7px;flex:0 0 auto}
h1{font-size:15px;margin:0;letter-spacing:.16em;text-transform:uppercase;white-space:nowrap}
h1 span{color:var(--accent)}
.spacer{flex:1}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;border:1px solid var(--line);
font-size:11px;letter-spacing:.05em;color:var(--dim);white-space:nowrap}
.pill.live{border-color:#1f5c3a;color:var(--ok);background:#0d2018}
.pill.dead{border-color:#5c1f1f;color:var(--bad);background:#200d0d}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--ok);
margin-right:6px;vertical-align:1px;animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(61,220,132,.5)}
50%{opacity:.55;box-shadow:0 0 0 6px rgba(61,220,132,0)}}
.ts{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums}
main{padding:20px 24px 70px;max-width:1400px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(146px,1fr));
gap:10px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;
padding:12px 14px;position:relative;overflow:hidden}
.card .n{font-size:23px;font-variant-numeric:tabular-nums;letter-spacing:-.02em;
transition:color .25s}
.card .l{color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:.09em}
.card.flash{border-color:var(--accent)}
h2{font-size:11.5px;text-transform:uppercase;letter-spacing:.12em;color:var(--dim);
margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line);
display:flex;align-items:center;gap:10px}
h2 .count{color:var(--fg);letter-spacing:.04em}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:22px}
@media(max-width:900px){.cols{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:500;font-size:10.5px;
text-transform:uppercase;letter-spacing:.08em;padding:6px 8px;
border-bottom:1px solid var(--line);position:sticky;top:53px;background:var(--bg)}
td{padding:6px 8px;border-bottom:1px solid #171c26;vertical-align:top}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.dim{color:var(--dim)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.notice{border:1px solid var(--warn);background:#241f10;color:var(--warn);
padding:12px 14px;border-radius:9px;margin-bottom:18px}
.notice code{color:#fff}
.ev-auth_success{color:var(--ok);font-weight:600}
.ev-auth_failed{color:var(--bad)}
.ev-command{color:var(--accent)}
.ev-session_connect{color:var(--mag)}
tr.fresh{animation:slidein .55s ease-out}
@keyframes slidein{from{background:#16243a;transform:translateY(-3px)}
to{background:transparent;transform:none}}
#feed td{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px}
#feed tr{transition:background .2s}
#feed tr:hover{background:var(--panel2)}
.sess{background:var(--panel);border:1px solid var(--line);border-radius:9px;
padding:10px 13px;margin-bottom:7px}
.sess summary{cursor:pointer;font-family:ui-monospace,monospace;font-size:12.5px}
ul.cmds{margin:8px 0 0;padding-left:20px;color:var(--accent)}
ul.cmds li{margin-bottom:2px}
footer{color:var(--dim);font-size:11.5px;padding:0 24px 40px;border-top:1px solid var(--line);
padding-top:14px;margin-top:10px}
footer code{color:var(--accent)}
"""

EVENT_CLASS = {
    "auth_success": "ev-auth_success",
    "auth_failed": "ev-auth_failed",
    "command": "ev-command",
}


def _row(e: dict) -> str:
    """One event as a table row. Every field comes from the log and is hostile."""
    cls = EVENT_CLASS.get(str(e.get("event")), "")
    detail = (e.get("command") or e.get("http_path")
              or e.get("username") or "")
    if e.get("http_status"):
        # Built as separate escaped pieces. Passing a pre-made "&rarr;"
        # through esc() printed the entity as literal text, which is what
        # the first run of this page did.
        detail = (f"{esc(detail)} <span class=\"dim\">&rarr; "
                  f"{esc(e['http_status'])}</span>")
    else:
        detail = esc(detail)
    return (f'<tr><td class="mono dim">{esc(e.get("ts"))}</td>'
            f'<td class="mono">{esc(e.get("sensor"))}</td>'
            f'<td class="mono {cls}">{esc(e.get("event"))}</td>'
            f'<td class="mono">{esc(e.get("src_ip"))}</td>'
            f'<td class="mono">{detail}</td></tr>')


def render(s: dict, events: list[dict], h: dict) -> str:
    parts: list[str] = []
    add = parts.append

    add(f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(CONSOLE_NAME)}</title><style>{CSS}</style></head><body>
<img class="banner" src="/static/banner.jpg" alt="TRAPDOOR">
<div class="topbar">
<img class="mark" src="/static/logo.png" alt="">
<h1>{esc(CONSOLE_NAME)}</h1>
<span class="pill">read-only</span>
<span class="spacer"></span>
<span class="pill live" id="link"><span class="dot"></span>live</span>
<span class="ts" id="stamp">rendered {esc(s['generated_at'])}</span>
</div><main>""")

    if not s["events_file_present"]:
        add(f"""<div class="notice"><strong>No events yet.</strong>
Nothing has been written to <code>{esc(str(EVENTS))}</code>.
That is what an empty pipeline and a missing pipeline look like at the same
time, so nothing below is a verdict. Start the stack (<code>make up</code>) and
run a scenario (<code>make scenario SCENARIO=ssh-bruteforce</code>).</div>""")
    elif s["parsed_events"] == 0:
        add(f"""<div class="notice"><strong>The events file exists and has no
parsable events.</strong> {esc(s['total_lines'])} lines read. A shipper starts
writing before it can parse, so this is a real state, not an error.</div>""")

    add('<div class="cards">')
    for cid, n, l in (
        ("c-events", s["total_lines"], "events on disk"),
        ("c-parsed", s["parsed_events"], "parsed"),
        ("c-sessions", s["session_count"], "sessions"),
        ("c-auth", s["auth_success"], "auth successes"),
        ("c-403", s["http_forbidden"], "403s served"),
    ):
        add(f'<div class="card"><div class="n" id="{cid}">{n}</div>'
            f'<div class="l">{esc(l)}</div></div>')
    add("</div>")
    add(f'<div class="ts">window: {esc(s["first_ts"] or "none")} '
        f'&rarr; {esc(s["last_ts"] or "none")}</div>')

    # by event / by sensor / by source
    add("<h2>by event type</h2><table><tr><th>event</th><th>count</th></tr>")
    for k, v in s["by_event"].items():
        add(f'<tr><td class="mono">{esc(k)}</td><td>{v}</td></tr>')
    if not s["by_event"]:
        add('<tr><td class="dim" colspan="2">nothing yet</td></tr>')
    add("</table>")

    add("<h2>by sensor</h2><table><tr><th>sensor</th><th>count</th></tr>")
    for k, v in s["by_sensor"].items():
        add(f'<tr><td class="mono">{esc(k)}</td><td>{v}</td></tr>')
    if not s["by_sensor"]:
        add('<tr><td class="dim" colspan="2">nothing yet</td></tr>')
    add("</table>")

    add("<h2>top sources</h2><table><tr><th>src_ip</th><th>events</th></tr>")
    for k, v in s["top_sources"].items():
        add(f'<tr><td class="mono">{esc(k)}</td><td>{v}</td></tr>')
    if not s["top_sources"]:
        add('<tr><td class="dim" colspan="2">nothing yet</td></tr>')
    add("</table>")

    # sessions
    add("<h2>sessions (newest first)</h2>")
    if not s["sessions"]:
        add('<p class="dim">No session_id on any event yet. Cowrie assigns one '
            'on connect; nginx requests have none.</p>')
    for sess in s["sessions"]:
        cmds = "".join(f"<li><code>{esc(c)}</code></li>" for c in sess["commands"])
        add(f"""<details><summary>{esc(sess['session_id'])}
<span class="dim"> &middot; {esc(sess['sensor'])} &middot;
{esc(sess['src_ip'])} &middot; {sess['events']} events</span></summary>
<div class="ts">{esc(sess['first'])} &rarr; {esc(sess['last'])}</div>
{'<ul class="cmds">' + cmds + '</ul>' if cmds else '<div class="ts">no commands typed</div>'}
</details>""")

    # live feed. Deliberately the first table on the page: a honeypot is an
    # event stream, not a report, and the newest line should be the thing your
    # eye lands on when the page opens.
    add('<h2>live feed <span class="count" id="feedcount">'
        f'({len(events[-DEFAULT_LIMIT:])})</span>'
        '<span class="spacer"></span><span class="ts">'
        'streams new events as they land</span></h2>')
    add('<table id="feed"><thead><tr><th>ts</th><th>sensor</th>'
        '<th>event</th><th>src</th><th>detail</th></tr></thead><tbody>')
    for e in events[-DEFAULT_LIMIT:][::-1]:
        add(_row(e))
    if not events:
        add('<tr><td class="dim" colspan="5">nothing yet</td></tr>')
    add("</tbody></table>")

    # health
    add("<h2>health reports</h2>")
    if not h["present"]:
        add(f'<p class="dim">No health directory mounted at '
            f'<code>{esc(h["source"])}</code>. Run <code>make health</code> and '
            f'this list fills in.</p>')
    elif not h["entries"]:
        add('<p class="dim">Health directory is mounted and empty. '
            '<code>make health</code> has not run yet.</p>')
    else:
        add("<table><tr><th>file</th><th>modified</th><th>bytes</th></tr>")
        for ent in h["entries"]:
            add(f'<tr><td class="mono">{esc(ent["name"])}</td>'
                f'<td class="mono dim">{esc(ent["modified"])}</td>'
                f'<td>{ent["bytes"]}</td></tr>')
        add("</table>")

    add("""</main><footer>
Read-only. This page cannot start, stop, or change anything: the decoy at
:8080 is bait, and the console shares its host, so it gets no actions.
JSON: <code>/api/events</code>, <code>/api/stats</code>,
stream: <code>/api/live</code>. Every field below is attacker-written text,
escaped before it reaches this page.
</footer>
<script>
// Live feed. EventSource reconnects on its own, so a dropped connection heals
// without a reload; the status pill tells you which state you are in rather
// than pretending the page is live when the socket died.
(function () {
  var feed = document.getElementById("feed").querySelector("tbody");
  var pill = document.getElementById("link");
  var stamp = document.getElementById("stamp");
  var cap = 400;

  function setState(live, why) {
    pill.className = "pill " + (live ? "live" : "dead");
    pill.innerHTML = (live ? '<span class="dot"></span>live' : 'offline');
    if (why) pill.title = why;
  }

  function pad(n) { return n < 10 ? "0" + n : "" + n; }
  function clock() {
    var d = new Date();
    stamp.textContent = "gap " + pad(d.getHours()) + ":" + pad(d.getMinutes()) +
      ":" + pad(d.getSeconds()) + " \u00b7 auto";
  }

  function bump(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var n = parseInt(el.textContent, 10);
    if (!isNaN(n)) el.textContent = n + 1;
  }

  var es = new EventSource("/api/live");
  es.onopen = function () { setState(true); };
  es.onerror = function () { setState(false, "stream closed, retrying"); };
  es.addEventListener("event", function (msg) {
    var e;
    try { e = JSON.parse(msg.data); } catch (x) { return; }
    var tr = document.createElement("tr");
    tr.className = "fresh";
    var cls = {auth_success: "ev-auth_success", auth_failed: "ev-auth_failed",
               command: "ev-command", session_connect: "ev-session_connect"}[e.event] || "";
    var detail = e.command || e.http_path || e.username || "";
    if (e.http_status) detail += " \u2192 " + e.http_status;
    [["ts", e.ts, "mono dim"], ["sensor", e.sensor, "mono"],
     ["event", e.event, "mono " + cls], ["src", e.src_ip, "mono"],
     ["detail", detail, "mono"]].forEach(function (c) {
      var td = document.createElement("td");
      td.className = c[2];
      td.textContent = c[1] == null ? "" : String(c[1]);
      tr.appendChild(td);
    });
    feed.insertBefore(tr, feed.firstChild);
    while (feed.children.length > cap) feed.removeChild(feed.lastChild);
    var fc = document.getElementById("feedcount");
    if (fc) fc.textContent = "(" + feed.children.length + ")";
    bump("c-events"); bump("c-parsed");
    clock();
    setTimeout(function () { tr.className = ""; }, 600);
  });
})();
</script>
</body></html>""")
    return "".join(parts)


# --------------------------------------------------------------------------
# http
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "trapdoor-console"
    sys_version = ""

    def log_message(self, fmt, *args):  # keep container logs quiet
        pass

    def _static(self, path: str) -> None:
        """Serve the banner and logo from this process.

        Whitelisted by exact filename rather than by joining paths. A console
        on a honeypot does not need to be talked into reading arbitrary files
        by a ../ that some future edit stops sanitising.
        """
        allowed = {
            "/static/banner.jpg": "image/jpeg",
            "/static/logo.png": "image/png",
        }
        ctype = allowed.get(path)
        if ctype is None:
            self._send(404, json.dumps({"error": "not found"}),
                       "application/json")
            return
        try:
            raw = (STATIC_DIR / path.rsplit("/", 1)[-1]).read_bytes()
        except OSError:
            self._send(404, json.dumps({"error": "asset missing",
                                        "path": path}), "application/json")
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _stream(self) -> None:
        """Server-sent events: new lines from events.jsonl as they land.

        Read-only in the strictest sense: this opens the log for reading and
        writes bytes to a socket. It cannot cause an event, change one, or
        reach anything but EVENTS.

        On connect the offset starts at the CURRENT end of file, so a visitor
        sees what happens next rather than a replay of four days of history.
        The first rows on the page already cover the past.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            offset = EVENTS.stat().st_size
        except OSError:
            offset = 0
        last_write = time.time()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                lines, offset = tail_new(offset)
                if lines:
                    for line in lines:
                        try:
                            json.loads(line)  # only ship what parses
                        except ValueError:
                            continue
                        self.wfile.write(
                            b"event: event\ndata: " + line.encode("utf-8", "replace")
                            + b"\n\n")
                    self.wfile.flush()
                    last_write = time.time()
                elif time.time() - last_write >= STREAM_KEEPALIVE:
                    # A comment line. Keeps proxies from closing an idle stream
                    # and tells the browser the connection is still real.
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    last_write = time.time()
                time.sleep(STREAM_POLL)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            # A stream must never take the server down with it.
            return


        raw = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _send(self, code: int, body: str, ctype: str) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/healthz":
            self._send(200, json.dumps({"ok": True, "at": now_iso()}),
                       "application/json")
            return

        events, total = read_events()
        s = stats(events, total)

        if path == "/api/stats":
            self._send(200, json.dumps(s, indent=2), "application/json")
            return
        if path == "/api/events":
            q = parse_qs(parsed.query)
            try:
                limit = max(1, min(2000, int(q.get("limit", ["200"])[0])))
            except ValueError:
                limit = 200
            self._send(200, json.dumps(events[-limit:], indent=2),
                       "application/json")
            return
        if path in ("/", "/index.html"):
            self._send(200, render(s, events, health()), "text/html; charset=utf-8")
            return
        if path == "/api/live":
            self._stream()
            return
        if path.startswith("/static/"):
            self._static(path)
            return

        self._send(404, json.dumps({"error": "not found", "path": parsed.path}),
                   "application/json")

    def do_POST(self):
        # Deliberate, and it is the whole security posture of this service.
        self._send(405, json.dumps(
            {"error": "read only",
             "detail": "the console has no actions by design"}),
            "application/json")

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST


def main() -> int:
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"{CONSOLE_NAME} on http://{BIND}:{PORT}  events={EVENTS}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
