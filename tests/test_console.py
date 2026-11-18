"""Tests for the console. No Docker, no network, no host.

The console is the first thing in this repo a human is meant to LOOK at, so
the tests look at it too: they render real pages and read what came back. A
count in a card is a claim, and a claim about a honeypot that nobody checks is
how six days went by with no door.

What is covered:
  - empty state says "no events" instead of showing zeros as if they meant
    something (the shipper's silent failure, one layer up)
  - counts actually count
  - attacker-controlled text is escaped, because every field in the log is
    whatever an attacker typed
  - the service is read-only in fact, not just in a comment
  - /healthz answers even when the log is missing
"""

from __future__ import annotations

import http.client
import importlib
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

CONSOLE_DIR = Path(__file__).resolve().parent.parent / "console"
sys.path.insert(0, str(CONSOLE_DIR))


def load_console(out_dir: Path, verify_dir: Path):
    """Import server.py fresh, pointed at a temp directory."""
    os.environ["OUT_DIR"] = str(out_dir)
    os.environ["VERIFY_DIR"] = str(verify_dir)
    os.environ["CONSOLE_BIND"] = "127.0.0.1"
    os.environ["CONSOLE_PORT"] = "0"
    if "server" in sys.modules:
        del sys.modules["server"]
    return importlib.import_module("server")


SAMPLE = [
    {"ts": "2026-11-12T05:00:00.000Z", "sensor": "cowrie", "event": "connect",
     "proto": "ssh", "src_ip": "10.20.30.50", "session_id": "s1"},
    {"ts": "2026-11-12T05:00:01.000Z", "sensor": "cowrie", "event": "auth_failed",
     "proto": "ssh", "src_ip": "10.20.30.50", "session_id": "s1",
     "username": "root", "password": "123456"},
    {"ts": "2026-11-12T05:00:02.000Z", "sensor": "cowrie", "event": "auth_success",
     "proto": "ssh", "src_ip": "10.20.30.50", "session_id": "s1",
     "username": "root"},
    {"ts": "2026-11-12T05:00:03.000Z", "sensor": "cowrie", "event": "command",
     "proto": "ssh", "src_ip": "10.20.30.50", "session_id": "s1",
     "command": "cat /etc/passwd"},
    {"ts": "2026-11-12T05:00:04.000Z", "sensor": "nginx", "event": "http_request",
     "proto": "http", "src_ip": "10.20.30.51", "http_method": "GET",
     "http_path": "/.env", "http_status": 403},
]


class ConsoleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.verify = Path(self.tmp.name) / "verify"
        self.out.mkdir()
        self.verify.mkdir()
        self.mod = load_console(self.out, self.verify)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rows):
        with (self.out / "events.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    # -- the "nothing happened" and "I cannot see anything" distinction ------

    def test_missing_file_is_announced_not_shown_as_zero(self):
        events, total = self.mod.read_events()
        self.assertEqual((events, total), ([], 0))
        s = self.mod.stats(events, total)
        self.assertFalse(s["events_file_present"])
        page = self.mod.render(s, events, self.mod.health())
        self.assertIn("No events yet", page)
        self.assertIn("nothing below is a verdict", page)

    def test_present_but_unparsable_is_its_own_state(self):
        (self.out / "events.jsonl").write_text("not json\n", encoding="utf-8")
        events, total = self.mod.read_events()
        self.assertEqual(total, 1)
        self.assertEqual(events, [])
        page = self.mod.render(self.mod.stats(events, total), events,
                               self.mod.health())
        # collapsed, because the source wraps this sentence across two lines
        # and the assertion should test the words, not the whitespace
        self.assertIn("no parsable events", " ".join(page.split()))

    # -- counts --------------------------------------------------------------

    def test_counts_are_real(self):
        self.write(SAMPLE)
        events, total = self.mod.read_events()
        s = self.mod.stats(events, total)
        self.assertEqual(total, 5)
        self.assertEqual(s["parsed_events"], 5)
        self.assertEqual(s["session_count"], 1)
        self.assertEqual(s["auth_success"], 1)
        self.assertEqual(s["http_forbidden"], 1)
        self.assertEqual(s["by_sensor"], {"cowrie": 4, "nginx": 1})
        self.assertEqual(s["by_event"]["command"], 1)

    def test_session_groups_commands(self):
        self.write(SAMPLE)
        events, total = self.mod.read_events()
        s = self.mod.stats(events, total)
        sess = s["sessions"][0]
        self.assertEqual(sess["session_id"], "s1")
        self.assertEqual(sess["events"], 4)
        self.assertEqual(sess["commands"], ["cat /etc/passwd"])

    # -- hostile input -------------------------------------------------------

    def test_attacker_text_is_escaped(self):
        rows = [dict(SAMPLE[3], command='<script>alert(1)</script>'),
                dict(SAMPLE[4], http_path='"><img src=x onerror=alert(1)>')]
        self.write(rows)
        events, total = self.mod.read_events()
        page = self.mod.render(self.mod.stats(events, total), events,
                               self.mod.health())
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;script&gt;", page)

    # -- read only, in fact --------------------------------------------------

    def test_post_is_refused_and_changes_nothing(self):
        self.write(SAMPLE)
        before = (self.out / "events.jsonl").read_bytes()

        mod = self.mod
        srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            for method in ("POST", "PUT", "DELETE"):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(method, "/", body=b'{"event":"auth_success"}')
                r = c.getresponse()
                self.assertEqual(r.status, 405)
                body = json.loads(r.read())
                self.assertEqual(body["error"], "read only")
                c.close()
        finally:
            srv.shutdown()
            srv.server_close()

        self.assertEqual((self.out / "events.jsonl").read_bytes(), before,
                         "console modified the event log")

    def test_healthz_answers_with_no_log_present(self):
        mod = self.mod
        srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/healthz")
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())["ok"])
            c.close()

            # and the dashboard still renders rather than 500s
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/")
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertIn("No events yet", r.read().decode())
            c.close()

            # unknown path is a clean 404, not a traceback
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/nope")
            r = c.getresponse()
            self.assertEqual(r.status, 404)
            c.close()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_api_events_limit(self):
        self.write(SAMPLE)
        mod = self.mod
        srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/api/events?limit=2")
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            rows = json.loads(r.read())
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[-1]["event"], "http_request")
            c.close()
        finally:
            srv.shutdown()
            srv.server_close()

    # -- health panel --------------------------------------------------------

    def test_health_dir_absent_is_stated(self):
        mod = self.mod
        mod.VERIFY_DIR = Path(self.tmp.name) / "does-not-exist"
        h = mod.health()
        self.assertFalse(h["present"])
        page = mod.render({"events_file_present": False, "total_lines": 0,
                           "parsed_events": 0, "session_count": 0,
                           "auth_success": 0, "http_forbidden": 0,
                           "by_event": {}, "by_sensor": {}, "top_sources": {},
                           "sessions": [], "first_ts": None, "last_ts": None,
                           "generated_at": mod.now_iso()}, [], h)
        self.assertIn("No health directory mounted", page)

    def test_health_files_are_listed(self):
        (self.verify / "health-2026-11-12.txt").write_text("DRIFT: clean\n")
        h = self.mod.health()
        self.assertTrue(h["present"])
        self.assertEqual(h["entries"][0]["name"], "health-2026-11-12.txt")


class LiveTest(unittest.TestCase):
    """The live feed, and the ways it could be wrong.

    A stream that has silently stopped delivering looks exactly like a quiet
    honeypot. These exist so "no events" is never merely assumed.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.verify = Path(self.tmp.name) / "verify"
        self.out.mkdir()
        self.verify.mkdir()
        self.mod = load_console(self.out, self.verify)
        self.log = self.out / "events.jsonl"
        self.srv = self.mod.ThreadingHTTPServer(("127.0.0.1", 0), self.mod.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        code = r.status
        c.close()
        return code, body

    def write(self, rows):
        with self.log.open("a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    # -- tailing the file ----------------------------------------------------

    def test_tail_reads_only_what_was_appended(self):
        lines, off = self.mod.tail_new(0)
        self.assertEqual(lines, [], "missing file must yield no lines, not raise")
        self.write([{"event": "command"}])
        lines, off2 = self.mod.tail_new(off)
        self.assertEqual(len(lines), 1)
        self.assertGreater(off2, off)
        again, off3 = self.mod.tail_new(off2)
        self.assertEqual((again, off3), ([], off2), "no new bytes must mean no rows")

    def test_half_written_line_is_not_shipped_and_is_read_later(self):
        self.log.write_text('{"partial":', encoding="utf-8")
        lines, off = self.mod.tail_new(0)
        self.assertEqual(lines, [], "a half-written line must not be shipped")
        with self.log.open("a", encoding="utf-8") as fh:
            fh.write('true}\n')
        lines2, _ = self.mod.tail_new(off)
        self.assertTrue(any('"partial"' in ln for ln in lines2),
                        "the completed line must still arrive, not be lost")

    def test_truncated_file_rewinds_instead_of_going_silent(self):
        self.log.write_text('{"new":1}\n', encoding="utf-8")
        lines, off = self.mod.tail_new(10_000)
        self.assertEqual(len(lines), 1,
                         "an offset past EOF means the file shrank, not silence")
        self.assertLess(off, 10_000)

    # -- the stream itself ---------------------------------------------------

    def test_stream_delivers_an_event_written_after_connect(self):
        mod = self.mod
        old = mod.STREAM_POLL
        mod.STREAM_POLL = 0.05
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        try:
            sock.sendall(b"GET /api/live HTTP/1.1\r\nHost: x\r\n\r\n")
            # Written AFTER the stream opened: proves live, not a replay.
            threading.Timer(0.2, self.write,
                            args=([{"ts": "2026-01-01T00:00:00Z",
                                    "sensor": "cowrie", "event": "auth_failed",
                                    "proto": "ssh", "src_ip": "203.0.113.9",
                                    "username": "root"}],)).start()
            buf = b""
            deadline = time.time() + 8
            while b"203.0.113.9" not in buf and time.time() < deadline:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            self.assertIn(b"200", buf.split(b"\r\n", 1)[0])
            self.assertIn(b"text/event-stream", buf)
            self.assertIn(b"203.0.113.9", buf,
                          "an event written after connect must stream out")
        finally:
            mod.STREAM_POLL = old
            sock.close()

    # -- static assets -------------------------------------------------------

    def test_static_serves_banner_and_refuses_anything_else(self):
        code, body = self.get("/static/banner.jpg")
        # asset may be absent in a source-only checkout; then 404 is correct
        self.assertIn(code, (200, 404))
        if code == 200:
            self.assertTrue(len(body) > 1000)
        for bad in ("/static/../../etc/passwd", "/static/..%2f..%2fetc/passwd",
                    "/static/passwd", "/static/server.py"):
            code, _ = self.get(bad)
            self.assertEqual(code, 404, f"{bad} must not be served")

    # -- the page ------------------------------------------------------------

    def test_page_has_banner_and_no_full_reload(self):
        self.write([{"ts": "2026-01-01T00:00:00Z", "sensor": "cowrie",
                     "event": "command", "proto": "ssh", "command": "ls"}])
        code, page = self.get("/")
        self.assertEqual(code, 200)
        self.assertIn("banner.jpg", page)
        self.assertIn("logo.png", page)
        self.assertIn('id="feed"', page)
        self.assertIn("/api/live", page)
        self.assertNotIn('http-equiv="refresh"', page,
                         "a page reload every N seconds is not a live feed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
