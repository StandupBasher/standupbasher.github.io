#!/usr/bin/env python3
"""waelsocial feed API — phase 1. Deliberately boring and disposable;
the Rust service (Ch.6) replaces this behind the identical contract.

Read-only by construction: the only file access in this program is opening
feed.json for reading. It runs as the unprivileged `wsapi` user, which
cannot traverse /home/claude — the signing key is unreachable from this
process even in principle (systemd additionally sets ProtectHome=yes).

Contract: GET /api/feed[?before=<ISO-ts>&limit=<n>]
  -> { v:1, alg:"Ed25519", pubkey, generated, entries[] } newest-first
  limit: default 20, hard max 50. No bulk-export endpoint exists.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FEED_PATH = os.environ.get("WAELSOCIAL_FEED", "/srv/waelsocial/feed.json")
BIND = ("127.0.0.1", 8080)  # only cloudflared can reach this
ALLOW_ORIGIN = "https://wael.sh"
DEFAULT_LIMIT, MAX_LIMIT = 20, 50

_cache = {"mtime": None, "feed": None}


def get_feed() -> dict:
    mtime = os.stat(FEED_PATH).st_mtime_ns
    if _cache["mtime"] != mtime:
        with open(FEED_PATH, encoding="utf-8") as f:
            feed = json.load(f)
        feed["entries"].sort(key=lambda e: e["ts"], reverse=True)
        _cache.update(mtime=mtime, feed=feed)
    return _cache["feed"]


class Handler(BaseHTTPRequestHandler):
    server_version = "waelsocial/phase1"

    def do_GET(self):
        url = urlparse(self.path)
        if url.path != "/api/feed":
            return self.send_json(404, {"error": "not found"})

        q = parse_qs(url.query)
        try:
            limit = int(q.get("limit", [DEFAULT_LIMIT])[0])
        except ValueError:
            limit = DEFAULT_LIMIT
        limit = max(1, min(limit, MAX_LIMIT))
        before = q.get("before", [None])[0]

        try:
            feed = get_feed()
        except Exception:
            return self.send_json(503, {"error": "feed unavailable"})

        entries = feed["entries"]
        if before:
            entries = [e for e in entries if e["ts"] < before]
        self.send_json(200, {**feed, "entries": entries[:limit]})

    def do_HEAD(self):
        self.do_GET()  # send_json suppresses the body for HEAD

    def send_json(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", ALLOW_ORIGIN)
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control",
                         "public, max-age=60" if code == 200 else "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass  # no per-request logging: nothing sensitive to record, no IP trail


if __name__ == "__main__":
    print(f"waelsocial feed api on {BIND[0]}:{BIND[1]} feed={FEED_PATH}", flush=True)
    ThreadingHTTPServer(BIND, Handler).serve_forever()
