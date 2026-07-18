#!/usr/bin/env python3
"""waelsocial dashboard — Tailscale-only queue/publish UI. NOT public. NO login.

Security model (all structural, none of it convention):
  * Binds exclusively to CT 102's Tailscale interface address. Reaching this
    page at all requires being on the Tailnet — the network is the auth.
  * Runs as `wsdash`, which cannot read the signing key (cannot even traverse
    /home/claude). Everything that touches feed.json goes through
    `sudo -u claude sign-post` — one binary, one sudoers line.
  * Post text travels to sign-post via stdin and argv arrays. There is no
    shell anywhere in the invocation path, so nothing typed into this UI is
    ever shell-interpreted.
  * Cross-site POSTs are refused: any request with an Origin header that
    doesn't match our own host is rejected (blocks CSRF from random websites
    against the Tailscale IP), and Host must match the bind address.
"""

import html
import json
import subprocess
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg2

PORT = 8081
QUEUE_PATH = Path("/srv/waelsocial/queue.json")
DSN = "dbname=waelsocial"  # local socket, peer auth as wsdash (SELECT-only role)
SIGN_POST = ["sudo", "-n", "-u", "claude", "--", "/home/claude/bin/sign-post"]
RELAY_CAP = 2


def tailscale_ip() -> str:
    """The Tailscale interface address — the only address we will bind."""
    out = subprocess.run(["ip", "-j", "addr", "show", "tailscale0"],
                         capture_output=True, text=True, check=True).stdout
    for iface in json.loads(out):
        for a in iface.get("addr_info", []):
            if a.get("family") == "inet":
                return a["local"]
    raise RuntimeError("tailscale0 has no IPv4 address — is tailscale up?")


def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_queue(q: dict) -> None:
    tmp = QUEUE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(q, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(QUEUE_PATH)


def run_sign_post(args: list[str], stdin_text: str | None = None) -> tuple[bool, str]:
    """Invoke sign-post through sudo. argv only — no shell, ever."""
    try:
        r = subprocess.run(SIGN_POST + args, input=stdin_text, text=True,
                           capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "sign-post timed out"
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out[-500:]


def feed_stats() -> dict:
    """Live counts from Postgres via the read-only wsdash role. The console
    never writes the feed — it only reads it — so a failed read degrades to
    zeros rather than blocking the page."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = {"relays_week": 0, "takes": 0, "relays": 0, "mine": 0}
    try:
        conn = psycopg2.connect(DSN)
        try:
            cur = conn.cursor()
            cur.execute("SELECT type, count(*) FROM entries GROUP BY type")
            counts = dict(cur.fetchall())
            cur.execute("SELECT count(*) FROM entries WHERE type = 'relay' AND ts >= %s", (cutoff,))
            stats.update(relays_week=cur.fetchone()[0], takes=counts.get("take", 0),
                         relays=counts.get("relay", 0), mine=counts.get("mine", 0))
        finally:
            conn.close()
    except Exception:
        pass
    return stats


STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0b0c10; color: #e8e8e8; padding-bottom: 40px;
  font-family: ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace; }
main { max-width: 680px; margin: 0 auto; padding: 12px; }
h1 { font-size: 1.1rem; margin: 10px 0; }
h1 span { color: #00ff99; }
.stats { font-size: .85rem; color: #a5a5a5; margin-bottom: 14px; line-height: 1.6; }
.stats b { color: #e8e8e8; }
.warn { color: #ffb454; }
.flash { border: 1px solid rgba(0,255,153,.4); background: rgba(0,255,153,.07);
  border-radius: 10px; padding: 10px 12px; margin: 10px 0; font-size: .9rem;
  white-space: pre-wrap; overflow-wrap: anywhere; }
.flash.err { border-color: rgba(255,107,107,.5); background: rgba(255,107,107,.08); }
.card { border: 1px solid rgba(255,255,255,.1); border-radius: 12px;
  padding: 12px; margin: 10px 0; background: #111216; }
.cve { font-weight: 700; }
.sev { color: #ffb454; margin-left: 8px; }
.src { color: #00e0ff; font-size: .8rem; text-decoration: none; }
.sum { color: #cfcfcf; font-size: .9rem; margin: 8px 0; line-height: 1.45; }
textarea, input[type=text] { width: 100%; background: #0b0c10; color: #e8e8e8;
  border: 1px solid rgba(255,255,255,.18); border-radius: 10px; padding: 10px;
  font: inherit; font-size: 16px; /* 16px stops iOS zoom-on-focus */ }
textarea { min-height: 88px; }
.row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
button { font: inherit; border-radius: 10px; padding: 12px 16px; min-height: 44px;
  cursor: pointer; border: 1px solid rgba(255,255,255,.15); }
.primary { background: rgba(0,255,153,.15); color: #caffea;
  border-color: rgba(0,255,153,.45); font-weight: 700; flex: 1; }
.ghost { background: rgba(255,255,255,.05); color: #e8e8e8; }
.danger { background: rgba(255,107,107,.08); color: #ffb3b3;
  border-color: rgba(255,107,107,.3); }
button:disabled { opacity: .45; cursor: not-allowed; }
details summary { cursor: pointer; min-height: 44px; display: flex;
  align-items: center; color: #a5a5a5; font-size: .85rem; }
.empty { color: #a5a5a5; }
"""


def page(queue: dict, stats: dict, flash: str = "", flash_err: bool = False) -> str:
    e = html.escape
    relay_left = max(0, RELAY_CAP - stats["relays_week"])
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<meta name='robots' content='noindex'>",
        f"<title>waelsocial console</title><style>{STYLE}</style></head><body><main>",
        "<h1>waelsocial <span>console</span></h1>",
        f"<div class='stats'>feed: <b>{stats['mine']}</b> mine · <b>{stats['takes']}</b> takes · "
        f"<b>{stats['relays']}</b> relays &nbsp;|&nbsp; relay budget this week: "
        f"<b class='{'warn' if relay_left == 0 else ''}'>{stats['relays_week']}/{RELAY_CAP} used</b></div>",
    ]
    if flash:
        parts.append(f"<div class='flash{' err' if flash_err else ''}'>{e(flash)}</div>")

    parts.append("<div class='card'><form method='post' action='/mine'>"
                 "<textarea name='text' placeholder='new post — your words, signed' required></textarea>"
                 "<input type='text' name='tags' placeholder='tags, comma-separated (optional)' style='margin-top:8px'>"
                 "<div class='row'><button class='primary'>sign &amp; publish</button></div></form></div>")

    cands = queue.get("candidates", [])
    parts.append(f"<h1>queue <span>{len(cands)}</span></h1>")
    if not cands:
        parts.append("<p class='empty'>Queue is empty. The ingester runs every 6 hours.</p>")
    for c in cands:
        cve, sev = e(c["cve"]), e(str(c.get("severity", "?")))
        parts.append(
            f"<div class='card'><div><span class='cve'>{cve}</span><span class='sev'>{sev}</span> "
            f"<span class='src'>{e(c['source'])} · {e(c['date'])}</span></div>"
            f"<div class='sum'>{e(c['summary'])}</div>"
            f"<a class='src' href='{e(c['url'])}' target='_blank' rel='noopener'>{e(c['url'])}</a>"
            f"<form method='post' action='/take'><input type='hidden' name='cve' value='{cve}'>"
            f"<textarea name='text' placeholder='your take — this is the good path' required></textarea>"
            f"<div class='row'><button class='primary'>publish signed take ✓</button></div></form>"
            f"<details><summary>other actions…</summary><div class='row'>"
            f"<form method='post' action='/relay' style='display:inline'>"
            f"<input type='hidden' name='cve' value='{cve}'>"
            f"<button class='ghost' {'disabled' if relay_left == 0 else ''}>relay unsigned"
            f"{' (budget spent)' if relay_left == 0 else f' ({relay_left} left)'}</button></form>"
            f"<form method='post' action='/discard' style='display:inline'>"
            f"<input type='hidden' name='cve' value='{cve}'>"
            f"<button class='danger'>discard</button></form>"
            f"</div></details></div>")
    parts.append("</main></body></html>")
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    server_version = "waelsocial-console"

    def _deny_cross_site(self) -> bool:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        me = f"{self.server.server_address[0]}:{PORT}"
        if host != me or (origin and origin != f"http://{me}"):
            self.send_error(403, "cross-site request refused")
            return True
        return False

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path != "/":
            self.send_error(404)
            return
        q = urllib.parse.parse_qs(url.query)
        body = page(load(QUEUE_PATH, {"candidates": []}), feed_stats(),
                    flash=q.get("m", [""])[0], flash_err=q.get("e", ["0"])[0] == "1")
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self._deny_cross_site():
            return
        length = min(int(self.headers.get("Content-Length", 0)), 65536)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        text = form.get("text", [""])[0].strip()
        cve = form.get("cve", [""])[0].strip()
        tags = form.get("tags", [""])[0].strip()

        if self.path == "/mine":
            args = ["--type", "mine"] + (["--tags", tags] if tags else [])
            ok, out = run_sign_post(args, stdin_text=text)
        elif self.path == "/take":
            ok, out = run_sign_post(["--take-from", cve], stdin_text=text)
        elif self.path == "/relay":
            ok, out = run_sign_post(["--publish-relay", cve])
        elif self.path == "/discard":
            q = load(QUEUE_PATH, {"candidates": [], "seen": []})
            cand = next((c for c in q["candidates"] if c["cve"] == cve), None)
            if cand:
                q["candidates"].remove(cand)
                if cand["cve"] not in q["seen"]:
                    q["seen"].append(cand["cve"])
                save_queue(q)
            ok, out = bool(cand), f"discarded {cve}" if cand else f"{cve} not in queue"
        else:
            self.send_error(404)
            return

        dest = "/?" + urllib.parse.urlencode({"m": out, "e": "0" if ok else "1"})
        self.send_response(303)
        self.send_header("Location", dest)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ip = tailscale_ip()
    print(f"waelsocial console on http://{ip}:{PORT} (Tailnet only)", flush=True)
    ThreadingHTTPServer((ip, PORT), Handler).serve_forever()
