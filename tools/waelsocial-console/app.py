#!/usr/bin/env python3
"""waelsocial console — Tailnet-only operator dashboard. NOT public. NO login.

Security model (structural, inherited from the Ch.5 console):
  * Binds exclusively to CT 102's Tailscale interface address. Reaching this
    page at all requires being on the Tailnet — the network is the auth.
  * Runs as `wsdash`: read-only DB role (SELECT on entries + feed_meta),
    cannot traverse /home/claude. The web process holds no DB write grants.
  * Publishing goes through `sudo -n -u claude sign-post` with argv arrays
    and stdin. There is no shell anywhere in the invocation path.
  * Cross-site POSTs are refused: Host must match the bind address and any
    Origin header must match our own origin.
  * All external text (CVE summaries, titles) is rendered through Jinja
    autoescaping; the client JS only ever assigns via textContent.
"""

import base64
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, abort, redirect, render_template, request, url_for

PORT = int(os.environ.get("CONSOLE_PORT", "8081"))
QUEUE_PATH = Path("/srv/waelsocial/queue.json")
DSN = "dbname=waelsocial"  # local socket, peer auth as wsdash (SELECT-only role)
SIGN_POST = ["sudo", "-n", "-u", "claude", "--", "/home/claude/bin/sign-post"]
FEED_REMOVE = ["sudo", "-n", "-u", "claude", "--", "/home/claude/bin/feed-remove"]
RELAY_CAP = 2

app = Flask(__name__)


def tailscale_ip() -> str:
    """The Tailscale interface address — the only address we will bind."""
    out = subprocess.run(["ip", "-j", "addr", "show", "tailscale0"],
                         capture_output=True, text=True, check=True).stdout
    for iface in json.loads(out):
        for a in iface.get("addr_info", []):
            if a.get("family") == "inet":
                return a["local"]
    raise RuntimeError("tailscale0 has no IPv4 address — is tailscale up?")


BIND_IP = tailscale_ip()


# ── data access (read-only) ─────────────────────────────────────────

def db():
    conn = psycopg2.connect(DSN)
    conn.set_client_encoding("UTF8")  # never trust the ambient locale with signed bytes
    conn.set_session(readonly=True)
    return conn


def feed_stats() -> dict:
    stats = {"relays_week": 0, "takes": 0, "relays": 0, "mine": 0, "pubkey": ""}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        conn = db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT type, count(*) FROM entries GROUP BY type")
            counts = dict(cur.fetchall())
            cur.execute("SELECT count(*) FROM entries WHERE type = 'relay' AND ts >= %s", (cutoff,))
            relays_week = cur.fetchone()[0]
            cur.execute("SELECT pubkey FROM feed_meta")
            row = cur.fetchone()
            stats.update(relays_week=relays_week, takes=counts.get("take", 0),
                         relays=counts.get("relay", 0), mine=counts.get("mine", 0),
                         pubkey=row[0] if row else "")
        finally:
            conn.close()
    except Exception:
        pass
    return stats


def published_entries() -> list[dict]:
    cols = ("id", "ts", "type", "text", "tags", "source_title", "source_url",
            "media_url", "media_sha256", "media_alt", "sig")
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT {', '.join(cols)} FROM entries ORDER BY ts DESC")
        entries = [dict(zip(cols, row)) for row in cur.fetchall()]
        for e in entries:
            e["source_url"] = safe_url(e["source_url"]) or None
        return entries
    finally:
        conn.close()


def canonical(e: dict) -> bytes:
    """Byte-identical twin of canonicalize() in waelsocial.js and sign-post.
    v2 (8 lines, edited: after ts:) iff the entry carries edited_at."""
    edited = e.get("edited_at")
    lines = ["waelsocial-v2" if edited else "waelsocial-v1",
             f"id:{e['id']}", f"ts:{e['ts']}"]
    if edited:
        lines.append(f"edited:{edited}")
    lines += [f"type:{e['type']}", f"source:{e.get('source_url') or ''}",
              f"media:{e.get('media_sha256') or ''}", f"text:{e['text']}"]
    return "\n".join(lines).encode("utf-8")


def verify_entries(entries: list[dict], pubkey: str) -> None:
    """Server-side Ed25519 check against the pinned pubkey. Public-key math
    only — the console never holds private key material. (Done here rather
    than in the browser: crypto.subtle needs a secure context and the
    console is plain http over Tailscale.)"""
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey))
    except Exception:
        for e in entries:
            e["verify"] = "relay" if e["type"] == "relay" else "unavailable"
        return
    for e in entries:
        if e["type"] == "relay":
            e["verify"] = "relay"
            continue
        try:
            pk.verify(base64.b64decode(e.get("sig") or ""), canonical(e))
            e["verify"] = "ok-edited" if e.get("edited_at") else "ok"
        except Exception:
            e["verify"] = "bad"


def load_queue() -> dict:
    try:
        return json.loads(QUEUE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"candidates": [], "seen": []}


def save_queue(q: dict) -> None:
    tmp = QUEUE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(q, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(QUEUE_PATH)


def sev_key(c: dict) -> float:
    try:
        return float(c.get("severity"))
    except (TypeError, ValueError):
        return -1.0


def safe_url(u) -> str:
    """External URLs render as links only if they are plain http(s) —
    Jinja escaping stops HTML injection but not a javascript: scheme."""
    u = str(u or "")
    return u if u.startswith(("https://", "http://")) else ""


def grouped_queue(sort: str) -> tuple[list, list]:
    cands = load_queue().get("candidates", [])
    for c in cands:
        c["url"] = safe_url(c.get("url"))
    kev = [c for c in cands if c.get("source") == "kev"]
    nvd = [c for c in cands if c.get("source") != "kev"]
    kev.sort(key=lambda c: c.get("added", ""), reverse=True)
    if sort == "date":
        nvd.sort(key=lambda c: (c.get("date", ""), sev_key(c)), reverse=True)
    else:
        nvd.sort(key=lambda c: (sev_key(c), c.get("date", "")), reverse=True)
    return kev, nvd


def find_candidate(cve: str):
    cand = next((c for c in load_queue().get("candidates", [])
                 if c.get("cve", "").upper() == cve.upper()), None)
    if cand:
        cand["url"] = safe_url(cand.get("url"))
    return cand


# ── privileged tool invocation (argv + stdin only, never a shell) ───

def _run_tool(base: list[str], args: list[str], stdin_text: str | None = None,
              full_stdout: bool = False) -> tuple[bool, str]:
    try:
        r = subprocess.run(base + args, input=stdin_text, text=True,
                           capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, f"{base[-1]} timed out"
    if full_stdout and r.returncode == 0:
        return True, r.stdout
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out[-500:]


def run_sign_post(args: list[str], stdin_text: str | None = None,
                  full_stdout: bool = False) -> tuple[bool, str]:
    return _run_tool(SIGN_POST, args, stdin_text, full_stdout)


def run_feed_remove(args: list[str]) -> tuple[bool, str]:
    return _run_tool(FEED_REMOVE, args)


# ── request guards & headers ────────────────────────────────────────

@app.before_request
def deny_cross_site():
    if request.method != "POST":
        return
    me = f"{BIND_IP}:{PORT}"
    if request.host != me:
        abort(403)
    origin = request.headers.get("Origin")
    if origin and origin != f"http://{me}":
        abort(403)


@app.after_request
def harden(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
    return resp


@app.context_processor
def inject_shell():
    s = feed_stats()
    return {"stats": s, "relay_left": max(0, RELAY_CAP - s["relays_week"]),
            "relay_cap": RELAY_CAP,
            "queue_count": len(load_queue().get("candidates", [])),
            "flash": request.args.get("m", ""),
            "flash_err": request.args.get("e") == "1"}


def done(view: str, msg: str, ok: bool):
    return redirect(url_for(view, m=msg, e="0" if ok else "1"))


# ── views ───────────────────────────────────────────────────────────

@app.get("/")
def home():
    return redirect(url_for("queue_view"))


@app.get("/queue")
def queue_view():
    sort = request.args.get("sort", "sev")
    kev, nvd = grouped_queue(sort)
    return render_template("queue.html", kev=kev, nvd=nvd, sort=sort, active="queue")


@app.get("/published")
def published_view():
    entries = published_entries()
    verify_entries(entries, feed_stats()["pubkey"])
    return render_template("published.html", entries=entries, active="published")


@app.get("/compose")
def compose_view():
    cve = request.args.get("cve", "").strip()
    cand = find_candidate(cve) if cve else None
    if cve and not cand:
        return done("queue_view", f"{cve} is not in the queue", False)
    return render_template("compose.html", cand=cand, active="compose")


# ── actions ─────────────────────────────────────────────────────────

@app.post("/publish/mine")
def publish_mine():
    text = request.form.get("text", "").strip()
    tags = request.form.get("tags", "").strip()
    if not text:
        return done("compose_view", "empty post text", False)
    args = ["--type", "mine"] + (["--tags", tags] if tags else [])
    ok, out = run_sign_post(args, stdin_text=text)
    return done("published_view" if ok else "compose_view", out, ok)


@app.post("/publish/take")
def publish_take():
    text = request.form.get("text", "").strip()
    cve = request.form.get("cve", "").strip()
    if not text:
        return done("compose_view", "empty take text", False)
    ok, out = run_sign_post(["--take-from", cve], stdin_text=text)
    return done("published_view" if ok else "queue_view", out, ok)


@app.post("/publish/relay")
def publish_relay():
    cve = request.form.get("cve", "").strip()
    ok, out = run_sign_post(["--publish-relay", cve])
    return done("published_view" if ok else "queue_view", out, ok)


@app.post("/preview")
def preview():
    """Dry-run the exact publish path (same argv+stdin into sign-post) and
    return the entry as it would be signed. Nothing is written; the returned
    signature is verified server-side so the badge is honest, not cosmetic."""
    text = request.form.get("text", "")
    kind = request.form.get("kind", "mine")
    if not text.strip():
        return {"ok": False, "error": "type something to preview"}
    if kind == "take":
        cve = request.form.get("cve", "").strip()
        if not find_candidate(cve):
            return {"ok": False, "error": f"{cve} is not in the queue"}
        args = ["--take-from", cve, "--dry-run"]
    else:
        tags = request.form.get("tags", "").strip()
        args = ["--type", "mine"] + (["--tags", tags] if tags else []) + ["--dry-run"]
    ok, out = run_sign_post(args, stdin_text=text, full_stdout=True)
    if not ok:
        return {"ok": False, "error": out}
    marker = "entry JSON (not written):"
    if marker not in out:
        return {"ok": False, "error": "unexpected sign-post output"}
    entry = json.loads(out.split(marker, 1)[1])
    flat = {"id": entry["id"], "ts": entry["ts"], "type": entry["type"],
            "text": entry["text"], "tags": entry.get("tags", []),
            "source_url": (entry.get("source") or {}).get("url"),
            "source_title": (entry.get("source") or {}).get("title"),
            "media_sha256": (entry.get("media") or {}).get("sha256"),
            "sig": entry.get("sig"), "edited_at": entry.get("edited_at")}
    verify_entries([flat], feed_stats()["pubkey"])
    return {"ok": True, "entry": flat,
            "canonical": canonical(flat).decode("utf-8"),
            "verified": flat["verify"] == "ok"}


@app.post("/remove")
def remove_entry():
    """Archive-then-delete via feed-remove. The console never deletes
    directly — wsdash has no DB write grants; the claude-owned tool does the
    transactional archive+delete and the archive table is append-only."""
    entry_id = request.form.get("id", "").strip()
    if not entry_id:
        return done("published_view", "no entry id given", False)
    ok, out = run_feed_remove(["--reason", "console", "--", entry_id])
    return done("published_view", out, ok)


@app.post("/queue/dismiss")
def queue_dismiss():
    cves = {c.strip().upper() for c in request.form.getlist("cve") if c.strip()}
    if not cves:
        return done("queue_view", "nothing selected", False)
    q = load_queue()
    q.setdefault("seen", [])
    kept, dropped = [], []
    for c in q.get("candidates", []):
        if c.get("cve", "").upper() in cves:
            dropped.append(c["cve"])
            if c["cve"] not in q["seen"]:
                q["seen"].append(c["cve"])
        else:
            kept.append(c)
    q["candidates"] = kept
    save_queue(q)
    n = len(dropped)
    return done("queue_view", f"dismissed {n} candidate{'s' if n != 1 else ''}", n > 0)


if __name__ == "__main__":
    print(f"waelsocial console on http://{BIND_IP}:{PORT} (Tailnet only)", flush=True)
    app.run(host=BIND_IP, port=PORT, threaded=True, debug=False)
