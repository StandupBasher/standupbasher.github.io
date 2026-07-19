#!/usr/bin/env python3
"""sign-post — author and sign waelsocial-v1 feed entries.

Runs on CT 102, where the private key lives. The key never leaves that box;
this file is public tooling and contains no secrets.

Two rules are enforced structurally, not by convention:
  * relay entries cannot be signed (argparse won't accept the type, and
    sign_entry() raises if one ever reaches it)
  * an image's SHA-256 can only be computed on re-encoded bytes — EXIF
    stripped and auto-oriented first. There is no code path that hashes the
    original file and no flag to skip the strip.

Canonical signing contract — byte-identical twin of canonicalize() in
waelsocial.js. waelsocial-v1: seven LF-joined lines. waelsocial-v2 (edit,
signed off 2026-07-19): eight lines, `edited:<ts>` after `ts:`; a post is
v2 iff it carries edited_at. ts stays the original publish time and both
timestamps are under the signature. Only text and tags are editable; the
pre-edit row (old signature included) is archived to entries_revisions in
the same transaction. Any further change requires a version bump and
explicit sign-off.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTRACT = "waelsocial-v1"
CONTRACT_V2 = "waelsocial-v2"  # edited posts only; never used at first publish
SIGNABLE_TYPES = ("mine", "take")  # relay is deliberately absent
ID_PREFIX = {"mine": "m-", "take": "t-"}

KEY_PATH = Path(os.environ.get("WAELSOCIAL_KEY", "~/keys/waelsocial-signing.pem")).expanduser()
OUTBOX = Path(os.environ.get("WAELSOCIAL_OUTBOX", "~/waelsocial/outbox")).expanduser()
MEDIA_BASE = os.environ.get("WAELSOCIAL_MEDIA_BASE", "").rstrip("/")
QUEUE_PATH = Path(os.environ.get("WAELSOCIAL_QUEUE", "/srv/waelsocial/queue.json")).expanduser()
DSN = os.environ.get("WAELSOCIAL_DSN", "dbname=waelsocial")  # local socket, peer auth
RELAY_CAP_PER_WEEK = 2  # hard cap, no override: news must not drown authored work


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonicalize(entry: dict) -> bytes:
    """LF-joined lines, no trailing newline, UTF-8 bytes. v1 = 7 lines;
    v2 (iff the entry carries edited_at) = 8, `edited:` after `ts:`."""
    source = (entry.get("source") or {}).get("url") or ""
    media = (entry.get("media") or {}).get("sha256") or ""
    edited = entry.get("edited_at")
    lines = [CONTRACT_V2 if edited else CONTRACT,
             f"id:{entry['id']}",
             f"ts:{entry['ts']}"]
    if edited:
        lines.append(f"edited:{edited}")
    lines += [f"type:{entry['type']}",
              f"source:{source}",
              f"media:{media}",
              f"text:{entry['text']}"]
    return "\n".join(lines).encode("utf-8")


def load_key() -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    except FileNotFoundError:
        sys.exit(f"error: signing key not found at {KEY_PATH}")
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit(f"error: {KEY_PATH} is not an Ed25519 private key")
    return key


def pubkey_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def sign_entry(entry: dict, key: Ed25519PrivateKey) -> str:
    if entry["type"] not in SIGNABLE_TYPES:
        raise ValueError(
            f"refusing to sign type={entry['type']!r}: relays are unsigned by design")
    return base64.b64encode(key.sign(canonicalize(entry))).decode("ascii")


def process_image(path: Path):
    """The only place a media hash can come from.

    Open -> physically rotate pixels per the EXIF orientation flag ->
    re-encode into a fresh buffer carrying no metadata -> SHA-256 the clean
    bytes. Finishes with a self-check that the re-encoded image really has
    no EXIF; aborts rather than sign a dirty hash.
    """
    from PIL import Image, ImageOps

    with Image.open(path) as im:
        fmt = (im.format or "PNG").upper()
        if fmt not in ("JPEG", "PNG", "WEBP"):
            fmt = "PNG"
        im = ImageOps.exif_transpose(im)
        if fmt == "JPEG" and im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        im.info.clear()  # nothing from the source may ride along into save()
        buf = io.BytesIO()
        save_args = {"quality": 92, "optimize": True} if fmt == "JPEG" else {}
        im.save(buf, format=fmt, exif=b"", **save_args)

    clean = buf.getvalue()
    with Image.open(io.BytesIO(clean)) as check:
        if dict(check.getexif()):
            sys.exit("error: re-encoded image still carries EXIF — refusing to hash")

    digest = hashlib.sha256(clean).hexdigest()
    ext = ".jpg" if fmt == "JPEG" else "." + fmt.lower()
    return clean, digest, f"{digest[:16]}{ext}"


def db_conn():
    conn = psycopg2.connect(DSN)
    conn.set_client_encoding("UTF8")  # never trust the ambient locale with signed bytes
    return conn


def check_pubkey(cur, key: Ed25519PrivateKey) -> None:
    cur.execute("SELECT pubkey FROM feed_meta")
    row = cur.fetchone()
    if row is None:
        sys.exit("error: feed_meta is empty — run migrate-feed first")
    if row[0] != pubkey_b64(key):
        sys.exit("error: DB pubkey does not match the signing key — refusing to mix keys")


def entry_exists(cur, entry_id: str) -> bool:
    cur.execute("SELECT 1 FROM entries WHERE id = %s", (entry_id,))
    return cur.fetchone() is not None


def insert_entry(cur, e: dict, upsert: bool = False) -> None:
    src = e.get("source") or {}
    med = e.get("media") or {}
    conflict = ("""ON CONFLICT (id) DO UPDATE SET ts=EXCLUDED.ts, ts_at=EXCLUDED.ts_at,
                   type=EXCLUDED.type, text=EXCLUDED.text, tags=EXCLUDED.tags,
                   source_title=EXCLUDED.source_title, source_url=EXCLUDED.source_url,
                   media_url=EXCLUDED.media_url, media_sha256=EXCLUDED.media_sha256,
                   media_alt=EXCLUDED.media_alt, sig=EXCLUDED.sig,
                   edited_at=EXCLUDED.edited_at"""
                if upsert else "")
    cur.execute(
        f"""INSERT INTO entries (id, ts, ts_at, type, text, tags, source_title,
                source_url, media_url, media_sha256, media_alt, sig, edited_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) {conflict}""",
        (e["id"], e["ts"], datetime.fromisoformat(e["ts"]), e["type"], e["text"],
         e.get("tags", []), src.get("title"), src.get("url"), med.get("url"),
         med.get("sha256"), med.get("alt"), e.get("sig"), e.get("edited_at")))


def next_id(cur, type_: str) -> str:
    prefix = ID_PREFIX[type_]
    cur.execute("SELECT id FROM entries WHERE id LIKE %s", (prefix + "%",))
    nums = [int(r[0][len(prefix):]) for r in cur.fetchall()
            if r[0][len(prefix):].isdigit()]
    return f"{prefix}{max(nums, default=0) + 1:04d}"


def visible_canonical(canon: bytes) -> str:
    """Render the canonical string with LFs made visible for --dry-run."""
    return canon.decode("utf-8").replace("\n", "\\n\n") + "␄"  # ␄ marks true end


def read_text(args) -> str:
    if args.text is not None:
        text = args.text
    elif args.text_file:
        text = args.text_file.read_text(encoding="utf-8").rstrip("\n")
    else:
        print("reading post text from stdin (^D to finish)…", file=sys.stderr)
        text = sys.stdin.read().rstrip("\n")
    if not text.strip():
        sys.exit("error: empty post text")
    return text


def build_entry(args, key: Ed25519PrivateKey, cur) -> tuple[dict, bytes | None, str | None]:
    text = read_text(args)

    entry = {
        "id": args.id_override or next_id(cur, args.type),
        "ts": args.ts_override or now_ts(),
        "type": args.type,
        "text": text,
        "tags": [t.strip() for t in (args.tags or "").split(",") if t.strip()],
    }

    if args.type == "take" and not args.source_url:
        sys.exit("error: a take needs --source-url (the signature covers your text + the source URL)")
    if args.source_url:
        entry["source"] = {"title": args.source_title or args.source_url,
                           "url": args.source_url}

    clean_bytes = out_name = None
    if args.image:
        if not (args.alt or "").strip():
            sys.exit("error: --image requires a descriptive --alt")
        clean_bytes, digest, out_name = process_image(args.image)
        entry["media"] = {
            "url": f"{MEDIA_BASE}/{out_name}" if MEDIA_BASE else out_name,
            "sha256": digest,
            "alt": args.alt,
        }

    entry["sig"] = sign_entry(entry, key)
    return entry, clean_bytes, out_name


def load_queue() -> dict:
    if not QUEUE_PATH.exists():
        return {"candidates": [], "seen": []}
    return json.loads(QUEUE_PATH.read_text(encoding="utf-8"))


def save_queue(q: dict) -> None:
    tmp = QUEUE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(q, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(QUEUE_PATH)
    try:
        os.chmod(QUEUE_PATH, 0o660)
    except OSError:
        pass


def take_candidate(cve: str) -> tuple[dict, dict]:
    q = load_queue()
    cand = next((c for c in q["candidates"] if c["cve"].upper() == cve.upper()), None)
    if cand is None:
        sys.exit(f"error: {cve} is not in the candidate queue (see `queue list`)")
    return q, cand


def retire_candidate(q: dict, cand: dict) -> None:
    q["candidates"].remove(cand)
    if cand["cve"] not in q["seen"]:
        q["seen"].append(cand["cve"])
    save_queue(q)


def cmd_publish_relay(cve: str, dry_run: bool) -> None:
    """Publish an UNSIGNED relay from a queue candidate.

    This path never loads the signing key and never calls sign_entry():
    relays are other people's advisories and must not carry my signature.
    Text comes from the queue candidate (US-gov public-domain summary) —
    there is deliberately no way to freehand relay text.
    """
    q, cand = take_candidate(cve)
    conn = db_conn()  # DB access, yes — key access, never, in this path
    cur = conn.cursor()

    entry_id = f"r-{cand['cve'].upper()}"
    if entry_exists(cur, entry_id):
        sys.exit(f"error: {entry_id} already in feed")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur.execute("SELECT id FROM entries WHERE type = 'relay' AND ts >= %s", (cutoff,))
    recent = [r[0] for r in cur.fetchall()]
    if len(recent) >= RELAY_CAP_PER_WEEK:
        sys.exit(f"relay cap reached: {len(recent)}/{RELAY_CAP_PER_WEEK} unsigned relays "
                 f"in the last 7 days ({', '.join(recent)}).\n"
                 f"Write a take instead — that's the point of the cap.")

    entry = {
        "id": entry_id,
        "ts": now_ts(),
        "type": "relay",
        "text": cand["summary"],
        "tags": ["cve", cand["source"]],
        "source": {"title": cand["title"], "url": cand["url"]},
    }
    if dry_run:
        print("UNSIGNED relay (not written):")
        print(json.dumps(entry, ensure_ascii=False, indent=2))
        return
    insert_entry(cur, entry)
    conn.commit()
    retire_candidate(q, cand)
    print(f"published UNSIGNED relay {entry_id} -> postgres:waelsocial")
    print(f"relay budget: {len(recent) + 1}/{RELAY_CAP_PER_WEEK} used this week")


EDIT_COLS = ("id", "ts", "ts_at", "type", "text", "tags", "source_title",
             "source_url", "media_url", "media_sha256", "media_alt", "sig",
             "edited_at")


def cmd_edit(args, key: Ed25519PrivateKey) -> None:
    """Edit text/tags of an existing signed post -> waelsocial-v2.

    Everything else is frozen: id, ts (the original publish time), type,
    source, media — argv flags that would change them are rejected. The
    pre-edit row, old signature included, is archived into entries_revisions
    in the same transaction that updates the entry, so an edit can never
    silently rewrite history. Relays cannot be edited: they are unsigned by
    design and there would be nothing honest to re-sign.
    """
    for flag, name in ((args.type, "--type"), (args.source_url, "--source-url"),
                       (args.source_title, "--source-title"), (args.image, "--image"),
                       (args.alt, "--alt"), (args.id_override, "--id"),
                       (args.ts_override, "--ts")):
        if flag:
            sys.exit(f"error: {name} is not allowed with --edit — only text and tags are editable")

    conn = db_conn()
    cur = conn.cursor()
    check_pubkey(cur, key)
    cur.execute(f"SELECT {', '.join(EDIT_COLS)} FROM entries WHERE id = %s", (args.edit,))
    row = cur.fetchone()
    if row is None:
        sys.exit(f"error: {args.edit} is not in the feed")
    old = dict(zip(EDIT_COLS, row))
    if old["type"] not in SIGNABLE_TYPES:
        sys.exit(f"error: {old['id']} is a {old['type']} — relays are unsigned and cannot be edited")

    entry = {
        "id": old["id"],
        "ts": old["ts"],
        "type": old["type"],
        "text": read_text(args),
        "tags": ([t.strip() for t in args.tags.split(",") if t.strip()]
                 if args.tags is not None else old["tags"]),
        "edited_at": now_ts(),
    }
    if old["source_url"]:
        entry["source"] = {"title": old["source_title"] or old["source_url"],
                           "url": old["source_url"]}
    if old["media_sha256"]:
        entry["media"] = {"url": old["media_url"], "sha256": old["media_sha256"],
                          "alt": old["media_alt"]}
    entry["sig"] = sign_entry(entry, key)
    canon = canonicalize(entry)

    if args.emit_canonical:
        args.emit_canonical.write_bytes(canon)
        print(f"canonical bytes -> {args.emit_canonical} ({len(canon)} bytes)")

    if args.dry_run:
        print("canonical string (LF shown as \\n, ␄ = end, no trailing newline):")
        print(visible_canonical(canon))
        print("entry JSON (not written):")
        print(json.dumps(entry, ensure_ascii=False, indent=2))
        return

    cur.execute(
        f"""INSERT INTO entries_revisions ({', '.join(EDIT_COLS)}, reason)
            SELECT {', '.join(EDIT_COLS)}, %s FROM entries WHERE id = %s""",
        ("edit", old["id"]))
    cur.execute(
        "UPDATE entries SET text = %s, tags = %s, edited_at = %s, sig = %s WHERE id = %s",
        (entry["text"], entry["tags"], entry["edited_at"], entry["sig"], old["id"]))
    conn.commit()
    print(f"edited {old['id']} -> {CONTRACT_V2} (edited:{entry['edited_at']})")
    print("pre-edit row archived to entries_revisions (old signature kept)")


def cmd_resign(path: Path, key: Ed25519PrivateKey) -> None:
    """Migration helper: (re-)sign entries from a JSON file into the feed.

    Accepts a JSON array of entries or a full feed object. Existing sigs are
    discarded; mine/take get fresh signatures from the current key, relays
    stay unsigned. Entries replace same-id entries already in the feed.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data["entries"] if isinstance(data, dict) else data
    conn = db_conn()
    cur = conn.cursor()
    check_pubkey(cur, key)
    for e in entries:
        e.pop("sig", None)
        if e["type"] in SIGNABLE_TYPES:
            e["sig"] = sign_entry(e, key)
            state = "signed"
        else:
            state = "unsigned (relay)"
        insert_entry(cur, e, upsert=True)
        print(f"  {e['id']}: {state}")
    conn.commit()
    cur.execute("SELECT count(*) FROM entries")
    print(f"wrote postgres:waelsocial ({cur.fetchone()[0]} entries total)")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="sign-post",
        description="Author and sign a waelsocial-v1 feed entry.")
    p.add_argument("--type", choices=SIGNABLE_TYPES,
                   help="entry type (relays are unsigned by design and not accepted)")
    p.add_argument("--text", help="post text (or use --text-file / stdin)")
    p.add_argument("--text-file", type=Path)
    p.add_argument("--tags", default=None,
                   help="comma-separated tags (with --edit: omit to keep, empty to clear)")
    p.add_argument("--source-title")
    p.add_argument("--source-url", help="required for takes; covered by the signature")
    p.add_argument("--image", type=Path, help="attach an image (EXIF strip is mandatory and automatic)")
    p.add_argument("--alt", help="alt text, required with --image")
    p.add_argument("--id", dest="id_override", help="override id (migrations/testing)")
    p.add_argument("--ts", dest="ts_override", help="override ISO-8601Z timestamp (migrations/testing)")
    p.add_argument("--dry-run", action="store_true",
                   help="print canonical string + entry JSON; write nothing")
    p.add_argument("--emit-canonical", type=Path,
                   help="also write the exact canonical bytes to a file (for hexdump checks)")
    p.add_argument("--show-pubkey", action="store_true",
                   help="print the raw-32-byte base64 public key and exit")
    p.add_argument("--resign", type=Path, metavar="ENTRIES_JSON",
                   help="(re-)sign entries from a JSON file into the feed")
    p.add_argument("--edit", metavar="ENTRY-ID",
                   help="edit text/tags of an existing signed post "
                        "(re-signed as waelsocial-v2; pre-edit row archived)")
    p.add_argument("--take-from", metavar="CVE-ID",
                   help="signed take about a queue candidate (source prefilled, candidate retired)")
    p.add_argument("--publish-relay", metavar="CVE-ID",
                   help="publish a queue candidate as an UNSIGNED relay (capped, never signed)")
    args = p.parse_args()

    if args.publish_relay:  # before load_key(): this path must never touch the key
        cmd_publish_relay(args.publish_relay, args.dry_run)
        return

    key = load_key()

    if args.show_pubkey:
        print(pubkey_b64(key))
        return
    if args.edit:
        if args.resign or args.take_from:
            p.error("--edit cannot be combined with --resign/--take-from")
        cmd_edit(args, key)
        return
    if args.resign:
        cmd_resign(args.resign, key)
        return

    queue = cand = None
    if args.take_from:
        if args.type not in (None, "take"):
            p.error("--take-from implies --type take")
        args.type = "take"
        queue, cand = take_candidate(args.take_from)
        if not args.source_url:
            args.source_url = cand["url"]
            args.source_title = args.source_title or cand["title"]
        if not args.tags:
            args.tags = f"cve,{cand['source']}"
    if not args.type:
        p.error("--type is required (mine|take)")

    conn = db_conn()
    cur = conn.cursor()
    check_pubkey(cur, key)
    entry, clean_bytes, out_name = build_entry(args, key, cur)
    canon = canonicalize(entry)

    if args.emit_canonical:
        args.emit_canonical.write_bytes(canon)
        print(f"canonical bytes -> {args.emit_canonical} ({len(canon)} bytes)")

    if args.dry_run:
        print("canonical string (LF shown as \\n, ␄ = end, no trailing newline):")
        print(visible_canonical(canon))
        print("entry JSON (not written):")
        print(json.dumps(entry, ensure_ascii=False, indent=2))
        return

    if entry_exists(cur, entry["id"]):
        sys.exit(f"error: id {entry['id']} already exists in feed")
    if clean_bytes:
        OUTBOX.mkdir(parents=True, exist_ok=True)
        (OUTBOX / out_name).write_bytes(clean_bytes)
        print(f"stripped image -> {OUTBOX / out_name}")
    insert_entry(cur, entry)
    conn.commit()
    if cand is not None:
        retire_candidate(queue, cand)
        print(f"retired {cand['cve']} from the candidate queue")
    print(f"signed {entry['id']} -> postgres:waelsocial")


if __name__ == "__main__":
    main()
