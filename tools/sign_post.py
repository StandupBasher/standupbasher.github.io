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

Canonical signing contract (waelsocial-v1) — byte-identical twin of
canonicalize() in waelsocial.js. Any change requires a version bump and
explicit sign-off.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTRACT = "waelsocial-v1"
SIGNABLE_TYPES = ("mine", "take")  # relay is deliberately absent
ID_PREFIX = {"mine": "m-", "take": "t-"}

KEY_PATH = Path(os.environ.get("WAELSOCIAL_KEY", "~/keys/waelsocial-signing.pem")).expanduser()
FEED_PATH = Path(os.environ.get("WAELSOCIAL_FEED", "~/waelsocial/feed.json")).expanduser()
OUTBOX = Path(os.environ.get("WAELSOCIAL_OUTBOX", "~/waelsocial/outbox")).expanduser()
MEDIA_BASE = os.environ.get("WAELSOCIAL_MEDIA_BASE", "").rstrip("/")


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonicalize(entry: dict) -> bytes:
    """Seven lines joined with a single LF, no trailing newline, UTF-8 bytes."""
    source = (entry.get("source") or {}).get("url") or ""
    media = (entry.get("media") or {}).get("sha256") or ""
    return "\n".join([
        CONTRACT,
        f"id:{entry['id']}",
        f"ts:{entry['ts']}",
        f"type:{entry['type']}",
        f"source:{source}",
        f"media:{media}",
        f"text:{entry['text']}",
    ]).encode("utf-8")


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


def empty_feed(key: Ed25519PrivateKey) -> dict:
    return {"v": 1, "alg": "Ed25519", "pubkey": pubkey_b64(key),
            "generated": now_ts(), "entries": []}


def load_feed(key: Ed25519PrivateKey) -> dict:
    if not FEED_PATH.exists():
        return empty_feed(key)
    feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    if feed.get("pubkey") != pubkey_b64(key):
        sys.exit("error: feed pubkey does not match the signing key — refusing to mix keys")
    return feed


def save_feed(feed: dict) -> None:
    feed["generated"] = now_ts()
    feed["entries"].sort(key=lambda e: e["ts"], reverse=True)  # newest-first
    FEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = FEED_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(FEED_PATH)


def next_id(feed: dict, type_: str) -> str:
    prefix = ID_PREFIX[type_]
    nums = [int(e["id"][len(prefix):]) for e in feed["entries"]
            if e["id"].startswith(prefix) and e["id"][len(prefix):].isdigit()]
    return f"{prefix}{max(nums, default=0) + 1:04d}"


def visible_canonical(canon: bytes) -> str:
    """Render the canonical string with LFs made visible for --dry-run."""
    return canon.decode("utf-8").replace("\n", "\\n\n") + "␄"  # ␄ marks true end


def build_entry(args, key: Ed25519PrivateKey, feed: dict) -> tuple[dict, bytes | None, str | None]:
    if args.text is not None:
        text = args.text
    elif args.text_file:
        text = args.text_file.read_text(encoding="utf-8").rstrip("\n")
    else:
        print("reading post text from stdin (^D to finish)…", file=sys.stderr)
        text = sys.stdin.read().rstrip("\n")
    if not text.strip():
        sys.exit("error: empty post text")

    entry = {
        "id": args.id_override or next_id(feed, args.type),
        "ts": args.ts_override or now_ts(),
        "type": args.type,
        "text": text,
        "tags": [t.strip() for t in args.tags.split(",") if t.strip()],
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


def cmd_resign(path: Path, key: Ed25519PrivateKey) -> None:
    """Migration helper: (re-)sign entries from a JSON file into the feed.

    Accepts a JSON array of entries or a full feed object. Existing sigs are
    discarded; mine/take get fresh signatures from the current key, relays
    stay unsigned. Entries replace same-id entries already in the feed.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data["entries"] if isinstance(data, dict) else data
    feed = load_feed(key)
    by_id = {e["id"]: e for e in feed["entries"]}
    for e in entries:
        e.pop("sig", None)
        if e["type"] in SIGNABLE_TYPES:
            e["sig"] = sign_entry(e, key)
            state = "signed"
        else:
            state = "unsigned (relay)"
        by_id[e["id"]] = e
        print(f"  {e['id']}: {state}")
    feed["entries"] = list(by_id.values())
    save_feed(feed)
    print(f"wrote {FEED_PATH} ({len(feed['entries'])} entries)")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="sign-post",
        description="Author and sign a waelsocial-v1 feed entry.")
    p.add_argument("--type", choices=SIGNABLE_TYPES,
                   help="entry type (relays are unsigned by design and not accepted)")
    p.add_argument("--text", help="post text (or use --text-file / stdin)")
    p.add_argument("--text-file", type=Path)
    p.add_argument("--tags", default="", help="comma-separated tags")
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
    args = p.parse_args()

    key = load_key()

    if args.show_pubkey:
        print(pubkey_b64(key))
        return
    if args.resign:
        cmd_resign(args.resign, key)
        return
    if not args.type:
        p.error("--type is required (mine|take)")

    feed = load_feed(key)
    entry, clean_bytes, out_name = build_entry(args, key, feed)
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

    if any(e["id"] == entry["id"] for e in feed["entries"]):
        sys.exit(f"error: id {entry['id']} already exists in feed")
    if clean_bytes:
        OUTBOX.mkdir(parents=True, exist_ok=True)
        (OUTBOX / out_name).write_bytes(clean_bytes)
        print(f"stripped image -> {OUTBOX / out_name}")
    feed["entries"].insert(0, entry)
    save_feed(feed)
    print(f"signed {entry['id']} -> {FEED_PATH}")


if __name__ == "__main__":
    main()
