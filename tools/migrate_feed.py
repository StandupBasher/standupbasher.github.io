#!/usr/bin/env python3
"""One-time migration: feed.json -> Postgres, with byte-identical verification.

Acceptance criterion (Ch.6): for every entry, the canonical waelsocial-v1
string rebuilt FROM THE DATABASE must equal, byte for byte, the canonical
string built from the frozen feed.json — and every signature must verify
against the real pubkey. Any mismatch = abort loudly, change nothing else.

feed.json is not modified, moved, or deleted. It is the immutable backup.

Run on CT 102 as `claude` (peer auth -> writer role):  migrate-feed [--verify-only]
"""

import base64
import json
import sys
from datetime import datetime
from pathlib import Path

import psycopg2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

FEED_PATH = Path("/srv/waelsocial/feed.json")
DSN = "dbname=waelsocial"  # local socket, peer auth: OS user == DB role


def canonicalize(e: dict) -> bytes:
    """Must stay byte-identical to sign-post and waelsocial.js."""
    source = (e.get("source") or {}).get("url") or ""
    media = (e.get("media") or {}).get("sha256") or ""
    return "\n".join([
        "waelsocial-v1",
        f"id:{e['id']}",
        f"ts:{e['ts']}",
        f"type:{e['type']}",
        f"source:{source}",
        f"media:{media}",
        f"text:{e['text']}",
    ]).encode("utf-8")


def row_to_entry(row: dict) -> dict:
    """Rebuild the JSON entry shape from a DB row — the exact inverse of
    migration. ts comes from the TEXT column only; ts_at is never used here."""
    e = {"id": row["id"], "ts": row["ts"], "type": row["type"],
         "text": row["text"], "tags": row["tags"]}
    if row["source_url"] is not None:
        e["source"] = {"title": row["source_title"], "url": row["source_url"]}
    if row["media_sha256"] is not None:
        e["media"] = {"url": row["media_url"], "sha256": row["media_sha256"],
                      "alt": row["media_alt"]}
    if row["sig"] is not None:
        e["sig"] = row["sig"]
    return e


def main() -> None:
    verify_only = "--verify-only" in sys.argv
    feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    conn = psycopg2.connect(DSN)
    conn.set_client_encoding("UTF8")  # never trust the ambient locale with signed bytes
    cur = conn.cursor()

    if not verify_only:
        cur.execute("INSERT INTO feed_meta (v, alg, pubkey) VALUES (%s, %s, %s) "
                    "ON CONFLICT (only_row) DO UPDATE SET v=EXCLUDED.v, "
                    "alg=EXCLUDED.alg, pubkey=EXCLUDED.pubkey",
                    (feed["v"], feed["alg"], feed["pubkey"]))
        for e in feed["entries"]:
            src, med = e.get("source") or {}, e.get("media") or {}
            cur.execute(
                """INSERT INTO entries (id, ts, ts_at, type, text, tags,
                       source_title, source_url, media_url, media_sha256,
                       media_alt, sig)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (id) DO NOTHING""",
                (e["id"], e["ts"], datetime.fromisoformat(e["ts"]), e["type"],
                 e["text"], e.get("tags", []), src.get("title"), src.get("url"),
                 med.get("url"), med.get("sha256"), med.get("alt"), e.get("sig")))
        conn.commit()
        print(f"migrated: {len(feed['entries'])} entries offered to DB")

    # --- verification: DB -> canonical bytes must equal JSON -> canonical bytes
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(feed["pubkey"]))
    cur.execute("""SELECT id, ts, type, text, tags, source_title, source_url,
                          media_url, media_sha256, media_alt, sig
                   FROM entries ORDER BY ts DESC""")
    cols = [d[0] for d in cur.description]
    db_entries = {r[0]: row_to_entry(dict(zip(cols, r))) for r in cur.fetchall()}

    failed = 0
    for e in feed["entries"]:
        db_e = db_entries.get(e["id"])
        if db_e is None:
            print(f"FAIL  {e['id']}: missing from DB")
            failed += 1
            continue
        want, got = canonicalize(e), canonicalize(db_e)
        if want != got:
            print(f"FAIL  {e['id']}: canonical bytes differ\n  json: {want!r}\n  db:   {got!r}")
            failed += 1
            continue
        if e.get("sig"):
            try:
                pub.verify(base64.b64decode(db_e["sig"]), got)
                state = "sig VERIFIED against DB bytes"
            except InvalidSignature:
                print(f"FAIL  {e['id']}: signature does not verify from DB bytes")
                failed += 1
                continue
        else:
            state = "unsigned (relay) — no sig, as designed"
        print(f"PASS  {e['id']:<20} canonical byte-identical; {state}")

    if failed:
        sys.exit(f"\n{failed} FAILURE(S) — migration NOT accepted. feed.json untouched.")
    print(f"\nall {len(feed['entries'])} entries byte-identical and verified. "
          f"feed.json remains the immutable backup.")


if __name__ == "__main__":
    main()
