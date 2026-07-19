#!/usr/bin/env python3
"""feed-remove — archive-then-delete a waelsocial feed entry.

Runs on CT 102 as `claude`, the only DB writer. The console (wsdash) may
invoke it only through its sudoers line — argv arrays, never a shell — and
wsdash itself holds zero DB write grants.

Removal is never destruction: the full row (signature included) is copied
into `entries_removed` in the same transaction that deletes it from
`entries`. The archive is append-only *by grant* — the claude role has
INSERT+SELECT on entries_removed and no UPDATE/DELETE, so not even this
tool can un-archive or purge history. The frozen /srv/waelsocial/feed.json
backup is never touched.
"""

import argparse
import json
import os
import sys

import psycopg2

DSN = os.environ.get("WAELSOCIAL_DSN", "dbname=waelsocial")  # local socket, peer auth

COLS = ("id", "ts", "ts_at", "type", "text", "tags", "source_title",
        "source_url", "media_url", "media_sha256", "media_alt", "sig")


def db_conn():
    conn = psycopg2.connect(DSN)
    conn.set_client_encoding("UTF8")
    return conn


def fetch_entry(cur, entry_id: str) -> dict | None:
    cur.execute(f"SELECT {', '.join(COLS)} FROM entries WHERE id = %s", (entry_id,))
    row = cur.fetchone()
    return dict(zip(COLS, row)) if row else None


def cmd_list(cur) -> None:
    cur.execute("""SELECT id, type, ts, removed_at, reason
                   FROM entries_removed ORDER BY removed_at""")
    rows = cur.fetchall()
    if not rows:
        print("archive is empty — nothing has ever been removed")
        return
    for id_, type_, ts, removed_at, reason in rows:
        print(f"{removed_at:%Y-%m-%dT%H:%M:%SZ}  {id_:<18} {type_:<6} "
              f"(posted {ts})  {reason or ''}".rstrip())
    print(f"{len(rows)} archived removal(s)")


def cmd_remove(cur, entry_id: str, reason: str, dry_run: bool) -> bool:
    entry = fetch_entry(cur, entry_id)
    if entry is None:
        sys.exit(f"error: {entry_id} is not in the feed")

    if dry_run:
        printable = {**entry, "ts_at": entry["ts_at"].isoformat()}
        print("would archive to entries_removed, then delete (nothing written):")
        print(json.dumps(printable, ensure_ascii=False, indent=2))
        return False

    cur.execute(
        f"""INSERT INTO entries_removed ({', '.join(COLS)}, reason)
            SELECT {', '.join(COLS)}, %s FROM entries WHERE id = %s
            RETURNING removed_at""",
        (reason, entry_id))
    removed_at = cur.fetchone()[0]
    cur.execute("DELETE FROM entries WHERE id = %s", (entry_id,))
    if cur.rowcount != 1:
        sys.exit(f"error: delete touched {cur.rowcount} rows — rolled back")
    print(f"archived {entry_id} -> entries_removed at "
          f"{removed_at:%Y-%m-%dT%H:%M:%SZ}, deleted from entries")
    print("frozen /srv/waelsocial/feed.json backup untouched (by design)")
    return True


def main() -> None:
    p = argparse.ArgumentParser(
        prog="feed-remove",
        description="Archive a feed entry into entries_removed, then delete it.")
    p.add_argument("entry_id", nargs="?", help="feed entry id (e.g. m-0006)")
    p.add_argument("--reason", default="", help="short note stored with the archive row")
    p.add_argument("--dry-run", action="store_true",
                   help="print the row that would be archived; write nothing")
    p.add_argument("--list", action="store_true", dest="list_archive",
                   help="show the removal archive and exit")
    args = p.parse_args()

    conn = db_conn()
    try:
        cur = conn.cursor()
        if args.list_archive:
            cmd_list(cur)
            return
        if not args.entry_id:
            p.error("entry_id is required (or use --list)")
        if cmd_remove(cur, args.entry_id, args.reason, args.dry_run):
            conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
