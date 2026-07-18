#!/usr/bin/env python3
"""queue — inspect and work the waelsocial candidate queue from a shell.

Read/discard only. Publishing always goes through sign-post:
  sign-post --take-from CVE-2026-XXXX --text "my commentary"   (signed take)
  sign-post --publish-relay CVE-2026-XXXX                      (unsigned relay)
"""

import json
import os
import sys
from pathlib import Path

BASE = Path(os.environ.get("WAELSOCIAL_DATA", "/srv/waelsocial"))
QUEUE_PATH = BASE / "queue.json"
LOG_PATH = BASE / "ingest.log"


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


def cmd_list() -> None:
    q = load_queue()
    if not q["candidates"]:
        print("queue is empty")
        return
    for c in q["candidates"]:
        sev = str(c.get("severity", "?"))
        print(f"{c['cve']:<18} {sev:>5} {c['source']:<4} {c['date']}  {c['summary'][:72]}")
    print(f"-- {len(q['candidates'])} candidate(s)")


def find(q: dict, cve: str) -> dict | None:
    return next((c for c in q["candidates"] if c["cve"].upper() == cve.upper()), None)


def cmd_show(cve: str) -> None:
    c = find(load_queue(), cve)
    if not c:
        sys.exit(f"{cve} is not in the queue")
    print(json.dumps(c, ensure_ascii=False, indent=2))


def cmd_discard(cve: str) -> None:
    q = load_queue()
    c = find(q, cve)
    if not c:
        sys.exit(f"{cve} is not in the queue")
    q["candidates"].remove(c)
    if c["cve"] not in q["seen"]:
        q["seen"].append(c["cve"])  # discard is permanent across re-runs
    save_queue(q)
    print(f"discarded {c['cve']} (will not be re-queued)")


def cmd_log(n: str = "40") -> None:
    if not LOG_PATH.exists():
        print("no ingest log yet")
        return
    lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
    print("\n".join(lines[-int(n):]))


def main() -> None:
    args = sys.argv[1:]
    cmd = args[0] if args else "list"
    if cmd == "list":
        cmd_list()
    elif cmd == "show" and len(args) == 2:
        cmd_show(args[1])
    elif cmd == "discard" and len(args) == 2:
        cmd_discard(args[1])
    elif cmd == "log":
        cmd_log(args[1] if len(args) > 1 else "40")
    else:
        sys.exit(__doc__ + "\nusage: queue [list | show CVE | discard CVE | log [N]]")


if __name__ == "__main__":
    main()
