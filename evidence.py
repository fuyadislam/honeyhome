# The evidence log.
#
# Every event the honeypots see is written here, one JSON line per event.
# Each line includes the hash of the line before it, like links in a chain.
# If anyone edits or deletes an old line, every hash after it stops matching,
# so verify_chain() can prove the log hasn't been tampered with.
# This is the same idea as chain of custody in digital forensics.

import hashlib
import json
import os
import threading
from datetime import datetime, timezone

LOG_FILE = os.path.join(os.path.dirname(__file__), "data", "evidence.jsonl")
GENESIS = "0" * 64  # the "previous hash" of the very first record

_lock = threading.Lock()
_listeners = []  # functions to call when a new record is added


def _hash(record):
    # Hash every field except the hash itself, in a fixed key order
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _read_all():
    if not os.path.exists(LOG_FILE):
        return []
    records = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    records.append({"broken_line": line})
    return records


def add(event_type, src_ip, service, port, details=None):
    """Write one event to the evidence log and return the saved record."""
    with _lock:
        records = _read_all()
        prev = records[-1].get("hash", GENESIS) if records else GENESIS
        record = {
            "seq": len(records) + 1,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "type": event_type,
            "src_ip": src_ip,
            "service": service,
            "port": port,
            "details": details or {},
            "prev_hash": prev,
        }
        record["hash"] = _hash(record)

        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

    for listener in list(_listeners):
        try:
            listener(record)
        except Exception:
            pass
    return record


def on_new_record(func):
    _listeners.append(func)


def all_records():
    with _lock:
        return _read_all()


def records_after(seq):
    return [r for r in all_records() if r.get("seq", 0) > seq]


def verify_chain():
    """Check every link in the chain. Returns a short report."""
    records = all_records()
    prev = GENESIS
    for i, r in enumerate(records, start=1):
        if "broken_line" in r:
            return {"intact": False, "records": len(records), "problem_at": i,
                    "reason": "a line in the log is not valid JSON"}
        if r.get("seq") != i:
            return {"intact": False, "records": len(records), "problem_at": i,
                    "reason": "a record is missing or out of order"}
        if r.get("prev_hash") != prev:
            return {"intact": False, "records": len(records), "problem_at": i,
                    "reason": "the link to the previous record is broken"}
        if r.get("hash") != _hash(r):
            return {"intact": False, "records": len(records), "problem_at": i,
                    "reason": "the record was changed after it was written"}
        prev = r["hash"]
    return {"intact": True, "records": len(records), "last_hash": prev}
