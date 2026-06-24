import json
import os
import secrets
import time

SECURITY_DIR_NAME = ".p2p_security"
SESSION_CACHE_FILE = "session_cache.json"
SESSION_FRESHNESS_WINDOW_SECONDS = 15 * 60
SESSION_COMPLETED_RETENTION_SECONDS = 24 * 60 * 60


def generate_session_id():
    return secrets.token_hex(16)


def current_timestamp():
    return int(time.time())


def security_directory(base_dir):
    path = os.path.join(base_dir, SECURITY_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def cache_path(base_dir):
    return os.path.join(security_directory(base_dir), SESSION_CACHE_FILE)


def load_session_cache(base_dir):
    path = cache_path(base_dir)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_session_cache(base_dir, cache):
    path = cache_path(base_dir)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2, sort_keys=True)


def session_fingerprint(metadata):
    return "|".join(
        [
            metadata["transfer_id"],
            metadata["filename"],
            str(metadata["file_size"]),
            str(metadata["chunk_size"]),
            str(metadata["total_chunks"]),
        ]
    )


def is_timestamp_fresh(
    session_started_at, now=None, window_seconds=SESSION_FRESHNESS_WINDOW_SECONDS
):
    now = current_timestamp() if now is None else now
    return abs(now - session_started_at) <= window_seconds


def register_or_reject_session(base_dir, metadata):
    """Return (allowed, reason, cache, record)."""
    cache = load_session_cache(base_dir)
    now = current_timestamp()
    session_id = metadata["session_id"]
    started_at = metadata["session_started_at"]
    fingerprint = session_fingerprint(metadata)

    expired_sessions = []
    for cached_session_id, record in cache.items():
        completed_at = record.get("completed_at")
        if completed_at and (now - completed_at) > SESSION_COMPLETED_RETENTION_SECONDS:
            expired_sessions.append(cached_session_id)

    for cached_session_id in expired_sessions:
        cache.pop(cached_session_id, None)

    if not is_timestamp_fresh(started_at, now=now):
        return False, "stale session timestamp", cache, None

    record = cache.get(session_id)
    if record is None:
        record = {
            "session_id": session_id,
            "fingerprint": fingerprint,
            "status": "active",
            "started_at": started_at,
            "last_seen_at": now,
            "completed_at": None,
        }
        cache[session_id] = record
        save_session_cache(base_dir, cache)
        return True, None, cache, record

    if record.get("fingerprint") != fingerprint:
        return False, "duplicate session id for different transfer", cache, record

    if record.get("status") == "completed":
        return False, "replayed completed session", cache, record

    record["last_seen_at"] = now
    save_session_cache(base_dir, cache)
    return True, None, cache, record


def mark_session_completed(base_dir, metadata):
    cache = load_session_cache(base_dir)
    session_id = metadata["session_id"]
    record = cache.get(session_id)
    if record is None:
        record = {
            "session_id": session_id,
            "fingerprint": session_fingerprint(metadata),
            "status": "completed",
            "started_at": metadata["session_started_at"],
            "last_seen_at": current_timestamp(),
            "completed_at": current_timestamp(),
        }
        cache[session_id] = record
    else:
        record["status"] = "completed"
        record["completed_at"] = current_timestamp()
        record["last_seen_at"] = record["completed_at"]
    save_session_cache(base_dir, cache)


def is_replayed_session(base_dir, metadata):
    cache = load_session_cache(base_dir)
    record = cache.get(metadata["session_id"])
    if record is None:
        return False
    return record.get("status") == "completed"
