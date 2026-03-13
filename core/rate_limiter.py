import time
import threading
from collections import defaultdict

# ── Config ────────────────────────────────────────────────────────────────────
COOLDOWN_SECONDS  = 10   # minimum seconds between scans for the same user
MAX_SCANS_PER_MIN = 6    # maximum scans per 60-second rolling window
CLEANUP_INTERVAL  = 300  # prune stale entries every 5 minutes

# ── Thread-safe state ─────────────────────────────────────────────────────────
# FIX: a single lock guards ALL reads and writes to shared state,
# eliminating the TOCTOU race condition where two threads could both
# pass the check before either recorded their timestamp.
_lock            = threading.Lock()
_last_scan_time  = defaultdict(float)
_scan_timestamps = defaultdict(list)
_last_cleanup    = time.time()


def _cleanup_stale_entries(now: float) -> None:
    """
    Remove entries for users who haven't scanned in over a minute.
    Called periodically inside the lock — no separate thread needed.
    FIX: prevents _last_scan_time growing forever in long-running deployments.
    """
    global _last_cleanup
    if now - _last_cleanup < CLEANUP_INTERVAL:
        return

    stale = [
        uid for uid, ts in _last_scan_time.items()
        if now - ts > 60
    ]
    for uid in stale:
        del _last_scan_time[uid]
        _scan_timestamps.pop(uid, None)

    _last_cleanup = now


def check_rate_limit(user_id: str = "default") -> tuple[bool, str]:
    """
    Thread-safe rate limit check.

    Returns (allowed: bool, message: str).

    Note
    ----
    All callers should pass a meaningful user_id (e.g. a session hash from
    Gradio's gr.Request) so limits are per-user rather than global.
    Passing no argument falls back to a shared "default" bucket, meaning
    one user's scans count against everyone.
    """
    now = time.time()

    # FIX: entire check-and-record is atomic under the lock
    with _lock:

        # ── Periodic cleanup inside lock (cheap, infrequent) ─────────────────
        _cleanup_stale_entries(now)

        # ── 1. Cooldown check ─────────────────────────────────────────────────
        elapsed = now - _last_scan_time[user_id]
        if elapsed < COOLDOWN_SECONDS:
            wait = round(COOLDOWN_SECONDS - elapsed, 1)
            return False, f"⏳ Please wait {wait}s before scanning again."

        # ── 2. Per-minute rolling window check ───────────────────────────────
        _scan_timestamps[user_id] = [
            t for t in _scan_timestamps[user_id] if now - t < 60
        ]
        if len(_scan_timestamps[user_id]) >= MAX_SCANS_PER_MIN:
            return False, (
                f"❌ Too many scans. "
                f"Maximum is {MAX_SCANS_PER_MIN} per minute."
            )

        # ── 3. Allow — record atomically ─────────────────────────────────────
        _last_scan_time[user_id] = now
        _scan_timestamps[user_id].append(now)
        return True, "OK"