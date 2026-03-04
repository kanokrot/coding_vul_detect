import time
from collections import defaultdict

# ── Config ─────────────────────────────────────────
COOLDOWN_SECONDS  = 10    # wait between scans
MAX_SCANS_PER_MIN = 6     # max scans per minute

# ── State ──────────────────────────────────────────
last_scan_time  = defaultdict(float)
scan_timestamps = defaultdict(list)


def check_rate_limit(user_id: str = "default") -> tuple[bool, str]:
    """
    Returns (allowed: bool, message: str)
    """
    now = time.time()

    # ── 1. Cooldown check ─────────────────────────
    elapsed = now - last_scan_time[user_id]
    if elapsed < COOLDOWN_SECONDS:
        wait = round(COOLDOWN_SECONDS - elapsed, 1)
        return False, f"⏳ Please wait {wait}s before scanning again."

    # ── 2. Per-minute limit ───────────────────────
    scan_timestamps[user_id] = [
        t for t in scan_timestamps[user_id] if now - t < 60
    ]
    if len(scan_timestamps[user_id]) >= MAX_SCANS_PER_MIN:
        return False, f"❌ Too many scans. Maximum is {MAX_SCANS_PER_MIN} scans per minute."

    # ── 3. Allow — record timestamp ───────────────
    last_scan_time[user_id]  = now
    scan_timestamps[user_id].append(now)
    return True, "OK"