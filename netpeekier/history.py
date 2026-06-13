"""Rolling activity log.

The monitor feeds per-process byte deltas here each tick. To keep the file
compact, samples are aggregated in memory and flushed once per interval (default
30s): one JSON line per executable that moved data in that window, plus a
process "seen" record so we can report how long each app ran.

Format (one JSON object per line, append-only) in ``log/history.jsonl``:
  {"t": <epoch>, "exe": "...", "name": "...", "up": <bytes>, "down": <bytes>,
   "secs": <seconds the window covered>}

This is intentionally simple and dependency-free so it can't fail the monitor.
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, Tuple


class HistoryLogger:
    def __init__(self, path: str, interval: float = 30.0) -> None:
        self.path = path
        self.interval = interval
        self._bucket: Dict[str, Dict] = {}     # exe -> aggregate for window
        self._window_start = time.time()
        self._last_flush = time.time()

    def record(self, exe: str, name: str, up_bytes: float,
               down_bytes: float) -> None:
        """Add this tick's per-exe byte deltas to the current window."""
        if not exe or (up_bytes <= 0 and down_bytes <= 0):
            return
        b = self._bucket.get(exe)
        if b is None:
            b = self._bucket[exe] = {"name": name, "up": 0.0, "down": 0.0}
        b["up"] += max(0.0, up_bytes)
        b["down"] += max(0.0, down_bytes)

    def maybe_flush(self) -> None:
        now = time.time()
        if now - self._last_flush < self.interval:
            return
        self.flush(now)

    def flush(self, now: float | None = None) -> None:
        now = now or time.time()
        secs = max(1.0, now - self._window_start)
        if self._bucket:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    for exe, b in self._bucket.items():
                        fh.write(json.dumps({
                            "t": round(now, 1),
                            "exe": exe,
                            "name": b["name"],
                            "up": int(b["up"]),
                            "down": int(b["down"]),
                            "secs": round(secs, 1),
                        }) + "\n")
            except Exception:
                pass
        self._bucket.clear()
        self._window_start = now
        self._last_flush = now
        self._maybe_rotate()

    # Roll the log over once it passes this size, keeping one backup. Caps total
    # on-disk history at ~2x this without any time-based pruning dependency.
    _MAX_BYTES = 5 * 1024 * 1024

    def _maybe_rotate(self) -> None:
        try:
            if os.path.getsize(self.path) < self._MAX_BYTES:
                return
        except OSError:
            return
        try:
            bak = self.path + ".1"
            if os.path.exists(bak):
                os.remove(bak)
            os.replace(self.path, bak)   # current -> .1, fresh file starts next
        except Exception:
            pass


def load_history(path: str, since: float | None = None) -> list[dict]:
    """Read all sample records (optionally only those at/after `since` epoch).

    Also reads the rotated backup (``<path>.1``) so history isn't lost from the
    stats view after the live file rolls over. Backup is read first (older)."""
    out: list[dict] = []
    for p in (path + ".1", path):       # backup first => chronological-ish order
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if since is not None and rec.get("t", 0) < since:
                        continue
                    out.append(rec)
        except Exception:
            pass
    return out


def aggregate(records: list[dict]) -> dict:
    """Roll records up into the summaries the stats window draws.

    Returns a dict with:
      per_exe:   {exe: {"name","up","down","total","secs","first","last"}}
      per_hour:  {0..23: {"up","down"}}     (by hour of day, local time)
      timeline:  [(t_bucket_epoch, up, down)] sorted, ~per flush window
      totals:    {"up","down","total"}
    """
    per_exe: Dict[str, dict] = {}
    per_hour: Dict[int, dict] = {h: {"up": 0, "down": 0} for h in range(24)}
    timeline_map: Dict[int, Tuple[int, int]] = {}
    tot_up = tot_down = 0

    for r in records:
        exe = r.get("exe", "")
        up = int(r.get("up", 0))
        down = int(r.get("down", 0))
        t = float(r.get("t", 0))
        secs = float(r.get("secs", 0))
        tot_up += up
        tot_down += down

        e = per_exe.get(exe)
        if e is None:
            e = per_exe[exe] = {"name": r.get("name", exe), "up": 0, "down": 0,
                                "total": 0, "secs": 0.0,
                                "first": t, "last": t}
        e["up"] += up
        e["down"] += down
        e["total"] += up + down
        e["secs"] += secs
        e["first"] = min(e["first"], t) if e["first"] else t
        e["last"] = max(e["last"], t)

        hr = time.localtime(t).tm_hour
        per_hour[hr]["up"] += up
        per_hour[hr]["down"] += down

        # 1-minute timeline buckets
        bucket = int(t // 60 * 60)
        cu, cd = timeline_map.get(bucket, (0, 0))
        timeline_map[bucket] = (cu + up, cd + down)

    timeline = sorted((b, u, d) for b, (u, d) in timeline_map.items())
    return {
        "per_exe": per_exe,
        "per_hour": per_hour,
        "timeline": timeline,
        "totals": {"up": tot_up, "down": tot_down, "total": tot_up + tot_down},
    }
