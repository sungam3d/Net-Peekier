"""Small formatting helpers shared by the GUI."""
from __future__ import annotations


def human_speed(bps: float, unit: str = "auto") -> str:
    """Bytes/sec -> string. `unit` is one of auto/B/s/KB/s/MB/s.

    'auto' scales each value individually; a fixed unit always renders in that
    unit so a whole column reads consistently (e.g. everything in KB/s).
    """
    if unit == "B/s":
        return f"{bps:.0f} B/s"
    if unit == "KB/s":
        return f"{bps / 1024:.2f} KB/s"
    if unit == "MB/s":
        return f"{bps / (1024 * 1024):.2f} MB/s"
    # auto
    if bps < 1:
        return "0 B/s"
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{bps / (1024 * 1024):.2f} MB/s"


def unit_suffix(unit: str) -> str:
    """Header suffix for a fixed unit, e.g. ' (KB/s)'. Empty for auto."""
    return "" if unit == "auto" else f" ({unit})"


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} EB"


def ports_str(ports: list[int], limit: int = 6) -> str:
    if not ports:
        return ""
    shown = ", ".join(str(p) for p in ports[:limit])
    if len(ports) > limit:
        shown += ", ..."
    return shown
