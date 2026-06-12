"""Small formatting helpers shared by the GUI."""
from __future__ import annotations


def human_speed(bps: float) -> str:
    """Bytes/sec -> compact string like NetPeeker's '51.60 K/s'."""
    if bps < 1:
        return "0/s"
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.2f} K/s"
    return f"{bps / (1024 * 1024):.2f} M/s"


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"


def ports_str(ports: list[int], limit: int = 6) -> str:
    if not ports:
        return ""
    shown = ", ".join(str(p) for p in ports[:limit])
    if len(ports) > limit:
        shown += ", ..."
    return shown
