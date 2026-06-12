"""All persisted program state, kept inside the program folder.

Everything Net-Peekier writes lives under the program root (the folder that
contains run.py):
    <root>/settings.txt   - this file (JSON text): options, firewall blocks,
                            per-process limits, tags, and tag limits
    <root>/log/           - exported packet logs

The one thing that CANNOT live here is the actual firewall block: those are
Windows Firewall rules created via netsh and stored by the OS, not by us. We
remember which apps we blocked (so the UI and limits stay in sync), but the
enforcing rule itself is owned by Windows. The WinDivert driver is likewise a
system component. Nothing else is written outside the program folder.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SPEED_UNITS = ("auto", "B/s", "KB/s", "MB/s")

# All filesystem locations live in paths.py (single source of truth).
from .paths import ROOT as PROGRAM_ROOT, SETTINGS_FILE as SETTINGS_PATH, \
    LOG_DIR, ensure_log_dir  # noqa: F401  (re-exported for convenience)


@dataclass
class Settings:
    # display / housekeeping
    speed_unit: str = "auto"
    packet_purge_minutes: Optional[int] = None
    # firewall + limits (keyed by executable path)
    blocked_exes: List[str] = field(default_factory=list)
    exe_limits: Dict[str, List[int]] = field(default_factory=dict)  # exe -> [up,down] bytes/s
    # tagging
    exe_tags: Dict[str, str] = field(default_factory=dict)          # exe -> tag
    tag_limits: Dict[str, List[int]] = field(default_factory=dict)  # tag -> [up,down] bytes/s
    tag_blocked: List[str] = field(default_factory=list)            # tags blocked
    # remembered column widths: {window_key: {column_id: width}}
    column_widths: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # ---- convenience views -----------------------------------------------
    def exe_limit(self, exe: str) -> Tuple[int, int]:
        v = self.exe_limits.get(exe)
        return (int(v[0]), int(v[1])) if v else (0, 0)

    def tag_limit(self, tag: str) -> Tuple[int, int]:
        v = self.tag_limits.get(tag)
        return (int(v[0]), int(v[1])) if v else (0, 0)

    def exes_with_tag(self, tag: str) -> List[str]:
        return [e for e, t in self.exe_tags.items() if t == tag]

    def all_tags(self) -> List[str]:
        return sorted(set(self.exe_tags.values()) | set(self.tag_limits)
                      | set(self.tag_blocked))

    def tags(self) -> List[str]:
        return self.all_tags()

    # ---- persistence ------------------------------------------------------
    @classmethod
    def load(cls) -> "Settings":
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return cls()
        s = cls()
        try:
            if data.get("speed_unit") in SPEED_UNITS:
                s.speed_unit = data["speed_unit"]
            ppm = data.get("packet_purge_minutes")
            s.packet_purge_minutes = int(ppm) if ppm not in (None, "") else None
            s.blocked_exes = list(data.get("blocked_exes", []))
            s.exe_limits = {k: [int(v[0]), int(v[1])]
                            for k, v in data.get("exe_limits", {}).items()}
            s.exe_tags = {k: str(v) for k, v in data.get("exe_tags", {}).items()}
            s.tag_limits = {k: [int(v[0]), int(v[1])]
                            for k, v in data.get("tag_limits", {}).items()}
            s.tag_blocked = list(data.get("tag_blocked", []))
            cw = data.get("column_widths", {})
            s.column_widths = {k: {c: int(w) for c, w in v.items()}
                               for k, v in cw.items()}
        except Exception:
            pass
        return s

    def save(self) -> None:
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "speed_unit": self.speed_unit,
                    "packet_purge_minutes": self.packet_purge_minutes,
                    "blocked_exes": self.blocked_exes,
                    "exe_limits": self.exe_limits,
                    "exe_tags": self.exe_tags,
                    "tag_limits": self.tag_limits,
                    "tag_blocked": self.tag_blocked,
                    "column_widths": self.column_widths,
                }, f, indent=2)
        except Exception:
            pass
