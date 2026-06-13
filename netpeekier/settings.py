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

# Default "LAN" ranges: private, loopback, link-local, etc. Anything a remote
# address falls outside of is treated as WAN (internet) traffic.
DEFAULT_LAN_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
]

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
    # remembered main-window geometry string, e.g. "880x560+100+50"
    window_geometry: Optional[str] = None
    # hide processes idle (no internet activity) for this many minutes; None=off
    idle_hide_minutes: Optional[int] = None
    # LAN address ranges (CIDR). Remotes outside these are WAN/internet.
    lan_ranges: List[str] = field(
        default_factory=lambda: list(DEFAULT_LAN_RANGES))
    # main-list view toggles
    show_lan: bool = True
    show_wan: bool = True
    # master switch: when off, our firewall blocks are removed (traffic flows)
    # but the block configuration is preserved and re-applied when turned on.
    firewall_enabled: bool = True
    # Lockdown mode: default-deny. Only allowed exes/tags reach the internet;
    # anything else prompts. allow_minutes is the remembered "allow for N min"
    # value shown in the prompt.
    lockdown_mode: bool = False
    allowed_exes: List[str] = field(default_factory=list)   # permanent allow
    tag_allowed: List[str] = field(default_factory=list)    # tags allowed
    allow_minutes: int = 5
    # per-IP firewall rules: list of dicts
    # {exe, action, direction, remote_ip, ports, protocol, note}
    ip_rules: List[dict] = field(default_factory=list)

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
                      | set(self.tag_blocked) | set(self.tag_allowed))

    def ip_rules_for(self, exe: str) -> List[dict]:
        return [r for r in self.ip_rules if r.get("exe") == exe]

    def is_allowed_exe(self, exe: str) -> bool:
        """True if this exe is on the permanent allow list, directly or via an
        allowed tag. Mirrors how blocking works with tags."""
        if not exe:
            return False
        if exe in self.allowed_exes:
            return True
        tag = self.exe_tags.get(exe)
        return bool(tag) and tag in self.tag_allowed

    def lan_networks(self):
        """Parsed ip_network objects for the configured LAN ranges."""
        import ipaddress
        nets = []
        for c in self.lan_ranges:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass
        return nets

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
            wg = data.get("window_geometry")
            s.window_geometry = str(wg) if wg else None
            ihm = data.get("idle_hide_minutes")
            s.idle_hide_minutes = int(ihm) if ihm not in (None, "") else None
            lr = data.get("lan_ranges")
            if isinstance(lr, list) and lr:
                s.lan_ranges = [str(x) for x in lr]
            s.show_lan = bool(data.get("show_lan", True))
            s.show_wan = bool(data.get("show_wan", True))
            s.firewall_enabled = bool(data.get("firewall_enabled", True))
            s.lockdown_mode = bool(data.get("lockdown_mode", False))
            s.allowed_exes = list(data.get("allowed_exes", []))
            s.tag_allowed = list(data.get("tag_allowed", []))
            am = data.get("allow_minutes", 5)
            s.allow_minutes = int(am) if am else 5
            s.ip_rules = [dict(r) for r in data.get("ip_rules", [])
                          if isinstance(r, dict)]
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
                    "window_geometry": self.window_geometry,
                    "idle_hide_minutes": self.idle_hide_minutes,
                    "lan_ranges": self.lan_ranges,
                    "show_lan": self.show_lan,
                    "show_wan": self.show_wan,
                    "firewall_enabled": self.firewall_enabled,
                    "lockdown_mode": self.lockdown_mode,
                    "allowed_exes": self.allowed_exes,
                    "tag_allowed": self.tag_allowed,
                    "allow_minutes": self.allow_minutes,
                    "ip_rules": self.ip_rules,
                }, f, indent=2)
        except Exception:
            pass
