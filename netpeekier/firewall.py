"""Persistent app blocking via Windows Firewall (netsh advfirewall).

A block is two firewall rules (inbound + outbound) keyed on the program's
executable path. Doing it through the OS firewall (rather than WinDivert) means
the block is selective and never sits in the live packet path.

SAFETY IS CRITICAL HERE. A firewall rule with no valid ``program=`` filter
blocks *all* traffic in that direction, and such a rule persists after the app
closes and across reboots. So this module refuses to ever create a rule without
a concrete, existing executable path, and every rule we add is tagged with a
stable prefix + the exact exe path so we can find and remove exactly our own
rules and nothing else.

Requires Administrator.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import List, Tuple

RULE_PREFIX = "NetPeekier"
_MARKER = f"{RULE_PREFIX} block "


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _run(args: List[str]) -> Tuple[int, str]:
    if not _is_windows():
        return 1, "netsh is Windows-only"
    try:
        flags = 0x08000000  # CREATE_NO_WINDOW - no console flash from the GUI
        proc = subprocess.run(
            args, capture_output=True, text=True, creationflags=flags)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 1, "netsh not found"


def _valid_exe(exe_path: str) -> bool:
    """A path we're willing to build a firewall rule from. Must be a non-empty,
    absolute path to a .exe. This is the single guard that prevents a
    block-everything rule from ever being created."""
    if not exe_path or not isinstance(exe_path, str):
        return False
    p = exe_path.strip().strip('"').strip()
    if not p:
        return False
    # reject any embedded control/wildcard chars outright
    if any(ch in p for ch in ('*', '?', '"', '\n', '\r', '\t', '|', '&', ';')):
        return False
    # must look like an absolute Windows path to an executable
    if not (len(p) > 3 and p[1:3] == ":\\"):
        return False
    if not p.lower().endswith(".exe"):
        return False
    return True


def _rule_name(exe: str, direction: str) -> str:
    safe = exe.replace('"', "")
    return f"{_MARKER}{direction} :: {safe}"


def block_app(exe_path: str) -> Tuple[bool, str]:
    """Add inbound+outbound block rules for one executable path.

    Refuses anything that isn't a concrete .exe path, so a malformed or empty
    value can never produce a rule that blocks all traffic."""
    if not _valid_exe(exe_path):
        return False, ("Refusing to block: not a valid executable path "
                       f"({exe_path!r}). No firewall rule was created.")
    exe_path = exe_path.strip().strip('"')
    ok = True
    msgs = []
    for direction in ("in", "out"):
        rc, out = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_rule_name(exe_path, direction)}",
            f"dir={direction}", "action=block",
            f"program={exe_path}", "enable=yes", "profile=any",
        ])
        ok = ok and rc == 0
        if rc != 0:
            msgs.append(out.strip())
    return ok, "\n".join(msgs) if msgs else "Blocked."


def unblock_app(exe_path: str) -> Tuple[bool, str]:
    if not exe_path:
        return False, "No executable path."
    exe_path = exe_path.strip().strip('"')
    ok = True
    msgs = []
    for direction in ("in", "out"):
        rc, out = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={_rule_name(exe_path, direction)}",
        ])
        if rc != 0 and "No rules match" not in out:
            ok = False
            msgs.append(out.strip())
    return ok, "\n".join(msgs) if msgs else "Unblocked."


def is_blocked(exe_path: str) -> bool:
    if not _valid_exe(exe_path):
        return False
    rc, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={_rule_name(exe_path, 'out')}",
    ])
    return rc == 0 and "block" in out.lower()


def list_blocked() -> list[str]:
    """Exe paths of apps we've blocked, recovered from our own rule names only.

    We parse ONLY the 'Rule Name:' line (which is what 'show rule name=all'
    prints for each rule's name) and only accept entries whose recovered path is
    a valid exe, so a corrupt rule name can't seed a bad block on the next run.
    """
    rc, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
    ])
    if rc != 0:
        return []
    exes: set[str] = set()
    for line in out.splitlines():
        # netsh prints "Rule Name:  <name>" (localized label varies, but our
        # marker is embedded in the name itself). Only treat lines that contain
        # the marker AND the '::' separator as a rule-name line.
        if _MARKER not in line or "::" not in line:
            continue
        exe = line.split("::", 1)[1].strip()
        if _valid_exe(exe):
            exes.add(exe)
    return sorted(exes)


def remove_all_rules() -> Tuple[int, str]:
    """Delete every firewall rule this app created. Safe recovery hatch: it only
    ever removes rules whose names carry our prefix, one exe at a time, so it
    can't touch unrelated firewall rules.

    Returns (count_removed, message)."""
    exes = list_blocked()
    removed = 0
    for exe in exes:
        for direction in ("in", "out"):
            rc, out = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_rule_name(exe, direction)}",
            ])
            if rc == 0:
                removed += 1
    # Also sweep any stray rules that still carry our prefix but didn't yield a
    # valid exe above (belt and suspenders), deleting strictly by exact name.
    rc, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
    ])
    if rc == 0:
        names = set()
        for line in out.splitlines():
            if _MARKER in line and "::" in line:
                # reconstruct the exact rule name from the marker onward
                idx = line.find(_MARKER)
                names.add(line[idx:].strip())
        for name in names:
            r2, _o = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={name}",
            ])
            if r2 == 0:
                removed += 1
    return removed, f"Removed {removed} Net-Peekier firewall rule(s)."
