"""Persistent app blocking via Windows Firewall (netsh advfirewall).

This is the same mechanism NetPeeker's "block application" used in spirit: a
rule keyed on the program's executable path that drops its traffic. Doing it
through the OS firewall (rather than WinDivert) means the block survives app
restarts and even reboots, and never sits in your live packet path.

Requires Administrator. Each app gets two rules (in + out) tagged so we can
find and remove them later.
"""
from __future__ import annotations

import subprocess
import sys
from typing import List

RULE_PREFIX = "NetPeekier"


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _run(args: List[str]) -> tuple[int, str]:
    if not _is_windows():
        return 1, "netsh is Windows-only"
    try:
        # CREATE_NO_WINDOW so we don't flash console windows from a GUI app.
        flags = 0x08000000 if _is_windows() else 0
        proc = subprocess.run(
            args, capture_output=True, text=True, creationflags=flags)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 1, "netsh not found"


def _rule_name(exe: str, direction: str) -> str:
    # Keep names stable & unique-ish per exe; netsh matches on the whole name.
    safe = exe.replace('"', "")
    return f"{RULE_PREFIX} block {direction} :: {safe}"


def block_app(exe_path: str) -> tuple[bool, str]:
    """Add inbound+outbound block rules for an executable path."""
    if not exe_path:
        return False, "No executable path for this process (try running as admin)."
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


def unblock_app(exe_path: str) -> tuple[bool, str]:
    if not exe_path:
        return False, "No executable path."
    ok = True
    msgs = []
    for direction in ("in", "out"):
        rc, out = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={_rule_name(exe_path, direction)}",
        ])
        # delete returns nonzero if no matching rule; treat that as fine.
        if rc != 0 and "No rules match" not in out:
            ok = False
            msgs.append(out.strip())
    return ok, "\n".join(msgs) if msgs else "Unblocked."


def is_blocked(exe_path: str) -> bool:
    if not exe_path:
        return False
    rc, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={_rule_name(exe_path, 'out')}",
    ])
    return rc == 0 and "block" in out.lower()


def list_blocked() -> list[str]:
    """Return the exe paths of every app we've blocked via the firewall.

    We embed the exe path in our rule names ('<prefix> block out :: <exe>'),
    so we can recover the list locale-independently by scanning rule names
    rather than parsing localized 'Program:' fields.
    """
    rc, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
    ])
    if rc != 0:
        return []
    marker = f"{RULE_PREFIX} block "
    exes: set[str] = set()
    for line in out.splitlines():
        if marker in line and "::" in line:
            exe = line.split("::", 1)[1].strip()
            if exe:
                exes.add(exe)
    return sorted(exes)


def clear_all() -> None:
    """Remove every rule this app ever created (housekeeping)."""
    _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f'name=all', f'program=*',
    ])  # best-effort; primary cleanup is per-rule above
