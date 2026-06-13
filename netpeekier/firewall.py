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
_IP_MARKER = f"{RULE_PREFIX} ip "        # per-IP allow/block rules


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


import hashlib
import ipaddress


def _valid_ip_spec(spec: str) -> bool:
    """Accept a single IP, a CIDR subnet, an a.b.c.d-e.f.g.h range, or a
    comma-separated list of those. Rejects anything else so we never feed netsh
    a malformed remoteip."""
    if not spec or not isinstance(spec, str):
        return False
    spec = spec.strip()
    if spec.lower() in ("any", "*"):
        return True
    for part in spec.split(","):
        p = part.strip()
        if not p:
            return False
        try:
            if "-" in p:
                lo, hi = p.split("-", 1)
                ipaddress.ip_address(lo.strip())
                ipaddress.ip_address(hi.strip())
            elif "/" in p:
                ipaddress.ip_network(p, strict=False)
            else:
                ipaddress.ip_address(p)
        except Exception:
            return False
    return True


def _valid_ports(spec: str) -> bool:
    """Empty (= all ports) is fine; otherwise a comma list of ports / ranges."""
    if not spec:
        return True
    for part in str(spec).split(","):
        p = part.strip()
        if not p:
            return False
        try:
            if "-" in p:
                a, b = p.split("-", 1)
                if not (0 < int(a) <= 65535 and 0 < int(b) <= 65535):
                    return False
            else:
                if not 0 < int(p) <= 65535:
                    return False
        except Exception:
            return False
    return True


def _ip_rule_id(exe: str, action: str, direction: str, remote_ip: str,
                ports: str, protocol: str) -> str:
    raw = f"{exe}|{action}|{direction}|{remote_ip}|{ports}|{protocol}".lower()
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:12]


def _ip_rule_name(rule_id: str, direction: str, proto: str) -> str:
    return f"{_IP_MARKER}{rule_id} {direction} {proto}"


def _concrete_dirs(direction: str):
    return ("in", "out") if direction == "both" else (direction,)


def _concrete_protos(protocol: str, ports: str):
    protocol = (protocol or "any").lower()
    if protocol in ("tcp", "udp"):
        return (protocol,)
    # 'any' protocol: if ports are specified, netsh requires TCP/UDP, so split
    if ports:
        return ("tcp", "udp")
    return ("any",)


def add_ip_rule(exe: str, action: str, direction: str, remote_ip: str,
                ports: str = "", protocol: str = "any") -> Tuple[bool, str]:
    """Create a per-IP firewall rule scoped to one program.

    action: 'allow' | 'block'; direction: 'in'|'out'|'both';
    remote_ip: IP / CIDR / range / comma-list / 'any';
    ports: '' (all) or comma list/ranges; protocol: 'tcp'|'udp'|'any'.

    NOTE on Windows semantics: explicit BLOCK rules take precedence over ALLOW
    rules, so an allow rule cannot punch a hole through a whole-app block. Use
    allow rules to *restrict* an otherwise-open app to certain destinations, and
    block rules to carve specific destinations out of an app.
    """
    if not _valid_exe(exe):
        return False, f"Refusing: not a valid executable path ({exe!r})."
    if action not in ("allow", "block"):
        return False, f"Bad action {action!r}."
    if direction not in ("in", "out", "both"):
        return False, f"Bad direction {direction!r}."
    if not _valid_ip_spec(remote_ip):
        return False, f"Bad remote IP/range ({remote_ip!r})."
    if not _valid_ports(ports):
        return False, f"Bad ports ({ports!r})."
    exe = exe.strip().strip('"')
    rid = _ip_rule_id(exe, action, direction, remote_ip, ports, protocol)
    ok, msgs = True, []
    for d in _concrete_dirs(direction):
        for proto in _concrete_protos(protocol, ports):
            args = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={_ip_rule_name(rid, d, proto)}",
                f"dir={d}", f"action={action}",
                f"program={exe}", "enable=yes", "profile=any",
            ]
            if remote_ip.strip().lower() not in ("any", "*"):
                args.append(f"remoteip={remote_ip.strip()}")
            if proto != "any":
                args.append(f"protocol={proto}")
            if ports:
                args.append(f"remoteport={ports}")
            rc, out = _run(args)
            ok = ok and rc == 0
            if rc != 0:
                msgs.append(out.strip())
    return ok, ("\n".join(msgs) if msgs else "IP rule added.")


def remove_ip_rule(exe: str, action: str, direction: str, remote_ip: str,
                   ports: str = "", protocol: str = "any") -> Tuple[bool, str]:
    exe = (exe or "").strip().strip('"')
    rid = _ip_rule_id(exe, action, direction, remote_ip, ports, protocol)
    ok, msgs = True, []
    for d in _concrete_dirs(direction):
        for proto in _concrete_protos(protocol, ports):
            rc, out = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_ip_rule_name(rid, d, proto)}",
            ])
            if rc != 0 and "No rules match" not in out:
                ok = False
                msgs.append(out.strip())
    return ok, ("\n".join(msgs) if msgs else "IP rule removed.")


def remove_all_ip_rules() -> int:
    """Delete every per-IP rule we created (matched by our IP marker)."""
    rc, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
    if rc != 0:
        return 0
    names = set()
    for line in out.splitlines():
        if _IP_MARKER in line:
            idx = line.find(_IP_MARKER)
            names.add(line[idx:].strip())
    removed = 0
    for name in names:
        r2, _o = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}"])
        if r2 == 0:
            removed += 1
    return removed


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
