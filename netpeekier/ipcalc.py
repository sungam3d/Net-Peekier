"""Interval maths for the per-process *whitelist* (allow-only) feature.

Windows Firewall evaluates block rules before allow rules, so "allow only IP X"
cannot be done with an allow rule. Instead we invert it: compute every IP/port
*except* the allowed ones and emit those as BLOCK rules. This module does the
set arithmetic -- turning a list of allowed IP specs into the netsh remote-IP
ranges that cover everything else, and likewise for ports.

Pure functions only; no Tk, no netsh. This is the part worth testing hard.
"""
from __future__ import annotations

import ipaddress
from typing import List, Tuple

V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1


def _spec_to_intervals(spec: str) -> List[Tuple[int, int, int]]:
    """Parse an IP spec (single / CIDR / a-b range / comma list) into a list of
    (family, lo, hi) integer intervals. family is 4 or 6. Unparseable parts are
    skipped."""
    out: List[Tuple[int, int, int]] = []
    if not spec:
        return out
    for part in str(spec).split(","):
        p = part.strip()
        if not p or p.lower() in ("any", "*"):
            continue
        try:
            if "-" in p and "/" not in p:
                lo_s, hi_s = p.split("-", 1)
                lo = ipaddress.ip_address(lo_s.strip())
                hi = ipaddress.ip_address(hi_s.strip())
                if lo.version != hi.version:
                    continue
                fam = lo.version
                a, b = int(lo), int(hi)
                out.append((fam, min(a, b), max(a, b)))
            elif "/" in p:
                net = ipaddress.ip_network(p, strict=False)
                out.append((net.version, int(net.network_address),
                            int(net.broadcast_address)))
            else:
                a = ipaddress.ip_address(p)
                out.append((a.version, int(a), int(a)))
        except Exception:
            continue
    return out


def _merge(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping / adjacent [lo,hi] intervals."""
    if not intervals:
        return []
    s = sorted(intervals)
    merged = [list(s[0])]
    for lo, hi in s[1:]:
        if lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def _complement(intervals: List[Tuple[int, int]], lo_bound: int,
                hi_bound: int) -> List[Tuple[int, int]]:
    """Everything in [lo_bound, hi_bound] not covered by `intervals`."""
    merged = _merge([(max(lo, lo_bound), min(hi, hi_bound))
                     for lo, hi in intervals if hi >= lo_bound and lo <= hi_bound])
    result: List[Tuple[int, int]] = []
    cur = lo_bound
    for lo, hi in merged:
        if lo > cur:
            result.append((cur, lo - 1))
        cur = max(cur, hi + 1)
        if cur > hi_bound:
            break
    if cur <= hi_bound:
        result.append((cur, hi_bound))
    return result


def _v4_str(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def _v6_str(n: int) -> str:
    return str(ipaddress.IPv6Address(n))


def block_ranges_except(allowed_specs: List[str]) -> Tuple[List[str], List[str]]:
    """Given allowed IP specs, return (v4_ranges, v6_ranges) as netsh remoteip
    range strings ("lo-hi") covering EVERYTHING EXCEPT the allowed addresses.

    If a family has no allowed entries, its full range is returned (so allowing
    only an IPv4 also blocks all IPv6, and vice-versa) -- a strict whitelist.
    If allowed covers an entire family, that family's list is empty (nothing to
    block there).
    """
    v4: List[Tuple[int, int]] = []
    v6: List[Tuple[int, int]] = []
    for spec in allowed_specs:
        for fam, lo, hi in _spec_to_intervals(spec):
            (v4 if fam == 4 else v6).append((lo, hi))
    v4_ranges = [f"{_v4_str(lo)}-{_v4_str(hi)}"
                 for lo, hi in _complement(v4, 0, V4_MAX)]
    v6_ranges = [f"{_v6_str(lo)}-{_v6_str(hi)}"
                 for lo, hi in _complement(v6, 0, V6_MAX)]
    return v4_ranges, v6_ranges


# ---- ports ----------------------------------------------------------------
def _port_intervals(spec: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    if not spec:
        return out
    for part in str(spec).split(","):
        p = part.strip()
        if not p:
            continue
        try:
            if "-" in p:
                a, b = p.split("-", 1)
                a, b = int(a), int(b)
            else:
                a = b = int(p)
            if a > b:
                a, b = b, a
            out.append((max(1, a), min(65535, b)))
        except Exception:
            continue
    return out


def complement_ports(spec: str) -> str:
    """netsh remoteport string for every port 1-65535 EXCEPT those in `spec`.
    Empty result means the spec already covers all ports."""
    comp = _complement(_port_intervals(spec), 1, 65535)
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in comp)
