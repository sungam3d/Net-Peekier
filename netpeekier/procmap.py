"""Process, connection and port enumeration via psutil.

This module is fully cross-platform and needs no driver. On Windows you should
run as Administrator to see connections owned by *other* users' processes;
without elevation you only get your own.

Two jobs:
  1. Build a fast lookup from a packet's local endpoint -> owning PID, so the
     capture backend can attribute bandwidth to a process.
  2. Produce the per-process connection lists and listening ports the GUI shows.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

import psutil

from .models import Connection

# psutil kind strings we care about
_KINDS = ("tcp", "tcp6", "udp", "udp6")


class ProcessMap:
    """Caches process metadata and the endpoint->PID table.

    Refreshing the connection table is relatively expensive, so the capture
    thread calls refresh() on an interval (e.g. once a second) rather than per
    packet, and packet lookups hit the cached dicts.
    """

    def __init__(self) -> None:
        # (proto, local_ip, local_port) -> pid   (exact match, preferred)
        self._exact: Dict[Tuple[str, str, int], int] = {}
        # (proto, local_port) -> pid             (loose fallback; ip wildcarded)
        self._loose: Dict[Tuple[str, int], int] = {}
        self._names: Dict[int, str] = {}
        self._exes: Dict[int, str] = {}
        self._last_refresh = 0.0

    # ---- process metadata -------------------------------------------------
    def name(self, pid: Optional[int]) -> str:
        if pid is None:
            return "System Idle / Unknown"
        if pid not in self._names:
            try:
                self._names[pid] = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                self._names[pid] = f"PID {pid}"
        return self._names[pid]

    def exe(self, pid: Optional[int]) -> str:
        if pid is None:
            return ""
        if pid not in self._exes:
            try:
                self._exes[pid] = psutil.Process(pid).exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError,
                    OSError):
                self._exes[pid] = ""
        return self._exes[pid]

    # ---- packet attribution ----------------------------------------------
    def pid_for_endpoint(self, proto: str, local_ip: str,
                         local_port: int) -> Optional[int]:
        """Best-effort owner of a local (ip, port). Tries exact then loose."""
        pid = self._exact.get((proto, local_ip, local_port))
        if pid is not None:
            return pid
        return self._loose.get((proto, local_port))

    def pid_for_port(self, proto: str, local_port: int) -> Optional[int]:
        """Owner of a local (proto, port) ignoring IP. Used by the throttle's
        hot path, which only knows the port and wants to stay cheap."""
        return self._loose.get((proto, local_port))

    # ---- refresh ----------------------------------------------------------
    def refresh(self, force: bool = False, min_interval: float = 0.9) -> None:
        now = time.time()
        if not force and (now - self._last_refresh) < min_interval:
            return
        self._last_refresh = now

        exact: Dict[Tuple[str, str, int], int] = {}
        loose: Dict[Tuple[str, int], int] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Not elevated: fall back to per-process scan of what we can see.
            conns = self._scan_own_connections()

        for c in conns:
            if not c.laddr or c.pid is None:
                continue
            proto = _proto_name(c.type)
            lip = c.laddr.ip
            lport = c.laddr.port
            exact[(proto, lip, lport)] = c.pid
            # Loose key: last writer wins, which is fine for the common case.
            loose[(proto, lport)] = c.pid

        self._exact = exact
        self._loose = loose

    @staticmethod
    def _scan_own_connections() -> list:
        out = []
        for p in psutil.process_iter():
            try:
                out.extend(p.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return out

    # ---- GUI data ---------------------------------------------------------
    def snapshot_connections(self) -> Dict[int, List[Connection]]:
        """All live connections grouped by PID, for the detail windows."""
        result: Dict[int, List[Connection]] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = self._scan_own_connections()

        for c in conns:
            if c.pid is None:
                continue
            laddr = c.laddr
            raddr = c.raddr
            conn = Connection(
                pid=c.pid,
                protocol=_proto_name(c.type),
                local_ip=laddr.ip if laddr else "",
                local_port=laddr.port if laddr else 0,
                remote_ip=raddr.ip if raddr else "",
                remote_port=raddr.port if raddr else 0,
                status=c.status or "",
            )
            result.setdefault(c.pid, []).append(conn)
        return result

    def listening_ports(self, conns: List[Connection]) -> List[int]:
        ports = sorted({c.local_port for c in conns
                        if c.status == psutil.CONN_LISTEN and c.local_port})
        return ports


def _proto_name(socktype) -> str:
    import socket
    if socktype == socket.SOCK_STREAM:
        return "TCP"
    if socktype == socket.SOCK_DGRAM:
        return "UDP"
    return str(socktype)
