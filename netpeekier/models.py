"""Plain data containers shared across the app.

Everything here is intentionally dumb: no behaviour, just typed fields so the
monitor, capture backend and GUI all speak the same language.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Packet:
    """One captured packet, as shown in the 'Captured Packets' window."""
    ts: float                 # epoch seconds
    outbound: bool            # True = local -> remote (-->), False = inbound (<--)
    protocol: str             # 'TCP' / 'UDP' / 'ICMP' / ...
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    length: int               # total packet length on the wire
    raw: bytes = b""          # full bytes, for the hex dump pane
    pid: Optional[int] = None

    @property
    def direction_arrow(self) -> str:
        return "-->" if self.outbound else "<--"


@dataclass
class Connection:
    """A live socket belonging to a process (the 'Detail Information' rows)."""
    pid: int
    protocol: str             # TCP / UDP
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str               # ESTABLISHED / LISTEN / CLOSE_WAIT ...
    start_time: float = field(default_factory=time.time)
    # live, per-connection rates (bytes/sec), filled in by the monitor:
    up_bps: float = 0.0
    down_bps: float = 0.0

    @property
    def key(self) -> tuple:
        """Stable identity used to correlate packets and carry rates over."""
        return (self.protocol, self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)

    @property
    def direction_arrow(self) -> str:
        # Sockets with a remote endpoint are outbound from our point of view.
        return "-->" if self.remote_port else ""


@dataclass
class ProcStat:
    """One row in the main application list."""
    pid: int
    name: str
    exe: str = ""
    up_bps: float = 0.0
    down_bps: float = 0.0
    up_total: float = 0.0     # cumulative bytes sent since app start
    down_total: float = 0.0   # cumulative bytes received since app start
    listening_ports: list[int] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    blocked: bool = False
    up_limit: int = 0         # bytes/sec, 0 = unlimited
    down_limit: int = 0


@dataclass
class Totals:
    """Dashboard figures."""
    up_now: float = 0.0
    down_now: float = 0.0
    up_peak: float = 0.0
    down_peak: float = 0.0
    up_total: float = 0.0     # cumulative bytes sent since app start
    down_total: float = 0.0   # cumulative bytes received since app start
