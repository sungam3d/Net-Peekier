"""The monitor: a background worker that produces a fresh snapshot ~1/sec.

It owns the ProcessMap and the capture backend, and on each tick:
  1. refreshes the connection/PID tables,
  2. drains per-PID and per-connection byte counters into rates,
  3. assembles a list[ProcStat] (one row per process with network activity)
     plus dashboard Totals,
  4. hands a thread-safe snapshot to whoever asks (the GUI polls it).
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple

import psutil

from .capture import CaptureBackend, make_backend
from .models import Connection, ProcStat, Totals
from .procmap import ProcessMap

ConnKey = Tuple[str, str, int, str, int]


class Monitor:
    def __init__(self, interval: float = 1.0) -> None:
        self.interval = interval
        self.procmap = ProcessMap()
        self.backend: CaptureBackend = make_backend(self.procmap)

        self._lock = threading.Lock()
        self._procs: List[ProcStat] = []
        self._totals = Totals()
        # remember rules so they persist across snapshots
        self._blocked: set[int] = set()
        self._limits: Dict[int, Tuple[int, int]] = {}
        # last per-connection rates, so detail windows can show them
        self._conn_rates: Dict[ConnKey, Tuple[float, float]] = {}

        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_tick = time.monotonic()

        # system-wide fallback counters (used when backend has no per-PID data)
        self._last_io = psutil.net_io_counters()
        self._last_io_t = time.monotonic()

    @property
    def backend_name(self) -> str:
        return type(self.backend).__name__

    @property
    def has_per_process_speed(self) -> bool:
        return self.backend.available

    # ---- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self.backend.start()
        self._thread = threading.Thread(
            target=self._loop, name="np-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        self.backend.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    # ---- snapshot accessors (called from GUI thread) ----------------------
    def snapshot(self) -> Tuple[List[ProcStat], Totals]:
        with self._lock:
            return list(self._procs), Totals(**vars(self._totals))

    def connections_for(self, pid: int) -> List[Connection]:
        with self._lock:
            for p in self._procs:
                if p.pid == pid:
                    return list(p.connections)
        return []

    def packets_for(self, conn_key: ConnKey):
        return self.backend.recent_packets(conn_key)

    # ---- control passthrough ---------------------------------------------
    def set_blocked(self, pid: int, blocked: bool) -> None:
        with self._lock:
            if blocked:
                self._blocked.add(pid)
            else:
                self._blocked.discard(pid)
        self.backend.set_blocked(pid, blocked)

    def set_limit(self, pid: int, up_bps: int, down_bps: int) -> None:
        with self._lock:
            if up_bps <= 0 and down_bps <= 0:
                self._limits.pop(pid, None)
            else:
                self._limits[pid] = (up_bps, down_bps)
        self.backend.set_limit(pid, up_bps, down_bps)

    # ---- worker -----------------------------------------------------------
    def _loop(self) -> None:
        while self._running.is_set():
            t0 = time.monotonic()
            try:
                self._tick()
            except Exception as exc:  # never let the worker die silently
                print(f"[netpeeker] monitor tick error: {exc}")
            dt = time.monotonic() - t0
            time.sleep(max(0.05, self.interval - dt))

    def _tick(self) -> None:
        now = time.monotonic()
        interval = now - self._last_tick
        self._last_tick = now

        self.procmap.refresh(force=True)
        conns_by_pid = self.procmap.snapshot_connections()
        pid_rates, conn_rates = self.backend.drain_rates(interval)

        procs: List[ProcStat] = []
        up_total = down_total = 0.0

        # Union of pids that have connections OR measured traffic.
        pids = set(conns_by_pid) | set(pid_rates)
        for pid in pids:
            conns = conns_by_pid.get(pid, [])
            up, down = pid_rates.get(pid, (0.0, 0.0))
            up_total += up
            down_total += down

            # stamp per-connection rates onto the Connection objects
            for c in conns:
                cr = conn_rates.get(c.key)
                if cr:
                    c.up_bps, c.down_bps = cr

            ps = ProcStat(
                pid=pid,
                name=self.procmap.name(pid),
                exe=self.procmap.exe(pid),
                up_bps=up,
                down_bps=down,
                listening_ports=self.procmap.listening_ports(conns),
                connections=conns,
                blocked=pid in self._blocked,
                up_limit=self._limits.get(pid, (0, 0))[0],
                down_limit=self._limits.get(pid, (0, 0))[1],
            )
            procs.append(ps)

        procs.sort(key=lambda p: (p.down_bps + p.up_bps, len(p.connections)),
                   reverse=True)

        totals = self._compute_totals(up_total, down_total)

        with self._lock:
            self._procs = procs
            self._conn_rates = conn_rates
            with self._totals_guard():
                self._totals.up_now = totals.up_now
                self._totals.down_now = totals.down_now
                self._totals.up_peak = max(self._totals.up_peak, totals.up_now)
                self._totals.down_peak = max(self._totals.down_peak,
                                             totals.down_now)

    def _totals_guard(self):
        # totals are mutated under the same _lock already held; this is a no-op
        # context manager kept for readability.
        class _N:
            def __enter__(self_): return None
            def __exit__(self_, *a): return False
        return _N()

    def _compute_totals(self, up: float, down: float) -> Totals:
        """If the backend gave us real per-PID data, sum it. Otherwise fall
        back to the OS-wide counters so the dashboard still moves."""
        if self.has_per_process_speed and (up or down):
            return Totals(up_now=up, down_now=down)
        # system-wide fallback
        now = time.monotonic()
        io = psutil.net_io_counters()
        dt = max(0.001, now - self._last_io_t)
        up_bps = (io.bytes_sent - self._last_io.bytes_sent) / dt
        down_bps = (io.bytes_recv - self._last_io.bytes_recv) / dt
        self._last_io = io
        self._last_io_t = now
        return Totals(up_now=max(0.0, up_bps), down_now=max(0.0, down_bps))
