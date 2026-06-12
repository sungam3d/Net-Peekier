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
        # Rules are keyed by executable PATH, not PID, so they survive process
        # restarts and can be managed even when the app isn't running.
        self._blocked_exes: set[str] = set()
        self._limits_by_exe: Dict[str, Tuple[int, int]] = {}
        # last per-connection rates, so detail windows can show them
        self._conn_rates: Dict[ConnKey, Tuple[float, float]] = {}

        # Seed the blocked set from any firewall rules we created previously.
        try:
            from . import firewall
            self._blocked_exes.update(firewall.list_blocked())
        except Exception:
            pass

        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_tick = time.monotonic()

        # system-wide fallback counters (used when backend has no per-PID data)
        self._last_io = psutil.net_io_counters()
        self._last_io_t = time.monotonic()
        # baseline for cumulative "total sent/received" since app start
        self._baseline_io = self._last_io

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

    # ---- control passthrough (all keyed by executable path) ---------------
    def set_blocked(self, exe: str, blocked: bool) -> None:
        # Bookkeeping only. The actual block is applied by the OS firewall
        # (firewall.block_app / unblock_app, called from the GUI). We do NOT
        # route blocking through the capture backend, because diverting all
        # traffic to drop one app's packets stalls the whole connection.
        if not exe:
            return
        with self._lock:
            if blocked:
                self._blocked_exes.add(exe)
            else:
                self._blocked_exes.discard(exe)

    def set_limit(self, exe: str, up_bps: int, down_bps: int) -> None:
        if not exe:
            return
        with self._lock:
            if up_bps <= 0 and down_bps <= 0:
                self._limits_by_exe.pop(exe, None)
            else:
                self._limits_by_exe[exe] = (up_bps, down_bps)
        self.backend.set_limit(exe, up_bps, down_bps)

    def remove_app(self, exe: str) -> None:
        """Fully unmanage an app: drop its block and its limit."""
        self.set_blocked(exe, False)
        self.set_limit(exe, 0, 0)

    # ---- rule queries (for the firewall manager window) -------------------
    def list_blocked(self) -> set[str]:
        with self._lock:
            return set(self._blocked_exes)

    def list_limits(self) -> Dict[str, Tuple[int, int]]:
        with self._lock:
            return dict(self._limits_by_exe)

    def managed_apps(self) -> Dict[str, Tuple[bool, Tuple[int, int]]]:
        """{exe: (blocked, (up_limit, down_limit))} for every managed app."""
        with self._lock:
            exes = set(self._blocked_exes) | set(self._limits_by_exe)
            return {
                exe: (exe in self._blocked_exes,
                      self._limits_by_exe.get(exe, (0, 0)))
                for exe in exes
            }

    # ---- worker -----------------------------------------------------------
    def _loop(self) -> None:
        while self._running.is_set():
            t0 = time.monotonic()
            try:
                self._tick()
            except Exception as exc:  # never let the worker die silently
                print(f"[netpeekier] monitor tick error: {exc}")
            dt = time.monotonic() - t0
            time.sleep(max(0.05, self.interval - dt))

    def _tick(self) -> None:
        now = time.monotonic()
        interval = now - self._last_tick
        self._last_tick = now

        self.procmap.refresh(force=True)
        conns_by_pid = self.procmap.snapshot_connections()
        pid_rates, conn_rates = self.backend.drain_rates(interval)
        pid_totals = self.backend.pid_totals()

        procs: List[ProcStat] = []
        up_total = down_total = 0.0

        # Union of pids that have connections, current traffic, or any history.
        pids = set(conns_by_pid) | set(pid_rates) | set(pid_totals)
        for pid in pids:
            conns = conns_by_pid.get(pid, [])
            up, down = pid_rates.get(pid, (0.0, 0.0))
            tup, tdown = pid_totals.get(pid, (0, 0))
            up_total += up
            down_total += down

            # stamp per-connection rates onto the Connection objects
            for c in conns:
                cr = conn_rates.get(c.key)
                if cr:
                    c.up_bps, c.down_bps = cr

            exe = self.procmap.exe(pid)
            limit = self._limits_by_exe.get(exe, (0, 0)) if exe else (0, 0)
            ps = ProcStat(
                pid=pid,
                name=self.procmap.name(pid),
                exe=exe,
                up_bps=up,
                down_bps=down,
                up_total=tup,
                down_total=tdown,
                listening_ports=self.procmap.listening_ports(conns),
                connections=conns,
                blocked=bool(exe) and exe in self._blocked_exes,
                up_limit=limit[0],
                down_limit=limit[1],
            )
            procs.append(ps)

        procs.sort(key=lambda p: (p.down_bps + p.up_bps, len(p.connections)),
                   reverse=True)

        totals = self._compute_totals(up_total, down_total)

        # Cumulative session totals: system-wide bytes since app start. Using
        # the OS counters here keeps this accurate and always-available, even
        # in psutil-only mode where per-process bytes aren't measured.
        cur_io = psutil.net_io_counters()
        sess_up = max(0, cur_io.bytes_sent - self._baseline_io.bytes_sent)
        sess_down = max(0, cur_io.bytes_recv - self._baseline_io.bytes_recv)

        with self._lock:
            self._procs = procs
            self._conn_rates = conn_rates
            self._totals.up_now = totals.up_now
            self._totals.down_now = totals.down_now
            self._totals.up_peak = max(self._totals.up_peak, totals.up_now)
            self._totals.down_peak = max(self._totals.down_peak,
                                         totals.down_now)
            self._totals.up_total = sess_up
            self._totals.down_total = sess_down

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
