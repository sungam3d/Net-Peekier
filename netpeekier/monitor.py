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

        from .settings import Settings
        self.settings = Settings.load()

        self._lock = threading.Lock()
        self._procs: List[ProcStat] = []
        self._totals = Totals()
        # last per-connection rates, so detail windows can show them
        self._conn_rates: Dict[ConnKey, Tuple[float, float]] = {}

        # Reconcile with the OS firewall: anything Windows still blocks that we
        # created should appear in our settings too (and vice-versa on apply).
        try:
            from . import firewall
            for exe in firewall.list_blocked():
                if exe not in self.settings.blocked_exes:
                    self.settings.blocked_exes.append(exe)
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
        self.apply_settings()
        self._running.set()
        self.backend.start()
        self._thread = threading.Thread(
            target=self._loop, name="np-monitor", daemon=True)
        self._thread.start()

    def apply_settings(self) -> None:
        """Push every rule from settings into the backend and the OS firewall.
        Safe to call after any edit; it's idempotent."""
        s = self.settings
        self.backend.set_purge_minutes(s.packet_purge_minutes)
        # per-exe limits
        for exe in list(self.backend.limited_exes()):
            self.backend.set_limit(exe, 0, 0)   # clear stale
        for exe, (up, down) in list(s.exe_limits.items()):
            self.backend.set_limit(exe, up, down)
        # tags + tag limits
        for exe, tag in s.exe_tags.items():
            self.backend.set_exe_tag(exe, tag)
        for tag, (up, down) in list(s.tag_limits.items()):
            self.backend.set_tag_limit(tag, up, down)
        # (re-)apply firewall blocks for exes we intend to block
        try:
            from . import firewall
            for exe in list(s.blocked_exes):
                firewall.block_app(exe)
            # tag blocks: block every exe carrying a blocked tag
            for tag in s.tag_blocked:
                for exe in s.exes_with_tag(tag):
                    firewall.block_app(exe)
        except Exception:
            pass
        s.save()

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

    # ---- control (all settings-backed, keyed by executable path) ----------
    def set_blocked(self, exe: str, blocked: bool) -> None:
        if not exe:
            return
        if blocked:
            if exe not in self.settings.blocked_exes:
                self.settings.blocked_exes.append(exe)
        else:
            if exe in self.settings.blocked_exes:
                self.settings.blocked_exes.remove(exe)
        self.settings.save()

    def set_limit(self, exe: str, up_bps: int, down_bps: int) -> None:
        if not exe:
            return
        if up_bps <= 0 and down_bps <= 0:
            self.settings.exe_limits.pop(exe, None)
        else:
            self.settings.exe_limits[exe] = [up_bps, down_bps]
        self.backend.set_limit(exe, up_bps, down_bps)
        self.settings.save()

    def set_exe_tag(self, exe: str, tag) -> None:
        if not exe:
            return
        if tag:
            self.settings.exe_tags[exe] = tag
        else:
            self.settings.exe_tags.pop(exe, None)
        self.backend.set_exe_tag(exe, tag)
        # re-apply tag rules so a freshly-tagged app picks up group limits
        self.apply_settings()

    def set_tag_limit(self, tag: str, up_bps: int, down_bps: int) -> None:
        if not tag:
            return
        if up_bps <= 0 and down_bps <= 0:
            self.settings.tag_limits.pop(tag, None)
        else:
            self.settings.tag_limits[tag] = [up_bps, down_bps]
        self.backend.set_tag_limit(tag, up_bps, down_bps)
        self.settings.save()

    def set_tag_blocked(self, tag: str, blocked: bool) -> None:
        if not tag:
            return
        if blocked and tag not in self.settings.tag_blocked:
            self.settings.tag_blocked.append(tag)
        elif not blocked and tag in self.settings.tag_blocked:
            self.settings.tag_blocked.remove(tag)
        try:
            from . import firewall
            for exe in self.settings.exes_with_tag(tag):
                if blocked:
                    firewall.block_app(exe)
                elif exe not in self.settings.blocked_exes:
                    firewall.unblock_app(exe)
        except Exception:
            pass
        self.settings.save()

    def remove_app(self, exe: str) -> None:
        """Fully unmanage an app: drop block, limit and tag."""
        self.set_blocked(exe, False)
        self.set_limit(exe, 0, 0)
        self.set_exe_tag(exe, None)

    # ---- rule queries (for the manager windows) ---------------------------
    def list_blocked(self) -> set[str]:
        return set(self.settings.blocked_exes)

    def list_limits(self) -> Dict[str, Tuple[int, int]]:
        return {k: (v[0], v[1]) for k, v in self.settings.exe_limits.items()}

    def managed_apps(self) -> Dict[str, tuple]:
        """{exe: (blocked, (up_limit, down_limit), tag)} for every managed app."""
        s = self.settings
        exes = set(s.blocked_exes) | set(s.exe_limits) | set(s.exe_tags)
        return {
            exe: (exe in s.blocked_exes, s.exe_limit(exe),
                  s.exe_tags.get(exe, ""))
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
        conn_totals = self.backend.conn_totals()
        # trim captured packet logs if a purge window is configured
        self.backend.purge_packets()

        s = self.settings
        blocked_exes = set(s.blocked_exes)
        # exes that the limiter must police (own limit, or a limited tag)
        limited_exes = self.backend.limited_exes()
        enforced_ports: set = set()

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

            # stamp per-connection rates + totals onto the Connection objects
            for c in conns:
                cr = conn_rates.get(c.key)
                if cr:
                    c.up_bps, c.down_bps = cr
                ct = conn_totals.get(c.key)
                if ct:
                    c.up_total, c.down_total = ct

            exe = self.procmap.exe(pid)
            limit = s.exe_limit(exe) if exe else (0, 0)
            # collect this app's local ports if it's under a limit, so the
            # enforcer's divert filter targets only these.
            if exe and exe in limited_exes:
                for c in conns:
                    if c.local_port:
                        enforced_ports.add(c.local_port)

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
                blocked=bool(exe) and exe in blocked_exes,
                up_limit=limit[0],
                down_limit=limit[1],
                tag=s.exe_tags.get(exe, "") if exe else "",
            )
            procs.append(ps)

        # hand the limited apps' ports to the enforcer (narrow divert filter)
        self.backend.set_enforced_ports(enforced_ports)

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
