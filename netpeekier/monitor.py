"""The monitor: a background worker that produces a fresh snapshot ~1/sec.

It owns the ProcessMap and the capture backend, and on each tick:
  1. refreshes the connection/PID tables,
  2. drains per-PID and per-connection byte counters into rates,
  3. assembles a list[ProcStat] (one row per process with network activity)
     plus dashboard Totals,
  4. hands a thread-safe snapshot to whoever asks (the GUI polls it).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Dict, List, Optional, Tuple

import psutil

from .capture import CaptureBackend, make_backend
from .models import Connection, ProcStat, Totals
from .procmap import ProcessMap

ConnKey = Tuple[str, str, int, str, int]


def _pid_alive(pid: int) -> bool:
    try:
        return psutil.pid_exists(pid)
    except Exception:
        return True   # if unsure, keep it rather than wrongly dropping


def _is_wan(ip_str: str, nets) -> bool:
    """True if a remote IP is a routable internet (WAN) address, i.e. not in
    any configured LAN range and not otherwise private/local."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for n in nets:
        try:
            if ip in n:
                return False
        except Exception:
            continue
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_unspecified or ip.is_reserved):
        return False
    return True


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
                if exe and exe not in self.settings.blocked_exes:
                    self.settings.blocked_exes.append(exe)
            # drop any empty/garbage entries that may have crept in previously
            self.settings.blocked_exes = [
                e for e in self.settings.blocked_exes if e]
        except Exception:
            pass

        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_tick = time.monotonic()

        # activity tracking for idle-hiding and terminated-process cleanup
        self._last_active: Dict[int, float] = {}    # pid -> monotonic ts
        self._prev_conns: Dict[int, frozenset] = {}  # pid -> conn-key set
        self._lan_nets = self.settings.lan_networks()  # cached parsed ranges

        # rolling activity log (for the Statistics window)
        from . import paths
        from .history import HistoryLogger
        self.history = HistoryLogger(
            os.path.join(paths.LOG_DIR, "history.jsonl"))
        self._prev_pid_totals: Dict[int, Tuple[int, int]] = {}

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
        self.apply_settings(sync_firewall=True)
        self._running.set()
        self.backend.start()
        self._thread = threading.Thread(
            target=self._loop, name="np-monitor", daemon=True)
        self._thread.start()

    def apply_settings(self, sync_firewall: bool = False) -> None:
        """Push every rule from settings into the backend in one atomic resync,
        clearing anything stale. Idempotent and safe to call after any edit.

        netsh (the OS firewall) is slow, so we only touch it when asked
        (sync_firewall=True, used at startup). Per-edit block/unblock is done
        directly by the caller, not here, so editing a limit or tag never
        spawns netsh processes on the GUI thread."""
        s = self.settings
        self._lan_nets = s.lan_networks()
        self.backend.set_purge_minutes(s.packet_purge_minutes)
        # One authoritative resync: the backend drops anything not in here.
        self.backend.sync_rules(
            exe_limits={e: tuple(v) for e, v in s.exe_limits.items()},
            tag_limits={t: tuple(v) for t, v in s.tag_limits.items()},
            exe_tags=dict(s.exe_tags),
        )
        if sync_firewall:
            try:
                from . import firewall
                if s.firewall_enabled:
                    # Only ever block concrete, valid exe paths. An empty/garbage
                    # path could otherwise become a block-everything rule.
                    to_block = set(e for e in s.blocked_exes if e)
                    for tag in s.tag_blocked:
                        to_block.update(e for e in s.exes_with_tag(tag) if e)
                    for exe in to_block:
                        firewall.block_app(exe)   # block_app re-validates too
                else:
                    # master switch is off: make sure none of our rules linger
                    firewall.remove_all_rules()
            except Exception:
                pass
        s.save()

    def stop(self) -> None:
        self._running.clear()
        self.backend.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        try:
            self.history.flush()
        except Exception:
            pass

    # ---- snapshot accessors (called from GUI thread) ----------------------
    def snapshot(self) -> Tuple[List[ProcStat], Totals]:
        with self._lock:
            return list(self._procs), Totals(**vars(self._totals))

    def restamp_rules(self) -> None:
        """Recompute the rule-derived fields (blocked / limits / tag) on the
        CURRENT snapshot from settings, without waiting for the next tick.

        Block/limit/tag state lives in settings and is changed synchronously by
        the GUI, but ProcStat carries a copy taken at tick time. Re-stamping
        lets the list reflect a just-applied rule immediately. This only touches
        derived fields (cheap, settings-only) so it's safe from the GUI thread."""
        s = self.settings
        if s.firewall_enabled:
            blocked_exes = set(s.blocked_exes)
            for btag in s.tag_blocked:
                blocked_exes.update(e for e in s.exes_with_tag(btag) if e)
        else:
            blocked_exes = set()
        with self._lock:
            for p in self._procs:
                exe = p.exe
                p.blocked = bool(exe) and exe in blocked_exes
                up, down = (s.exe_limit(exe) if exe else (0, 0))
                p.up_limit, p.down_limit = up, down
                p.tag = s.exe_tags.get(exe, "") if exe else ""

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
        """Set an app's own limit. It is clamped to its tag's limit (if any):
        an individual cap can be lower than the group cap but never higher."""
        if not exe:
            return
        up_bps, down_bps = self._clamp_to_tag(exe, up_bps, down_bps)
        if up_bps <= 0 and down_bps <= 0:
            self.settings.exe_limits.pop(exe, None)
        else:
            self.settings.exe_limits[exe] = [up_bps, down_bps]
        self.apply_settings()

    def set_exe_tag(self, exe: str, tag) -> None:
        if not exe:
            return
        if tag:
            self.settings.exe_tags[exe] = tag
        else:
            self.settings.exe_tags.pop(exe, None)
        # re-clamp this app's own limit against its (possibly new) tag cap
        if exe in self.settings.exe_limits:
            up, down = self.settings.exe_limit(exe)
            up, down = self._clamp_to_tag(exe, up, down)
            self.settings.exe_limits[exe] = [up, down]
        self.apply_settings()

    def set_tag_limit(self, tag: str, up_bps: int, down_bps: int) -> None:
        if not tag:
            return
        if up_bps <= 0 and down_bps <= 0:
            self.settings.tag_limits.pop(tag, None)
        else:
            self.settings.tag_limits[tag] = [up_bps, down_bps]
        # lowering a tag cap must pull every member's own limit down to fit
        for exe in self.settings.exes_with_tag(tag):
            if exe in self.settings.exe_limits:
                u, d = self.settings.exe_limit(exe)
                u, d = self._clamp_to_tag(exe, u, d)
                self.settings.exe_limits[exe] = [u, d]
        self.apply_settings()

    def set_tag_blocked(self, tag: str, blocked: bool) -> None:
        if not tag:
            return
        if blocked and tag not in self.settings.tag_blocked:
            self.settings.tag_blocked.append(tag)
        elif not blocked and tag in self.settings.tag_blocked:
            self.settings.tag_blocked.remove(tag)
        # block/unblock is the one thing that must hit netsh, done here directly
        try:
            from . import firewall
            for exe in self.settings.exes_with_tag(tag):
                if not exe:
                    continue
                if blocked:
                    if self.settings.firewall_enabled:
                        firewall.block_app(exe)
                elif exe not in self.settings.blocked_exes:
                    firewall.unblock_app(exe)
        except Exception:
            pass
        self.settings.save()

    def set_firewall_enabled(self, enabled: bool) -> None:
        """Master switch for firewall enforcement. Off removes all our block
        rules (traffic flows) but keeps the block configuration; On re-applies
        every configured block. Configuration is never lost either way."""
        self.settings.firewall_enabled = bool(enabled)
        self.settings.save()
        try:
            from . import firewall
            if enabled:
                to_block = set(e for e in self.settings.blocked_exes if e)
                for tag in self.settings.tag_blocked:
                    to_block.update(
                        e for e in self.settings.exes_with_tag(tag) if e)
                for exe in to_block:
                    firewall.block_app(exe)
            else:
                firewall.remove_all_rules()   # keeps settings, drops netsh rules
        except Exception:
            pass

    def remove_all_firewall_rules(self):
        """Emergency cleanup: delete every firewall rule this app created and
        clear our block state. Returns (count, message)."""
        try:
            from . import firewall
            count, msg = firewall.remove_all_rules()
        except Exception as exc:
            return 0, f"Could not remove rules: {exc}"
        self.settings.blocked_exes = []
        self.settings.tag_blocked = []
        self.settings.save()
        return count, msg

    def remove_app(self, exe: str) -> None:
        """Fully unmanage an app: drop block, limit and tag, then resync once."""
        if not exe:
            return
        s = self.settings
        if exe in s.blocked_exes:
            s.blocked_exes.remove(exe)
            try:
                from . import firewall
                firewall.unblock_app(exe)
            except Exception:
                pass
        s.exe_limits.pop(exe, None)
        s.exe_tags.pop(exe, None)
        self.apply_settings()

    # ---- tag-cap helper ---------------------------------------------------
    def _clamp_to_tag(self, exe: str, up: int, down: int) -> Tuple[int, int]:
        """An app under a tagged limit can never exceed the tag's cap."""
        tag = self.settings.exe_tags.get(exe)
        if not tag:
            return up, down
        tup, tdown = self.settings.tag_limit(tag)
        if tup > 0:
            up = tup if up <= 0 else min(up, tup)
        if tdown > 0:
            down = tdown if down <= 0 else min(down, tdown)
        return up, down

    def effective_limit(self, exe: str) -> Tuple[int, int, bool]:
        """The cap actually applied to an app: its own limit clamped by its
        tag's limit. Returns (up, down, from_tag) where from_tag is True if the
        cap comes purely from the tag (the app has no tighter own limit)."""
        own_up, own_down = self.settings.exe_limit(exe)
        capped_up, capped_down = self._clamp_to_tag(exe, own_up, own_down)
        from_tag = (own_up <= 0 and own_down <= 0) and \
                   (capped_up > 0 or capped_down > 0)
        return capped_up, capped_down, from_tag

    # ---- rule queries (for the manager windows) ---------------------------
    def is_blocked(self, exe: str) -> bool:
        """Effective block state: a direct block OR membership of a blocked tag.
        A block overrides all other rules."""
        if not exe:
            return False
        if exe in self.settings.blocked_exes:
            return True
        tag = self.settings.exe_tags.get(exe)
        return bool(tag) and tag in self.settings.tag_blocked

    def list_blocked(self) -> set[str]:
        return set(self.settings.blocked_exes)

    def list_limits(self) -> Dict[str, Tuple[int, int]]:
        return {k: (v[0], v[1]) for k, v in self.settings.exe_limits.items()}

    def managed_apps(self) -> Dict[str, tuple]:
        """{exe: (blocked, (eff_up, eff_down), tag, from_tag, via_tag)}.
        `blocked` is EFFECTIVE (direct or via a blocked tag); `via_tag` is True
        when the block comes from the tag rather than the app itself."""
        s = self.settings
        exes = set(s.blocked_exes) | set(s.exe_limits) | set(s.exe_tags)
        out = {}
        for exe in exes:
            eup, edown, from_tag = self.effective_limit(exe)
            tag = s.exe_tags.get(exe, "")
            direct = exe in s.blocked_exes
            via_tag = bool(tag) and tag in s.tag_blocked
            out[exe] = (direct or via_tag, (eup, edown), tag, from_tag, via_tag)
        return out

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
        # When the firewall master switch is off, nothing is actually enforced,
        # so the live list shows no blocks (the config is preserved in settings
        # and shown in the firewall manager).
        if s.firewall_enabled:
            blocked_exes = set(s.blocked_exes)
            # a tag with a block marks all its members as (effectively) blocked
            for btag in s.tag_blocked:
                blocked_exes.update(s.exes_with_tag(btag))
        else:
            blocked_exes = set()
        # exes that the limiter must police (own limit, or a limited tag)
        limited_exes = self.backend.limited_exes()
        enforced_ports: set = set()

        procs: List[ProcStat] = []
        up_total = down_total = 0.0

        # Union of pids that have connections, current traffic, or any history.
        live_pids = set(conns_by_pid) | set(pid_rates)
        pids = live_pids | set(pid_totals)
        now_wall = time.time()
        idle_secs = (s.idle_hide_minutes * 60) if s.idle_hide_minutes else None
        nets = self._lan_nets
        dead_pids: set = set()
        seen_pids: set = set()

        for pid in pids:
            # --- terminated-process cleanup: a history-only pid that no longer
            # exists is gone; drop it and forget its counters.
            if pid not in live_pids and not _pid_alive(pid):
                dead_pids.add(pid)
                continue
            seen_pids.add(pid)

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

            # --- activity tracking for idle-hiding. "Active" = measurable
            # traffic, or the set of connections changed (covers the no-driver
            # case where we can't see bytes).
            conn_set = frozenset(c.key for c in conns)
            changed = self._prev_conns.get(pid) != conn_set
            self._prev_conns[pid] = conn_set
            if (up > 0 or down > 0) or changed:
                self._last_active[pid] = now_wall
            last = self._last_active.setdefault(pid, now_wall)
            idle = idle_secs is not None and (now_wall - last) > idle_secs

            # --- WAN/LAN classification from the connections' remote IPs
            uses_wan = False
            for c in conns:
                if c.remote_ip and _is_wan(c.remote_ip, nets):
                    uses_wan = True
                    break

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
                uses_wan=uses_wan,
            )
            if not idle:                 # idle processes drop off the list
                procs.append(ps)

            # --- activity logging: per-exe byte delta since last tick
            if exe and (tup or tdown):
                ptup, ptdown = self._prev_pid_totals.get(pid, (0, 0))
                d_up = tup - ptup if tup >= ptup else tup
                d_down = tdown - ptdown if tdown >= ptdown else tdown
                if d_up > 0 or d_down > 0:
                    self.history.record(exe, ps.name, d_up, d_down)
            self._prev_pid_totals[pid] = (tup, tdown)

        # forget terminated pids everywhere
        if dead_pids:
            for pid in dead_pids:
                self._last_active.pop(pid, None)
                self._prev_conns.pop(pid, None)
                self._prev_pid_totals.pop(pid, None)
            self.backend.forget_pids(dead_pids)
        # also prune activity maps for pids we no longer track at all
        stale = set(self._last_active) - seen_pids - live_pids
        for pid in stale:
            self._last_active.pop(pid, None)
            self._prev_conns.pop(pid, None)

        # write out the rolling activity log every interval
        self.history.maybe_flush()

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
