"""Packet capture + traffic control backends.

WinDivertBackend is the real engine. It runs a SNIFF handle (read-only, never
affects your connectivity) that:
  * attributes every packet to a PID via ProcessMap,
  * accumulates per-process and per-connection byte counts (-> speeds),
  * keeps a ring buffer of recent packets per connection for the hex view.

When you apply a speed limit (or opt into WinDivert-based blocking) a SECOND,
separate ENFORCER handle is opened in normal (divert) mode. It only runs while
at least one rule is active, so your traffic path is untouched the rest of the
time. Persistent app blocking is handled by firewall.py (netsh) instead, which
carries no data-path risk.

If pydivert / WinDivert isn't installed, NullBackend is used and the app still
shows processes, connections and ports (just no per-process speeds or packets).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from .models import Packet
from .procmap import ProcessMap

# pydivert is Windows-only and needs the WinDivert driver. Import lazily so the
# rest of the app imports fine everywhere (Linux dev, CI, etc.).
try:
    import pydivert  # type: ignore
    HAVE_PYDIVERT = True
except Exception:  # ImportError on non-Windows, OSError if driver missing
    pydivert = None
    HAVE_PYDIVERT = False


ConnKey = Tuple[str, str, int, str, int]  # proto, lip, lport, rip, rport


class TokenBucket:
    """Classic token bucket for per-PID rate limiting (bytes/sec)."""

    def __init__(self, rate: int) -> None:
        self.rate = max(1, rate)
        self.tokens = float(self.rate)
        self.last = time.monotonic()

    def set_rate(self, rate: int) -> None:
        self.rate = max(1, rate)

    def allow(self, size: int) -> bool:
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= size:
            self.tokens -= size
            return True
        return False


class _Accum:
    """Mutable up/down byte counter, drained once per second into a rate."""
    __slots__ = ("up", "down")

    def __init__(self) -> None:
        self.up = 0
        self.down = 0


class CaptureBackend:
    """Interface the monitor/GUI program against."""

    available = False

    def start(self) -> None: ...
    def stop(self) -> None: ...

    def drain_rates(self, interval: float):
        """Return (pid_rates, conn_rates) as {key: (up_bps, down_bps)} and
        reset the counters. interval is seconds since the last drain."""
        return {}, {}

    def pid_totals(self):
        """Cumulative {pid: (bytes_up, bytes_down)} since start. Empty if the
        backend can't measure per-process bytes."""
        return {}

    def recent_packets(self, conn_key: ConnKey):
        return []

    # traffic control (keyed by executable path) ---------------------------
    def set_limit(self, exe: str, up_bps: int, down_bps: int) -> None: ...
    def set_blocked(self, exe: str, blocked: bool) -> None: ...


class NullBackend(CaptureBackend):
    """No driver available: monitoring still works, just no packets/speeds."""
    available = False

    def __init__(self, procmap: ProcessMap) -> None:
        self.procmap = procmap


class WinDivertBackend(CaptureBackend):
    available = True

    # A broad filter that captures IPv4/IPv6 TCP+UDP. ICMP omitted from control
    # but you can widen this to "ip or ipv6".
    SNIFF_FILTER = "tcp or udp"

    def __init__(self, procmap: ProcessMap,
                 packet_ring: int = 1500,
                 capture_payload: bool = True) -> None:
        self.procmap = procmap
        self.capture_payload = capture_payload

        self._lock = threading.Lock()
        self._pid_acc: Dict[int, _Accum] = defaultdict(_Accum)
        self._conn_acc: Dict[ConnKey, _Accum] = defaultdict(_Accum)
        # Cumulative per-PID byte totals since start. Unlike _pid_acc these are
        # never cleared, so they back the "total sent/received" columns.
        self._pid_total: Dict[int, _Accum] = defaultdict(_Accum)
        self._packets: Dict[ConnKey, Deque[Packet]] = defaultdict(
            lambda: deque(maxlen=packet_ring))

        self._sniff_thread: Optional[threading.Thread] = None
        self._enforce_thread: Optional[threading.Thread] = None
        self._running = threading.Event()

        # Rate-limit rules, keyed by executable path. NOTE: blocking is handled
        # exclusively by the OS firewall (firewall.py), NOT here. Diverting all
        # traffic through this userspace loop just to drop one app's packets
        # stalls everything else, so the enforcer only ever runs for limits.
        self._rules_lock = threading.Lock()
        self._buckets: Dict[str, Tuple[TokenBucket, TokenBucket]] = {}

    # ---- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, name="np-sniff", daemon=True)
        self._sniff_thread.start()

    def stop(self) -> None:
        self._running.clear()
        # threads are daemon + WinDivert handles unblock on close; give them a
        # moment to exit cleanly.
        for t in (self._sniff_thread, self._enforce_thread):
            if t and t.is_alive():
                t.join(timeout=2.0)

    # ---- monitoring (sniff) ----------------------------------------------
    def _sniff_loop(self) -> None:
        try:
            handle = pydivert.WinDivert(self.SNIFF_FILTER,
                                        flags=pydivert.Flag.SNIFF)
        except Exception as exc:  # driver not loadable / not elevated
            print(f"[netpeekier] WinDivert sniff failed: {exc}")
            self._running.clear()
            return
        with handle:
            while self._running.is_set():
                try:
                    packet = handle.recv()
                except Exception:
                    if not self._running.is_set():
                        break
                    continue
                self._on_packet(packet)

    def _on_packet(self, packet) -> None:
        proto, lip, lport, rip, rport, length = _decode(packet)
        if proto is None:
            return
        pid = self.procmap.pid_for_endpoint(proto, lip, lport)
        conn_key: ConnKey = (proto, lip, lport, rip, rport)
        outbound = bool(packet.is_outbound)

        with self._lock:
            if pid is not None:
                acc = self._pid_acc[pid]
                tot = self._pid_total[pid]
                if outbound:
                    acc.up += length
                    tot.up += length
                else:
                    acc.down += length
                    tot.down += length
            cacc = self._conn_acc[conn_key]
            if outbound:
                cacc.up += length
            else:
                cacc.down += length

            self._packets[conn_key].append(Packet(
                ts=time.time(), outbound=outbound, protocol=proto,
                local_ip=lip, local_port=lport, remote_ip=rip,
                remote_port=rport, length=length,
                raw=bytes(packet.raw) if self.capture_payload else b"",
                pid=pid,
            ))

    def drain_rates(self, interval: float):
        if interval <= 0:
            interval = 1.0
        with self._lock:
            pid_rates = {
                pid: (a.up / interval, a.down / interval)
                for pid, a in self._pid_acc.items() if a.up or a.down
            }
            conn_rates = {
                key: (a.up / interval, a.down / interval)
                for key, a in self._conn_acc.items() if a.up or a.down
            }
            self._pid_acc.clear()
            self._conn_acc.clear()
        return pid_rates, conn_rates

    def pid_totals(self) -> Dict[int, Tuple[int, int]]:
        """Cumulative (bytes_up, bytes_down) per PID since start."""
        with self._lock:
            return {pid: (a.up, a.down) for pid, a in self._pid_total.items()}

    def recent_packets(self, conn_key: ConnKey):
        with self._lock:
            return list(self._packets.get(conn_key, ()))

    # ---- traffic control (enforcer) --------------------------------------
    def set_limit(self, exe: str, up_bps: int, down_bps: int) -> None:
        if not exe:
            return
        with self._rules_lock:
            if up_bps <= 0 and down_bps <= 0:
                self._buckets.pop(exe, None)
            else:
                self._buckets[exe] = (
                    TokenBucket(up_bps if up_bps > 0 else 10**12),
                    TokenBucket(down_bps if down_bps > 0 else 10**12),
                )
        self._sync_enforcer()

    def set_blocked(self, exe: str, blocked: bool) -> None:
        # Intentionally a no-op. Blocking is enforced by the OS firewall
        # (firewall.py), which is selective and kernel-level. Doing it here
        # would force every packet through this loop and stall all traffic.
        return

    def _has_rules(self) -> bool:
        with self._rules_lock:
            return bool(self._buckets)

    def _sync_enforcer(self) -> None:
        """Start the enforcer thread on first limit; it self-exits when idle."""
        if self._has_rules() and (
                self._enforce_thread is None
                or not self._enforce_thread.is_alive()):
            self._enforce_thread = threading.Thread(
                target=self._enforce_loop, name="np-enforce", daemon=True)
            self._enforce_thread.start()

    def _enforce_loop(self) -> None:
        # Divert (not sniff): we now OWN these packets and MUST reinject the
        # ones we allow, or they are dropped. This loop is FAIL-OPEN: any error
        # or uncertainty reinjects the packet, so a bug here can never take the
        # machine offline. Only packets we can positively attribute to a
        # rate-limited app and that exceed its budget are dropped.
        try:
            handle = pydivert.WinDivert(self.SNIFF_FILTER)
        except Exception as exc:
            print(f"[netpeekier] WinDivert enforcer failed: {exc}")
            return
        with handle:
            while self._running.is_set() and self._has_rules():
                try:
                    packet = handle.recv()
                except Exception:
                    if not self._running.is_set():
                        break
                    continue
                # Keep our PID table fresh without depending on the monitor
                # thread's cadence (cheap: guarded by min_interval internally).
                try:
                    self.procmap.refresh()
                except Exception:
                    pass
                drop = False
                try:
                    drop = not self._allow_packet(packet)
                except Exception:
                    drop = False  # fail open
                if not drop:
                    try:
                        handle.send(packet)
                    except Exception:
                        pass

    def _allow_packet(self, packet) -> bool:
        # Fast path: no limits at all -> allow everything immediately.
        with self._rules_lock:
            if not self._buckets:
                return True
        proto, lip, lport, rip, rport, length = _decode(packet)
        if proto is None:
            return True
        pid = self.procmap.pid_for_endpoint(proto, lip, lport)
        if pid is None:
            return True
        exe = self.procmap.exe(pid)
        if not exe:
            return True
        with self._rules_lock:
            buckets = self._buckets.get(exe)
        if buckets is None:
            return True  # this app has no limit -> always allow
        up_b, down_b = buckets
        bucket = up_b if packet.is_outbound else down_b
        return bucket.allow(length)


def _decode(packet):
    """Pull (proto, local_ip, local_port, remote_ip, remote_port, length) out
    of a pydivert packet, oriented so local/remote are consistent regardless of
    direction. Returns proto=None for packets we don't track."""
    length = len(packet.raw)
    if packet.tcp is not None:
        proto = "TCP"
    elif packet.udp is not None:
        proto = "UDP"
    else:
        return None, "", 0, "", 0, length

    src_ip = packet.src_addr or ""
    dst_ip = packet.dst_addr or ""
    src_port = packet.src_port or 0
    dst_port = packet.dst_port or 0

    if packet.is_outbound:
        return proto, src_ip, src_port, dst_ip, dst_port, length
    else:
        return proto, dst_ip, dst_port, src_ip, src_port, length


def make_backend(procmap: ProcessMap) -> CaptureBackend:
    """Pick the best backend that will actually work right now."""
    if HAVE_PYDIVERT:
        try:
            # Probe: opening + closing a handle confirms driver + privilege.
            with pydivert.WinDivert("false"):
                pass
            return WinDivertBackend(procmap)
        except Exception as exc:
            print(f"[netpeekier] WinDivert unavailable ({exc}); "
                  "falling back to psutil-only mode.")
    return NullBackend(procmap)
