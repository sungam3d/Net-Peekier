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
    """Classic token bucket for rate limiting (bytes/sec).

    Split into can()/take() so a packet that must satisfy several buckets (its
    own limit AND a shared tag limit) only consumes tokens when ALL of them can
    afford it -- otherwise checking the first would wrongly burn its tokens.
    """

    def __init__(self, rate: int) -> None:
        self.rate = max(1, rate)
        self.tokens = float(self.rate)
        self.last = time.monotonic()

    def set_rate(self, rate: int) -> None:
        self.rate = max(1, rate)

    def _refill(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
        self.last = now

    def can(self, size: int) -> bool:
        self._refill()
        return self.tokens >= size

    def take(self, size: int) -> None:
        self.tokens -= size

    def allow(self, size: int) -> bool:
        if self.can(size):
            self.take(size)
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

    def forget_pids(self, pids) -> None:
        """Drop cached byte counters for terminated PIDs."""
        ...

    def conn_totals(self):
        """Cumulative {conn_key: (bytes_up, bytes_down)} since start."""
        return {}

    def set_purge_minutes(self, minutes) -> None: ...
    def purge_packets(self) -> None: ...

    def recent_packets(self, conn_key: ConnKey):
        return []

    # traffic control (keyed by executable path) ---------------------------
    def set_limit(self, exe: str, up_bps: int, down_bps: int) -> None: ...
    def set_blocked(self, exe: str, blocked: bool) -> None: ...
    def set_tag_limit(self, tag: str, up_bps: int, down_bps: int) -> None: ...
    def set_exe_tag(self, exe: str, tag) -> None: ...
    def set_enforced_ports(self, ports) -> None: ...

    def sync_rules(self, exe_limits, tag_limits, exe_tags) -> None:
        """Atomically replace ALL limit/tag rules with the given snapshot,
        dropping anything stale. This is the authoritative path."""
        ...

    def limited_exes(self) -> set:
        return set()


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
        # Cumulative byte totals since start. Unlike the *_acc dicts these are
        # never reset, so they back the "total sent/received" columns.
        self._pid_total: Dict[int, _Accum] = defaultdict(_Accum)
        self._conn_total: Dict[ConnKey, _Accum] = defaultdict(_Accum)
        self._packets: Dict[ConnKey, Deque[Packet]] = defaultdict(
            lambda: deque(maxlen=packet_ring))
        # packet-log purge: None = keep (ring cap only); N = drop older than N min
        self._purge_minutes: Optional[int] = None

        self._sniff_thread: Optional[threading.Thread] = None
        self._enforce_thread: Optional[threading.Thread] = None
        self._running = threading.Event()

        # Rate-limit rules. Blocking is handled exclusively by the OS firewall
        # (firewall.py), never here. The enforcer ONLY diverts the specific
        # ports of limited apps (see _enforced_ports), so other processes are
        # never pulled through this userspace loop.
        self._rules_lock = threading.Lock()
        self._buckets: Dict[str, Tuple[TokenBucket, TokenBucket]] = {}  # exe
        self._tag_buckets: Dict[str, Tuple[TokenBucket, TokenBucket]] = {}  # tag
        self._exe_tag: Dict[str, str] = {}        # exe -> tag
        # Lock-free snapshot the enforcer reads on the per-packet hot path, so a
        # packet storm never contends on _rules_lock with the GUI/monitor (which
        # would make rule edits hang). Rebound atomically whenever rules change.
        self._snapshot: Tuple[dict, dict, dict] = ({}, {}, {})
        # Local ports of all limited apps; the divert filter is built from this
        # so the enforcer only ever sees the targeted apps' packets.
        self._enforced_ports: set[int] = set()
        self._enforce_handle = None               # live divert handle (to close)

    def _rebuild_snapshot(self) -> None:
        """Refresh the lock-free snapshot. Call with _rules_lock held."""
        self._snapshot = (dict(self._buckets), dict(self._tag_buckets),
                          dict(self._exe_tag))

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
            ctot = self._conn_total[conn_key]
            if outbound:
                cacc.up += length
                ctot.up += length
            else:
                cacc.down += length
                ctot.down += length

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

    def forget_pids(self, pids) -> None:
        with self._lock:
            for pid in pids:
                self._pid_total.pop(pid, None)
                self._pid_acc.pop(pid, None)

    def conn_totals(self) -> Dict[ConnKey, Tuple[int, int]]:
        """Cumulative (bytes_up, bytes_down) per connection since start."""
        with self._lock:
            return {k: (a.up, a.down) for k, a in self._conn_total.items()}

    def set_purge_minutes(self, minutes: Optional[int]) -> None:
        with self._lock:
            self._purge_minutes = minutes if minutes and minutes > 0 else None

    def purge_packets(self) -> None:
        """Drop captured packets older than the configured window, and forget
        connections whose buffers go empty. No-op when purging is disabled."""
        with self._lock:
            if not self._purge_minutes:
                return
            cutoff = time.time() - self._purge_minutes * 60
            empty: list = []
            for key, dq in self._packets.items():
                while dq and dq[0].ts < cutoff:
                    dq.popleft()
                if not dq:
                    empty.append(key)
            for key in empty:
                del self._packets[key]
                # the cumulative counter for a long-dead connection can go too
                self._conn_total.pop(key, None)

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
            self._rebuild_snapshot()
        self._sync_enforcer()

    def set_tag_limit(self, tag: str, up_bps: int, down_bps: int) -> None:
        """Aggregate limit shared by every app carrying this tag."""
        if not tag:
            return
        with self._rules_lock:
            if up_bps <= 0 and down_bps <= 0:
                self._tag_buckets.pop(tag, None)
            else:
                self._tag_buckets[tag] = (
                    TokenBucket(up_bps if up_bps > 0 else 10**12),
                    TokenBucket(down_bps if down_bps > 0 else 10**12),
                )
            self._rebuild_snapshot()
        self._sync_enforcer()

    def set_exe_tag(self, exe: str, tag: Optional[str]) -> None:
        with self._rules_lock:
            if tag:
                self._exe_tag[exe] = tag
            else:
                self._exe_tag.pop(exe, None)
            self._rebuild_snapshot()

    def sync_rules(self, exe_limits, tag_limits, exe_tags) -> None:
        """Atomically rebuild every rule from an authoritative snapshot. Any
        bucket/tag/mapping not present here is dropped -- this is what prevents
        stale rules (e.g. a tag whose apps were removed) from lingering and
        keeping the enforcer alive or mis-attributing packets."""
        with self._rules_lock:
            self._buckets = {
                exe: (TokenBucket(u if u > 0 else 10**12),
                      TokenBucket(d if d > 0 else 10**12))
                for exe, (u, d) in exe_limits.items() if (u > 0 or d > 0)
            }
            self._tag_buckets = {
                tag: (TokenBucket(u if u > 0 else 10**12),
                      TokenBucket(d if d > 0 else 10**12))
                for tag, (u, d) in tag_limits.items() if (u > 0 or d > 0)
            }
            self._exe_tag = {e: t for e, t in exe_tags.items() if t}
            self._rebuild_snapshot()
        # If that cleared the last rule, wake the enforcer so it releases its
        # divert handle now instead of waiting for the next packet -- otherwise
        # a handle could linger with no rules behind it.
        if not self._has_rules():
            handle = self._enforce_handle
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
        self._sync_enforcer()

    def set_enforced_ports(self, ports: set) -> None:
        """Local ports of all limited apps. The divert filter is rebuilt from
        these so ONLY those apps' packets are pulled into userspace; everything
        else stays on the kernel fast path and is never affected."""
        ports = set(ports)
        with self._rules_lock:
            changed = ports != self._enforced_ports
            self._enforced_ports = ports
            handle = self._enforce_handle
        if changed and handle is not None:
            # break the blocking recv so the loop rebuilds its filter
            try:
                handle.close()
            except Exception:
                pass

    def set_blocked(self, exe: str, blocked: bool) -> None:
        # No-op. Blocking is the OS firewall's job (selective, kernel-level).
        return

    def _has_rules(self) -> bool:
        with self._rules_lock:
            return bool(self._buckets or self._tag_buckets)

    def _sync_enforcer(self) -> None:
        """Start the enforcer thread on first limit; it self-exits when idle."""
        if self._has_rules() and (
                self._enforce_thread is None
                or not self._enforce_thread.is_alive()):
            self._enforce_thread = threading.Thread(
                target=self._enforce_loop, name="np-enforce", daemon=True)
            self._enforce_thread.start()

    def _build_filter(self) -> Optional[str]:
        """A WinDivert filter that matches ONLY the limited apps' ports, so the
        enforcer never touches unrelated traffic. None -> nothing to enforce."""
        with self._rules_lock:
            ports = sorted(self._enforced_ports)
        if not ports:
            return None
        clauses = [
            f"(tcp.SrcPort=={p} or tcp.DstPort=={p} or "
            f"udp.SrcPort=={p} or udp.DstPort=={p})"
            for p in ports
        ]
        flt = " or ".join(clauses)
        # WinDivert caps filter length; if we somehow exceed it, enforce nothing
        # rather than fall back to a machine-wide divert (which is the bug we're
        # avoiding). In practice a handful of limited apps stays well under.
        return flt if len(flt) < 1800 else None

    def _enforce_loop(self) -> None:
        # Divert mode: we OWN matched packets and MUST reinject the allowed ones
        # or they're dropped. FAIL-OPEN throughout: any error reinjects. Because
        # the filter is scoped to limited ports, the blast radius is only the
        # apps you chose to limit -- never the rest of the system.
        current_filter = None
        handle = None
        processed = 0
        dropped = 0
        while self._running.is_set() and self._has_rules():
            want = self._build_filter()
            if want != current_filter:
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
                    handle = None
                    with self._rules_lock:
                        self._enforce_handle = None
                current_filter = want
                if want is None:
                    time.sleep(0.4)  # nothing to police yet; wait for ports
                    continue
                try:
                    handle = pydivert.WinDivert(want)
                    handle.open()
                    # Keep the driver's queue shallow so that when an app blasts
                    # above its limit, excess packets are dropped quickly by the
                    # driver (the throttle) instead of buffering up latency.
                    try:
                        handle.queue_len = 2048
                        handle.queue_time = 256   # ms
                    except Exception:
                        pass
                    with self._rules_lock:
                        self._enforce_handle = handle
                except Exception as exc:
                    print(f"[netpeekier] WinDivert enforcer failed: {exc}")
                    time.sleep(0.5)
                    handle = None
                    continue
            try:
                packet = handle.recv()
            except Exception:
                # handle was closed (ports changed) or stopping; re-evaluate
                handle = None
                current_filter = None
                with self._rules_lock:
                    self._enforce_handle = None
                continue
            drop = False
            try:
                drop = not self._allow_packet(packet)
            except Exception:
                drop = False
            if not drop:
                try:
                    handle.send(packet)
                except Exception:
                    pass
            # Yield the GIL periodically so a high-rate flow (e.g. throttling a
            # game blasting UDP) can never starve the Tkinter GUI thread. When
            # we're dropping (a storm above budget) we yield more eagerly; the
            # over-budget packets we don't pull fast enough overflow the driver
            # queue and get dropped there -- which is the throttle doing its job
            # while keeping the UI responsive.
            processed += 1
            if drop:
                dropped += 1
                if (dropped & 0x3F) == 0:          # every 64 drops
                    time.sleep(0.001)
            elif (processed & 0xFF) == 0:           # every 256 forwarded
                time.sleep(0)                       # bare GIL yield
        # cleanup
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
            with self._rules_lock:
                self._enforce_handle = None

    def _allow_packet(self, packet) -> bool:
        # Cheapest possible early-out: read the snapshot once (atomic rebind).
        exe_b, tag_b, exe_tag = self._snapshot
        if not exe_b and not tag_b:
            return True
        proto, lport, length = _decode_fast(packet)
        if proto is None or not lport:
            return True
        pid = self.procmap.pid_for_port(proto, lport)
        if pid is None:
            return True
        exe = self.procmap.exe(pid)
        if not exe:
            return True
        exe_buckets = exe_b.get(exe)
        tag = exe_tag.get(exe)
        tag_buckets = tag_b.get(tag) if tag else None
        if exe_buckets is None and tag_buckets is None:
            return True
        outbound = packet.is_outbound
        # Must satisfy BOTH its own limit and any shared tag limit. The shared
        # tag bucket is what makes several tagged apps compete for one budget.
        # Check all relevant buckets first and only consume if every one fits.
        relevant = []
        for buckets in (exe_buckets, tag_buckets):
            if buckets is not None:
                relevant.append(buckets[0] if outbound else buckets[1])
        if all(b.can(length) for b in relevant):
            for b in relevant:
                b.take(length)
            return True
        return False

    def limited_exes(self) -> set:
        """Exes that currently have any limit (own or via a limited tag)."""
        with self._rules_lock:
            exes = set(self._buckets)
            limited_tags = set(self._tag_buckets)
            for exe, tag in self._exe_tag.items():
                if tag in limited_tags:
                    exes.add(exe)
        return exes


def _decode(packet):
    """Pull (proto, local_ip, local_port, remote_ip, remote_port, length) out
    of a pydivert packet, oriented so local/remote are consistent regardless of
    direction. Returns proto=None for packets we don't track. Used for the
    packet-capture view where full addresses matter."""
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


def _decode_fast(packet):
    """Minimal decode for the enforcer hot path: only the protocol, the LOCAL
    port and the length -- enough to attribute the packet to a process. Skips
    the (relatively costly) src/dst IP string parsing that the throttle never
    needs, so a high-rate flow stays cheap to process.

    Returns (proto, local_port, length) or (None, 0, length)."""
    length = len(packet.raw)
    tcp = packet.tcp
    if tcp is not None:
        proto = "TCP"
    elif packet.udp is not None:
        proto = "UDP"
    else:
        return None, 0, length
    # local port = src port when outbound, dst port when inbound
    if packet.is_outbound:
        return proto, (packet.src_port or 0), length
    return proto, (packet.dst_port or 0), length


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
