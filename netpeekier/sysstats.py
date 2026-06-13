"""System stats for the dashboard's third column.

Everything here is best-effort and degrades gracefully, exactly like the
WinDivert backend does: if a sensor (or the optional temperature library) isn't
available, the value is just None and the UI shows a dash. Nothing here can
raise into the monitor loop.

Sources, in order of preference:
  * psutil            -> CPU load + clock, RAM used%   (already a dependency)
  * HardwareMonitor   -> CPU/GPU/RAM temperatures, GPU clock/load  (OPTIONAL,
    LibreHardwareMonitor via pythonnet; needs admin + .NET on Windows)
  * pynvml (NVIDIA)   -> GPU temp/clock/load fallback if present  (OPTIONAL)

Temperatures and GPU details are simply absent without one of the optional
libraries; that's expected and documented.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

import psutil


@dataclass
class SysStats:
    cpu_load: Optional[float] = None     # %
    cpu_clock: Optional[float] = None    # MHz
    cpu_temp: Optional[float] = None     # °C
    gpu_load: Optional[float] = None     # %
    gpu_clock: Optional[float] = None    # MHz
    gpu_temp: Optional[float] = None     # °C
    ram_used: Optional[float] = None     # %
    ram_clock: Optional[float] = None    # MHz (rarely available)
    ram_temp: Optional[float] = None     # °C (rarely available)


def _fmt(value, suffix, decimals=0):
    if value is None:
        return "--"
    if decimals:
        return f"{value:.{decimals}f}{suffix}"
    return f"{value:.0f}{suffix}"


def _pick(named: dict, prefer=()):
    """Choose a value from {name: value}. Prefer a sensor whose name contains
    one of `prefer` (in order); otherwise return the max (the headline figure)."""
    if not named:
        return None
    for key in prefer:
        for name, val in named.items():
            if key in name:
                return val
    return max(named.values())


def _pick_temp(named: dict, prefer=(), avoid=()):
    """Like _pick but for temperatures: drop obviously-bogus readings (<=0 or
    absurdly high) so a 0 °C placeholder sensor never wins, and skip names in
    `avoid` (e.g. GPU hotspot) when a better one exists."""
    good = {n: v for n, v in named.items() if v is not None and 0 < v < 150}
    if not good:
        return None
    if avoid:
        filtered = {n: v for n, v in good.items()
                    if not any(a in n for a in avoid)}
        if filtered:
            good = filtered
    for key in prefer:
        for name, val in good.items():
            if key in name:
                return val
    return max(good.values())


class SystemMonitor:
    """Polls system sensors on a background thread so the GUI just reads the
    latest snapshot. Sensor reads (especially the .NET temp library) can be
    slow, so they never run on the GUI or network-monitor threads."""

    def __init__(self, interval: float = 2.0) -> None:
        self.interval = interval
        self._stats = SysStats()
        self._lock = threading.Lock()
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._hw = None            # LibreHardwareMonitor handle, if available
        self._nvml = None          # pynvml handle, if available
        self.temp_source = "none"  # for the status bar / about info

    # ---- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._running.is_set():
            return
        self._init_optional_sensors()
        self._running.set()
        self._thread = threading.Thread(
            target=self._loop, name="np-sysmon", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        try:
            if self._hw is not None:
                self._hw.Close()
        except Exception:
            pass

    def snapshot(self) -> SysStats:
        with self._lock:
            return SysStats(**vars(self._stats))

    # ---- optional sensor setup -------------------------------------------
    def _init_optional_sensors(self) -> None:
        # LibreHardwareMonitor (covers CPU/GPU/RAM temps + GPU clock/load)
        try:
            from HardwareMonitor.Hardware import Computer  # type: ignore
            c = Computer()
            c.IsCpuEnabled = True
            c.IsGpuEnabled = True
            c.IsMemoryEnabled = True
            c.Open()
            self._hw = c
            self.temp_source = "LibreHardwareMonitor"
            return
        except Exception:
            self._hw = None
        # NVIDIA-only fallback for GPU
        try:
            import pynvml  # type: ignore
            pynvml.nvmlInit()
            self._nvml = pynvml
            if self.temp_source == "none":
                self.temp_source = "NVML (GPU only)"
        except Exception:
            self._nvml = None

    # ---- polling ----------------------------------------------------------
    def _loop(self) -> None:
        # prime cpu_percent so the first real reading isn't 0.0
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass
        while self._running.is_set():
            s = SysStats()
            self._read_psutil(s)
            if self._hw is not None:
                self._read_hardwaremonitor(s)
            elif self._nvml is not None:
                self._read_nvml(s)
            with self._lock:
                self._stats = s
            # responsive shutdown
            for _ in range(int(self.interval * 10)):
                if not self._running.is_set():
                    break
                time.sleep(0.1)

    def _read_psutil(self, s: SysStats) -> None:
        try:
            s.cpu_load = psutil.cpu_percent(interval=None)
        except Exception:
            pass
        try:
            freq = psutil.cpu_freq()
            if freq:
                s.cpu_clock = float(freq.current)
        except Exception:
            pass
        try:
            s.ram_used = psutil.virtual_memory().percent
        except Exception:
            pass

    def _read_hardwaremonitor(self, s: SysStats) -> None:
        try:
            from HardwareMonitor.Hardware import HardwareType, SensorType  # type: ignore
        except Exception:
            return
        try:
            # collect candidate sensors, then choose the best per metric
            cpu_temps = {}   # name -> value
            gpu_temps = {}
            mem_temps = {}
            cpu_clocks = []
            gpu_clocks = {}
            gpu_loads = {}
            mem_clocks = {}
            for hw in self._hw.Hardware:
                hw.Update()
                for sub in hw.SubHardware:
                    sub.Update()
                htype = hw.HardwareType
                is_cpu = htype == HardwareType.Cpu
                is_gpu = str(htype).startswith("Gpu")
                is_mem = htype == HardwareType.Memory
                for sensor in hw.Sensors:
                    val = sensor.Value
                    if val is None:
                        continue
                    val = float(val)
                    st = sensor.SensorType
                    name = (sensor.Name or "").lower()
                    if st == SensorType.Temperature:
                        if is_cpu:
                            cpu_temps[name] = val
                        elif is_gpu:
                            gpu_temps[name] = val
                        elif is_mem:
                            mem_temps[name] = val
                    elif st == SensorType.Load:
                        if is_gpu:
                            gpu_loads[name] = val
                    elif st == SensorType.Clock:
                        if is_cpu:
                            cpu_clocks.append(val)
                        elif is_gpu:
                            gpu_clocks[name] = val
                        elif is_mem:
                            mem_clocks[name] = val

            s.cpu_temp = _pick_temp(
                cpu_temps, prefer=("package", "tctl", "tdie", "ccd", "core max"))
            s.gpu_temp = _pick_temp(
                gpu_temps, prefer=("core", "gpu", "edge"), avoid=("hot", "junction"))
            s.ram_temp = _pick_temp(mem_temps, prefer=("memory", "dimm", "module"))
            s.gpu_clock = _pick(gpu_clocks, prefer=("core", "gpu"))
            s.gpu_load = _pick(gpu_loads, prefer=("core", "gpu"))
            s.ram_clock = _pick(mem_clocks, prefer=("memory", "clock"))
        except Exception:
            pass

    def _read_nvml(self, s: SysStats) -> None:
        try:
            h = self._nvml.nvmlDeviceGetHandleByIndex(0)
            s.gpu_temp = float(self._nvml.nvmlDeviceGetTemperature(
                h, self._nvml.NVML_TEMPERATURE_GPU))
            util = self._nvml.nvmlDeviceGetUtilizationRates(h)
            s.gpu_load = float(util.gpu)
            s.gpu_clock = float(self._nvml.nvmlDeviceGetClockInfo(
                h, self._nvml.NVML_CLOCK_GRAPHICS))
        except Exception:
            pass
