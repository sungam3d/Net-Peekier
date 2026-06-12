"""Settings page.

Two controls, both persisted:
  * Speed unit  - how upload/download rates are shown across the app. A live
    preview shows a sample speed in the chosen unit.
  * Packet log purge - drop captured packets older than N minutes (blank = keep,
    relying only on the per-connection ring buffer). This keeps long sessions
    from growing the in-memory packet logs without bound.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from ..monitor import Monitor
from ..settings import SPEED_UNITS
from ..util import human_speed

_SAMPLE_BPS = 1_572_864  # 1.5 MB/s, a tidy number to preview each unit with


class SettingsWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.settings = monitor.settings
        self.title("Net-Peekier - Settings")
        self.resizable(False, False)
        self.transient(master)

        pad = {"padx": 10, "pady": 6}

        # ---- speed unit ---------------------------------------------------
        unit_box = tk.LabelFrame(self, text="Speed display unit")
        unit_box.grid(row=0, column=0, sticky="ew", **pad)

        self.var_unit = tk.StringVar(value=self.settings.speed_unit)
        for i, u in enumerate(SPEED_UNITS):
            label = "Auto (scale each value)" if u == "auto" else u
            ttk.Radiobutton(unit_box, text=label, value=u,
                            variable=self.var_unit,
                            command=self._update_preview).grid(
                row=i, column=0, sticky="w", padx=8, pady=2)

        self.preview = tk.Label(unit_box, text="", fg="#0a4d7d",
                                font=("Consolas", 11, "bold"))
        self.preview.grid(row=0, column=1, rowspan=len(SPEED_UNITS),
                          padx=16, sticky="w")

        # ---- packet purge -------------------------------------------------
        purge_box = tk.LabelFrame(self, text="Captured packet logs")
        purge_box.grid(row=1, column=0, sticky="ew", **pad)

        tk.Label(purge_box, justify="left", anchor="w",
                 text="Delete captured packets older than:").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 2))

        row = tk.Frame(purge_box)
        row.grid(row=1, column=0, sticky="w", padx=8, pady=(0, 4))
        ppm = self.settings.packet_purge_minutes
        self.var_purge = tk.StringVar(value=str(ppm) if ppm else "")
        tk.Entry(row, textvariable=self.var_purge, width=8).pack(side="left")
        tk.Label(row, text="minutes   (leave blank to never delete)").pack(
            side="left", padx=6)

        tk.Label(purge_box, fg="#666", justify="left", anchor="w",
                 wraplength=380,
                 text="Packets are also capped per connection, but over a long "
                      "session the number of tracked connections can grow. A "
                      "purge interval keeps memory in check.").grid(
            row=2, column=0, sticky="w", padx=8, pady=(0, 8))

        # ---- buttons ------------------------------------------------------
        btns = tk.Frame(self)
        btns.grid(row=2, column=0, sticky="e", padx=10, pady=(2, 10))
        tk.Button(btns, text="Save", width=10, command=self._save).pack(
            side="left", padx=4)
        tk.Button(btns, text="Close", width=10, command=self.destroy).pack(
            side="left", padx=4)

        self._update_preview()
        self.grab_set()

    def _update_preview(self) -> None:
        unit = self.var_unit.get()
        self.preview.config(text="Example:\n" + human_speed(_SAMPLE_BPS, unit))

    def _save(self) -> None:
        raw = self.var_purge.get().strip()
        if raw == "":
            minutes = None
        else:
            try:
                minutes = int(raw)
                if minutes <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror(
                    "Settings",
                    "Purge interval must be a whole number of minutes,\n"
                    "or blank to disable deletion.", parent=self)
                return

        self.settings.speed_unit = self.var_unit.get()
        self.settings.packet_purge_minutes = minutes
        self.settings.save()
        self.monitor.apply_settings()
        self.destroy()
