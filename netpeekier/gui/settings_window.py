"""Settings page.

Controls, all persisted:
  * Speed unit  - how upload/download rates are shown across the app.
  * Packet log purge - drop captured packets older than N minutes.
  * Idle hiding - drop processes with no internet activity for N minutes (they
    reappear when they next use the network).
  * LAN ranges - the address ranges treated as local; anything outside them is
    WAN. Drives the Show LAN / Show WAN toggles on the main window.
"""
from __future__ import annotations

import ipaddress
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from ..monitor import Monitor
from ..settings import SPEED_UNITS, DEFAULT_LAN_RANGES
from ..util import human_speed
from .winutil import center_on_parent

_SAMPLE_BPS = 1_572_864  # 1.5 MB/s, a tidy number to preview each unit with
_INVALID = object()


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
        prow = tk.Frame(purge_box)
        prow.grid(row=1, column=0, sticky="w", padx=8, pady=(0, 8))
        ppm = self.settings.packet_purge_minutes
        self.var_purge = tk.StringVar(value=str(ppm) if ppm else "")
        tk.Entry(prow, textvariable=self.var_purge, width=8).pack(side="left")
        tk.Label(prow, text="minutes   (blank = never delete)").pack(
            side="left", padx=6)

        # ---- idle hiding --------------------------------------------------
        idle_box = tk.LabelFrame(self, text="Hide idle processes")
        idle_box.grid(row=2, column=0, sticky="ew", **pad)
        tk.Label(idle_box, justify="left", anchor="w",
                 text="Remove processes with no internet activity for:").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 2))
        irow = tk.Frame(idle_box)
        irow.grid(row=1, column=0, sticky="w", padx=8, pady=(0, 4))
        ihm = self.settings.idle_hide_minutes
        self.var_idle = tk.StringVar(value=str(ihm) if ihm else "")
        tk.Entry(irow, textvariable=self.var_idle, width=8).pack(side="left")
        tk.Label(irow, text="minutes   (blank = always show)").pack(
            side="left", padx=6)
        tk.Label(idle_box, fg="#666", justify="left", anchor="w",
                 wraplength=380,
                 text="A hidden process reappears the moment it uses the "
                      "network again.").grid(
            row=2, column=0, sticky="w", padx=8, pady=(0, 8))

        # ---- LAN ranges ---------------------------------------------------
        lan_box = tk.LabelFrame(self, text="LAN address ranges "
                                          "(everything else is WAN / internet)")
        lan_box.grid(row=3, column=0, sticky="ew", **pad)
        lwrap = tk.Frame(lan_box)
        lwrap.grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.lan_list = tk.Listbox(lwrap, height=6, width=34,
                                   exportselection=False)
        self.lan_list.pack(side="left")
        lsb = ttk.Scrollbar(lwrap, orient="vertical",
                            command=self.lan_list.yview)
        self.lan_list.configure(yscrollcommand=lsb.set)
        lsb.pack(side="left", fill="y")
        for r in self.settings.lan_ranges:
            self.lan_list.insert("end", r)
        lbtns = tk.Frame(lan_box)
        lbtns.grid(row=0, column=1, sticky="n", padx=6, pady=6)
        tk.Button(lbtns, text="Add...", width=12,
                  command=self._lan_add).pack(pady=2)
        tk.Button(lbtns, text="Edit...", width=12,
                  command=self._lan_edit).pack(pady=2)
        tk.Button(lbtns, text="Remove", width=12,
                  command=self._lan_remove).pack(pady=2)
        tk.Button(lbtns, text="Reset defaults", width=12,
                  command=self._lan_reset).pack(pady=2)

        # ---- buttons ------------------------------------------------------
        btns = tk.Frame(self)
        btns.grid(row=4, column=0, sticky="e", padx=10, pady=(2, 10))
        tk.Button(btns, text="Save", width=10, command=self._save).pack(
            side="left", padx=4)
        tk.Button(btns, text="Close", width=10, command=self.destroy).pack(
            side="left", padx=4)

        self._update_preview()
        center_on_parent(self, master)
        self.grab_set()

    def _update_preview(self) -> None:
        unit = self.var_unit.get()
        self.preview.config(text="Example:\n" + human_speed(_SAMPLE_BPS, unit))

    # ---- LAN range editing ------------------------------------------------
    @staticmethod
    def _valid_cidr(text: str):
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except Exception:
            return None

    def _lan_add(self) -> None:
        raw = simpledialog.askstring(
            "Add LAN range",
            "Enter a CIDR range (e.g. 192.168.0.0/16 or 10.0.0.0/8):",
            parent=self)
        if raw is None:
            return
        cidr = self._valid_cidr(raw.strip())
        if not cidr:
            messagebox.showerror("Add LAN range",
                                 "That isn't a valid CIDR range.", parent=self)
            return
        if cidr not in self.lan_list.get(0, "end"):
            self.lan_list.insert("end", cidr)

    def _lan_edit(self) -> None:
        sel = self.lan_list.curselection()
        if not sel:
            return
        idx = sel[0]
        raw = simpledialog.askstring(
            "Edit LAN range", "CIDR range:",
            initialvalue=self.lan_list.get(idx), parent=self)
        if raw is None:
            return
        cidr = self._valid_cidr(raw.strip())
        if not cidr:
            messagebox.showerror("Edit LAN range",
                                 "That isn't a valid CIDR range.", parent=self)
            return
        self.lan_list.delete(idx)
        self.lan_list.insert(idx, cidr)
        self.lan_list.selection_set(idx)

    def _lan_remove(self) -> None:
        sel = self.lan_list.curselection()
        if sel:
            self.lan_list.delete(sel[0])

    def _lan_reset(self) -> None:
        if messagebox.askyesno("Reset LAN ranges",
                               "Replace the list with the built-in defaults?",
                               parent=self):
            self.lan_list.delete(0, "end")
            for r in DEFAULT_LAN_RANGES:
                self.lan_list.insert("end", r)

    # ---- save -------------------------------------------------------------
    def _save(self) -> None:
        purge = self._parse_minutes(self.var_purge.get(), "Purge interval")
        if purge is _INVALID:
            return
        idle = self._parse_minutes(self.var_idle.get(), "Idle timeout")
        if idle is _INVALID:
            return
        self.settings.speed_unit = self.var_unit.get()
        self.settings.packet_purge_minutes = purge
        self.settings.idle_hide_minutes = idle
        ranges = list(self.lan_list.get(0, "end"))
        self.settings.lan_ranges = ranges or list(DEFAULT_LAN_RANGES)
        self.settings.save()
        self.monitor.apply_settings()
        self.destroy()

    def _parse_minutes(self, raw: str, label: str):
        raw = raw.strip()
        if raw == "":
            return None
        try:
            v = int(raw)
            if v <= 0:
                raise ValueError
            return v
        except ValueError:
            messagebox.showerror(
                "Settings",
                f"{label} must be a whole number of minutes, or blank.",
                parent=self)
            return _INVALID
