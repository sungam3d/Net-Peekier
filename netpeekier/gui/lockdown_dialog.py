"""Lockdown permission prompt.

Shown when, under Lockdown Mode, a non-allowed process tries to reach the
internet. The process is already blocked by default-deny; this dialog lets the
user decide what to do, NetPeeker-style:

  * Allow for N minutes   (N is remembered between prompts)
  * Add to allow list      (permanent)
  * Block this time        (stays blocked this session)
  * Add to block list      (permanent block)
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import font as tkfont

from .winutil import center_on_parent


class LockdownPrompt(tk.Toplevel):
    def __init__(self, master, monitor, exe: str, name: str,
                 on_done=None) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.exe = exe
        self._on_done = on_done
        self.title("Lockdown - allow connection?")
        self.resizable(False, False)
        self.configure(bg="white")
        base = tkfont.nametofont("TkDefaultFont").actual("family")

        tk.Label(self, bg="white", fg="#9a2b2b", font=(base, 12, "bold"),
                 text="A program is trying to reach the internet").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(14, 4))

        tk.Label(self, bg="white", font=(base, 11, "bold"),
                 text=name).grid(row=1, column=0, columnspan=2, sticky="w",
                                 padx=16)
        tk.Label(self, bg="white", fg="#666", font=(base, 9),
                 wraplength=420, justify="left",
                 text=exe).grid(row=2, column=0, columnspan=2, sticky="w",
                                padx=16, pady=(0, 10))

        # allow-for-N-minutes row
        row = tk.Frame(self, bg="white")
        row.grid(row=3, column=0, columnspan=2, sticky="w", padx=16)
        tk.Label(row, bg="white", text="Allow for").pack(side="left")
        self.var_min = tk.StringVar(value=str(monitor.settings.allow_minutes))
        tk.Entry(row, textvariable=self.var_min, width=5).pack(
            side="left", padx=4)
        tk.Label(row, bg="white", text="minutes").pack(side="left")

        btns = tk.Frame(self, bg="white")
        btns.grid(row=4, column=0, columnspan=2, pady=12, padx=16, sticky="ew")
        tk.Button(btns, text="Allow for N min", width=16,
                  command=self._allow_temp).grid(row=0, column=0, padx=3, pady=3)
        tk.Button(btns, text="Add to allow list", width=16,
                  command=self._allow_perm).grid(row=0, column=1, padx=3, pady=3)
        tk.Button(btns, text="Block this time", width=16,
                  command=self._block_once).grid(row=1, column=0, padx=3, pady=3)
        tk.Button(btns, text="Add to block list", width=16,
                  command=self._block_perm).grid(row=1, column=1, padx=3, pady=3)

        self.protocol("WM_DELETE_WINDOW", self._block_once)  # default = stay denied
        center_on_parent(self, master)
        try:
            self.attributes("-topmost", True)
        except Exception:
            pass

    def _minutes(self) -> int:
        try:
            return max(1, int(self.var_min.get().strip()))
        except ValueError:
            return self.monitor.settings.allow_minutes

    def _allow_temp(self) -> None:
        self.monitor.allow_temporarily(self.exe, self._minutes())
        self._finish()

    def _allow_perm(self) -> None:
        self.monitor.set_allowed(self.exe, True)
        self._finish()

    def _block_once(self) -> None:
        self.monitor.lockdown_block(self.exe, permanent=False)
        self._finish()

    def _block_perm(self) -> None:
        self.monitor.lockdown_block(self.exe, permanent=True)
        self._finish()

    def _finish(self) -> None:
        if self._on_done:
            try:
                self._on_done()
            except Exception:
                pass
        self.destroy()
