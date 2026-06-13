"""A small dialog for choosing a group tag.

Offers existing tags in an editable combobox (drop-down) while still allowing a
brand-new tag to be typed in. Used by the main-list "Set tag" action and by the
firewall manager's per-app rule dialog so the two stay consistent.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List, Optional

from .winutil import center_on_parent


class TagPickerDialog(tk.Toplevel):
    def __init__(self, master, title: str, prompt: str,
                 existing: List[str], current: str = "") -> None:
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.transient(master)
        self.result: Optional[str] = None
        self._committed = False

        tk.Label(self, text=prompt, justify="left", anchor="w",
                 wraplength=360).grid(row=0, column=0, columnspan=2,
                                      sticky="w", padx=10, pady=(10, 6))

        tk.Label(self, text="Tag:").grid(row=1, column=0, sticky="e",
                                         padx=(10, 4), pady=4)
        self.var = tk.StringVar(value=current)
        self.combo = ttk.Combobox(self, textvariable=self.var, width=26,
                                  values=sorted(set(existing)))
        self.combo.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=4)
        self.combo.focus_set()

        tk.Label(self, fg="#666", text="Pick an existing tag or type a new one. "
                 "Leave blank to remove.", wraplength=300,
                 justify="left").grid(row=2, column=0, columnspan=2,
                                      sticky="w", padx=10, pady=(0, 6))

        btns = tk.Frame(self)
        btns.grid(row=3, column=0, columnspan=2, pady=(2, 10))
        tk.Button(btns, text="OK", width=10, command=self._ok).pack(
            side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=self.destroy).pack(
            side="left", padx=4)

        self.bind("<Return>", lambda _e: self._ok())
        center_on_parent(self, master)
        self.grab_set()

    def _ok(self) -> None:
        self.result = self.var.get().strip()
        self._committed = True
        self.destroy()


def ask_tag(master, title: str, prompt: str,
            existing: List[str], current: str = "") -> Optional[str]:
    """Show the picker modally. Returns the chosen tag string ('' to clear),
    or None if cancelled."""
    dlg = TagPickerDialog(master, title, prompt, existing, current)
    master.wait_window(dlg)
    return dlg.result if dlg._committed else None
