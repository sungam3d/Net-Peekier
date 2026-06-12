r"""Firewall & rate-limit manager.

One place to see and edit every app rule, independent of whether the app is
currently running. Rules are keyed by executable path, so they persist.

  +--------------------------------------------------------------+
  | Application      | Blocked | Up limit | Down limit | Path     |
  | chrome.exe       |   Yes   |    -     |  200 KB/s  | C:\...    |
  | steam.exe        |   No    |  50 KB/s |    -       | C:\...    |
  +--------------------------------------------------------------+
  [Add running app][Add by path][Edit][Remove]      [Refresh][Close]

Add/Edit opens a small dialog with a Block checkbox and up/down limit fields.
Blocking goes through Windows Firewall (netsh); limits go through the WinDivert
enforcer. Both need Administrator; the window says so if it can't apply a rule.
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .. import firewall
from ..monitor import Monitor
from ..util import human_speed

REFRESH_MS = 1500


def _fmt_limit(bps: int) -> str:
    return human_speed(bps) if bps > 0 else "-"


class RuleDialog(tk.Toplevel):
    """Modal add/edit dialog for one app's block + limit settings."""

    def __init__(self, master, exe: str,
                 blocked: bool, up_bps: int, down_bps: int) -> None:
        super().__init__(master)
        self.title("App rule")
        self.resizable(False, False)
        self.transient(master)
        self.result: Optional[tuple] = None

        self.exe = exe
        pad = {"padx": 8, "pady": 4}

        tk.Label(self, text="Application:", anchor="w").grid(
            row=0, column=0, sticky="w", **pad)
        tk.Label(self, text=os.path.basename(exe) or exe,
                 font=("Segoe UI", 9, "bold")).grid(
            row=0, column=1, sticky="w", **pad)

        tk.Label(self, text=exe, fg="#666", wraplength=360, justify="left",
                 anchor="w").grid(row=1, column=0, columnspan=2, sticky="w",
                                  padx=8)

        self.var_block = tk.BooleanVar(value=blocked)
        tk.Checkbutton(self, text="Block all traffic (firewall)",
                       variable=self.var_block).grid(
            row=2, column=0, columnspan=2, sticky="w", **pad)

        tk.Label(self, text="Upload limit (KB/s, 0 = unlimited):").grid(
            row=3, column=0, sticky="w", **pad)
        self.var_up = tk.StringVar(value=str(up_bps // 1024 if up_bps else 0))
        tk.Entry(self, textvariable=self.var_up, width=10).grid(
            row=3, column=1, sticky="w", **pad)

        tk.Label(self, text="Download limit (KB/s, 0 = unlimited):").grid(
            row=4, column=0, sticky="w", **pad)
        self.var_down = tk.StringVar(
            value=str(down_bps // 1024 if down_bps else 0))
        tk.Entry(self, textvariable=self.var_down, width=10).grid(
            row=4, column=1, sticky="w", **pad)

        btns = tk.Frame(self)
        btns.grid(row=5, column=0, columnspan=2, pady=(8, 8))
        tk.Button(btns, text="OK", width=10, command=self._ok).pack(
            side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=self.destroy).pack(
            side="left", padx=4)

        self.bind("<Return>", lambda _e: self._ok())
        self.grab_set()

    def _ok(self) -> None:
        try:
            up = int(self.var_up.get().strip() or "0")
            down = int(self.var_down.get().strip() or "0")
            if up < 0 or down < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("App rule", "Limits must be whole numbers >= 0.",
                                 parent=self)
            return
        self.result = (self.var_block.get(), up * 1024, down * 1024)
        self.destroy()


class ProcessPicker(tk.Toplevel):
    """Pick a currently-running networked app to manage."""

    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.title("Pick a running app")
        self.geometry("460x360")
        self.transient(master)
        self.monitor = monitor
        self.result: Optional[str] = None

        tk.Label(self, text="Processes with network activity / connections:",
                 anchor="w").pack(fill="x", padx=8, pady=(8, 2))

        self.tree = ttk.Treeview(self, columns=("pid",), show="tree headings")
        self.tree.heading("#0", text="Application")
        self.tree.heading("pid", text="PID")
        self.tree.column("#0", width=320, anchor="w")
        self.tree.column("pid", width=80, anchor="e")
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)

        # de-dupe by exe; only apps with a resolvable path can be managed
        procs, _ = monitor.snapshot()
        self._exe_by_iid: dict[str, str] = {}
        seen_exes: set[str] = set()
        for p in sorted(procs, key=lambda x: x.name.lower()):
            if not p.exe or p.exe in seen_exes:
                continue
            seen_exes.add(p.exe)
            iid = f"{p.pid}"
            self.tree.insert("", "end", iid=iid,
                             text=f"{p.name}", values=(p.pid,))
            self._exe_by_iid[iid] = p.exe

        btns = tk.Frame(self)
        btns.pack(fill="x", pady=6)
        tk.Button(btns, text="Select", command=self._select).pack(
            side="right", padx=6)
        tk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        self.tree.bind("<Double-1>", lambda _e: self._select())
        self.grab_set()

    def _select(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        self.result = self._exe_by_iid.get(sel[0])
        self.destroy()


class FirewallManagerWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.title("Net-Peekier - Firewall & limits manager")
        self.geometry("720x420")

        self._build_table()
        self._build_buttons()
        self._refresh()

    # ---- layout -----------------------------------------------------------
    def _build_table(self) -> None:
        frame = tk.Frame(self)
        frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)

        cols = ("blocked", "up", "down", "path")
        self.tree = ttk.Treeview(frame, columns=cols, show="tree headings")
        self.tree.heading("#0", text="Application")
        self.tree.heading("blocked", text="Blocked")
        self.tree.heading("up", text="Upload limit")
        self.tree.heading("down", text="Download limit")
        self.tree.heading("path", text="Path")
        self.tree.column("#0", width=150, anchor="w")
        self.tree.column("blocked", width=70, anchor="center")
        self.tree.column("up", width=100, anchor="e")
        self.tree.column("down", width=100, anchor="e")
        self.tree.column("path", width=270, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("blocked", foreground="#b00000")
        self.tree.bind("<Double-1>", lambda _e: self._edit())

    def _build_buttons(self) -> None:
        bar = tk.Frame(self)
        bar.pack(side="bottom", fill="x", padx=6, pady=(0, 8))
        tk.Button(bar, text="Add running app...",
                  command=self._add_running).pack(side="left", padx=2)
        tk.Button(bar, text="Add by path...",
                  command=self._add_by_path).pack(side="left", padx=2)
        tk.Button(bar, text="Edit...", command=self._edit).pack(
            side="left", padx=2)
        tk.Button(bar, text="Remove", command=self._remove).pack(
            side="left", padx=2)
        tk.Button(bar, text="Close", command=self.destroy).pack(
            side="right", padx=2)
        tk.Button(bar, text="Refresh", command=self._refresh).pack(
            side="right", padx=2)

    # ---- data -------------------------------------------------------------
    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        selected = self._selected_exe()
        self.tree.delete(*self.tree.get_children())
        for exe, (blocked, (up, down)) in sorted(
                self.monitor.managed_apps().items(),
                key=lambda kv: os.path.basename(kv[0]).lower()):
            iid = exe
            self.tree.insert(
                "", "end", iid=iid, text=os.path.basename(exe) or exe,
                values=("Yes" if blocked else "No",
                        _fmt_limit(up), _fmt_limit(down), exe),
                tags=("blocked",) if blocked else ())
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)

    def _selected_exe(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # ---- actions ----------------------------------------------------------
    def _apply_rule(self, exe: str, blocked: bool,
                    up_bps: int, down_bps: int) -> None:
        """Push a desired state to firewall + monitor, reporting failures."""
        errors = []
        # block / unblock via the OS firewall
        was_blocked = exe in self.monitor.list_blocked()
        if blocked and not was_blocked:
            ok, msg = firewall.block_app(exe)
            if not ok:
                errors.append(f"Block failed: {msg}")
        elif not blocked and was_blocked:
            ok, msg = firewall.unblock_app(exe)
            if not ok:
                errors.append(f"Unblock failed: {msg}")
        self.monitor.set_blocked(exe, blocked)
        # limits via the enforcer
        self.monitor.set_limit(exe, up_bps, down_bps)
        if (up_bps or down_bps) and not self.monitor.has_per_process_speed:
            errors.append("Speed limit saved, but enforcement needs WinDivert "
                          "(pip install pydivert).")
        if errors:
            messagebox.showwarning("Firewall & limits", "\n\n".join(errors),
                                   parent=self)
        self._refresh()

    def _edit_exe(self, exe: str) -> None:
        managed = self.monitor.managed_apps().get(exe, (False, (0, 0)))
        blocked, (up, down) = managed
        dlg = RuleDialog(self, exe, blocked, up, down)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        new_blocked, new_up, new_down = dlg.result
        self._apply_rule(exe, new_blocked, new_up, new_down)

    def _edit(self) -> None:
        exe = self._selected_exe()
        if not exe:
            messagebox.showinfo("Firewall & limits",
                                "Select an app first.", parent=self)
            return
        self._edit_exe(exe)

    def _add_running(self) -> None:
        picker = ProcessPicker(self, self.monitor)
        self.wait_window(picker)
        if picker.result:
            self._edit_exe(picker.result)

    def _add_by_path(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose an executable",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
            parent=self)
        if path:
            self._edit_exe(os.path.normpath(path))

    def _remove(self) -> None:
        exe = self._selected_exe()
        if not exe:
            return
        if not messagebox.askyesno(
                "Remove rule",
                f"Remove all rules (block + limits) for\n"
                f"{os.path.basename(exe)}?", parent=self):
            return
        if exe in self.monitor.list_blocked():
            firewall.unblock_app(exe)
        self.monitor.remove_app(exe)
        self._refresh()
