"""Main window: dashboard + application list, modelled on NetPeeker 2.x.

Layout
------
  +----------------------------------------------------------+
  |  UPLOAD  peak / now        DOWNLOAD  peak / now           |  <- dashboard
  +----------------------------------------------------------+
  |  Program            Upload   Download   Listening Ports   |  <- Treeview
  |   svchost.exe        16/s     161/s     135, 1025, ...     |
  |     PID 796          16/s     161/s                        |
  |     PID 616           0/s       0/s     1025, 3002         |
  |   iexplore.exe ...                                         |
  +----------------------------------------------------------+
  |  status bar: backend mode / admin hint                    |
  +----------------------------------------------------------+

Double-click a process (leaf) -> Connections window.
Right-click / Firewall menu -> block, unblock, set speed limit.
"""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Dict, List

from ..models import ProcStat
from ..monitor import Monitor
from ..util import human_speed, human_bytes, ports_str
from .connections_window import ConnectionsWindow

REFRESH_MS = 1000


def _is_admin() -> bool:
    try:
        if sys.platform.startswith("win"):
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        import os
        return os.geteuid() == 0
    except Exception:
        return False


class NetPeekierApp(tk.Tk):
    def __init__(self, monitor: Monitor) -> None:
        super().__init__()
        self.monitor = monitor
        self.title("Net-Peekier  -  per-process network monitor")
        self.geometry("840x560")
        self.minsize(700, 420)

        self._child_windows: Dict[int, ConnectionsWindow] = {}
        self._known_iids: set[str] = set()

        self._build_style()
        self._build_dashboard()
        self._build_app_list()
        self._build_menu()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self._refresh)

    # ---- styling ----------------------------------------------------------
    def _build_style(self) -> None:
        self.configure(bg="#d6dce4")
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=22, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Dash.TLabel", background="#10212e",
                        foreground="#7fe3ff", font=("Consolas", 22, "bold"))
        style.configure("DashCap.TLabel", background="#10212e",
                        foreground="#5a93ad", font=("Segoe UI", 8, "bold"))

    # ---- dashboard --------------------------------------------------------
    def _build_dashboard(self) -> None:
        bar = tk.Frame(self, bg="#10212e", bd=2, relief="ridge")
        bar.pack(side="top", fill="x", padx=6, pady=(6, 3))

        self.var_up_now = tk.StringVar(value="0/s")
        self.var_up_peak = tk.StringVar(value="0/s")
        self.var_up_total = tk.StringVar(value="0 B")
        self.var_down_now = tk.StringVar(value="0/s")
        self.var_down_peak = tk.StringVar(value="0/s")
        self.var_down_total = tk.StringVar(value="0 B")

        def block(parent, title, now_var, peak_var, total_var, color):
            f = tk.Frame(parent, bg="#10212e")
            tk.Label(f, text=title, bg="#10212e", fg="#5a93ad",
                     font=("Segoe UI", 8, "bold")).grid(
                row=0, column=0, columnspan=2, sticky="w")
            tk.Label(f, text="NOW", bg="#10212e", fg="#3d6577",
                     font=("Segoe UI", 7)).grid(row=1, column=0, sticky="e",
                                                padx=(0, 4))
            tk.Label(f, textvariable=now_var, bg="#10212e", fg=color,
                     font=("Consolas", 20, "bold")).grid(row=1, column=1,
                                                         sticky="w")
            tk.Label(f, text="PEAK", bg="#10212e", fg="#3d6577",
                     font=("Segoe UI", 7)).grid(row=2, column=0, sticky="e",
                                                padx=(0, 4))
            tk.Label(f, textvariable=peak_var, bg="#10212e", fg="#3d6577",
                     font=("Consolas", 11)).grid(row=2, column=1, sticky="w")
            tk.Label(f, text="TOTAL", bg="#10212e", fg="#3d6577",
                     font=("Segoe UI", 7)).grid(row=3, column=0, sticky="e",
                                                padx=(0, 4))
            tk.Label(f, textvariable=total_var, bg="#10212e", fg="#8fb6c8",
                     font=("Consolas", 11)).grid(row=3, column=1, sticky="w")
            return f

        up = block(bar, "UPLOAD", self.var_up_now, self.var_up_peak,
                   self.var_up_total, "#ffb454")
        down = block(bar, "DOWNLOAD", self.var_down_now, self.var_down_peak,
                     self.var_down_total, "#7fe3ff")
        up.pack(side="left", expand=True, padx=18, pady=6)
        tk.Frame(bar, bg="#1d3a4d", width=2).pack(side="left", fill="y", pady=8)
        down.pack(side="left", expand=True, padx=18, pady=6)

    # ---- application list -------------------------------------------------
    def _build_app_list(self) -> None:
        frame = tk.Frame(self, bg="#d6dce4")
        frame.pack(side="top", fill="both", expand=True, padx=6, pady=3)

        cols = ("up", "down", "tup", "tdown", "ports")
        self.tree = ttk.Treeview(frame, columns=cols, show="tree headings")
        self.tree.heading("#0", text="Program")
        self.tree.heading("up", text="Upload")
        self.tree.heading("down", text="Download")
        self.tree.heading("tup", text="Total Up")
        self.tree.heading("tdown", text="Total Down")
        self.tree.heading("ports", text="Listening Ports")
        self.tree.column("#0", width=200, anchor="w")
        self.tree.column("up", width=80, anchor="e")
        self.tree.column("down", width=80, anchor="e")
        self.tree.column("tup", width=90, anchor="e")
        self.tree.column("tdown", width=90, anchor="e")
        self.tree.column("ports", width=190, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("blocked", foreground="#b00000")
        self.tree.tag_configure("active", foreground="#0a7d00")

        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)

        # context menu
        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Show connections",
                             command=self._open_selected_connections)
        self.ctx.add_separator()
        self.ctx.add_command(label="Block (firewall)",
                             command=lambda: self._block_selected(True))
        self.ctx.add_command(label="Unblock",
                             command=lambda: self._block_selected(False))
        self.ctx.add_command(label="Set speed limit...",
                             command=self._limit_selected)
        self.ctx.add_separator()
        self.ctx.add_command(label="Firewall & limits manager...",
                             command=self._open_firewall_manager)

    # ---- menus ------------------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filem)

        fw = tk.Menu(menubar, tearoff=0)
        fw.add_command(label="Firewall & limits manager...",
                       command=self._open_firewall_manager)
        fw.add_separator()
        fw.add_command(label="Block selected app",
                       command=lambda: self._block_selected(True))
        fw.add_command(label="Unblock selected app",
                       command=lambda: self._block_selected(False))
        fw.add_command(label="Set speed limit on selected...",
                       command=self._limit_selected)
        menubar.add_cascade(label="Firewall", menu=fw)

        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=helpm)
        self.config(menu=menubar)

    def _build_statusbar(self) -> None:
        admin = _is_admin()
        backend = self.monitor.backend_name
        if backend == "WinDivertBackend":
            mode = "WinDivert active: live per-process speeds + packets"
        else:
            mode = ("psutil-only: connections & ports shown, "
                    "per-process speeds need WinDivert")
        extra = "" if admin else "   |   NOT elevated: run as Administrator for full visibility"
        self.status = tk.Label(self, anchor="w", bg="#c3cbd6",
                               text=f"{mode}{extra}",
                               font=("Segoe UI", 8))
        self.status.pack(side="bottom", fill="x")

    # ---- refresh loop -----------------------------------------------------
    def _refresh(self) -> None:
        procs, totals = self.monitor.snapshot()
        self.var_up_now.set(human_speed(totals.up_now))
        self.var_down_now.set(human_speed(totals.down_now))
        self.var_up_peak.set(human_speed(totals.up_peak))
        self.var_down_peak.set(human_speed(totals.down_peak))
        self.var_up_total.set(human_bytes(totals.up_total))
        self.var_down_total.set(human_bytes(totals.down_total))

        self._update_tree(procs)
        self.after(REFRESH_MS, self._refresh)

    def _update_tree(self, procs: List[ProcStat]) -> None:
        # group by process name (svchost.exe -> several PIDs), like NetPeeker
        groups: Dict[str, List[ProcStat]] = {}
        for p in procs:
            groups.setdefault(p.name, []).append(p)

        seen: set[str] = set()
        for name, members in sorted(
                groups.items(),
                key=lambda kv: sum(m.up_bps + m.down_bps for m in kv[1]),
                reverse=True):
            gid = f"name::{name}"
            up = sum(m.up_bps for m in members)
            down = sum(m.down_bps for m in members)
            tup = sum(m.up_total for m in members)
            tdown = sum(m.down_total for m in members)
            ports = sorted({pt for m in members for pt in m.listening_ports})
            blocked = any(m.blocked for m in members)
            tag = "blocked" if blocked else ("active" if (up + down) > 0 else "")
            vals = (human_speed(up), human_speed(down),
                    human_bytes(tup) if tup else "-",
                    human_bytes(tdown) if tdown else "-",
                    ports_str(ports))

            if self.tree.exists(gid):
                self.tree.item(gid, text=name, values=vals,
                               tags=(tag,) if tag else ())
            else:
                self.tree.insert("", "end", iid=gid, text=name, values=vals,
                                 tags=(tag,) if tag else (), open=False)
            seen.add(gid)

            single = len(members) == 1
            for m in members:
                cid = f"pid::{m.pid}"
                label = (f"PID {m.pid}" if not single
                         else f"{name}  (PID {m.pid})")
                ctag = "blocked" if m.blocked else (
                    "active" if (m.up_bps + m.down_bps) > 0 else "")
                cvals = (human_speed(m.up_bps), human_speed(m.down_bps),
                         human_bytes(m.up_total) if m.up_total else "-",
                         human_bytes(m.down_total) if m.down_total else "-",
                         ports_str(m.listening_ports))
                if self.tree.exists(cid):
                    self.tree.item(cid, text=label, values=cvals,
                                   tags=(ctag,) if ctag else ())
                    if self.tree.parent(cid) != gid:
                        self.tree.move(cid, gid, "end")
                else:
                    self.tree.insert(gid, "end", iid=cid, text=label,
                                     values=cvals,
                                     tags=(ctag,) if ctag else ())
                seen.add(cid)

        # delete rows that disappeared
        for iid in list(self._known_iids):
            if iid not in seen and self.tree.exists(iid):
                try:
                    self.tree.delete(iid)
                except tk.TclError:
                    pass
        self._known_iids = seen

    # ---- selection helpers ------------------------------------------------
    def _selected_pid(self):
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        if iid.startswith("pid::"):
            return int(iid.split("::", 1)[1])
        # parent selected: act on its first child pid
        kids = self.tree.get_children(iid)
        if kids and kids[0].startswith("pid::"):
            return int(kids[0].split("::", 1)[1])
        return None

    def _selected_proc(self):
        pid = self._selected_pid()
        if pid is None:
            return None
        procs, _ = self.monitor.snapshot()
        for p in procs:
            if p.pid == pid:
                return p
        return None

    # ---- events -----------------------------------------------------------
    def _on_double_click(self, _event) -> None:
        iid = self.tree.focus()
        if iid.startswith("pid::"):
            self._open_selected_connections()

    def _on_right_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.ctx.tk_popup(event.x_root, event.y_root)

    def _open_selected_connections(self) -> None:
        proc = self._selected_proc()
        if proc is None:
            messagebox.showinfo("Net-Peekier", "Select a process first.")
            return
        existing = self._child_windows.get(proc.pid)
        if existing and existing.winfo_exists():
            existing.lift()
            return
        win = ConnectionsWindow(self, self.monitor, proc.pid, proc.name)
        self._child_windows[proc.pid] = win

    def _block_selected(self, block: bool) -> None:
        proc = self._selected_proc()
        if proc is None:
            return
        from .. import firewall
        if not proc.exe:
            messagebox.showwarning(
                "Net-Peekier",
                "No executable path available for this process.\n"
                "Run as Administrator to resolve it.")
            return
        if block:
            ok, msg = firewall.block_app(proc.exe)
        else:
            ok, msg = firewall.unblock_app(proc.exe)
        self.monitor.set_blocked(proc.exe, block)
        if not ok:
            messagebox.showerror("Firewall", msg or "Failed (need admin?).")

    def _limit_selected(self) -> None:
        proc = self._selected_proc()
        if proc is None:
            return
        if not proc.exe:
            messagebox.showwarning(
                "Speed limit",
                "No executable path available for this process.\n"
                "Run as Administrator to resolve it.")
            return
        ans = simpledialog.askstring(
            "Speed limit",
            f"Limit for {proc.name} (PID {proc.pid})\n"
            "Enter as 'UP_KBps,DOWN_KBps'  (0 = unlimited).\n"
            "Example: 50,200",
            parent=self)
        if ans is None:
            return
        try:
            up_k, down_k = (int(x.strip()) for x in ans.split(","))
        except ValueError:
            messagebox.showerror("Speed limit", "Use the form '50,200'.")
            return
        self.monitor.set_limit(proc.exe, up_k * 1024, down_k * 1024)
        if not self.monitor.has_per_process_speed:
            messagebox.showinfo(
                "Speed limit",
                "Limit recorded, but enforcement needs WinDivert installed.")

    def _open_firewall_manager(self) -> None:
        from .firewall_window import FirewallManagerWindow
        if getattr(self, "_fw_window", None) and self._fw_window.winfo_exists():
            self._fw_window.lift()
            return
        self._fw_window = FirewallManagerWindow(self, self.monitor)

    def _about(self) -> None:
        messagebox.showinfo(
            "About Net-Peekier",
            "Net-Peekier 0.1\n\n"
            "A small per-process network monitor inspired by NetPeeker.\n"
            f"Backend: {self.monitor.backend_name}\n\n"
            "Live speeds, packet capture, blocking and throttling require\n"
            "WinDivert (pip install pydivert) and Administrator rights.")

    def _on_close(self) -> None:
        self.monitor.stop()
        self.destroy()
