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
import os
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Dict, List

import psutil

from ..models import ProcStat
from ..monitor import Monitor
from ..util import human_speed, human_bytes, ports_str, unit_suffix
from .connections_window import ConnectionsWindow
from .treesort import TreeSorter
from .tablestyle import init_table, apply_stripes, restore_widths, capture_widths

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
        self.minsize(700, 420)
        self._apply_saved_geometry("880x560")

        self._child_windows: Dict[int, ConnectionsWindow] = {}
        self._known_iids: set[str] = set()

        self._build_style()
        self._build_dashboard()
        self._build_filterbar()
        self._build_app_list()
        self._build_menu()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self._refresh)

    # ---- window geometry persistence --------------------------------------
    def _apply_saved_geometry(self, default: str) -> None:
        """Restore the last window size/position, falling back to `default`.
        Guards against nonsense sizes and positions left off-screen (e.g. after
        a monitor change), in which case the saved size is kept but the OS
        places the window."""
        geo = self.monitor.settings.window_geometry
        if not geo:
            self.geometry(default)
            return
        try:
            size_part = geo.split("+")[0].split("-")[0]
            w_str, h_str = size_part.lower().split("x")
            w, h = int(w_str), int(h_str)
            if w < 400 or h < 300 or w > 20000 or h > 20000:
                self.geometry(default)
                return
            self.geometry(geo)
            # if that put the window off-screen, keep the size, drop the position
            self.update_idletasks()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            x, y = self.winfo_x(), self.winfo_y()
            if x < -50 or y < -10 or x > sw - 80 or y > sh - 80:
                self.geometry(f"{w}x{h}")
        except Exception:
            self.geometry(default)

    # ---- filter toolbar ---------------------------------------------------
    def _build_filterbar(self) -> None:
        bar = tk.Frame(self, bg="#d6dce4")
        bar.pack(side="top", fill="x", padx=8, pady=(2, 0))
        self.var_show_lan = tk.BooleanVar(value=self.monitor.settings.show_lan)
        self.var_show_wan = tk.BooleanVar(value=self.monitor.settings.show_wan)
        tk.Checkbutton(bar, text="Show LAN", bg="#d6dce4",
                       variable=self.var_show_lan,
                       command=self._on_filter_change).pack(side="left")
        tk.Checkbutton(bar, text="Show WAN", bg="#d6dce4",
                       variable=self.var_show_wan,
                       command=self._on_filter_change).pack(side="left", padx=(8, 0))

        # ---- firewall master switch (right side) ----
        self.var_fw_enabled = tk.BooleanVar(
            value=self.monitor.settings.firewall_enabled)
        self.fw_light = tk.Label(bar, text="\u25cf", bg="#d6dce4",
                                 font=("Segoe UI", 12))
        self.fw_light.pack(side="right", padx=(2, 6))
        tk.Checkbutton(bar, text="Enable Firewall", bg="#d6dce4",
                       variable=self.var_fw_enabled,
                       command=self._on_firewall_toggle).pack(side="right")
        self._update_fw_light()

        tk.Label(bar, bg="#d6dce4", fg="#666",
                 text="(LAN = local-only traffic; WAN = internet. "
                      "Edit LAN ranges in Settings.)").pack(side="left", padx=12)

    def _update_fw_light(self) -> None:
        on = self.var_fw_enabled.get()
        self.fw_light.config(fg="#1e9e3e" if on else "#cc2b2b")

    def _on_firewall_toggle(self) -> None:
        enabled = self.var_fw_enabled.get()
        self._update_fw_light()
        self.monitor.set_firewall_enabled(enabled)
        self._refresh_now()

    def _on_filter_change(self) -> None:
        self.monitor.settings.show_lan = self.var_show_lan.get()
        self.monitor.settings.show_wan = self.var_show_wan.get()
        self.monitor.settings.save()
        procs, _ = self.monitor.snapshot()
        self._update_tree(procs)

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

        cols = ("up", "down", "tup", "tdown", "tag", "ports")
        self.tree = ttk.Treeview(frame, columns=cols, show="tree headings")
        self.tree.column("#0", width=185, anchor="w")
        self.tree.column("up", width=78, anchor="e")
        self.tree.column("down", width=78, anchor="e")
        self.tree.column("tup", width=85, anchor="e")
        self.tree.column("tdown", width=85, anchor="e")
        self.tree.column("tag", width=80, anchor="w")
        self.tree.column("ports", width=160, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        init_table(self.tree)

        # raw values for click-to-sort + status tag per row, keyed by row id
        self._sortkeys: Dict[str, Dict[str, object]] = {}
        self._rowtags: Dict[str, tuple] = {}
        self._base_headings = {
            "#0": "Program", "up": "Upload", "down": "Download",
            "tup": "Total Up", "tdown": "Total Down",
            "tag": "Tag", "ports": "Listening Ports",
        }
        self.sorter = TreeSorter(
            self.tree, self._base_headings,
            lambda iid, col: self._sortkeys.get(iid, {}).get(col),
            default_col="down", default_reverse=True)

        self._main_cols = ("#0", "up", "down", "tup", "tdown", "tag", "ports")
        restore_widths(self.tree, "main", self.monitor.settings, self._main_cols)

        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)

        # context menu
        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Show connections",
                             command=self._open_selected_connections)
        self.ctx.add_separator()
        self.ctx.add_command(label="End Process",
                             command=self._end_selected_process)
        self.ctx.add_command(label="Open Program Path",
                             command=self._open_selected_path)
        self.ctx.add_separator()
        self.ctx.add_command(label="Set tag...",
                             command=self._tag_selected)
        self.ctx.add_command(label="Remove tag",
                             command=self._remove_tag_selected)
        self.ctx.add_command(label="Block (firewall)",
                             command=lambda: self._block_selected(True))
        self.ctx.add_command(label="Unblock",
                             command=lambda: self._block_selected(False))
        self.ctx.add_command(label="Set speed limit...",
                             command=self._limit_selected)
        self.ctx.add_separator()
        self.ctx.add_command(label="Firewall and Tags...",
                             command=self._open_firewall_manager)

    # ---- menus ------------------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filem)

        menubar.add_command(label="Statistics", command=self._open_stats)

        settingsm = tk.Menu(menubar, tearoff=0)
        settingsm.add_command(label="Firewall and Tags",
                              command=self._open_firewall_manager)
        settingsm.add_command(label="Preferences",
                              command=self._open_settings)
        menubar.add_cascade(label="Settings", menu=settingsm)

        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=helpm)
        self.config(menu=menubar)

    def _open_settings(self) -> None:
        from .settings_window import SettingsWindow
        if getattr(self, "_settings_window", None) and \
                self._settings_window.winfo_exists():
            self._settings_window.lift()
            return
        self._settings_window = SettingsWindow(self, self.monitor)

    def _open_stats(self) -> None:
        from .stats_window import StatsWindow
        if getattr(self, "_stats_window", None) and \
                self._stats_window.winfo_exists():
            self._stats_window.lift()
            return
        self._stats_window = StatsWindow(self, self.monitor)

    def _refresh_now(self) -> None:
        try:
            self.monitor.restamp_rules()      # reflect just-applied rules now
            procs, _ = self.monitor.snapshot()
            self._update_tree(procs)
        except Exception:
            pass

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
        unit = self.monitor.settings.speed_unit
        self.var_up_now.set(human_speed(totals.up_now, unit))
        self.var_down_now.set(human_speed(totals.down_now, unit))
        self.var_up_peak.set(human_speed(totals.up_peak, unit))
        self.var_down_peak.set(human_speed(totals.down_peak, unit))
        self.var_up_total.set(human_bytes(totals.up_total))
        self.var_down_total.set(human_bytes(totals.down_total))

        # reflect the chosen speed unit in the column headers
        suf = unit_suffix(unit)
        self.sorter.set_base("up", "Upload" + suf)
        self.sorter.set_base("down", "Download" + suf)

        self._update_tree(procs)
        self.after(REFRESH_MS, self._refresh)

    def _update_tree(self, procs: List[ProcStat]) -> None:
        unit = self.monitor.settings.speed_unit
        show_lan = self.var_show_lan.get()
        show_wan = self.var_show_wan.get()
        # LAN/WAN view filter: a WAN process has an internet remote; everything
        # else (local-only or no remote) counts as LAN.
        procs = [p for p in procs
                 if (p.uses_wan and show_wan) or (not p.uses_wan and show_lan)]
        # group by process name (svchost.exe -> several PIDs), like NetPeeker
        groups: Dict[str, List[ProcStat]] = {}
        for p in procs:
            groups.setdefault(p.name, []).append(p)

        seen: set[str] = set()
        sortkeys: Dict[str, Dict[str, object]] = {}
        rowtags: Dict[str, tuple] = {}
        for name, members in groups.items():
            gid = f"name::{name}"
            up = sum(m.up_bps for m in members)
            down = sum(m.down_bps for m in members)
            tup = sum(m.up_total for m in members)
            tdown = sum(m.down_total for m in members)
            ports = sorted({pt for m in members for pt in m.listening_ports})
            blocked = any(m.blocked for m in members)
            gtag = next((m.tag for m in members if m.tag), "")
            tag = "blocked" if blocked else ("active" if (up + down) > 0 else "")
            vals = (human_speed(up, unit), human_speed(down, unit),
                    human_bytes(tup) if tup else "-",
                    human_bytes(tdown) if tdown else "-",
                    gtag, ports_str(ports))
            sortkeys[gid] = {
                "#0": name.lower(), "up": up, "down": down,
                "tup": tup, "tdown": tdown, "tag": gtag.lower(),
                "ports": ports[0] if ports else -1,
            }
            rowtags[gid] = (tag,) if tag else ()

            if self.tree.exists(gid):
                self.tree.item(gid, text=name, values=vals)
            else:
                self.tree.insert("", "end", iid=gid, text=name, values=vals,
                                 open=False)
            seen.add(gid)

            single = len(members) == 1
            for m in members:
                cid = f"pid::{m.pid}"
                label = (f"PID {m.pid}" if not single
                         else f"{name}  (PID {m.pid})")
                ctag = "blocked" if m.blocked else (
                    "active" if (m.up_bps + m.down_bps) > 0 else "")
                cvals = (human_speed(m.up_bps, unit), human_speed(m.down_bps, unit),
                         human_bytes(m.up_total) if m.up_total else "-",
                         human_bytes(m.down_total) if m.down_total else "-",
                         m.tag, ports_str(m.listening_ports))
                sortkeys[cid] = {
                    "#0": label.lower(), "up": m.up_bps, "down": m.down_bps,
                    "tup": m.up_total, "tdown": m.down_total,
                    "tag": (m.tag or "").lower(),
                    "ports": (m.listening_ports[0]
                              if m.listening_ports else -1),
                }
                rowtags[cid] = (ctag,) if ctag else ()
                if self.tree.exists(cid):
                    self.tree.item(cid, text=label, values=cvals)
                    if self.tree.parent(cid) != gid:
                        self.tree.move(cid, gid, "end")
                else:
                    self.tree.insert(gid, "end", iid=cid, text=label,
                                     values=cvals)
                seen.add(cid)

        # delete rows that disappeared
        for iid in list(self._known_iids):
            if iid not in seen and self.tree.exists(iid):
                try:
                    self.tree.delete(iid)
                except tk.TclError:
                    pass
        self._known_iids = seen
        self._sortkeys = sortkeys
        self._rowtags = rowtags
        self.sorter.apply()
        apply_stripes(self.tree, self._rowtags)

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
            self.monitor.set_blocked(proc.exe, True)
            ok, msg = (True, "")
            if self.monitor.settings.firewall_enabled:
                ok, msg = firewall.block_app(proc.exe)
        else:
            self.monitor.set_blocked(proc.exe, False)
            ok, msg = firewall.unblock_app(proc.exe)
        if not ok:
            messagebox.showerror("Firewall", msg or "Failed (need admin?).")
        self._refresh_now()

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
        self._refresh_now()

    def _open_firewall_manager(self) -> None:
        from .firewall_window import FirewallManagerWindow
        if getattr(self, "_fw_window", None) and self._fw_window.winfo_exists():
            self._fw_window.lift()
            return
        self._fw_window = FirewallManagerWindow(self, self.monitor)

    def _end_selected_process(self) -> None:
        proc = self._selected_proc()
        if proc is None:
            return
        if not messagebox.askyesno(
                "End Process",
                f"End {proc.name} (PID {proc.pid})?\n\n"
                "Unsaved work in that program will be lost."):
            return
        try:
            p = psutil.Process(proc.pid)
            p.terminate()
            try:
                p.wait(timeout=3)
            except psutil.TimeoutExpired:
                p.kill()  # force if it didn't go quietly
        except psutil.NoSuchProcess:
            pass
        except (psutil.AccessDenied, PermissionError):
            messagebox.showerror(
                "End Process",
                "Access denied. Try running Net-Peekier as Administrator.")
        except Exception as exc:
            messagebox.showerror("End Process", f"Could not end process:\n{exc}")

    def _open_selected_path(self) -> None:
        proc = self._selected_proc()
        if proc is None:
            return
        if not proc.exe or not os.path.exists(proc.exe):
            messagebox.showwarning(
                "Open Program Path",
                "No executable path is available for this process.\n"
                "Try running as Administrator.")
            return
        try:
            if sys.platform.startswith("win"):
                # open the folder with the exe highlighted
                subprocess.Popen(["explorer", "/select,", proc.exe])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", proc.exe])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(proc.exe)])
        except Exception as exc:
            messagebox.showerror("Open Program Path", str(exc))

    def _tag_selected(self) -> None:
        proc = self._selected_proc()
        if proc is None:
            return
        if not proc.exe:
            messagebox.showwarning(
                "Set tag",
                "No executable path available for this process.\n"
                "Run as Administrator to resolve it.")
            return
        current = self.monitor.settings.exe_tags.get(proc.exe, "")
        from .tag_picker import ask_tag
        ans = ask_tag(
            self, "Set tag",
            f"Group tag for {proc.name}\n"
            "(processes sharing a tag can share a block or speed limit).",
            existing=self.monitor.settings.all_tags(), current=current)
        if ans is None:
            return
        self.monitor.set_exe_tag(proc.exe, ans.strip() or None)
        self._refresh_now()

    def _remove_tag_selected(self) -> None:
        proc = self._selected_proc()
        if proc is None or not proc.exe:
            return
        if not self.monitor.settings.exe_tags.get(proc.exe):
            return  # nothing to remove
        self.monitor.set_exe_tag(proc.exe, None)
        self._refresh_now()

    def _about(self) -> None:
        messagebox.showinfo(
            "About Net-Peekier",
            "Net-Peekier 0.1\n\n"
            "A small per-process network monitor inspired by NetPeeker.\n"
            f"Backend: {self.monitor.backend_name}\n\n"
            "Live speeds, packet capture, blocking and throttling require\n"
            "WinDivert (pip install pydivert) and Administrator rights.")

    def _on_close(self) -> None:
        try:
            # remember where/how big the window was (skip if maximized so we
            # restore to a sensible size next time, not a zoomed geometry)
            if self.state() == "normal":
                self.monitor.settings.window_geometry = self.geometry()
            capture_widths(self.tree, "main", self.monitor.settings,
                           self._main_cols)   # this save() persists both
        except Exception:
            pass
        self.monitor.stop()
        self.destroy()
