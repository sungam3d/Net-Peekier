"""Per-process connections window ('Detail Information' in NetPeeker).

Shows every live socket for one PID with its remote endpoint, status, live
up/down rate and cumulative total sent/received. Click a column header to sort.
Double-click a row to open the packet capture for that exact connection.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict

from ..monitor import Monitor
from ..util import human_speed, human_bytes, unit_suffix
from .packets_window import PacketsWindow
from .treesort import TreeSorter
from .tablestyle import init_table, apply_stripes, restore_widths, capture_widths
from .winutil import (center_on_parent, centered_message, restore_geometry,
                      save_geometry)

REFRESH_MS = 1000
_COLS = ("proto", "local", "dir", "remote", "status",
         "up", "down", "tup", "tdown")


class ConnectionsWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor, pid: int, name: str) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.pid = pid
        self.title(f"Detail Information - {name} (PID {pid})")
        restore_geometry(self, self.monitor.settings, "connections", "920x440")

        self._packet_windows: Dict[tuple, PacketsWindow] = {}
        self._known: set[str] = set()
        self._sortkeys: Dict[str, Dict[str, object]] = {}

        header = tk.Label(
            self, anchor="w", bg="#eef1f5",
            text=f"  {name}    PID {pid}    "
                 f"{self.monitor.procmap.exe(pid) or ''}",
            font=("Segoe UI", 9, "bold"))
        header.pack(side="top", fill="x")

        cols = ("proto", "local", "dir", "remote", "status",
                "up", "down", "tup", "tdown")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        layout = {
            "proto": ("Type", 55), "local": ("Local Address", 155),
            "dir": ("D.", 35), "remote": ("Remote Address", 165),
            "status": ("Status", 105), "up": ("Upload", 80),
            "down": ("Download", 80), "tup": ("Total Up", 90),
            "tdown": ("Total Down", 90),
        }
        for c, (txt, w) in layout.items():
            anchor = "center" if c == "dir" else (
                "e" if c in ("up", "down", "tup", "tdown") else "w")
            self.tree.column(c, width=w, anchor=anchor)
        self._base = {c: t for c, (t, _w) in layout.items()}
        self.sorter = TreeSorter(
            self.tree, self._base,
            lambda iid, col: self._sortkeys.get(iid, {}).get(col),
            default_col="down", default_reverse=True)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        init_table(self.tree)
        self.tree.tag_configure("fg_listen", foreground="#666666")
        restore_widths(self.tree, "connections", self.monitor.settings, _COLS)
        self.protocol("WM_DELETE_WINDOW", self._close)

        self.tree.bind("<Double-1>", self._on_double_click)
        self._build_ctx_menu()
        self.tree.bind("<Button-3>", self._on_right_click)

        if not self.monitor.settings.window_geometry_for("connections"):
            center_on_parent(self, master)
        self.after(REFRESH_MS, self._refresh)

    def _build_ctx_menu(self) -> None:
        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Allow this IP:port for this app",
                             command=lambda: self._ip_rule_from_sel("allow"))
        self.ctx.add_command(label="Block this IP:port for this app",
                             command=lambda: self._ip_rule_from_sel("block"))
        self.ctx.add_separator()
        self.ctx.add_command(label="Allow this IP (all ports)",
                             command=lambda: self._ip_rule_from_sel("allow", True))
        self.ctx.add_command(label="Block this IP (all ports)",
                             command=lambda: self._ip_rule_from_sel("block", True))

    def _on_right_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.ctx.tk_popup(event.x_root, event.y_root)

    def _ip_rule_from_sel(self, action: str, all_ports: bool = False) -> None:
        from tkinter import messagebox
        iid = self.tree.focus()
        if not iid or iid.count("|") != 4:
            return
        proto, lip, lport, rip, rport = iid.split("|")
        exe = self.monitor.procmap.exe(self.pid)
        if not exe:
            centered_message(self, "info", "IP rule",
                             "No executable path available for this process "
                             "(try running as Administrator).")
            return
        if not rip or rip in ("-", "0.0.0.0", "::"):
            centered_message(self, "info", "IP rule",
                             "This connection has no specific remote IP to add "
                             "a rule for.")
            return
        ports = "" if all_ports else (rport if rport and rport != "0" else "")
        # outbound is the meaningful direction for a remote endpoint
        ok, msg = self.monitor.add_ip_rule(
            exe, action, "out", rip, ports,
            proto.lower() if proto.lower() in ("tcp", "udp") else "any")
        if ok:
            scope = rip if all_ports else f"{rip}:{rport}"
            centered_message(self, "info", "IP rule",
                             f"{action.title()} rule added for {scope}.")
        else:
            centered_message(self, "error", "IP rule",
                             msg or "Failed to add rule (need admin?).")

    def _close(self) -> None:
        save_geometry(self, self.monitor.settings, "connections")
        capture_widths(self.tree, "connections", self.monitor.settings, _COLS)
        self.destroy()

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        unit = self.monitor.settings.speed_unit
        suf = unit_suffix(unit)
        self.sorter.set_base("up", "Upload" + suf)
        self.sorter.set_base("down", "Download" + suf)

        conns = self.monitor.connections_for(self.pid)
        seen = set()
        sortkeys: Dict[str, Dict[str, object]] = {}
        rowtags: Dict[str, tuple] = {}
        for c in conns:
            iid = "|".join(str(x) for x in c.key)
            local = (f"{c.local_ip}:{c.local_port}"
                     if c.local_port else c.local_ip)
            remote = (f"{c.remote_ip}:{c.remote_port}"
                      if c.remote_port else "-")
            arrow = c.direction_arrow if c.remote_port else ""
            tag = "listen" if c.status == "LISTEN" else (
                "active" if (c.up_bps + c.down_bps) > 0 else "")
            vals = (c.protocol, local, arrow, remote, c.status,
                    human_speed(c.up_bps, unit), human_speed(c.down_bps, unit),
                    human_bytes(c.up_total) if c.up_total else "-",
                    human_bytes(c.down_total) if c.down_total else "-")
            sortkeys[iid] = {
                "proto": c.protocol, "local": c.local_port,
                "dir": arrow, "remote": c.remote_ip, "status": c.status,
                "up": c.up_bps, "down": c.down_bps,
                "tup": c.up_total, "tdown": c.down_total,
            }
            rowtags[iid] = (tag,) if tag else ()
            if self.tree.exists(iid):
                self.tree.item(iid, values=vals)
            else:
                self.tree.insert("", "end", iid=iid, values=vals)
            seen.add(iid)

        for iid in list(self._known):
            if iid not in seen and self.tree.exists(iid):
                self.tree.delete(iid)
        self._known = seen
        self._sortkeys = sortkeys
        self.sorter.apply()
        apply_stripes(self.tree, rowtags)

        self.after(REFRESH_MS, self._refresh)

    def _on_double_click(self, _event) -> None:
        iid = self.tree.focus()
        if not iid:
            return
        parts = iid.split("|")
        if len(parts) != 5:
            return
        proto, lip, lport, rip, rport = parts
        conn_key = (proto, lip, int(lport), rip, int(rport))
        existing = self._packet_windows.get(conn_key)
        if existing and existing.winfo_exists():
            existing.lift()
            return
        title = f"{lip}:{lport} -> {rip}:{rport}"
        self._packet_windows[conn_key] = PacketsWindow(
            self, self.monitor, conn_key, title)
