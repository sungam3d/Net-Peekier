"""Per-process connections window ('Detail Information' in NetPeeker).

Shows every live socket for one PID with its remote endpoint, status and live
up/down rate. Double-click a row to open the packet capture for that exact
connection.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict

from ..monitor import Monitor
from ..util import human_speed
from .packets_window import PacketsWindow

REFRESH_MS = 1000


class ConnectionsWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor, pid: int, name: str) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.pid = pid
        self.title(f"Detail Information - {name} (PID {pid})")
        self.geometry("780x420")

        self._packet_windows: Dict[tuple, PacketsWindow] = {}
        self._known: set[str] = set()

        header = tk.Label(
            self, anchor="w", bg="#eef1f5",
            text=f"  {name}    PID {pid}    "
                 f"{self.monitor.procmap.exe(pid) or ''}",
            font=("Segoe UI", 9, "bold"))
        header.pack(side="top", fill="x")

        cols = ("proto", "local", "dir", "remote", "status", "down", "up")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        headings = {
            "proto": ("Type", 55), "local": ("Local Address", 165),
            "dir": ("D.", 35), "remote": ("Remote Address", 175),
            "status": ("Status", 110), "down": ("Download", 80),
            "up": ("Upload", 80),
        }
        for c, (txt, w) in headings.items():
            self.tree.heading(c, text=txt)
            anchor = "center" if c == "dir" else (
                "e" if c in ("down", "up") else "w")
            self.tree.column(c, width=w, anchor=anchor)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("listen", foreground="#666666")
        self.tree.tag_configure("active", foreground="#0a7d00")

        self.tree.bind("<Double-1>", self._on_double_click)

        self.after(REFRESH_MS, self._refresh)

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        conns = self.monitor.connections_for(self.pid)
        seen = set()
        for c in conns:
            iid = "|".join(str(x) for x in c.key)
            local = f"{c.local_ip}:{c.local_port}" if c.local_port else c.local_ip
            remote = (f"{c.remote_ip}:{c.remote_port}"
                      if c.remote_port else "-")
            arrow = c.direction_arrow if c.remote_port else ""
            tag = "listen" if c.status == "LISTEN" else (
                "active" if (c.up_bps + c.down_bps) > 0 else "")
            vals = (c.protocol, local, arrow, remote, c.status,
                    human_speed(c.down_bps), human_speed(c.up_bps))
            if self.tree.exists(iid):
                self.tree.item(iid, values=vals, tags=(tag,) if tag else ())
            else:
                self.tree.insert("", "end", iid=iid, values=vals,
                                 tags=(tag,) if tag else ())
            seen.add(iid)

        for iid in list(self._known):
            if iid not in seen and self.tree.exists(iid):
                self.tree.delete(iid)
        self._known = seen

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
        title = f"{lip}:{lport} {('->')} {rip}:{rport}"
        self._packet_windows[conn_key] = PacketsWindow(
            self, self.monitor, conn_key, title)
