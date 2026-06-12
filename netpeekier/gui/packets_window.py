"""Captured packets window with a hex/ASCII dump, like NetPeeker's packet view.

Live-updates the packet list for one connection (from the backend's ring
buffer). Click a packet to see its bytes in the classic offset / hex / ASCII
layout. Export writes the list (and dumps) to a text file.
"""
from __future__ import annotations

import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk
from typing import List

from ..models import Packet
from ..monitor import Monitor

REFRESH_MS = 1000


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        hexpart = f"{hexpart:<{width * 3 - 1}}"
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08X}  {hexpart}  {asciipart}")
    return "\n".join(lines) if lines else "(no payload captured)"


class PacketsWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor, conn_key, title: str) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.conn_key = conn_key
        self.title(f"Captured Packets - {title}")
        self.geometry("760x620")

        self._packets: List[Packet] = []
        self._paused = tk.BooleanVar(value=False)

        self._build_list()
        self._build_dump()
        self._build_buttons()

        self.after(REFRESH_MS, self._refresh)

    def _build_list(self) -> None:
        top = tk.Frame(self)
        top.pack(side="top", fill="both", expand=True)

        cols = ("time", "local", "dir", "remote", "proto", "len")
        self.tree = ttk.Treeview(top, columns=cols, show="headings", height=14)
        headings = {
            "time": ("Time", 175), "local": ("Local Address", 150),
            "dir": ("D.", 35), "remote": ("Remote Address", 150),
            "proto": ("Protocol", 70), "len": ("Packet", 60),
        }
        for c, (txt, w) in headings.items():
            self.tree.heading(c, text=txt)
            anchor = "center" if c == "dir" else (
                "e" if c == "len" else "w")
            self.tree.column(c, width=w, anchor=anchor)

        vsb = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("out", foreground="#0a7d00")
        self.tree.tag_configure("in", foreground="#1a4fc4")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _build_dump(self) -> None:
        frame = tk.LabelFrame(self, text="Packet bytes")
        frame.pack(side="top", fill="both", expand=True, padx=4, pady=2)
        self.dump = tk.Text(frame, height=12, wrap="none",
                            font=("Consolas", 9), bg="#fbfbf4")
        dvsb = ttk.Scrollbar(frame, orient="vertical", command=self.dump.yview)
        self.dump.configure(yscrollcommand=dvsb.set, state="disabled")
        self.dump.pack(side="left", fill="both", expand=True)
        dvsb.pack(side="right", fill="y")

    def _build_buttons(self) -> None:
        bar = tk.Frame(self)
        bar.pack(side="bottom", fill="x", pady=4)
        tk.Checkbutton(bar, text="Pause", variable=self._paused).pack(
            side="left", padx=6)
        tk.Button(bar, text="Clear", command=self._clear).pack(side="left")
        tk.Button(bar, text="Export...", command=self._export).pack(
            side="right", padx=6)
        tk.Button(bar, text="Close", command=self.destroy).pack(side="right")

    # ---- refresh ----------------------------------------------------------
    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        if not self._paused.get():
            packets = self.monitor.packets_for(self.conn_key)
            # only append new ones (ring buffer grows/rotates)
            if len(packets) != len(self._packets):
                self._render(packets)
        self.after(REFRESH_MS, self._refresh)

    def _render(self, packets: List[Packet]) -> None:
        at_bottom = self._is_scrolled_bottom()
        self.tree.delete(*self.tree.get_children())
        self._packets = list(packets)
        for i, p in enumerate(self._packets):
            ts = datetime.fromtimestamp(p.ts).strftime("%H:%M:%S.") + \
                f"{int((p.ts % 1) * 1000):03d}"
            local = f"{p.local_ip}:{p.local_port}"
            remote = f"{p.remote_ip}:{p.remote_port}"
            tag = "out" if p.outbound else "in"
            self.tree.insert("", "end", iid=str(i),
                             values=(ts, local, p.direction_arrow, remote,
                                     p.protocol, p.length),
                             tags=(tag,))
        if at_bottom and self._packets:
            self.tree.see(str(len(self._packets) - 1))

    def _is_scrolled_bottom(self) -> bool:
        try:
            return self.tree.yview()[1] >= 0.999
        except Exception:
            return True

    def _on_select(self, _event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if 0 <= idx < len(self._packets):
            p = self._packets[idx]
            self.dump.configure(state="normal")
            self.dump.delete("1.0", "end")
            self.dump.insert("1.0", hexdump(p.raw))
            self.dump.configure(state="disabled")

    def _clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._packets = []
        self.dump.configure(state="normal")
        self.dump.delete("1.0", "end")
        self.dump.configure(state="disabled")

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
            title="Export captured packets")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Net-Peekier capture  {time.ctime()}\n")
            f.write(f"# Connection: {self.conn_key}\n\n")
            for p in self._packets:
                ts = datetime.fromtimestamp(p.ts).isoformat()
                f.write(f"{ts}  {p.direction_arrow}  "
                        f"{p.local_ip}:{p.local_port} <-> "
                        f"{p.remote_ip}:{p.remote_port}  "
                        f"{p.protocol}  {p.length} bytes\n")
                if p.raw:
                    f.write(hexdump(p.raw) + "\n")
                f.write("\n")
