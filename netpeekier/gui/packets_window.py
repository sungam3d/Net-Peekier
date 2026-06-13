"""Captured packets window with a hex/ASCII dump, like NetPeeker's packet view.

Live-updates the packet list for one connection (from the backend's ring
buffer). Click a packet to see its bytes in the classic offset / hex / ASCII
layout. Export writes the list (and dumps) to a text file.
"""
from __future__ import annotations

import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import List

from ..models import Packet
from ..monitor import Monitor
from ..paths import ensure_log_dir
from .treesort import TreeSorter
from .tablestyle import init_table, apply_stripes, restore_widths, capture_widths
from .winutil import center_on_parent, restore_geometry, save_geometry

_PCOLS = ("time", "local", "dir", "remote", "proto", "len")

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
        restore_geometry(self, self.monitor.settings, "packets", "760x620")

        self._packets: List[Packet] = []
        self._paused = tk.BooleanVar(value=False)

        self._build_list()
        self._build_dump()
        self._build_buttons()

        restore_widths(self.tree, "packets", self.monitor.settings, _PCOLS)
        self.protocol("WM_DELETE_WINDOW", self._close)
        # only center if we don't have a remembered position
        if not self.monitor.settings.window_geometry_for("packets"):
            center_on_parent(self, master)
        self.after(REFRESH_MS, self._refresh)

    def _close(self) -> None:
        save_geometry(self, self.monitor.settings, "packets")
        capture_widths(self.tree, "packets", self.monitor.settings, _PCOLS)
        self.destroy()

    def _build_list(self) -> None:
        top = tk.Frame(self)
        top.pack(side="top", fill="both", expand=True)

        cols = ("time", "local", "dir", "remote", "proto", "len")
        self.tree = ttk.Treeview(top, columns=cols, show="headings", height=14,
                                 selectmode="extended")
        headings = {
            "time": ("Time", 175), "local": ("Local Address", 150),
            "dir": ("D.", 35), "remote": ("Remote Address", 150),
            "proto": ("Protocol", 70), "len": ("Packet", 60),
        }
        for c, (txt, w) in headings.items():
            anchor = "center" if c == "dir" else (
                "e" if c == "len" else "w")
            self.tree.column(c, width=w, anchor=anchor)
        self._sortkeys: dict[str, dict] = {}
        self.sorter = TreeSorter(
            self.tree, {c: t for c, (t, _w) in headings.items()},
            lambda iid, col: self._sortkeys.get(iid, {}).get(col),
            default_col="time", default_reverse=False)

        vsb = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        init_table(self.tree)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._on_right_click)

        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Export selected to log...",
                             command=self._export_selected)
        self.ctx.add_command(label="Export all to log...",
                             command=self._export)

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
        tk.Button(bar, text="Close", command=self._close).pack(side="right")

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
        sortkeys: dict[str, dict] = {}
        rowtags: dict[str, tuple] = {}
        for i, p in enumerate(self._packets):
            ts = datetime.fromtimestamp(p.ts).strftime("%H:%M:%S.") + \
                f"{int((p.ts % 1) * 1000):03d}"
            local = f"{p.local_ip}:{p.local_port}"
            remote = f"{p.remote_ip}:{p.remote_port}"
            tag = "out" if p.outbound else "in"
            self.tree.insert("", "end", iid=str(i),
                             values=(ts, local, p.direction_arrow, remote,
                                     p.protocol, p.length))
            rowtags[str(i)] = (tag,)
            sortkeys[str(i)] = {
                "time": p.ts, "local": p.local_port, "dir": p.direction_arrow,
                "remote": p.remote_ip, "proto": p.protocol, "len": p.length,
            }
        self._sortkeys = sortkeys
        self.sorter.apply()
        apply_stripes(self.tree, rowtags)
        if at_bottom and self.sorter.col == "time" and not self.sorter.reverse \
                and self._packets:
            self.tree.see(str(len(self._packets) - 1))

    def _is_scrolled_bottom(self) -> bool:
        try:
            return self.tree.yview()[1] >= 0.999
        except Exception:
            return True

    def _on_right_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.ctx.tk_popup(event.x_root, event.y_root)

    def _on_select(self, _event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[-1])
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

    # ---- export -----------------------------------------------------------
    def _packet_report(self, p: Packet, index: int) -> str:
        """As much detail as we have about one packet, plus its hex dump."""
        dt = datetime.fromtimestamp(p.ts)
        lines = [
            f"Packet #{index}",
            f"  Time          : {dt.strftime('%Y-%m-%d %H:%M:%S.')}"
            f"{int((p.ts % 1) * 1000):03d}",
            f"  Direction     : {'OUTBOUND -->' if p.outbound else 'INBOUND <--'}",
            f"  Protocol      : {p.protocol}",
            f"  Local address : {p.local_ip}:{p.local_port}",
            f"  Remote address: {p.remote_ip}:{p.remote_port}",
            f"  Length        : {p.length} bytes",
            f"  Owner PID     : {p.pid if p.pid is not None else 'unknown'}",
            "  Hex dump:",
        ]
        dump = hexdump(p.raw)
        lines.extend("    " + ln for ln in dump.splitlines())
        return "\n".join(lines)

    def _write_log(self, packets: List[Packet], title: str) -> None:
        if not packets:
            messagebox.showinfo("Export", "No packets to export.", parent=self)
            return
        default_name = "packets_" + datetime.now().strftime("%Y%m%d_%H%M%S") \
            + ".log"
        path = filedialog.asksaveasfilename(
            title=title, defaultextension=".log", initialdir=ensure_log_dir(),
            initialfile=default_name,
            filetypes=[("Log file", "*.log"), ("Text", "*.txt"),
                       ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Net-Peekier packet log\n")
                f.write(f"Generated : {datetime.now().isoformat()}\n")
                f.write(f"Connection: {self.conn_key}\n")
                f.write(f"Packets   : {len(packets)}\n")
                f.write("=" * 60 + "\n\n")
                for i, p in enumerate(packets, 1):
                    f.write(self._packet_report(p, i))
                    f.write("\n\n")
            messagebox.showinfo("Export",
                                f"Saved {len(packets)} packet(s) to:\n{path}",
                                parent=self)
        except Exception as exc:
            messagebox.showerror("Export", str(exc), parent=self)

    def _export_selected(self) -> None:
        sel = self.tree.selection()
        idxs = sorted(int(i) for i in sel if i.isdigit())
        packets = [self._packets[i] for i in idxs if 0 <= i < len(self._packets)]
        self._write_log(packets, "Export selected packets to log")

    def _export(self) -> None:
        self._write_log(self._packets, "Export all packets to log")
