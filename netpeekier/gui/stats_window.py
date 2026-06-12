"""Statistics window.

Reads the rolling activity log (log/history.jsonl) and renders a few charts:
  * total data used (this session's log) and a per-app summary table,
  * top apps by data (horizontal bars),
  * traffic by hour of day (stacked bars),
  * traffic over time (up/down lines).

All charts are drawn on plain tk Canvases (no external plotting libraries), so
there's nothing extra to install.
"""
from __future__ import annotations

import os
import time
import tkinter as tk
from tkinter import messagebox, ttk

from ..monitor import Monitor
from ..history import load_history, aggregate
from . import charts
from .charts import Chart, hbar_chart, hour_chart, timeline_chart, _human
from .winutil import center_on_parent
from .tablestyle import init_table, apply_stripes, restore_widths, capture_widths

_RANGES = {"Last hour": 3600, "Last 24 hours": 86400,
           "Last 7 days": 604800, "All time": None}
_SCOLS = ("name", "up", "down", "total", "runtime")


class StatsWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.title("Net-Peekier - Statistics")
        self.geometry("900x640")

        self._path = os.path.join(_log_dir(monitor), "history.jsonl")

        self._build_toolbar()
        self._build_body()
        restore_widths(self.tree, "stats", self.monitor.settings, _SCOLS)
        self.protocol("WM_DELETE_WINDOW", self._close)
        center_on_parent(self, master)
        self.reload()

    def _close(self) -> None:
        capture_widths(self.tree, "stats", self.monitor.settings, _SCOLS)
        self.destroy()

    # ---- layout -----------------------------------------------------------
    def _build_toolbar(self) -> None:
        bar = tk.Frame(self, bg="#d6dce4")
        bar.pack(side="top", fill="x")
        tk.Label(bar, text="  Range:", bg="#d6dce4").pack(side="left")
        self.var_range = tk.StringVar(value="Last 24 hours")
        cb = ttk.Combobox(bar, textvariable=self.var_range, width=16,
                          state="readonly", values=list(_RANGES))
        cb.pack(side="left", padx=4, pady=4)
        cb.bind("<<ComboboxSelected>>", lambda _e: self.reload())
        tk.Button(bar, text="Refresh", command=self.reload).pack(
            side="left", padx=4)
        self.var_summary = tk.StringVar(value="")
        tk.Label(bar, textvariable=self.var_summary, bg="#d6dce4",
                 fg="#0a4d7d", font=("Segoe UI", 9, "bold")).pack(
            side="left", padx=12)
        tk.Button(bar, text="Flush now",
                  command=self._flush_now).pack(side="right", padx=6)
        tk.Button(bar, text="Clear log...",
                  command=self._clear_log).pack(side="right")

    def _build_body(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(side="top", fill="both", expand=True, padx=6, pady=6)

        # --- charts tab ---
        charts_tab = tk.Frame(nb, bg="white")
        nb.add(charts_tab, text="Graphs")
        top = tk.Frame(charts_tab, bg="white")
        top.pack(side="top", fill="both", expand=True)
        self.c_top = Chart(top, lambda c: hbar_chart(
            c, self._top_rows, title="Top apps by data used"))
        self.c_top.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        self.c_hour = Chart(top, lambda c: hour_chart(
            c, self._agg["per_hour"], title="By hour of day"))
        self.c_hour.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        self.c_time = Chart(charts_tab, lambda c: timeline_chart(
            c, self._agg["timeline"], title="Traffic over time"), height=240)
        self.c_time.pack(side="top", fill="both", expand=True, padx=4, pady=4)

        # --- table tab ---
        table_tab = tk.Frame(nb)
        nb.add(table_tab, text="Per-app totals")
        cols = ("up", "down", "total", "runtime")
        self.tree = ttk.Treeview(table_tab, columns=cols, show="tree headings")
        self.tree.heading("#0", text="Application")
        self.tree.heading("up", text="Uploaded")
        self.tree.heading("down", text="Downloaded")
        self.tree.heading("total", text="Total")
        self.tree.heading("runtime", text="Active time")
        self.tree.column("#0", width=300, anchor="w")
        for c in cols:
            self.tree.column(c, width=120, anchor="e")
        self.tree.column("runtime", anchor="e")
        init_table(self.tree)
        vsb = ttk.Scrollbar(table_tab, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._agg = {"per_hour": {}, "timeline": [], "per_exe": {},
                     "totals": {"up": 0, "down": 0, "total": 0}}
        self._top_rows = []

    # ---- data -------------------------------------------------------------
    def reload(self) -> None:
        secs = _RANGES.get(self.var_range.get())
        since = (time.time() - secs) if secs else None
        records = load_history(self._path, since)
        self._agg = aggregate(records)
        per_exe = self._agg["per_exe"]
        # top rows by total bytes
        self._top_rows = [
            (e["name"] or exe, e["total"])
            for exe, e in sorted(per_exe.items(),
                                 key=lambda kv: kv[1]["total"], reverse=True)
        ]
        t = self._agg["totals"]
        self.var_summary.set(
            f"Total: {_human(t['total'])}   "
            f"\u2191 {_human(t['up'])}   \u2193 {_human(t['down'])}")
        self._fill_table()
        for c in (self.c_top, self.c_hour, self.c_time):
            c.redraw()

    def _fill_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        rowtags = {}
        per_exe = self._agg["per_exe"]
        for exe, e in sorted(per_exe.items(),
                             key=lambda kv: kv[1]["total"], reverse=True):
            iid = exe
            self.tree.insert(
                "", "end", iid=iid,
                text=e["name"] or os.path.basename(exe) or exe,
                values=(_human(e["up"]), _human(e["down"]),
                        _human(e["total"]), _fmt_secs(e["secs"])))
            rowtags[iid] = ()
        apply_stripes(self.tree, rowtags)

    # ---- actions ----------------------------------------------------------
    def _flush_now(self) -> None:
        try:
            self.monitor.history.flush()
        except Exception:
            pass
        self.reload()

    def _clear_log(self) -> None:
        if not messagebox.askyesno(
                "Clear statistics log",
                "Delete all recorded activity history?\n"
                "This cannot be undone.", parent=self):
            return
        try:
            self.monitor.history.flush()
            if os.path.exists(self._path):
                os.remove(self._path)
        except Exception as exc:
            messagebox.showerror("Clear log", str(exc), parent=self)
        self.reload()


def _log_dir(monitor) -> str:
    from .. import paths
    return paths.LOG_DIR


def _fmt_secs(s: float) -> str:
    s = int(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"
