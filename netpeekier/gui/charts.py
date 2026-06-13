"""Tiny dependency-free charts drawn on a tk.Canvas.

Just enough to render the Statistics window without pulling in matplotlib:
a horizontal bar chart (top talkers), a 24-bar by-hour chart, and a stacked
up/down area/line over time. Everything scales to the canvas size and redraws
on resize.
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable, List, Sequence, Tuple

UP_COLOR = "#2a6fb0"     # upload (blue)
DOWN_COLOR = "#2e9e5b"   # download (green)
GRID = "#dfe4ea"
AXIS = "#9aa3ad"
TEXT = "#333333"


def _human(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return (f"{n:.0f} {unit}" if unit == "B"
                    else f"{n:.1f} {unit}")
        n /= 1024
    return f"{n:.1f} TB"


def _legend(canvas, right_x: int, y: int) -> None:
    """Draw a colour-matched 'up / down' key at the top-right, with the swatch
    text in the same blue/green as the chart series (not grey)."""
    font = ("Segoe UI", 8)
    d = canvas.create_text(right_x, y, anchor="ne", text="\u25a0 down",
                           fill=DOWN_COLOR, font=font)
    bbox = canvas.bbox(d)
    left = (bbox[0] - 10) if bbox else (right_x - 50)
    canvas.create_text(left, y, anchor="ne", text="\u25a0 up",
                       fill=UP_COLOR, font=font)


class Chart(tk.Canvas):
    """Base canvas that redraws via a supplied draw fn on resize."""

    def __init__(self, master, draw: Callable[["Chart"], None],
                 height: int = 220, **kw) -> None:
        super().__init__(master, height=height, bg="white",
                         highlightthickness=0, **kw)
        self._draw = draw
        self.bind("<Configure>", lambda _e: self.redraw())

    def redraw(self) -> None:
        self.delete("all")
        try:
            self._draw(self)
        except Exception:
            pass


def hbar_chart(canvas: Chart, rows: Sequence[Tuple[str, float]],
               value_fmt=_human, title: str = "") -> None:
    """Horizontal bars: rows = [(label, value), ...] already sorted desc."""
    w = canvas.winfo_width() or 480
    h = canvas.winfo_height() or 220
    pad_l, pad_r, pad_t, pad_b = 150, 70, 24 if title else 8, 8
    if title:
        canvas.create_text(8, 12, text=title, anchor="w", fill=TEXT,
                           font=("Segoe UI", 10, "bold"))
    if not rows:
        canvas.create_text(w / 2, h / 2, text="No data yet", fill=AXIS)
        return
    rows = list(rows)[:12]
    vmax = max(v for _, v in rows) or 1
    avail_h = h - pad_t - pad_b
    bar_h = max(10, min(28, avail_h / len(rows) - 6))
    gap = (avail_h - bar_h * len(rows)) / max(1, len(rows))
    y = pad_t
    plot_w = w - pad_l - pad_r
    for label, val in rows:
        bw = plot_w * (val / vmax)
        canvas.create_text(pad_l - 8, y + bar_h / 2, text=_elide(label, 22),
                           anchor="e", fill=TEXT, font=("Segoe UI", 9))
        canvas.create_rectangle(pad_l, y, pad_l + bw, y + bar_h,
                                fill=UP_COLOR, outline="")
        canvas.create_text(pad_l + bw + 6, y + bar_h / 2,
                           text=value_fmt(val), anchor="w", fill=TEXT,
                           font=("Segoe UI", 9))
        y += bar_h + gap


def hour_chart(canvas: Chart, per_hour: dict, title: str = "") -> None:
    """24 vertical stacked bars (down on top of up) by hour of day."""
    w = canvas.winfo_width() or 480
    h = canvas.winfo_height() or 220
    pad_l, pad_r, pad_t, pad_b = 56, 12, 24 if title else 10, 26
    if title:
        canvas.create_text(8, 12, text=title, anchor="w", fill=TEXT,
                           font=("Segoe UI", 10, "bold"))
    hours = range(24)
    totals = [per_hour.get(hh, {"up": 0, "down": 0}) for hh in hours]
    vmax = max((t["up"] + t["down"]) for t in totals) or 1
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    bw = plot_w / 24 * 0.7
    step = plot_w / 24
    # y axis labels
    for frac in (0, 0.5, 1.0):
        yy = pad_t + plot_h * (1 - frac)
        canvas.create_line(pad_l, yy, w - pad_r, yy, fill=GRID)
        canvas.create_text(pad_l - 6, yy, text=_human(vmax * frac),
                           anchor="e", fill=AXIS, font=("Segoe UI", 8))
    for hh in hours:
        t = totals[hh]
        x = pad_l + step * hh + (step - bw) / 2
        up_h = plot_h * (t["up"] / vmax)
        down_h = plot_h * (t["down"] / vmax)
        base = pad_t + plot_h
        canvas.create_rectangle(x, base - up_h, x + bw, base,
                                fill=UP_COLOR, outline="")
        canvas.create_rectangle(x, base - up_h - down_h, x + bw, base - up_h,
                                fill=DOWN_COLOR, outline="")
        if hh % 3 == 0:
            canvas.create_text(x + bw / 2, base + 12, text=str(hh),
                               fill=AXIS, font=("Segoe UI", 8))
    _legend(canvas, int(w - pad_r), int(pad_t + 2))


def timeline_chart(canvas: Chart, points: List[Tuple[int, int, int]],
                   title: str = "") -> None:
    """Area lines of up/down over time. points = [(epoch, up, down)]."""
    import time as _t
    w = canvas.winfo_width() or 480
    h = canvas.winfo_height() or 220
    pad_l, pad_r, pad_t, pad_b = 56, 12, 24 if title else 10, 26
    if title:
        canvas.create_text(8, 12, text=title, anchor="w", fill=TEXT,
                           font=("Segoe UI", 10, "bold"))
    if len(points) < 2:
        canvas.create_text(w / 2, h / 2, text="Not enough data yet", fill=AXIS)
        return
    t0 = points[0][0]
    t1 = points[-1][0]
    span = (t1 - t0) or 1
    vmax = max(max(u, d) for _, u, d in points) or 1
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    base = pad_t + plot_h

    for frac in (0, 0.5, 1.0):
        yy = pad_t + plot_h * (1 - frac)
        canvas.create_line(pad_l, yy, w - pad_r, yy, fill=GRID)
        canvas.create_text(pad_l - 6, yy, text=_human(vmax * frac),
                           anchor="e", fill=AXIS, font=("Segoe UI", 8))

    def xy(t, v):
        x = pad_l + plot_w * ((t - t0) / span)
        y = base - plot_h * (v / vmax)
        return x, y

    for color, idx in ((UP_COLOR, 1), (DOWN_COLOR, 2)):
        coords = []
        for p in points:
            coords.extend(xy(p[0], p[idx]))
        canvas.create_line(*coords, fill=color, width=2, smooth=True)

    # time axis: start + end labels
    canvas.create_text(pad_l, base + 12,
                       text=_t.strftime("%H:%M", _t.localtime(t0)),
                       fill=AXIS, anchor="w", font=("Segoe UI", 8))
    canvas.create_text(w - pad_r, base + 12,
                       text=_t.strftime("%H:%M", _t.localtime(t1)),
                       fill=AXIS, anchor="e", font=("Segoe UI", 8))
    _legend(canvas, int(w - pad_r), int(pad_t + 2))


def _elide(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "\u2026"
