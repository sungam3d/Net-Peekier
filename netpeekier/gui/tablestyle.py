"""Shared Treeview styling helpers.

Three things every table window wants:
  * zebra striping, but blocked rows get light-red shades instead of blue;
  * a blocked row, when selected, highlights red with white text (normal rows
    keep the usual blue selection);
  * column widths that persist between runs.

Each row carries exactly ONE background tag and ONE foreground tag, so there's
never any tag-precedence ambiguity between striping and status colour.
"""
from __future__ import annotations

from tkinter import ttk
from typing import Dict, Iterable

# backgrounds
_STRIPE_EVEN = "#eef4fb"   # very light blue
_STRIPE_ODD = "#ffffff"
_BLK_EVEN = "#ffd6d6"      # light red
_BLK_ODD = "#ffe7e7"
# foregrounds
_FG_BLOCKED = "#b00000"
_FG_ACTIVE = "#0a7d00"
# selection colours
_SEL_NORMAL_BG = "#2a6fb0"
_SEL_BLOCKED_BG = "#c0392b"
_SEL_FG = "#ffffff"


def init_table(tree) -> None:
    """Give a Treeview a private style + the stripe/status tags, and wire its
    selection colour to flip red when a blocked row is selected."""
    style = ttk.Style()
    name = f"NP{id(tree)}.Treeview"
    style.configure(name, rowheight=22)
    tree.configure(style=name)
    tree._np_style = name            # type: ignore[attr-defined]
    tree._np_blocked = set()         # type: ignore[attr-defined]

    tree.tag_configure("bg_se", background=_STRIPE_EVEN)
    tree.tag_configure("bg_so", background=_STRIPE_ODD)
    tree.tag_configure("bg_be", background=_BLK_EVEN)
    tree.tag_configure("bg_bo", background=_BLK_ODD)
    tree.tag_configure("fg_blocked", foreground=_FG_BLOCKED)
    tree.tag_configure("fg_active", foreground=_FG_ACTIVE)
    tree.tag_configure("fg_listen", foreground="#666666")
    tree.tag_configure("fg_out", foreground="#0a7d00")
    tree.tag_configure("fg_in", foreground="#1a4fc4")

    def _on_select(_e=None):
        sel = set(tree.selection())
        blocked = bool(sel & tree._np_blocked)  # type: ignore[attr-defined]
        if blocked:
            style.map(name, background=[("selected", _SEL_BLOCKED_BG)],
                      foreground=[("selected", _SEL_FG)])
        else:
            style.map(name, background=[("selected", _SEL_NORMAL_BG)],
                      foreground=[("selected", _SEL_FG)])

    tree.bind("<<TreeviewSelect>>", _on_select, add="+")
    _on_select()


def apply_stripes(tree, rowflags: Dict[str, Iterable[str]] | None = None,
                  parent: str = "", counter=None) -> None:
    """Stripe rows in display order. `rowflags` maps iid -> flags containing
    'blocked' and/or 'active'. Blocked rows get light-red shades + red text;
    others get the blue zebra. Recurses so grouped rows stripe correctly."""
    if rowflags is None:
        rowflags = {}
    top = counter is None
    if top:
        counter = [0]
        tree._np_blocked = set()     # type: ignore[attr-defined]
    for iid in tree.get_children(parent):
        flags = set(rowflags.get(iid, ()))
        even = counter[0] % 2 == 0
        counter[0] += 1
        if "blocked" in flags:
            bg = "bg_be" if even else "bg_bo"
            fg = "fg_blocked"
            tree._np_blocked.add(iid)  # type: ignore[attr-defined]
        else:
            bg = "bg_se" if even else "bg_so"
            if "listen" in flags:
                fg = "fg_listen"
            elif "out" in flags:
                fg = "fg_out"
            elif "in" in flags:
                fg = "fg_in"
            elif "active" in flags:
                fg = "fg_active"
            else:
                fg = None
        tree.item(iid, tags=(bg, fg) if fg else (bg,))
        apply_stripes(tree, rowflags, iid, counter)


# ---- column-width persistence --------------------------------------------
def restore_widths(tree, key: str, settings, columns: Iterable[str]) -> None:
    saved = settings.column_widths.get(key, {})
    for col in columns:
        w = saved.get(col)
        if w:
            try:
                tree.column(col, width=int(w))
            except Exception:
                pass


def capture_widths(tree, key: str, settings, columns: Iterable[str]) -> None:
    out: Dict[str, int] = {}
    for col in columns:
        try:
            out[col] = int(tree.column(col, "width"))
        except Exception:
            pass
    if out:
        settings.column_widths[key] = out
        settings.save()
