"""Click-to-sort support for ttk.Treeview, shared by every window.

Usage:
    self.sorter = TreeSorter(tree, base_headings, key_getter,
                             default_col="down", default_reverse=True)
  - base_headings: {column_id: "Heading text"}; include "#0" for the tree col.
  - key_getter(iid, col) -> a sortable value (number or string) for that cell.

Clicking a heading sorts by that column and toggles direction; an arrow shows
the active column. Because the windows rebuild rows ~once a second, call
`sorter.apply()` at the end of each refresh so the chosen order persists. The
sort is hierarchy-aware: it orders top-level rows and recurses into children
(used by the grouped application list in the main window).
"""
from __future__ import annotations

from typing import Callable, Dict


class TreeSorter:
    def __init__(self, tree, base_headings: Dict[str, str],
                 key_getter: Callable[[str, str], object],
                 default_col: str | None = None,
                 default_reverse: bool = False) -> None:
        self.tree = tree
        self.key_getter = key_getter
        self.col = default_col
        self.reverse = default_reverse
        self._base = dict(base_headings)
        for col in self._base:
            self.tree.heading(col, command=lambda c=col: self._clicked(c))
        self._render_headings()

    # ---- public -----------------------------------------------------------
    def set_base(self, col: str, text: str) -> None:
        """Update a heading's base label (e.g. to append the current unit)."""
        if self._base.get(col) != text:
            self._base[col] = text
            self._render_headings()

    def apply(self, parent: str = "") -> None:
        if self.col is None:
            return
        kids = list(self.tree.get_children(parent))
        if not kids:
            return
        try:
            kids.sort(key=lambda i: _norm(self.key_getter(i, self.col)),
                      reverse=self.reverse)
        except Exception:
            return
        for idx, iid in enumerate(kids):
            self.tree.move(iid, parent, idx)
            self.apply(iid)  # keep children ordered too

    # ---- internals --------------------------------------------------------
    def _clicked(self, col: str) -> None:
        if self.col == col:
            self.reverse = not self.reverse
        else:
            self.col = col
            self.reverse = False
        self.apply()
        self._render_headings()

    def _render_headings(self) -> None:
        for col, base in self._base.items():
            arrow = ""
            if col == self.col:
                arrow = "  v" if self.reverse else "  ^"
            self.tree.heading(col, text=base + arrow)


def _norm(value):
    """Make values comparable: numbers sort numerically, everything else as a
    lowercased string, so mixed/None cells never raise."""
    if isinstance(value, (int, float)):
        return (0, value)
    return (1, str(value).lower())


# light zebra striping ------------------------------------------------------
STRIPE_EVEN = "_stripe_even"
STRIPE_ODD = "_stripe_odd"


def configure_stripes(tree, even_bg: str = "#eef4fb", odd_bg: str = "#ffffff"):
    """Set up the two stripe tags. Call once when building a tree. The default
    even-row colour is a very light blue that only just stands out."""
    tree.tag_configure(STRIPE_EVEN, background=even_bg)
    tree.tag_configure(STRIPE_ODD, background=odd_bg)


def apply_stripes(tree, base_tags: dict, parent: str = "", counter=None):
    """Walk the tree in display order and give every other visible row a light
    background, preserving each row's status tag (colour) from `base_tags`
    ({iid: (tag, ...)}). Recurses so grouped/expanded rows stripe correctly.
    """
    if counter is None:
        counter = [0]
    for iid in tree.get_children(parent):
        stripe = STRIPE_EVEN if counter[0] % 2 == 0 else STRIPE_ODD
        counter[0] += 1
        base = base_tags.get(iid, ())
        if isinstance(base, str):
            base = (base,) if base else ()
        # stripe first so the status tag's foreground wins on shared options
        tree.item(iid, tags=(stripe, *tuple(base)))
        apply_stripes(tree, base_tags, iid, counter)
