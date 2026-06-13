"""A small, dependency-free Markdown viewer in a Tk Text widget.

Not a full CommonMark implementation -- just enough to render this project's
README nicely: headings, bold, inline code, fenced code blocks, bullet lists,
horizontal rules and clickable [text](url) links.
"""
from __future__ import annotations

import os
import re
import tkinter as tk
import webbrowser
from tkinter import font as tkfont
from tkinter import ttk

from .winutil import center_on_parent

_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_CODE_RE = re.compile(r"`([^`]+)`")


class MarkdownViewer(tk.Toplevel):
    def __init__(self, master, path: str, title: str = "README") -> None:
        super().__init__(master)
        self.title(f"Net-Peekier - {title}")
        self.geometry("760x640")

        wrap = tk.Frame(self)
        wrap.pack(fill="both", expand=True)
        self.text = tk.Text(wrap, wrap="word", padx=18, pady=14,
                            bg="white", relief="flat", cursor="arrow",
                            spacing1=2, spacing3=4)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        self.text.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._link_count = 0
        self._configure_tags()
        self._render(path)
        self.text.configure(state="disabled")

        bar = tk.Frame(self)
        bar.pack(fill="x")
        tk.Button(bar, text="Close", command=self.destroy).pack(
            side="right", padx=8, pady=6)

        center_on_parent(self, master)

    # ---- styling ----------------------------------------------------------
    def _configure_tags(self) -> None:
        base = tkfont.nametofont("TkTextFont")
        family = base.actual("family")
        self.text.configure(font=(family, 11))
        sizes = {1: 20, 2: 16, 3: 14, 4: 12, 5: 11, 6: 11}
        for lvl, sz in sizes.items():
            self.text.tag_configure(
                f"h{lvl}", font=(family, sz, "bold"),
                spacing1=10, spacing3=4,
                foreground="#1a3a5a" if lvl <= 2 else "#23527c")
        self.text.tag_configure("bold", font=(family, 11, "bold"))
        self.text.tag_configure("code", font=("Consolas", 10),
                                background="#f0f2f5")
        self.text.tag_configure("codeblock", font=("Consolas", 10),
                                background="#f5f6f8", lmargin1=24, lmargin2=24,
                                spacing1=0, spacing3=0)
        self.text.tag_configure("bullet", lmargin1=22, lmargin2=38)
        self.text.tag_configure("hr", overstrike=False)
        self.text.tag_configure("link", foreground="#1565c0",
                                underline=True)
        self.text.tag_bind("link", "<Enter>",
                           lambda _e: self.text.configure(cursor="hand2"))
        self.text.tag_bind("link", "<Leave>",
                           lambda _e: self.text.configure(cursor="arrow"))

    # ---- rendering --------------------------------------------------------
    def _render(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except Exception as exc:
            self.text.insert("end", f"Could not open {path}:\n{exc}")
            return

        in_code = False
        for raw in lines:
            if raw.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                self.text.insert("end", raw + "\n", ("codeblock",))
                continue
            if re.match(r"^\s*([-*_])\1{2,}\s*$", raw):     # --- *** ___
                self.text.insert("end", "\u2500" * 60 + "\n", ("hr",))
                continue
            m = re.match(r"^(#{1,6})\s+(.*)$", raw)
            if m:
                lvl = len(m.group(1))
                self._insert_inline(m.group(2), extra=(f"h{lvl}",))
                self.text.insert("end", "\n")
                continue
            bullet = re.match(r"^\s*[-*]\s+(.*)$", raw)
            if bullet:
                self.text.insert("end", "\u2022 ", ("bullet",))
                self._insert_inline(bullet.group(1), extra=("bullet",))
                self.text.insert("end", "\n")
                continue
            num = re.match(r"^\s*(\d+)\.\s+(.*)$", raw)
            if num:
                self.text.insert("end", f"{num.group(1)}. ", ("bullet",))
                self._insert_inline(num.group(2), extra=("bullet",))
                self.text.insert("end", "\n")
                continue
            if raw.strip() == "":
                self.text.insert("end", "\n")
                continue
            self._insert_inline(raw)
            self.text.insert("end", "\n")

    def _insert_inline(self, s: str, extra: tuple = ()) -> None:
        """Render one line, handling links, **bold** and `code` spans."""
        pos = 0
        # tokenize by the three inline patterns, leftmost-first
        while pos < len(s):
            link = _LINK_RE.search(s, pos)
            bold = _BOLD_RE.search(s, pos)
            code = _CODE_RE.search(s, pos)
            cands = [c for c in (link, bold, code) if c]
            if not cands:
                self.text.insert("end", s[pos:], extra)
                break
            nxt = min(cands, key=lambda m: m.start())
            if nxt.start() > pos:
                self.text.insert("end", s[pos:nxt.start()], extra)
            if nxt is link:
                self._insert_link(nxt.group(1), nxt.group(2), extra)
            elif nxt is bold:
                self.text.insert("end", nxt.group(1), extra + ("bold",))
            else:  # code
                self.text.insert("end", nxt.group(1), extra + ("code",))
            pos = nxt.end()

    def _insert_link(self, label: str, url: str, extra: tuple) -> None:
        self._link_count += 1
        tag = f"link-{self._link_count}"
        self.text.insert("end", label, extra + ("link", tag))
        self.text.tag_bind(tag, "<Button-1>",
                           lambda _e, u=url: webbrowser.open(u))
