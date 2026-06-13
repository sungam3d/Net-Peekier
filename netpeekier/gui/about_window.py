"""About dialog: version, one-line description with a clickable Readme link
that opens the formatted README, and author credits that link out."""
from __future__ import annotations

import os
import tkinter as tk
import webbrowser
from tkinter import font as tkfont

from .. import get_version
from .. import paths
from .winutil import center_on_parent


class AboutWindow(tk.Toplevel):
    def __init__(self, master, monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.title("About Net-Peekier")
        self.resizable(False, False)
        self.configure(bg="white")

        pad = {"padx": 22}
        base = tkfont.nametofont("TkDefaultFont").actual("family")

        tk.Label(self, bg="white", fg="#1a3a5a",
                 font=(base, 10, "bold"),
                 text=f"Net-Peekier  v{get_version()}").grid(
            row=0, column=0, sticky="w", pady=(18, 2), **pad)

        tk.Label(self, bg="white", justify="left", anchor="w", font=(base, 10),
                 text="A small simple no-fuss network monitor inspired by "
                      "Net-Peeker.").grid(row=1, column=0, sticky="w", **pad)

        # "See Readme for further details." with Readme as a link
        line = tk.Frame(self, bg="white")
        line.grid(row=2, column=0, sticky="w", pady=(0, 10), **pad)
        tk.Label(line, bg="white", font=(base, 10), text="See ").pack(
            side="left")
        self._link(line, "Readme", self._open_readme).pack(side="left")
        tk.Label(line, bg="white", font=(base, 10),
                 text=" for further details.").pack(side="left")

        # credits with author links
        cred = tk.Frame(self, bg="white")
        cred.grid(row=3, column=0, sticky="w", pady=(0, 12), **pad)
        tk.Label(cred, bg="white", font=(base, 10), text="Created by ").pack(
            side="left")
        self._link(cred, "SunnyZ",
                   lambda: webbrowser.open("https://sunnyz.net/")).pack(
            side="left")
        tk.Label(cred, bg="white", font=(base, 10), text=" and ").pack(
            side="left")
        self._link(cred, "Claude.ai",
                   lambda: webbrowser.open("https://claude.ai/")).pack(
            side="left")

        tk.Button(self, text="Close", width=10, command=self.destroy).grid(
            row=4, column=0, pady=(0, 14))

        center_on_parent(self, master)

    def _link(self, parent, text, command) -> tk.Label:
        base = tkfont.nametofont("TkDefaultFont").actual("family")
        lbl = tk.Label(parent, text=text, bg="white", fg="#1565c0",
                       font=(base, 10, "underline"), cursor="hand2")
        lbl.bind("<Button-1>", lambda _e: command())
        return lbl

    def _open_readme(self) -> None:
        from .markdown_viewer import MarkdownViewer
        readme = os.path.join(paths.ROOT, "README.md")
        if not os.path.exists(readme):
            webbrowser.open("https://github.com/")  # harmless fallback
            return
        MarkdownViewer(self, readme, title="README")
