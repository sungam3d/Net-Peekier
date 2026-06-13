"""A small, dependency-free Markdown viewer in a Tk Text widget.

Not a full CommonMark implementation -- just enough to render this project's
README nicely: headings, bold, inline code, fenced code blocks, bullet lists,
horizontal rules, clickable [text](url) links, pipe tables, and images
(local files and remote https URLs).

Images use Tk's native PhotoImage (PNG/GIF). JPG/WebP render only if Pillow is
installed; otherwise the image's alt-text is shown as a placeholder. Nothing
here raises -- anything that can't be rendered degrades to readable text.
"""
from __future__ import annotations

import os
import re
import threading
import tkinter as tk
import webbrowser
from tkinter import font as tkfont
from tkinter import ttk

from .winutil import center_on_parent

_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_CODE_RE = re.compile(r"`([^`]+)`")
_IMG_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")


def _is_table_sep(line: str) -> bool:
    """A markdown header separator row, e.g. |---|:--:|---|."""
    s = line.strip()
    if "|" not in s or "-" not in s:
        return False
    cells = [c.strip() for c in s.strip("|").split("|")]
    return all(c and set(c) <= set("-: ") for c in cells)


def _split_row(line: str):
    return [c.strip() for c in line.strip().strip("|").split("|")]


class MarkdownViewer(tk.Toplevel):
    def __init__(self, master, path: str, title: str = "README") -> None:
        super().__init__(master)
        self.title(f"Net-Peekier - {title}")
        self.geometry("780x660")
        self._base_dir = os.path.dirname(os.path.abspath(path))
        self._images = []          # keep PhotoImage refs alive
        self._pending = {}         # remote url -> placeholder mark name

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
        self.text.tag_configure("link", foreground="#1565c0", underline=True)
        self.text.tag_bind("link", "<Enter>",
                           lambda _e: self.text.configure(cursor="hand2"))
        self.text.tag_bind("link", "<Leave>",
                           lambda _e: self.text.configure(cursor="arrow"))
        # table cell tags
        self.text.tag_configure("th", font=(family, 10, "bold"),
                                background="#eef1f5")
        self.text.tag_configure("td", font=(family, 10))
        self.text.tag_configure("imgalt", font=(family, 9, "italic"),
                                foreground="#888")

    # ---- rendering --------------------------------------------------------
    def _render(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except Exception as exc:
            self.text.insert("end", f"Could not open {path}:\n{exc}")
            return

        in_code = False
        i = 0
        n = len(lines)
        while i < n:
            raw = lines[i]
            if raw.strip().startswith("```"):
                in_code = not in_code
                i += 1
                continue
            if in_code:
                self.text.insert("end", raw + "\n", ("codeblock",))
                i += 1
                continue

            # table: a row of |...| followed by a |---| separator
            if ("|" in raw and i + 1 < n and _is_table_sep(lines[i + 1])
                    and raw.strip().startswith("|")):
                i = self._render_table(lines, i)
                continue

            if re.match(r"^\s*([-*_])\1{2,}\s*$", raw):     # --- *** ___
                self.text.insert("end", "\u2500" * 60 + "\n", ("hr",))
                i += 1
                continue
            m = re.match(r"^(#{1,6})\s+(.*)$", raw)
            if m:
                lvl = len(m.group(1))
                self._insert_inline(m.group(2), extra=(f"h{lvl}",))
                self.text.insert("end", "\n")
                i += 1
                continue
            # a line that is just an image
            only_img = _IMG_RE.fullmatch(raw.strip())
            if only_img:
                self._insert_image(only_img.group(1), only_img.group(2))
                self.text.insert("end", "\n")
                i += 1
                continue
            bullet = re.match(r"^\s*[-*]\s+(.*)$", raw)
            if bullet:
                self.text.insert("end", "\u2022 ", ("bullet",))
                self._insert_inline(bullet.group(1), extra=("bullet",))
                self.text.insert("end", "\n")
                i += 1
                continue
            num = re.match(r"^\s*(\d+)\.\s+(.*)$", raw)
            if num:
                self.text.insert("end", f"{num.group(1)}. ", ("bullet",))
                self._insert_inline(num.group(2), extra=("bullet",))
                self.text.insert("end", "\n")
                i += 1
                continue
            if raw.strip() == "":
                self.text.insert("end", "\n")
                i += 1
                continue
            self._insert_inline(raw)
            self.text.insert("end", "\n")
            i += 1

    def _render_table(self, lines, start: int) -> int:
        """Render a pipe table starting at `lines[start]`; return next index."""
        header = _split_row(lines[start])
        rows = []
        i = start + 2  # skip header + separator
        while i < len(lines) and "|" in lines[i] and lines[i].strip():
            rows.append(_split_row(lines[i]))
            i += 1

        ncols = max([len(header)] + [len(r) for r in rows]) if rows else len(header)
        # compute a per-column character width for monospace-ish alignment
        widths = [0] * ncols
        for row in [header] + rows:
            for c in range(len(row)):
                # strip inline markup for width measurement
                plain = re.sub(r"[*`]", "", row[c])
                plain = _LINK_RE.sub(r"\1", plain)
                widths[c] = max(widths[c], len(plain))
        widths = [min(w, 40) for w in widths]

        def emit(row, tag):
            for c in range(ncols):
                cell = row[c] if c < len(row) else ""
                self.text.insert("end", " ")
                self._insert_inline(cell, extra=(tag,))
                plain = re.sub(r"[*`]", "", cell)
                plain = _LINK_RE.sub(r"\1", plain)
                pad = max(0, widths[c] - len(plain))
                self.text.insert("end", " " * pad + " ", (tag,))
                if c < ncols - 1:
                    self.text.insert("end", "\u2502", (tag,))
            self.text.insert("end", "\n")

        emit(header, "th")
        # separator line under header
        sep = "\u2500".join("\u2500" * (widths[c] + 2) for c in range(ncols))
        self.text.insert("end", sep + "\n", ("td",))
        for row in rows:
            emit(row, "td")
        self.text.insert("end", "\n")
        return i

    def _insert_inline(self, s: str, extra: tuple = ()) -> None:
        """Render one line, handling links, **bold** and `code` spans."""
        pos = 0
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

    # ---- images -----------------------------------------------------------
    def _insert_image(self, alt: str, src: str) -> None:
        """Insert an image. Local paths load immediately; https URLs download on
        a background thread and swap in when ready. Failure -> alt-text."""
        if src.startswith(("http://", "https://")):
            mark = f"img-{len(self._pending)}"
            self.text.insert("end", f"[loading image: {alt or src}]", ("imgalt",))
            self.text.mark_set(mark, "end-1c")
            self.text.mark_gravity(mark, "left")
            self._pending[src] = (mark, alt)
            threading.Thread(target=self._fetch_remote, args=(src,),
                             daemon=True).start()
            return
        # local file (relative to the README's folder)
        path = src if os.path.isabs(src) else os.path.join(self._base_dir, src)
        img = self._load_image(path)
        if img is not None:
            self.text.image_create("end", image=img)
            self._images.append(img)
        else:
            self.text.insert("end", f"[image: {alt or os.path.basename(src)}]",
                             ("imgalt",))

    def _load_image(self, path: str, data: bytes = None):
        """Return a Tk image for a local path or raw bytes, or None."""
        # 1) native PhotoImage (PNG/GIF)
        try:
            if data is not None:
                return tk.PhotoImage(data=data)
            return tk.PhotoImage(file=path)
        except Exception:
            pass
        # 2) Pillow fallback (JPG/WebP/etc.) if available
        try:
            from PIL import Image, ImageTk   # type: ignore
            import io
            im = Image.open(io.BytesIO(data) if data is not None else path)
            im.thumbnail((700, 700))
            return ImageTk.PhotoImage(im)
        except Exception:
            return None

    def _fetch_remote(self, url: str) -> None:
        data = None
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "Net-Peekier"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = resp.read()
        except Exception:
            data = None
        # back to the GUI thread to place the image
        try:
            self.after(0, lambda: self._place_remote(url, data))
        except Exception:
            pass

    def _place_remote(self, url: str, data) -> None:
        info = self._pending.pop(url, None)
        if not info or not self.winfo_exists():
            return
        mark, alt = info
        try:
            self.text.configure(state="normal")
            # remove the placeholder text on that line
            line = self.text.index(mark).split(".")[0]
            self.text.delete(f"{line}.0", f"{line}.end")
            img = self._load_image("", data=data) if data else None
            if img is not None:
                self.text.image_create(f"{line}.0", image=img)
                self._images.append(img)
            else:
                self.text.insert(f"{line}.0", f"[image: {alt or url}]",
                                 ("imgalt",))
        except Exception:
            pass
        finally:
            self.text.configure(state="disabled")
