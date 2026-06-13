"""Window placement helpers."""
from __future__ import annotations


def center_on_parent(win, parent) -> None:
    """Position `win` centered over `parent`. Call after the window's widgets
    are built so its requested size is known."""
    try:
        win.update_idletasks()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        if pw <= 1:                     # parent not realized yet
            pw, ph = parent.winfo_reqwidth(), parent.winfo_reqheight()
            px, py = parent.winfo_x(), parent.winfo_y()
        ww = win.winfo_width()
        wh = win.winfo_height()
        if ww <= 1:
            ww, wh = win.winfo_reqwidth(), win.winfo_reqheight()
        x = px + (pw - ww) // 2
        y = py + (ph - wh) // 2
        x = max(0, x)
        y = max(0, y)
        win.geometry(f"+{x}+{y}")
    except Exception:
        pass


def centered_message(parent, kind: str, title: str, message: str) -> None:
    """Show a simple message dialog reliably centred over `parent`.

    The native tk messagebox ignores hidden helper windows and falls back to
    centring on the root window, so instead we build a tiny modal Toplevel and
    position it ourselves over `parent` with center_on_parent.
    """
    import tkinter as tk
    try:
        dlg = tk.Toplevel(parent)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.transient(parent)
        dlg.configure(bg="white")

        icon = {"error": "\u2716", "warning": "\u26a0"}.get(kind, "\u2139")
        icon_fg = {"error": "#c0392b", "warning": "#c08a00"}.get(kind, "#1565c0")

        body = tk.Frame(dlg, bg="white")
        body.pack(fill="both", expand=True, padx=18, pady=(16, 6))
        tk.Label(body, text=icon, bg="white", fg=icon_fg,
                 font=("Segoe UI", 20)).pack(side="left", padx=(0, 12),
                                             anchor="n")
        tk.Label(body, text=message, bg="white", justify="left",
                 wraplength=340, font=("Segoe UI", 10)).pack(side="left",
                                                             anchor="w")

        btnbar = tk.Frame(dlg, bg="white")
        btnbar.pack(fill="x", padx=12, pady=(0, 12))
        ok = tk.Button(btnbar, text="OK", width=10, command=dlg.destroy)
        ok.pack(side="right")

        dlg.bind("<Return>", lambda _e: dlg.destroy())
        dlg.bind("<Escape>", lambda _e: dlg.destroy())

        center_on_parent(dlg, parent)
        ok.focus_set()
        try:
            dlg.grab_set()
        except Exception:
            pass
        parent.wait_window(dlg)
    except Exception:
        # last-ditch fallback so the user still sees something
        try:
            from tkinter import messagebox as _mb
            _mb.showinfo(title, message, parent=parent)
        except Exception:
            pass
