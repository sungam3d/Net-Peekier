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
