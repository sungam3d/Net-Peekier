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
    """Show a messagebox reliably centred over `parent`.

    Tkinter's native messageboxes only center on the parent when that window is
    the transient/active owner, so a plain showinfo can land on the wrong
    screen. We place a tiny transient holder exactly at the parent's center and
    parent the dialog to that, which keeps the popup over the right window.
    """
    import tkinter as tk
    from tkinter import messagebox
    holder = None
    try:
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width() or parent.winfo_reqwidth()
        ph = parent.winfo_height() or parent.winfo_reqheight()
        holder = tk.Toplevel(parent)
        holder.withdraw()
        holder.overrideredirect(True)
        holder.transient(parent)
        # a 1x1 window at the parent's center; the messagebox centers on it
        holder.geometry(f"1x1+{px + pw // 2}+{py + ph // 2}")
        holder.update_idletasks()
        fn = {"info": messagebox.showinfo,
              "warning": messagebox.showwarning,
              "error": messagebox.showerror}.get(kind, messagebox.showinfo)
        fn(title, message, parent=holder)
    except Exception:
        # fall back to a normal parent-anchored dialog
        try:
            from tkinter import messagebox as _mb
            _mb.showinfo(title, message, parent=parent)
        except Exception:
            pass
    finally:
        if holder is not None:
            try:
                holder.destroy()
            except Exception:
                pass
