r"""Firewall & rate-limit manager.

One place to see and edit every app rule, independent of whether the app is
currently running. Rules are keyed by executable path, so they persist.

  +--------------------------------------------------------------+
  | Application      | Blocked | Up limit | Down limit | Path     |
  | chrome.exe       |   Yes   |    -     |  200 KB/s  | C:\...    |
  | steam.exe        |   No    |  50 KB/s |    -       | C:\...    |
  +--------------------------------------------------------------+
  [Add running app][Add by path][Edit][Remove]      [Refresh][Close]

Add/Edit opens a small dialog with a Block checkbox and up/down limit fields.
Blocking goes through Windows Firewall (netsh); limits go through the WinDivert
enforcer. Both need Administrator; the window says so if it can't apply a rule.
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .. import firewall
from ..monitor import Monitor
from ..util import human_speed
from .treesort import TreeSorter
from .tablestyle import init_table, apply_stripes, restore_widths, capture_widths

REFRESH_MS = 1500


def _fmt_limit(bps: int) -> str:
    return human_speed(bps) if bps > 0 else "-"


class RuleDialog(tk.Toplevel):
    """Modal add/edit dialog for one app's block + limit + tag settings."""

    def __init__(self, master, exe: str,
                 blocked: bool, up_bps: int, down_bps: int,
                 tag: str = "", existing_tags=None, tag_caps=None,
                 tag_blocked: bool = False) -> None:
        super().__init__(master)
        self.title("App rule")
        self.resizable(False, False)
        self.transient(master)
        self.result: Optional[tuple] = None
        self._existing_tags = sorted(set(existing_tags or []))
        # tag_caps: {tag -> (up_bps, down_bps)} so we can show/enforce the max
        self._tag_caps = dict(tag_caps or {})
        self._tag_blocked = tag_blocked

        self.exe = exe
        pad = {"padx": 8, "pady": 4}

        tk.Label(self, text="Application:", anchor="w").grid(
            row=0, column=0, sticky="w", **pad)
        tk.Label(self, text=os.path.basename(exe) or exe,
                 font=("Segoe UI", 9, "bold")).grid(
            row=0, column=1, sticky="w", **pad)

        tk.Label(self, text=exe, fg="#666", wraplength=360, justify="left",
                 anchor="w").grid(row=1, column=0, columnspan=2, sticky="w",
                                  padx=8)

        self.var_block = tk.BooleanVar(value=blocked)
        tk.Checkbutton(self, text="Block all traffic (firewall)",
                       variable=self.var_block).grid(
            row=2, column=0, columnspan=2, sticky="w", **pad)
        if self._tag_blocked:
            tk.Label(self, fg="#b00000", justify="left", anchor="w",
                     wraplength=340,
                     text="This app is also blocked by its tag's rule; that "
                          "block stays until you change the tag rule.").grid(
                row=2, column=0, columnspan=2, sticky="e", padx=8)

        tk.Label(self, text="Upload limit (KB/s, 0 = unlimited):").grid(
            row=3, column=0, sticky="w", **pad)
        self.var_up = tk.StringVar(value=str(up_bps // 1024 if up_bps else 0))
        tk.Entry(self, textvariable=self.var_up, width=10).grid(
            row=3, column=1, sticky="w", **pad)

        tk.Label(self, text="Download limit (KB/s, 0 = unlimited):").grid(
            row=4, column=0, sticky="w", **pad)
        self.var_down = tk.StringVar(
            value=str(down_bps // 1024 if down_bps else 0))
        tk.Entry(self, textvariable=self.var_down, width=10).grid(
            row=4, column=1, sticky="w", **pad)

        tk.Label(self, text="Group tag (optional):").grid(
            row=5, column=0, sticky="w", **pad)
        self.var_tag = tk.StringVar(value=tag or "")
        self.combo_tag = ttk.Combobox(self, textvariable=self.var_tag,
                                      width=12, values=self._existing_tags)
        self.combo_tag.grid(row=5, column=1, sticky="w", **pad)
        self.var_tag.trace_add("write", lambda *_: self._update_cap_note())

        # note showing the tag's cap (the individual limit can't exceed it)
        self.cap_note = tk.Label(self, fg="#0a4d7d", justify="left",
                                 anchor="w", wraplength=340)
        self.cap_note.grid(row=6, column=0, columnspan=2, sticky="w", padx=8)

        btns = tk.Frame(self)
        btns.grid(row=7, column=0, columnspan=2, pady=(8, 8))
        tk.Button(btns, text="OK", width=10, command=self._ok).pack(
            side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=self.destroy).pack(
            side="left", padx=4)

        self._update_cap_note()
        self.bind("<Return>", lambda _e: self._ok())
        from .winutil import center_on_parent
        center_on_parent(self, master)
        self.grab_set()

    def _tag_cap(self):
        """(up_kb, down_kb) cap from the chosen tag, or (0,0) for none."""
        tag = self.var_tag.get().strip()
        up, down = self._tag_caps.get(tag, (0, 0))
        return up // 1024, down // 1024

    def _update_cap_note(self) -> None:
        up_k, down_k = self._tag_cap()
        if up_k or down_k:
            parts = []
            if up_k:
                parts.append(f"up {up_k} KB/s")
            if down_k:
                parts.append(f"down {down_k} KB/s")
            self.cap_note.config(
                text=f"Tag '{self.var_tag.get().strip()}' caps this app at "
                     f"{', '.join(parts)} (your limit is clamped to it).")
        else:
            self.cap_note.config(text="")

    def _ok(self) -> None:
        try:
            up = int(self.var_up.get().strip() or "0")
            down = int(self.var_down.get().strip() or "0")
            if up < 0 or down < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("App rule", "Limits must be whole numbers >= 0.",
                                 parent=self)
            return
        # clamp the individual limit to the tag cap (KB/s) before saving
        cap_up, cap_down = self._tag_cap()
        if cap_up:
            up = cap_up if up <= 0 else min(up, cap_up)
        if cap_down:
            down = cap_down if down <= 0 else min(down, cap_down)
        self.result = (self.var_block.get(), up * 1024, down * 1024,
                       self.var_tag.get().strip())
        self.destroy()


class ProcessPicker(tk.Toplevel):
    """Pick a currently-running networked app to manage."""

    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.title("Pick a running app")
        self.geometry("460x360")
        self.transient(master)
        self.monitor = monitor
        self.result: Optional[str] = None

        tk.Label(self, text="Processes with network activity / connections:",
                 anchor="w").pack(fill="x", padx=8, pady=(8, 2))

        self.tree = ttk.Treeview(self, columns=("pid",), show="tree headings")
        self.tree.heading("#0", text="Application")
        self.tree.heading("pid", text="PID")
        self.tree.column("#0", width=320, anchor="w")
        self.tree.column("pid", width=80, anchor="e")
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)

        # de-dupe by exe; only apps with a resolvable path can be managed
        procs, _ = monitor.snapshot()
        self._exe_by_iid: dict[str, str] = {}
        seen_exes: set[str] = set()
        for p in sorted(procs, key=lambda x: x.name.lower()):
            if not p.exe or p.exe in seen_exes:
                continue
            seen_exes.add(p.exe)
            iid = f"{p.pid}"
            self.tree.insert("", "end", iid=iid,
                             text=f"{p.name}", values=(p.pid,))
            self._exe_by_iid[iid] = p.exe

        btns = tk.Frame(self)
        btns.pack(fill="x", pady=6)
        tk.Button(btns, text="Select", command=self._select).pack(
            side="right", padx=6)
        tk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        self.tree.bind("<Double-1>", lambda _e: self._select())
        from .winutil import center_on_parent
        center_on_parent(self, master)
        self.grab_set()

    def _select(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        self.result = self._exe_by_iid.get(sel[0])
        self.destroy()


class FirewallManagerWindow(tk.Toplevel):
    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.title("Net-Peekier - Firewall & limits manager")
        self.geometry("800x440")

        self._build_table()
        self._build_buttons()
        restore_widths(self.tree, "firewall", self.monitor.settings,
                       ("#0", "blocked", "up", "down", "tag", "path"))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._refresh()
        from .winutil import center_on_parent
        center_on_parent(self, master)
        self._auto_refresh()

    def _auto_refresh(self) -> None:
        """Keep the list in step with rule changes live, no manual refresh."""
        if not self.winfo_exists():
            return
        self._refresh()
        self.after(1000, self._auto_refresh)

    def _close(self) -> None:
        capture_widths(self.tree, "firewall", self.monitor.settings,
                       ("#0", "blocked", "up", "down", "tag", "path"))
        self.destroy()

    # ---- layout -----------------------------------------------------------
    def _build_table(self) -> None:
        frame = tk.Frame(self)
        frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)

        cols = ("blocked", "up", "down", "tag", "path")
        self.tree = ttk.Treeview(frame, columns=cols, show="tree headings")
        self.tree.column("#0", width=140, anchor="w")
        self.tree.column("blocked", width=62, anchor="center")
        self.tree.column("up", width=95, anchor="e")
        self.tree.column("down", width=95, anchor="e")
        self.tree.column("tag", width=80, anchor="w")
        self.tree.column("path", width=240, anchor="w")

        self._sortkeys: dict = {}
        self.sorter = TreeSorter(
            self.tree,
            {"#0": "Application", "blocked": "Blocked",
             "up": "Upload limit", "down": "Download limit",
             "tag": "Tag", "path": "Path"},
            lambda iid, col: self._sortkeys.get(iid, {}).get(col),
            default_col="#0", default_reverse=False)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        init_table(self.tree)
        self.tree.bind("<Double-1>", lambda _e: self._edit())

    def _build_buttons(self) -> None:
        bar = tk.Frame(self)
        bar.pack(side="bottom", fill="x", padx=6, pady=(0, 8))
        tk.Button(bar, text="Add running app...",
                  command=self._add_running).pack(side="left", padx=2)
        tk.Button(bar, text="Add by path...",
                  command=self._add_by_path).pack(side="left", padx=2)
        tk.Button(bar, text="Edit...", command=self._edit).pack(
            side="left", padx=2)
        tk.Button(bar, text="Remove", command=self._remove).pack(
            side="left", padx=2)
        tk.Button(bar, text="Tag rules...", command=self._open_tag_rules).pack(
            side="left", padx=10)
        tk.Button(bar, text="Close", command=self._close).pack(
            side="right", padx=2)

    def _open_tag_rules(self) -> None:
        if getattr(self, "_tagwin", None) and self._tagwin.winfo_exists():
            self._tagwin.lift()
            return
        self._tagwin = TagRulesWindow(self, self.monitor)

    # ---- data -------------------------------------------------------------
    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        selected = self._selected_exe()
        self.tree.delete(*self.tree.get_children())
        sortkeys: dict = {}
        rowtags: dict = {}
        for exe, (blocked, (up, down), tag, from_tag, via_tag) in \
                self.monitor.managed_apps().items():
            iid = exe
            # A block overrides everything, so don't clutter the row with limits.
            if blocked:
                blk_txt = "Yes (tag)" if via_tag else "Yes"
                up_txt = down_txt = "blocked"
            else:
                blk_txt = "No"
                suffix = "  (tag)" if from_tag else ""
                up_txt = _fmt_limit(up) + (suffix if up else "")
                down_txt = _fmt_limit(down) + (suffix if down else "")
            self.tree.insert(
                "", "end", iid=iid, text=os.path.basename(exe) or exe,
                values=(blk_txt, up_txt, down_txt, tag, exe))
            rowtags[iid] = ("blocked",) if blocked else ()
            sortkeys[iid] = {
                "#0": (os.path.basename(exe) or exe).lower(),
                "blocked": 1 if blocked else 0,
                "up": up, "down": down, "tag": (tag or "").lower(),
                "path": exe.lower(),
            }
        self._sortkeys = sortkeys
        self.sorter.apply()
        apply_stripes(self.tree, rowtags)
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)

    def _selected_exe(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # ---- actions ----------------------------------------------------------
    def _apply_rule(self, exe: str, blocked: bool,
                    up_bps: int, down_bps: int, tag: str = "") -> None:
        """Push a desired state to firewall + monitor, reporting failures."""
        errors = []
        # block / unblock via the OS firewall (only when the master switch is on)
        was_blocked = exe in self.monitor.list_blocked()
        fw_on = self.monitor.settings.firewall_enabled
        if blocked and not was_blocked:
            if fw_on:
                ok, msg = firewall.block_app(exe)
                if not ok:
                    errors.append(f"Block failed: {msg}")
        elif not blocked and was_blocked:
            ok, msg = firewall.unblock_app(exe)
            if not ok:
                errors.append(f"Unblock failed: {msg}")
        self.monitor.set_blocked(exe, blocked)
        # Set the tag FIRST so the limit is clamped against the right tag cap.
        self.monitor.set_exe_tag(exe, tag or None)
        self.monitor.set_limit(exe, up_bps, down_bps)
        if (up_bps or down_bps) and not self.monitor.has_per_process_speed:
            errors.append("Speed limit saved, but enforcement needs WinDivert "
                          "(pip install pydivert).")
        if errors:
            messagebox.showwarning("Firewall & limits", "\n\n".join(errors),
                                   parent=self)
        self._refresh()

    def _tag_caps(self) -> dict:
        """{tag -> (up_bps, down_bps)} for tags that have a limit."""
        return {t: self.monitor.settings.tag_limit(t)
                for t in self.monitor.settings.tag_limits}

    def _edit_exe(self, exe: str) -> None:
        managed = self.monitor.managed_apps().get(
            exe, (False, (0, 0), "", False, False))
        blocked, (up, down), tag, _from_tag, via_tag = managed
        # The dialog edits the app's OWN block checkbox; a block that comes from
        # a blocked TAG isn't the app's own state, so present the direct block.
        direct_block = exe in self.monitor.list_blocked()
        own_up, own_down = self.monitor.settings.exe_limit(exe)
        dlg = RuleDialog(self, exe, direct_block, own_up, own_down, tag,
                         existing_tags=self.monitor.settings.all_tags(),
                         tag_caps=self._tag_caps(),
                         tag_blocked=via_tag)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        new_blocked, new_up, new_down, new_tag = dlg.result
        self._apply_rule(exe, new_blocked, new_up, new_down, new_tag)

    def _edit(self) -> None:
        exe = self._selected_exe()
        if not exe:
            messagebox.showinfo("Firewall & limits",
                                "Select an app first.", parent=self)
            return
        self._edit_exe(exe)

    def _add_running(self) -> None:
        picker = ProcessPicker(self, self.monitor)
        self.wait_window(picker)
        if picker.result:
            self._edit_exe(picker.result)

    def _add_by_path(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose an executable",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
            parent=self)
        if path:
            self._edit_exe(os.path.normpath(path))

    def _remove(self) -> None:
        exe = self._selected_exe()
        if not exe:
            return
        if not messagebox.askyesno(
                "Remove rule",
                f"Remove all rules (block + limits) for\n"
                f"{os.path.basename(exe)}?", parent=self):
            return
        if exe in self.monitor.list_blocked():
            firewall.unblock_app(exe)
        self.monitor.remove_app(exe)
        self._refresh()


class TagRulesWindow(tk.Toplevel):
    """Manage per-tag group rules: an aggregate block or speed limit shared by
    every process carrying that tag. The limit is a single bucket the tagged
    apps draw from together, so their combined throughput stays under the cap.
    """

    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.title("Net-Peekier - Tag group rules")
        self.geometry("560x360")
        self.transient(master)

        frame = tk.Frame(self)
        frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)
        cols = ("members", "blocked", "up", "down")
        self.tree = ttk.Treeview(frame, columns=cols, show="tree headings")
        self.tree.heading("#0", text="Tag")
        self.tree.heading("members", text="Apps")
        self.tree.heading("blocked", text="Blocked")
        self.tree.heading("up", text="Upload limit")
        self.tree.heading("down", text="Download limit")
        self.tree.column("#0", width=120, anchor="w")
        self.tree.column("members", width=55, anchor="center")
        self.tree.column("blocked", width=62, anchor="center")
        self.tree.column("up", width=110, anchor="e")
        self.tree.column("down", width=110, anchor="e")
        init_table(self.tree)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self._tcols = ("#0", "members", "blocked", "up", "down")
        restore_widths(self.tree, "tagrules", self.monitor.settings,
                       self._tcols)
        self.protocol("WM_DELETE_WINDOW", self._close)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree.tag_configure("blocked", foreground="#b00000")
        self.tree.bind("<Double-1>", lambda _e: self._edit())

        bar = tk.Frame(self)
        bar.pack(side="bottom", fill="x", padx=6, pady=(0, 8))
        tk.Label(bar, fg="#666",
                 text="Only tags with a rule are listed. Tag processes from the "
                      "main list (right-click > Set tag).",
                 wraplength=300, justify="left").pack(side="left", padx=4)
        tk.Button(bar, text="Add rule...", command=self._add_rule).pack(
            side="left", padx=2)
        tk.Button(bar, text="Edit...", command=self._edit).pack(
            side="left", padx=2)
        tk.Button(bar, text="Remove rule", command=self._remove_rule).pack(
            side="left", padx=2)
        tk.Button(bar, text="Close", command=self._close).pack(
            side="right", padx=2)

        self._refresh()
        from .winutil import center_on_parent
        center_on_parent(self, master)
        self._auto_refresh()

    def _auto_refresh(self) -> None:
        if not self.winfo_exists():
            return
        self._refresh()
        self.after(1000, self._auto_refresh)

    def _close(self) -> None:
        capture_widths(self.tree, "tagrules", self.monitor.settings,
                       self._tcols)
        self.destroy()

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        sel = self.tree.selection()
        keep = sel[0] if sel else None
        self.tree.delete(*self.tree.get_children())
        s = self.monitor.settings
        rowtags = {}
        # Only tags that actually HAVE a rule (a limit or a block) are shown.
        ruled = sorted(set(s.tag_limits) | set(s.tag_blocked))
        for tag in ruled:
            up, down = s.tag_limit(tag)
            blocked = tag in s.tag_blocked
            members = len(s.exes_with_tag(tag))
            self.tree.insert(
                "", "end", iid=tag, text=tag,
                values=(members, "Yes" if blocked else "No",
                        _fmt_limit(up), _fmt_limit(down)))
            rowtags[tag] = ("blocked",) if blocked else ()
        apply_stripes(self.tree, rowtags)
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)

    def _add_rule(self) -> None:
        from .tag_picker import ask_tag
        s = self.monitor.settings
        # tags you can add a rule for = assigned tags that don't have one yet
        candidates = [t for t in s.all_tags()
                      if t not in s.tag_limits and t not in s.tag_blocked]
        if not candidates and not s.exe_tags:
            messagebox.showinfo(
                "Add tag rule",
                "No tags yet. Assign a tag to some processes first\n"
                "(main list > right-click > Set tag).", parent=self)
            return
        tag = ask_tag(self, "Add tag rule",
                      "Choose a tag to add a block or speed limit for.",
                      existing=candidates or s.all_tags())
        if not tag:
            return
        self._edit_tag(tag)

    def _edit(self) -> None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Tag rules", "Select a tag rule to edit, or "
                                "use 'Add rule...'.", parent=self)
            return
        self._edit_tag(sel[0])

    def _edit_tag(self, tag: str) -> None:
        s = self.monitor.settings
        up, down = s.tag_limit(tag)
        blocked = tag in s.tag_blocked
        dlg = _TagDialog(self, tag, blocked, up, down)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        new_blocked, new_up, new_down = dlg.result
        self.monitor.set_tag_limit(tag, new_up, new_down)
        self.monitor.set_tag_blocked(tag, new_blocked)
        self._refresh()

    def _remove_rule(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        tag = sel[0]
        if not messagebox.askyesno(
                "Remove tag rule",
                f"Remove the block/limit rule for tag '{tag}'?\n\n"
                "(Processes keep the tag; only the group rule is removed.)",
                parent=self):
            return
        self.monitor.set_tag_limit(tag, 0, 0)
        self.monitor.set_tag_blocked(tag, False)
        self._refresh()


class _TagDialog(tk.Toplevel):
    def __init__(self, master, tag, blocked, up_bps, down_bps) -> None:
        super().__init__(master)
        self.title(f"Tag rule - {tag}")
        self.resizable(False, False)
        self.transient(master)
        self.result = None
        pad = {"padx": 8, "pady": 5}

        tk.Label(self, text=f"Group tag: {tag}",
                 font=("Segoe UI", 9, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", **pad)
        self.var_block = tk.BooleanVar(value=blocked)
        tk.Checkbutton(self, text="Block all apps with this tag (firewall)",
                       variable=self.var_block).grid(
            row=1, column=0, columnspan=2, sticky="w", **pad)
        tk.Label(self, text="Group upload limit (KB/s, 0 = unlimited):").grid(
            row=2, column=0, sticky="w", **pad)
        self.var_up = tk.StringVar(value=str(up_bps // 1024 if up_bps else 0))
        tk.Entry(self, textvariable=self.var_up, width=10).grid(
            row=2, column=1, sticky="w", **pad)
        tk.Label(self, text="Group download limit (KB/s, 0 = unlimited):").grid(
            row=3, column=0, sticky="w", **pad)
        self.var_down = tk.StringVar(
            value=str(down_bps // 1024 if down_bps else 0))
        tk.Entry(self, textvariable=self.var_down, width=10).grid(
            row=3, column=1, sticky="w", **pad)

        btns = tk.Frame(self)
        btns.grid(row=4, column=0, columnspan=2, pady=(6, 8))
        tk.Button(btns, text="OK", width=10, command=self._ok).pack(
            side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=self.destroy).pack(
            side="left", padx=4)
        self.bind("<Return>", lambda _e: self._ok())
        from .winutil import center_on_parent
        center_on_parent(self, master)
        self.grab_set()

    def _ok(self) -> None:
        try:
            up = int(self.var_up.get().strip() or "0")
            down = int(self.var_down.get().strip() or "0")
            if up < 0 or down < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Tag rule",
                                 "Limits must be whole numbers >= 0.",
                                 parent=self)
            return
        self.result = (self.var_block.get(), up * 1024, down * 1024)
        self.destroy()
