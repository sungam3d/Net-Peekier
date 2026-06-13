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
                 tag_blocked: bool = False,
                 allowed: bool = False, tag_allowed: bool = False) -> None:
        super().__init__(master)
        self.title("App rule")
        self.resizable(False, False)
        self.transient(master)
        self.result: Optional[tuple] = None
        self._existing_tags = sorted(set(existing_tags or []))
        # tag_caps: {tag -> (up_bps, down_bps)} so we can show/enforce the max
        self._tag_caps = dict(tag_caps or {})
        self._tag_blocked = tag_blocked
        self._tag_allowed = tag_allowed

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
                       variable=self.var_block,
                       command=self._block_changed).grid(
            row=2, column=0, columnspan=2, sticky="w", **pad)
        if self._tag_blocked:
            tk.Label(self, fg="#b00000", justify="left", anchor="w",
                     wraplength=340,
                     text="This app is also blocked by its tag's rule; that "
                          "block stays until you change the tag rule.").grid(
                row=2, column=0, columnspan=2, sticky="e", padx=8)

        # Allow list (used by Lockdown Mode). Behaves like Block: mutually
        # exclusive, and a tag-allow marks all members allowed.
        self.var_allow = tk.BooleanVar(value=allowed)
        tk.Checkbutton(self, text="Allow internet (Lockdown allow-list)",
                       variable=self.var_allow,
                       command=self._allow_changed).grid(
            row=3, column=0, columnspan=2, sticky="w", **pad)
        if self._tag_allowed:
            tk.Label(self, fg="#0a7d00", justify="left", anchor="w",
                     wraplength=340,
                     text="This app is also allowed by its tag's rule.").grid(
                row=3, column=0, columnspan=2, sticky="e", padx=8)

        tk.Label(self, text="Upload limit (KB/s, 0 = unlimited):").grid(
            row=4, column=0, sticky="w", **pad)
        self.var_up = tk.StringVar(value=str(up_bps // 1024 if up_bps else 0))
        tk.Entry(self, textvariable=self.var_up, width=10).grid(
            row=4, column=1, sticky="w", **pad)

        tk.Label(self, text="Download limit (KB/s, 0 = unlimited):").grid(
            row=5, column=0, sticky="w", **pad)
        self.var_down = tk.StringVar(
            value=str(down_bps // 1024 if down_bps else 0))
        tk.Entry(self, textvariable=self.var_down, width=10).grid(
            row=5, column=1, sticky="w", **pad)

        tk.Label(self, text="Group tag (optional):").grid(
            row=6, column=0, sticky="w", **pad)
        self.var_tag = tk.StringVar(value=tag or "")
        self.combo_tag = ttk.Combobox(self, textvariable=self.var_tag,
                                      width=12, values=self._existing_tags)
        self.combo_tag.grid(row=6, column=1, sticky="w", **pad)
        self.var_tag.trace_add("write", lambda *_: self._update_cap_note())

        # note showing the tag's cap (the individual limit can't exceed it)
        self.cap_note = tk.Label(self, fg="#0a4d7d", justify="left",
                                 anchor="w", wraplength=340)
        self.cap_note.grid(row=7, column=0, columnspan=2, sticky="w", padx=8)

        btns = tk.Frame(self)
        btns.grid(row=8, column=0, columnspan=2, pady=(8, 8))
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
                       self.var_tag.get().strip(), self.var_allow.get())
        self.destroy()

    def _block_changed(self) -> None:
        # block and allow are mutually exclusive
        if self.var_block.get():
            self.var_allow.set(False)

    def _allow_changed(self) -> None:
        if self.var_allow.get():
            self.var_block.set(False)


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
    TABS = ("All Rules", "Blocked Rules", "Allowed Rules", "IP Rules",
            "Tag Rules", "No Rules")

    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        self.title("Net-Peekier - Firewall and Tags")
        self.geometry("840x470")
        self._tab = "All Rules"

        self._build_tabs()
        self._build_table()        # apps tree (used by app-filter tabs)
        self._build_ip_table()     # IP-rules tree
        self._build_tag_panel()    # embedded tag rules
        self._build_buttons()
        restore_widths(self.tree, "firewall", self.monitor.settings,
                       ("#0", "blocked", "allowed", "up", "down", "tag", "path"))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._select_tab("All Rules")
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
                       ("#0", "blocked", "allowed", "up", "down", "tag", "path"))
        self.destroy()

    # ---- tabs -------------------------------------------------------------
    def _build_tabs(self) -> None:
        bar = tk.Frame(self, bg="#cdd4dd")
        bar.pack(side="top", fill="x")
        self._tab_btns = {}
        for name in self.TABS:
            b = tk.Label(bar, text=name, padx=12, pady=6, bg="#cdd4dd",
                         font=("Segoe UI", 9), cursor="hand2")
            b.pack(side="left", padx=(2, 0), pady=(2, 0))
            b.bind("<Button-1>", lambda _e, n=name: self._select_tab(n))
            self._tab_btns[name] = b

    def _select_tab(self, name: str) -> None:
        self._tab = name
        for n, b in self._tab_btns.items():
            if n == name:
                b.configure(bg="white", font=("Segoe UI", 9, "bold"))
            else:
                b.configure(bg="#cdd4dd", font=("Segoe UI", 9))
        # show the right body
        is_ip = name == "IP Rules"
        is_tag = name == "Tag Rules"
        self._apps_frame.pack_forget()
        self._ip_frame.pack_forget()
        self._tag_frame.pack_forget()
        if is_ip:
            self._ip_frame.pack(side="top", fill="both", expand=True,
                                padx=6, pady=6)
        elif is_tag:
            self._tag_frame.pack(side="top", fill="both", expand=True,
                                 padx=6, pady=6)
        else:
            self._apps_frame.pack(side="top", fill="both", expand=True,
                                  padx=6, pady=6)
        self._update_buttons_for_tab()
        self._refresh()

    # ---- layout -----------------------------------------------------------
    def _build_table(self) -> None:
        frame = tk.Frame(self)
        self._apps_frame = frame
        frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)

        cols = ("blocked", "allowed", "up", "down", "tag", "path")
        self.tree = ttk.Treeview(frame, columns=cols, show="tree headings")
        self.tree.column("#0", width=140, anchor="w")
        self.tree.column("blocked", width=58, anchor="center")
        self.tree.column("allowed", width=70, anchor="center")
        self.tree.column("up", width=92, anchor="e")
        self.tree.column("down", width=92, anchor="e")
        self.tree.column("tag", width=78, anchor="w")
        self.tree.column("path", width=230, anchor="w")

        self._sortkeys: dict = {}
        self.sorter = TreeSorter(
            self.tree,
            {"#0": "Application", "blocked": "Blocked", "allowed": "Allowed",
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

    def _build_ip_table(self) -> None:
        frame = tk.Frame(self)
        self._ip_frame = frame
        cols = ("app", "action", "dir", "ip", "ports", "proto", "path")
        self.ip_tree = ttk.Treeview(frame, columns=cols, show="headings")
        layout = {"app": ("Application", 130), "action": ("Action", 60),
                  "dir": ("Dir", 50), "ip": ("Remote IP / range", 150),
                  "ports": ("Ports", 90), "proto": ("Proto", 55),
                  "path": ("Path", 210)}
        for c, (txt, w) in layout.items():
            self.ip_tree.heading(c, text=txt)
            self.ip_tree.column(c, width=w,
                                anchor="center" if c in ("action", "dir", "proto")
                                else "w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.ip_tree.yview)
        self.ip_tree.configure(yscrollcommand=vsb.set)
        self.ip_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        init_table(self.ip_tree)
        self.ip_tree.bind("<Double-1>", lambda _e: self._edit_ip_rule())

    def _build_tag_panel(self) -> None:
        self._tag_frame = tk.Frame(self)
        self._tag_panel = TagRulesPanel(self._tag_frame, self.monitor)
        self._tag_panel.pack(fill="both", expand=True)

    def _build_buttons(self) -> None:
        bar = tk.Frame(self)
        bar.pack(side="bottom", fill="x", padx=6, pady=(0, 8))
        self._btnbar = bar
        # app-tab buttons
        self._app_btns = tk.Frame(bar)
        tk.Button(self._app_btns, text="Add running app...",
                  command=self._add_running).pack(side="left", padx=2)
        tk.Button(self._app_btns, text="Add by path...",
                  command=self._add_by_path).pack(side="left", padx=2)
        tk.Button(self._app_btns, text="Edit...", command=self._edit).pack(
            side="left", padx=2)
        tk.Button(self._app_btns, text="Remove", command=self._remove).pack(
            side="left", padx=2)
        # ip-tab buttons
        self._ip_btns = tk.Frame(bar)
        tk.Button(self._ip_btns, text="Add IP rule...",
                  command=self._add_ip_rule).pack(side="left", padx=2)
        tk.Button(self._ip_btns, text="Edit...",
                  command=self._edit_ip_rule).pack(side="left", padx=2)
        tk.Button(self._ip_btns, text="Remove",
                  command=self._remove_ip_rule).pack(side="left", padx=2)
        # tag-tab buttons
        self._tag_btns = tk.Frame(bar)
        tk.Button(self._tag_btns, text="Add tag rule...",
                  command=lambda: self._tag_panel.add_rule()).pack(
            side="left", padx=2)
        tk.Button(self._tag_btns, text="Edit...",
                  command=lambda: self._tag_panel.edit_selected()).pack(
            side="left", padx=2)
        tk.Button(self._tag_btns, text="Remove",
                  command=lambda: self._tag_panel.remove_selected()).pack(
            side="left", padx=2)
        tk.Button(bar, text="Close", command=self._close).pack(
            side="right", padx=2)

    def _update_buttons_for_tab(self) -> None:
        self._app_btns.pack_forget()
        self._ip_btns.pack_forget()
        self._tag_btns.pack_forget()
        if self._tab == "IP Rules":
            self._ip_btns.pack(side="left")
        elif self._tab == "Tag Rules":
            self._tag_btns.pack(side="left")
        else:
            self._app_btns.pack(side="left")

    def _open_tag_rules(self) -> None:
        self._select_tab("Tag Rules")

    # ---- data -------------------------------------------------------------
    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        tab = getattr(self, "_tab", "All Rules")
        if tab == "IP Rules":
            self._refresh_ip()
            return
        if tab == "Tag Rules":
            self._tag_panel.refresh()
            return
        selected = self._selected_exe()
        self.tree.delete(*self.tree.get_children())
        sortkeys: dict = {}
        rowtags: dict = {}
        for exe, (blocked, (up, down), tag, from_tag, via_tag) in \
                self.monitor.managed_apps().items():
            allowed_now, _avt = self.monitor.allow_state(exe)
            has_limit = bool(up or down)
            # tab filter
            if tab == "Blocked Rules" and not blocked:
                continue
            if tab == "Allowed Rules" and not allowed_now:
                continue
            if tab == "No Rules" and (blocked or allowed_now or has_limit or tag):
                continue
            iid = exe
            allowed, allow_via_tag = self.monitor.allow_state(exe)
            allow_txt = ("Yes (tag)" if (allowed and allow_via_tag)
                         else ("Yes" if allowed else "No"))
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
                values=(blk_txt, allow_txt, up_txt, down_txt, tag, exe))
            rowtags[iid] = ("blocked",) if blocked else ()
            sortkeys[iid] = {
                "#0": (os.path.basename(exe) or exe).lower(),
                "blocked": 1 if blocked else 0,
                "allowed": 1 if allowed else 0,
                "up": up, "down": down, "tag": (tag or "").lower(),
                "path": exe.lower(),
            }
        self._sortkeys = sortkeys
        self.sorter.apply()
        apply_stripes(self.tree, rowtags)
        if getattr(self, "_tab", "") == "No Rules":
            self._augment_no_rules(rowtags)
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)

    def _augment_no_rules(self, rowtags: dict) -> None:
        """The managed list only contains apps that already have a rule, so for
        the No Rules tab we add currently-running executables that have none."""
        try:
            procs, _ = self.monitor.snapshot()
        except Exception:
            return
        seen = set(self.tree.get_children())
        s = self.monitor.settings
        for p in procs:
            exe = p.exe
            if not exe or exe in seen:
                continue
            if (exe in s.blocked_exes or s.is_allowed_exe(exe)
                    or s.exe_tags.get(exe) or s.exe_limit(exe) != (0, 0)
                    or s.ip_rules_for(exe)):
                continue
            seen.add(exe)
            self.tree.insert("", "end", iid=exe,
                             text=os.path.basename(exe) or exe,
                             values=("No", "No", "-", "-", "", exe))

    def _refresh_ip(self) -> None:
        sel = self.ip_tree.selection()
        sel_id = sel[0] if sel else None
        self.ip_tree.delete(*self.ip_tree.get_children())
        rowtags = {}
        for i, r in enumerate(self.monitor.all_ip_rules()):
            exe = r.get("exe", "")
            iid = str(i)
            self.ip_tree.insert(
                "", "end", iid=iid,
                values=(os.path.basename(exe) or exe, r.get("action", ""),
                        r.get("direction", ""), r.get("remote_ip", ""),
                        r.get("ports", "") or "all", r.get("protocol", "any"),
                        exe))
            rowtags[iid] = ("blocked",) if r.get("action") == "block" else ()
        apply_stripes(self.ip_tree, rowtags)
        if sel_id and self.ip_tree.exists(sel_id):
            self.ip_tree.selection_set(sel_id)

    # ---- IP rule actions --------------------------------------------------
    def _add_ip_rule(self) -> None:
        # pre-fill exe from the app tab selection if any
        exe = self._selected_exe() or ""
        dlg = IPRuleDialog(self, exe)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        exe2, action, direction, ip, ports, proto = dlg.result
        ok, msg = self.monitor.add_ip_rule(exe2, action, direction, ip, ports,
                                           proto)
        if not ok:
            from .winutil import centered_message
            centered_message(self, "error", "IP rule",
                             msg or "Failed (need admin?).")
        self._refresh_ip()

    def _selected_ip_rule(self):
        sel = self.ip_tree.selection()
        if not sel:
            return None
        try:
            return self.monitor.all_ip_rules()[int(sel[0])]
        except (ValueError, IndexError):
            return None

    def _edit_ip_rule(self) -> None:
        rule = self._selected_ip_rule()
        if not rule:
            from .winutil import centered_message
            centered_message(self, "info", "IP rule",
                             "Select an IP rule to edit, or use 'Add IP rule'.")
            return
        dlg = IPRuleDialog(self, rule.get("exe", ""), rule)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        # edit = remove old + add new
        self.monitor.remove_ip_rule(dict(rule))
        exe2, action, direction, ip, ports, proto = dlg.result
        ok, msg = self.monitor.add_ip_rule(exe2, action, direction, ip, ports,
                                           proto)
        if not ok:
            from .winutil import centered_message
            centered_message(self, "error", "IP rule",
                             msg or "Failed (need admin?).")
        self._refresh_ip()

    def _remove_ip_rule(self) -> None:
        rule = self._selected_ip_rule()
        if not rule:
            from .winutil import centered_message
            centered_message(self, "info", "IP rule", "Select an IP rule first.")
            return
        self.monitor.remove_ip_rule(dict(rule))
        self._refresh_ip()

    def _selected_exe(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # ---- actions ----------------------------------------------------------
    def _apply_rule(self, exe: str, blocked: bool,
                    up_bps: int, down_bps: int, tag: str = "",
                    allowed: bool = False) -> None:
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
        # allow-list membership (Lockdown). Block wins if somehow both set.
        self.monitor.set_allowed(exe, allowed and not blocked)
        if (up_bps or down_bps) and not self.monitor.has_per_process_speed:
            errors.append("Speed limit saved, but enforcement needs WinDivert "
                          "(pip install pydivert).")
        if errors:
            messagebox.showwarning("Firewall and Tags", "\n\n".join(errors),
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
        direct_allow = exe in self.monitor.settings.allowed_exes
        _allowed, allow_via_tag = self.monitor.allow_state(exe)
        own_up, own_down = self.monitor.settings.exe_limit(exe)
        dlg = RuleDialog(self, exe, direct_block, own_up, own_down, tag,
                         existing_tags=self.monitor.settings.all_tags(),
                         tag_caps=self._tag_caps(),
                         tag_blocked=via_tag,
                         allowed=direct_allow, tag_allowed=allow_via_tag)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        new_blocked, new_up, new_down, new_tag, new_allow = dlg.result
        self._apply_rule(exe, new_blocked, new_up, new_down, new_tag, new_allow)

    def _edit(self) -> None:
        exe = self._selected_exe()
        if not exe:
            from .winutil import centered_message
            centered_message(self, "info", "Firewall and Tags",
                             "Select an app first.")
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
            from .winutil import centered_message
            centered_message(self, "info", "Tag rules",
                             "Select a tag rule to edit, or use 'Add rule...'.")
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


class TagRulesPanel(tk.Frame):
    """Embeddable tag-rules view (same behaviour as the old TagRulesWindow, but
    as a frame so it can live inside the Firewall and Tags tabs)."""

    def __init__(self, master, monitor: Monitor) -> None:
        super().__init__(master)
        self.monitor = monitor
        cols = ("members", "blocked", "up", "down")
        self.tree = ttk.Treeview(self, columns=cols, show="tree headings")
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
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.tree.tag_configure("blocked", foreground="#b00000")
        self.tree.bind("<Double-1>", lambda _e: self.edit_selected())

    def refresh(self) -> None:
        sel = self.tree.selection()
        keep = sel[0] if sel else None
        self.tree.delete(*self.tree.get_children())
        s = self.monitor.settings
        rowtags = {}
        ruled = sorted(set(s.tag_limits) | set(s.tag_blocked))
        for tag in ruled:
            up, down = s.tag_limit(tag)
            blocked = tag in s.tag_blocked
            members = len(s.exes_with_tag(tag))
            self.tree.insert("", "end", iid=tag, text=tag,
                             values=(members, "Yes" if blocked else "No",
                                     _fmt_limit(up), _fmt_limit(down)))
            rowtags[tag] = ("blocked",) if blocked else ()
        apply_stripes(self.tree, rowtags)
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)

    def add_rule(self) -> None:
        from .tag_picker import ask_tag
        s = self.monitor.settings
        candidates = [t for t in s.all_tags()
                      if t not in s.tag_limits and t not in s.tag_blocked]
        if not candidates and not s.exe_tags:
            from .winutil import centered_message
            centered_message(self, "info", "Add tag rule",
                             "No tags yet. Assign a tag to some processes first "
                             "(main list > right-click > Set tag).")
            return
        tag = ask_tag(self, "Add tag rule",
                      "Choose a tag to add a block or speed limit for.",
                      existing=candidates or s.all_tags())
        if tag:
            self._edit_tag(tag)

    def edit_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            from .winutil import centered_message
            centered_message(self, "info", "Tag rules",
                             "Select a tag rule to edit, or use 'Add tag rule'.")
            return
        self._edit_tag(sel[0])

    def _edit_tag(self, tag: str) -> None:
        s = self.monitor.settings
        up, down = s.tag_limit(tag)
        dlg = _TagDialog(self, tag, tag in s.tag_blocked, up, down)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        new_blocked, new_up, new_down = dlg.result
        self.monitor.set_tag_limit(tag, new_up, new_down)
        self.monitor.set_tag_blocked(tag, new_blocked)
        self.refresh()

    def remove_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            from .winutil import centered_message
            centered_message(self, "info", "Tag rules", "Select a tag rule first.")
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
        self.refresh()


class IPRuleDialog(tk.Toplevel):
    """Add/edit a per-IP firewall rule scoped to one program."""

    def __init__(self, master, exe: str = "", rule: dict = None) -> None:
        super().__init__(master)
        self.title("IP rule")
        self.resizable(False, False)
        self.transient(master)
        self.result = None
        rule = rule or {}
        pad = {"padx": 8, "pady": 5}

        tk.Label(self, text="Application (.exe path):").grid(
            row=0, column=0, sticky="w", **pad)
        self.var_exe = tk.StringVar(value=rule.get("exe", exe))
        row0 = tk.Frame(self)
        row0.grid(row=0, column=1, sticky="w", **pad)
        tk.Entry(row0, textvariable=self.var_exe, width=34).pack(side="left")
        tk.Button(row0, text="...", width=2, command=self._browse).pack(
            side="left", padx=(3, 0))

        tk.Label(self, text="Action:").grid(row=1, column=0, sticky="w", **pad)
        self.var_action = tk.StringVar(value=rule.get("action", "block"))
        af = tk.Frame(self)
        af.grid(row=1, column=1, sticky="w", **pad)
        for val in ("block", "allow"):
            tk.Radiobutton(af, text=val.title(), value=val,
                           variable=self.var_action).pack(side="left")

        tk.Label(self, text="Direction:").grid(row=2, column=0, sticky="w", **pad)
        self.var_dir = tk.StringVar(value=rule.get("direction", "out"))
        df = tk.Frame(self)
        df.grid(row=2, column=1, sticky="w", **pad)
        for val, lab in (("out", "Outbound"), ("in", "Inbound"),
                         ("both", "Both")):
            tk.Radiobutton(df, text=lab, value=val,
                           variable=self.var_dir).pack(side="left")

        tk.Label(self, text="Remote IP / range:").grid(
            row=3, column=0, sticky="w", **pad)
        self.var_ip = tk.StringVar(value=rule.get("remote_ip", ""))
        tk.Entry(self, textvariable=self.var_ip, width=30).grid(
            row=3, column=1, sticky="w", **pad)
        tk.Label(self, fg="#666",
                 text="e.g. 1.2.3.4   |   10.0.0.0/24   |   1.2.3.4-1.2.3.10",
                 font=("Segoe UI", 8)).grid(row=4, column=1, sticky="w", padx=8)

        tk.Label(self, text="Ports (blank = all):").grid(
            row=5, column=0, sticky="w", **pad)
        self.var_ports = tk.StringVar(value=rule.get("ports", ""))
        tk.Entry(self, textvariable=self.var_ports, width=20).grid(
            row=5, column=1, sticky="w", **pad)
        tk.Label(self, fg="#666", text="e.g. 443   or   80,443,8000-8100",
                 font=("Segoe UI", 8)).grid(row=6, column=1, sticky="w", padx=8)

        tk.Label(self, text="Protocol:").grid(row=7, column=0, sticky="w", **pad)
        self.var_proto = tk.StringVar(value=rule.get("protocol", "any"))
        pf = tk.Frame(self)
        pf.grid(row=7, column=1, sticky="w", **pad)
        for val in ("any", "tcp", "udp"):
            tk.Radiobutton(pf, text=val.upper(), value=val,
                           variable=self.var_proto).pack(side="left")

        tk.Label(self, fg="#806000", wraplength=360, justify="left",
                 font=("Segoe UI", 8),
                 text="Note: Windows Firewall evaluates BLOCK before ALLOW, so "
                      "an allow rule can't override a full app block. Use allow "
                      "rules to restrict an open app to certain destinations.").grid(
            row=8, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 0))

        btns = tk.Frame(self)
        btns.grid(row=9, column=0, columnspan=2, pady=(8, 8))
        tk.Button(btns, text="OK", width=10, command=self._ok).pack(
            side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=self.destroy).pack(
            side="left", padx=4)
        self.bind("<Return>", lambda _e: self._ok())
        from .winutil import center_on_parent
        center_on_parent(self, master)
        self.grab_set()

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose an executable",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
            parent=self)
        if path:
            self.var_exe.set(os.path.normpath(path))

    def _ok(self) -> None:
        exe = self.var_exe.get().strip().strip('"')
        ip = self.var_ip.get().strip()
        ports = self.var_ports.get().strip()
        if not firewall._valid_exe(exe):
            from .winutil import centered_message
            centered_message(self, "error", "IP rule",
                             "Enter a valid absolute path to an .exe.")
            return
        if not firewall._valid_ip_spec(ip):
            from .winutil import centered_message
            centered_message(self, "error", "IP rule",
                             "Enter a valid IP, CIDR subnet, or a-b range.")
            return
        if not firewall._valid_ports(ports):
            from .winutil import centered_message
            centered_message(self, "error", "IP rule",
                             "Ports must be numbers 1-65535 (comma/range ok).")
            return
        self.result = (exe, self.var_action.get(), self.var_dir.get(),
                       ip, ports, self.var_proto.get())
        self.destroy()
