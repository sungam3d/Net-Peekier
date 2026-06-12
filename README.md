# Net-Peekier

A small, dependency-light per-process network monitor inspired by the old
**NetPeeker** — built in Python with a Tkinter GUI. It shows live upload/
download speeds, the processes using your network, their listening ports,
per-process live connections, real-time packet capture with a hex dump, and
firewall blocking / speed limiting.

It deliberately keeps NetPeeker's simple structure:

```
Dashboard (up/down now + peak)
   └─ Application list  (svchost.exe ▸ expands to its PIDs)
        └─ double-click ▸ Connections (Detail Information)
             └─ double-click ▸ Captured Packets (+ hex dump)
   Firewall menu ▸ Firewall & limits manager
                 ▸ Block / Unblock / Set speed limit on selection
```

## Quick start

```bash
pip install -r requirements.txt
python run.py
```

On **Windows**, launch from an **Administrator** terminal so you can see every
process's connections and so WinDivert can load.

## Two operating modes

The app auto-detects what's available and tells you in the status bar.

| Capability | psutil-only (no driver) | + WinDivert (`pip install pydivert`) |
|---|---|---|
| Process list, connections, statuses | ✅ | ✅ |
| Listening ports per app | ✅ | ✅ |
| Dashboard up/down totals | ✅ (system-wide) | ✅ (sum of processes) |
| **Per-process** up/down speed | ❌ | ✅ |
| Live packet capture + hex view | ❌ | ✅ |
| Block app (Windows Firewall) | ✅ (needs admin) | ✅ |
| Speed limit (throttle) | recorded only | ✅ enforced |

### Why WinDivert?

Windows has **no userland API for per-process bandwidth**. `psutil` exposes
connections and ports, but byte counters are only system-wide. NetPeeker solved
this with its own kernel driver; the modern, signed, Python-drivable equivalent
is **WinDivert** (via the `pydivert` package). Net-Peekier uses it the safe
way:

- a **SNIFF** handle (read-only) measures traffic and captures packets — it can
  never break your connectivity;
- a separate **enforcer** handle opens *only while* a block/throttle rule is
  active, putting Python in the data path solely for the apps you chose to
  control.

App **blocking** defaults to **Windows Firewall** (`netsh advfirewall`), so the
block is persistent and never sits in your packet path.

## Firewall & limits manager

Open it from **Firewall ▸ Firewall & limits manager** (or right-click an app).
It lists every managed app in one table — blocked state, upload limit, download
limit and path — independent of whether the app is currently running.

- **Add running app...** — pick from processes that currently have network
  activity (only ones with a resolvable executable path can be managed).
- **Add by path...** — browse to any `.exe`.
- **Edit...** (or double-click a row) — a small dialog with a *Block* checkbox
  and *Upload/Download limit* fields in KB/s (0 = unlimited).
- **Remove** — clears both the block and the limit for that app.

Rules are keyed by **executable path**, so they stick to the app across
restarts rather than to a one-off PID. Blocks are applied through Windows
Firewall (persistent); limits are enforced by the WinDivert throttler while
active. Both need Administrator — the window tells you if a rule couldn't be
applied.

## How packets are attributed to a process

The capture backend reads each packet's local `(ip, port)` and looks up the
owning PID from a connection table it refreshes ~once a second (`psutil`).
Bytes accumulate per-PID and per-connection; once a second those counters are
divided by the elapsed time to produce live speeds.

## Project layout

```
run.py                     entry point
netpeeker/
  models.py                dataclasses (Packet, Connection, ProcStat, Totals)
  procmap.py               psutil: processes, connections, ports, endpoint→PID
  capture.py               WinDivert sniff + enforcer + NullBackend fallback
  firewall.py              netsh advfirewall block/unblock
  monitor.py               background worker: builds the 1/sec snapshot
  util.py                  speed/byte formatting
  gui/
    main_window.py         dashboard + application treeview + firewall menu
    connections_window.py  per-process connections ("Detail Information")
    packets_window.py      captured packets + hex/ASCII dump + export
    firewall_window.py     firewall & rate-limit manager (add/edit/remove)
```

## Limitations & honest notes

- **Windows is the target.** psutil parts run on Linux/macOS too (handy for
  development), but WinDivert, `netsh` firewall and per-process speeds are
  Windows-only.
- **Throttling is a simple token bucket** that drops over-budget packets; TCP
  backs off in response. It's effective but coarser than a kernel QoS shaper.
- **Loose port→PID matching:** if two processes briefly share a local port view
  (rare), attribution falls back to "last seen wins". Exact `(ip,port)` is
  tried first.
- Requires **admin** for full visibility and for firewall/driver operations.
- This is a clean re-implementation of the *idea*; it shares no code with the
  original NetPeeker.

## Cleaning up firewall rules

Rules created by the app are named `NetPeekier block in/out :: <exe>`. Remove
them from inside the app (Firewall ▸ Unblock) or with:

```bash
netsh advfirewall firewall show rule name=all | findstr NetPeekier
```
