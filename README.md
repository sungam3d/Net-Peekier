# Net-Peekier

A small, dependency-light per-process network monitor inspired by the old
**NetPeeker** — built in Python with a Tkinter GUI. It shows live upload/
download speeds, the processes using your network, their listening ports,
per-process live connections, real-time packet capture with a hex dump, and
firewall blocking / speed limiting.

It deliberately keeps NetPeeker's simple structure:

```
Dashboard (up/down now + peak + total)
   └─ Application list  (svchost.exe ▸ expands to its PIDs)   [sortable headers]
        └─ double-click ▸ Connections (Detail Information)    [sortable headers]
             └─ double-click ▸ Captured Packets (+ hex dump)  [sortable headers]
   Firewall menu ▸ Firewall & limits manager
                 ▸ Block / Unblock / Set speed limit on selection
   Settings ▸ speed display unit + packet-log purge interval
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
| Dashboard up/down speed (now + peak) | ✅ (system-wide) | ✅ (sum of processes) |
| Dashboard total sent / received | ✅ (system-wide, since start) | ✅ |
| **Per-process** up/down speed | ❌ | ✅ |
| **Per-process** total sent / received | ❌ | ✅ |
| Live packet capture + hex view | ❌ | ✅ |
| Block app (Windows Firewall) | ✅ (needs admin) | ✅ |
| Speed limit (throttle) | recorded only | ✅ enforced |
| Tag groups with shared block / limit | recorded only | ✅ enforced |

### Why WinDivert?

Windows has **no userland API for per-process bandwidth**. `psutil` exposes
connections and ports, but byte counters are only system-wide. NetPeeker solved
this with its own kernel driver; the modern, signed, Python-drivable equivalent
is **WinDivert** (via the `pydivert` package). Net-Peekier uses it the safe
way:

- a **SNIFF** handle (read-only) measures traffic and captures packets — it can
  never break your connectivity;
- a separate **enforcer** handle opens *only while* a **speed limit** is active,
  putting Python in the data path solely to throttle. It is **fail-open**: any
  error reinjects the packet, so it can never take you offline. Crucially, the
  enforcer's WinDivert filter is **scoped to just the limited apps' current
  local ports**, rebuilt as those ports change. Everything else stays on the
  kernel fast path — so limiting one app never diverts (or stalls) anyone
  else's traffic. When a limited app has no live connections, the enforcer
  diverts nothing at all.

**Blocking is Windows Firewall only** (`netsh advfirewall`). It is selective and
kernel-enforced, so a block is persistent and never sits in your packet path.
This is deliberate: routing *all* traffic through a userspace loop just to drop
one app's packets would stall every other connection — so blocking never
touches the enforcer.

## Firewall & limits manager

Open it from **Firewall ▸ Firewall & limits manager** (or right-click an app).
It lists every managed app in one table — blocked state, upload limit, download
limit and path — independent of whether the app is currently running.

- **Add running app...** — pick from processes that currently have network
  activity (only ones with a resolvable executable path can be managed).
- **Add by path...** — browse to any `.exe`.
- **Edit...** (or double-click a row) — a small dialog with a *Block* checkbox,
  *Upload/Download limit* fields in KB/s (0 = unlimited), and a *Tag* field.
- **Remove** — clears the block, limit and tag for that app.
- **Tag rules...** — manage group rules (see Tag groups below).

Rules are keyed by **executable path**, so they stick to the app across
restarts rather than to a one-off PID. Blocks are applied through Windows
Firewall (persistent); limits are enforced by the WinDivert throttler while
active. Both need Administrator — the window tells you if a rule couldn't be
applied.

## Tag groups (shared limits)

Assign a **tag** to processes (right-click a process ▸ *Set tag*, or set it in
the firewall manager) to group them. In **Tag rules...** you can block or set an
aggregate speed limit on a whole tag. The limit is a **shared budget**: the
combined traffic of every app under the tag can't exceed it.

Example: tag three games as `games` and set the tag's download limit to
2000 KB/s. One game running alone uses the full 2000 KB/s. When a second game
launches and wants 500 KB/s, the first naturally backs off to ~1500 KB/s so the
group total stays at 2000 KB/s — a single shared token bucket hands tokens to
whichever app asks first.

## Main-list right-click

Right-click a process row for: **Show connections**, **End Process** (terminate,
then force-kill if needed), **Open Program Path** (opens the folder with the
executable highlighted), **Set tag**, **Block / Unblock**, **Set speed limit**,
and the manager.

## Captured packets → log files

In the Captured Packets window, right-click to **Export selected to log** or
**Export all to log**. Each entry records time, direction, protocol, local and
remote address, length and owner PID, followed by the full hex/ASCII dump. Logs
default to the program's own `log/` folder (see Where files live).

## Settings

Open the **Settings** menu (top bar). Settings persist with everything else to
`settings.txt` in the program folder (see Where files live):

- **Speed display unit** — show all rates in Auto (scale each value), B/s, KB/s
  or MB/s. The chosen unit appears in the cells and in the Upload/Download
  column headers on the main and Detail Information pages. A live preview shows
  a sample speed in the selected unit.
- **Captured packet logs** — delete captured packets older than *N* minutes;
  leave blank to never delete. Captured packets are already capped per
  connection, but over a long session the number of tracked connections grows,
  so a purge interval keeps memory in check. The purge runs on the monitor's
  one-second tick and also forgets connections whose buffers empty out.

## Where files live

Everything Net-Peekier writes stays inside the program folder:

```
<program root>/settings.txt   options, firewall blocks, per-app limits,
                              tags and tag limits  (JSON inside a .txt)
<program root>/log/           exported packet logs
```

The **only** things outside this folder are OS-level and not files Net-Peekier
manages: the **Windows Firewall rules** that actually enforce blocks (stored by
Windows, created via `netsh`) and the **WinDivert driver** (a system driver
installed with the `pydivert` package). Both are unavoidable for selective
blocking and throttling.

## Rows & sorting

Every other row is shaded a very light blue so adjacent rows are easy to tell
apart. Every table sorts by clicking a column header; click again to reverse,
and an arrow marks the active column. The chosen order is preserved across the
once-a-second refresh, and in the application list it also orders the PID rows
within each expanded program group.

## How packets are attributed to a process

The capture backend reads each packet's local `(ip, port)` and looks up the
owning PID from a connection table it refreshes ~once a second (`psutil`).
Bytes accumulate per-PID and per-connection; once a second those counters are
divided by the elapsed time to produce live speeds.

## Project layout

```
run.py                     entry point  (imports the `netpeekier` package)
settings.txt               created at runtime: all options/rules (JSON in .txt)
log/                       created at runtime: exported packet logs
netpeekier/
  models.py                dataclasses (Packet, Connection, ProcStat, Totals)
  procmap.py               psutil: processes, connections, ports, endpoint→PID
  capture.py               WinDivert sniff + scoped enforcer + NullBackend
  firewall.py              netsh advfirewall block/unblock
  monitor.py               background worker: builds the 1/sec snapshot
  util.py                  speed/byte formatting (unit-aware)
  paths.py                 program-root file locations (settings.txt, log/)
  settings.py              persisted state: options, blocks, limits, tags
  gui/
    main_window.py         dashboard + app list + right-click + menus
    connections_window.py  per-process connections ("Detail Information")
    packets_window.py      captured packets + hex dump + export-to-log
    firewall_window.py     firewall/limits manager + tag-group rules
    settings_window.py     speed unit + packet-log purge interval
    treesort.py            reusable click-to-sort + row striping
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
