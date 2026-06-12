"""Net-Peekier entry point.

Expects the `netpeekier` package folder alongside this file. Run with:
    python run.py

On Windows, run from an *Administrator* terminal for full visibility and to let
WinDivert load. Without elevation you'll still see your own processes.
"""
from __future__ import annotations

import sys


def main() -> int:
    from netpeekier.monitor import Monitor
    from netpeekier.gui.main_window import NetPeekierApp

    monitor = Monitor(interval=1.0)
    monitor.start()
    try:
        app = NetPeekierApp(monitor)
        app.mainloop()
    finally:
        monitor.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
