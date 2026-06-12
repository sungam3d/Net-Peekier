"""Net-Peekier entry point.

Run:
    python run.py

On Windows, run from an *Administrator* terminal for full visibility and to let
WinDivert load. Without elevation you'll still see your own processes.
"""
from __future__ import annotations

import sys


def main() -> int:
    from netpeeker.monitor import Monitor
    from netpeeker.gui.main_window import NetPeekierApp

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
