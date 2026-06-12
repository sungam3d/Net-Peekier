"""Filesystem locations, all anchored inside the program folder.

Everything the program writes lives under the project root (the folder that
contains run.py), so nothing is scattered across the user's home directory:

    <root>/settings.txt      all app settings & rules (JSON inside a .txt)
    <root>/log/              exported packet logs

The ONLY things that live outside this folder are OS-level and not files we
manage: Windows Firewall rules (stored by Windows; created via netsh) and the
WinDivert driver (a system driver installed by the pydivert package). These are
unavoidable for blocking/throttling and are documented in the README.
"""
from __future__ import annotations

import os

# settings.py lives at <root>/netpeekier/paths.py -> root is two levels up.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_FILE = os.path.join(ROOT, "settings.txt")
LOG_DIR = os.path.join(ROOT, "log")


def ensure_log_dir() -> str:
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass
    return LOG_DIR
