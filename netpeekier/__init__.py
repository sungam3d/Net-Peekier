"""Net-Peekier: a small per-process network monitor inspired by NetPeeker."""
import os
import re

# Fallback version. The single source of truth is the version line near the top
# of README.md ("##### vX.Y.Z"); get_version() reads it so the About box always
# matches what you publish. Keep this constant roughly in sync as a backup for
# when README.md isn't shipped alongside the code.
__version__ = "1.0.15"


def get_version() -> str:
    """Return the app version. Prefers the version line in README.md (the place
    the version is maintained), falling back to __version__."""
    try:
        from . import paths
        readme = os.path.join(paths.ROOT, "README.md")
        with open(readme, "r", encoding="utf-8") as fh:
            for _ in range(15):                # only scan the header area
                line = fh.readline()
                if not line:
                    break
                m = re.search(r"\bv(\d+\.\d+\.\d+)\b", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return __version__
