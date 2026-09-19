"""Frozen-app entry point. PyInstaller bundles this; it just boots the
in-process desktop app (dashboard + monitor in threads, native window)."""

import sys

from avai.desktop import main

if __name__ == "__main__":
    sys.exit(main())
