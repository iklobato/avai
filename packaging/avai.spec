# PyInstaller spec, one file for all three OSes.
#   pyinstaller packaging/avai.spec      (run from the repo root)
#
# UNVERIFIED until it runs in CI with the GUI extra installed
# (pip install -e '.[app]'): no PyInstaller build happens in the test suite.
#
# Per-OS:
#   Windows -> onedir + uac_admin (force-elevate the whole app, as chosen).
#   macOS   -> .app BUNDLE (codesigned + notarized later in CI).
#   Linux   -> onedir; the .deb's .desktop launches it via pkexec.
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# avai ships package data (templates/, static/, prompts.toml, rules/ incl. the
# YARA pack). PyInstaller does not grab non-.py files on its own.
datas = collect_data_files("avai")

# pywebview picks its backend at runtime; pull every webview submodule so the
# frozen app finds the platform one. waitress + litellm also import lazily.
hiddenimports = ["waitress"]
hiddenimports += collect_submodules("webview")
# ponytail: litellm/anthropic do dynamic provider imports. If the judge breaks
# in the frozen build, add `--collect-all litellm` here. Left out until it bites.

a = Analysis(
    # Relative to this spec file, not the working directory.
    ["avai_app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="avai",
    console=False,  # windowed app, no terminal
    # Phase B elevation: Windows runs the whole app elevated via the UAC
    # manifest. Clean only on Windows; Linux uses pkexec, macOS uses a helper.
    uac_admin=(sys.platform == "win32"),
    # icon=...  # add packaging/icons/avai.{ico,icns} when provided
)
coll = COLLECT(exe, a.binaries, a.datas, name="avai")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="avai.app",
        bundle_identifier="dev.avai.app",
        info_plist={
            "CFBundleName": "avai",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "12.0",
        },
        # icon=...
    )
