# Packaging the desktop app

`avai app` runs the dashboard + monitor in one process behind a native window
(`src/avai/desktop.py`). These files turn it into installers per OS. Tagging
`vX.Y.Z` runs `.github/workflows/release.yml`, which builds all three and
attaches them to the GitHub Release.

| OS | Artifact | How | Signed? |
|----|----------|-----|---------|
| Windows | `avai-setup-<v>.exe` | PyInstaller (`avai.spec`, `uac_admin`) + Inno Setup (`windows/avai.iss`) | no (SmartScreen warns) |
| macOS | `avai-<v>.dmg` -> Cask | PyInstaller `.app` + codesign + notarize | yes (Developer ID) |
| Linux | `avai_<v>_amd64.deb` | PyInstaller + `fpm` (`linux/build_deb.sh`) | no (on Releases) |

Install:
- Windows: download + run `avai-setup-<v>.exe`.
- macOS: `brew install --cask iklobato/avai/avai` (after the cask bump).
- Linux: `sudo apt install ./avai_<v>_amd64.deb`.

## Elevation (force-elevate, as chosen)
- **Windows:** clean, via the UAC manifest baked into the exe.
- **Linux:** `avai app` self-elevates with `pkexec` (X11; Wayland-as-root is
  usually refused). See `linux/avai`.
- **macOS:** deferred. Whole-GUI-as-root is not notarizable; v1 runs
  unprivileged (root-only collectors skip). See `macos/ELEVATION.md` for the
  privileged-helper upgrade path.

## CI secrets (macOS job)
`MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `APPLE_ID`, `APPLE_TEAM_ID`,
`APPLE_APP_PASSWORD`, and `HOMEBREW_TAP_TOKEN` (for the cask bump).

## Not yet done / known ceilings
- All build files are **unverified until CI runs a real tag** (no PyInstaller
  build in the test suite).
- Icon: add `packaging/icons/avai.{ico,icns}` and reference them in `avai.spec`.
- `/settings` route for the API key: the key is read from `~/.avai/config.json`;
  the in-app settings screen is a follow-up.
- litellm may need `--collect-all litellm` in the spec if the judge breaks
  frozen.
