# Packaging the desktop app

`avai app` runs the dashboard + monitor in one process behind a native window
(`src/avai/desktop.py`). These files turn it into installers per OS. Tagging
`vX.Y.Z` runs `.github/workflows/release.yml`, which builds all three and
attaches them to the GitHub Release. The same tag also runs `publish.yml`
(wheel and sdist to PyPI) and `docker.yml` (`iklob1/avai` for amd64 and arm64).
The full release steps are in `docs/KNOWLEDGE.md`, section 5.4.

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
- The Windows and Linux installers built from a real tag (v0.10.0,
  https://github.com/iklobato/avai/releases/tag/v0.10.0). The macOS job still
  fails at "Import signing certificate" ("At least one of p12-filepath or
  p12-file-base64 must be provided") until the secrets below are set. There
  is still no PyInstaller build in the test suite.
- Icon: add `packaging/icons/avai.{ico,icns}` and reference them in `avai.spec`.
- `/settings` route for the API key: the key is read from `~/.avai/config.json`;
  the in-app settings screen is a follow-up.
- litellm may need `--collect-all litellm` in the spec if the judge breaks
  frozen.
