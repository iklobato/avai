#!/usr/bin/env bash
# Package the PyInstaller onedir (dist/avai) into a .deb with fpm.
#   packaging/linux/build_deb.sh 0.8.0
# Needs: fpm (gem install fpm) + a prior `pyinstaller packaging/avai.spec`.
# UNVERIFIED until run in CI on an Ubuntu runner.
set -euo pipefail

VERSION="${1:?usage: build_deb.sh VERSION}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

[ -d "$ROOT/dist/avai" ] || { echo "missing dist/avai (run pyinstaller first)" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

install -D -m 0755 "$ROOT/packaging/linux/avai" "$STAGE/usr/bin/avai"
install -D -m 0644 "$ROOT/packaging/linux/avai.desktop" \
    "$STAGE/usr/share/applications/avai.desktop"
mkdir -p "$STAGE/opt/avai"
cp -a "$ROOT/dist/avai/." "$STAGE/opt/avai/"

fpm -s dir -t deb -n avai -v "$VERSION" --architecture amd64 \
    --description "avai host-security telemetry + dashboard (desktop app)" \
    --url "https://github.com/iklobato/avai" \
    --depends gir1.2-webkit2-4.1 --depends python3-gi --depends policykit-1 \
    -C "$STAGE" usr opt

echo "built avai_${VERSION}_amd64.deb"
