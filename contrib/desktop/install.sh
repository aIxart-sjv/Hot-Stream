#!/bin/sh
# Installs Hot-Stream for normal desktop use, so it can be launched from an application
# launcher/menu afterward without ever running npm/cargo/tauri commands again.
#
# What this does, precisely:
#   - copies the already-built release binaries into ~/.local/bin (no root needed: this is a
#     per-user location, on most desktop environments' PATH for GUI-launched apps already)
#   - installs a .desktop entry into ~/.local/share/applications and an icon into the standard
#     per-user icon theme location, so Hot-Stream shows up in application launchers/menus
#   - prints, but does not itself run, the one-time `sudo setcap` step block/bandwidth
#     enforcement needs — this project never invokes sudo on the user's behalf; see the main
#     README/CLAUDE.md for why
#
# It does not build anything. Build first:
#   cd <repo>
#   npm install && npm run build
#   (cd src-tauri && cargo build --release --bins)
set -eu

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/128x128/apps"
RELEASE_DIR="$REPO_DIR/src-tauri/target/release"

if [ ! -x "$RELEASE_DIR/hot-stream" ] || [ ! -x "$RELEASE_DIR/hot-stream-helper" ]; then
  echo "Release binaries not found in $RELEASE_DIR. Build them first:" >&2
  echo "  cd $REPO_DIR && npm install && npm run build && (cd src-tauri && cargo build --release --bins)" >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$APPS_DIR" "$ICON_DIR"
install -m 0755 "$RELEASE_DIR/hot-stream" "$BIN_DIR/hot-stream"
install -m 0755 "$RELEASE_DIR/hot-stream-helper" "$BIN_DIR/hot-stream-helper"
install -m 0644 "$REPO_DIR/src-tauri/icons/128x128.png" "$ICON_DIR/hot-stream.png"

cat > "$APPS_DIR/hot-stream.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Hot-Stream
Comment=See and control who is using this laptop's Wi-Fi hotspot
Exec=$BIN_DIR/hot-stream
Icon=hot-stream
Terminal=false
Categories=Network;System;
StartupWMClass=hot-stream
EOF

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Installed:"
echo "  $BIN_DIR/hot-stream"
echo "  $BIN_DIR/hot-stream-helper"
echo "  $APPS_DIR/hot-stream.desktop"
echo
echo "Hot-Stream should now appear in your application launcher. Launching it directly also"
echo "works: $BIN_DIR/hot-stream"
echo
echo "One remaining one-time step — without it the app runs and shows connected devices, but"
echo "Block and bandwidth-limit actions fail with a permissions error. Re-run this only after"
echo "reinstalling or rebuilding hot-stream-helper (a fresh build is a new file, which loses"
echo "the grant):"
echo
echo "  sudo setcap cap_net_admin+eip $BIN_DIR/hot-stream-helper"
