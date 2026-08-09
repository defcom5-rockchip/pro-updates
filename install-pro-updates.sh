#!/usr/bin/env bash
#
# install-pro-updates.sh — installs the Pro Updates tool (CLI + GTK GUI + launcher)
# on a Debian/Ubuntu box. Run it from the folder that holds pro-updates.py and
# pro-updates-gui.py (i.e. this Share/CLAUDE PI bundle).
#
#   bash install-pro-updates.sh            # install / update
#   bash install-pro-updates.sh --uninstall
#
# System-wide install (needs sudo): binaries -> /usr/local/bin, launcher +
# icon into the shared dirs. Idempotent.
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN=/usr/local/bin
APPS=/usr/share/applications
ICONS=/usr/share/icons/hicolor/scalable/apps

say(){ printf '\033[38;5;208m[pro-updates]\033[0m %s\n' "$*"; }

if [ "${1:-}" = "--uninstall" ]; then
  say "removing…"
  sudo rm -f "$BIN/pro-updates" "$BIN/pro-updates-gui" "$APPS/pro-updates.desktop" "$ICONS/pro-updates.svg"
  sudo update-desktop-database "$APPS" 2>/dev/null || true
  say "uninstalled (deps left in place)."
  exit 0
fi

# ---- deps ----
if command -v apt-get >/dev/null; then
  say "deps (sudo): flatpak + GTK python bindings…"
  sudo apt-get update -qq
  # flatpak = the runtime remedy path; python3-gi/gtk = the GUI; python3-apt reads the
  # dependency graph so children can be nested under the package that drags them in.
  # pkexec + ubuntu-pro-client
  # are already present on Ubuntu desktops; on Debian pro-client is absent and the tool degrades gracefully.
  sudo apt-get install -y flatpak python3-gi gir1.2-gtk-3.0 python3-apt >/dev/null
  flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo 2>/dev/null || true
fi

# ---- binaries ----
for f in pro-updates.py pro-updates-gui.py; do
  [ -f "$HERE/$f" ] || { echo "MISSING $HERE/$f — run this from the bundle folder"; exit 1; }
done
say "installing binaries -> $BIN"
sudo install -Dm755 "$HERE/pro-updates.py"     "$BIN/pro-updates"
sudo install -Dm755 "$HERE/pro-updates-gui.py" "$BIN/pro-updates-gui"

# ---- icon (embedded orange refresh; facehugger.svg is the project brand mark, shipped alongside) ----
say "installing icon + launcher"
sudo mkdir -p "$ICONS" "$APPS"
sudo tee "$ICONS/pro-updates.svg" >/dev/null <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="-3 -3 30 30" width="256" height="256">
  <path fill="#e85020" d="M17.65 6.35A7.958 7.958 0 0 0 12 4a8 8 0 0 0-8 8 8 8 0 0 0 8 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0 1 12 18a6 6 0 0 1 0-12c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
</svg>
SVG
# facehugger brand mark too, if present in the bundle
[ -f "$HERE/facehugger.svg" ] && sudo install -Dm644 "$HERE/facehugger.svg" "$ICONS/facehugger.svg"

sudo tee "$APPS/pro-updates.desktop" >/dev/null <<'DESK'
[Desktop Entry]
Type=Application
Name=Pro Updates
GenericName=Software Updates
Comment=Free security fixes + updates, no Ubuntu Pro — Flathub/upstream remedies, hold-aware
Exec=pro-updates-gui
Icon=pro-updates
Terminal=false
Categories=System;Settings;
Keywords=security;updates;esm;pro;universe;cve;flatpak;
DESK
sudo update-desktop-database "$APPS" 2>/dev/null || true
sudo gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

# ---- verify ----
say "installed:"
echo "   $(command -v pro-updates)   +   $(command -v pro-updates-gui)"
echo "   launcher: $APPS/pro-updates.desktop   icon: $ICONS/pro-updates.svg"
say "audit-only first run (no changes):  pro-updates --check"
say "GUI: launch 'Pro Updates' from the menu, or run  pro-updates-gui"
