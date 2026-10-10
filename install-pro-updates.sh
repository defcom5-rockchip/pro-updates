#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 defcom5-rockchip
#
# install-pro-updates.sh — builds the Pro Updates .deb from this folder and installs it
# with apt (so `apt remove pro-updates` takes it away again). Also removes a 1.x install,
# which put copies in /usr/local that would shadow the packaged ones.
#
#   bash install-pro-updates.sh             # build + install
#   bash install-pro-updates.sh --uninstall # apt remove, plus any 1.x leftovers
#
# Flathub is NOT added here: the tool adds it for your user when you choose a Flatpak install.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
say(){ printf '\033[38;5;208m[pro-updates]\033[0m %s\n' "$*"; }
# Already root (an image build): a shell function stands in for sudo.
if [ "$(id -u)" -eq 0 ]; then sudo(){ "$@"; }; fi

remove_legacy() {
	local f found=0
	for f in /usr/local/bin/pro-updates /usr/local/bin/pro-updates-gui; do
		[ -e "$f" ] && found=1
	done
	[ "$found" = 1 ] || return 0
	say "removing the 1.x copies from /usr/local"
	sudo rm -f /usr/local/bin/pro-updates /usr/local/bin/pro-updates-gui
	# 1.x wrote these into the shared dirs outside dpkg; leave them if a package owns them
	for f in /usr/share/applications/pro-updates.desktop /usr/share/icons/hicolor/scalable/apps/pro-updates.svg; do
		dpkg -S "$f" >/dev/null 2>&1 || sudo rm -f "$f"
	done
}

if [ "${1:-}" = "--uninstall" ]; then
	if dpkg -s pro-updates >/dev/null 2>&1; then sudo apt-get remove -y pro-updates; fi
	remove_legacy
	say "uninstalled. A Flathub remote you added stays (flatpak remote-delete --user flathub removes it)."
	exit 0
fi

command -v dpkg-buildpackage >/dev/null || { echo "needs dpkg-dev and debhelper: sudo apt install dpkg-dev debhelper"; exit 1; }
say "building the .deb"
( cd "$HERE" && dpkg-buildpackage -b -us -uc >/dev/null )
VER=$(dpkg-parsechangelog -l "$HERE/debian/changelog" -S Version)
DEB="$(cd "$HERE/.." && pwd)/pro-updates_${VER}_all.deb"
remove_legacy
say "installing $(basename "$DEB")"
sudo apt-get install -y "$DEB"
say "installed: $(pro-updates --version)   ·   audit only: pro-updates --check   ·   window: Pro Updates in the app grid"
