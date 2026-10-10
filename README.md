# Pro Updates

A window (and a terminal tool) for the updates on an apt-based system: pending apt and
Flatpak updates, held packages, which repository each browser updates from, and what the
Ubuntu Pro client says is published only through Ubuntu Pro.

Canonical publishes some security fixes for Universe and Multiverse packages only through
Ubuntu Pro (ESM, at `esm.ubuntu.com`). On a machine that is not attached to Ubuntu Pro
those updates never appear in `apt list --upgradable`, `unattended-upgrades` or the desktop
updater; `pro security-status` lists them. (Ubuntu Pro is free for personal use on a few
machines; attaching one makes them installable through apt.) Pro Updates shows that list
next to the ordinary updates and, where one exists, a free remedy.

```
0 apt  ·  2 flatpak  ·  31 Pro-only (ESM)  ·  1 held
```

## What it shows

**① Ubuntu Pro (ESM)** — each package `pro security-status` lists as ESM-only, with a
remedy where there is one: a Flathub build (a curated mapping, or a strict name match you
confirm), or a newer version in another repository you already use (whether that build has
the fix is not checked, and the tool says so). Without the Ubuntu Pro client this section
says **not checked**, never "nothing to fix".

**② Flatpak updates** — every pending ref, in both `--user` and `--system` scopes, each
with its own checkbox. Scope matters: a `--user`-only update silently skips everything
installed system-wide.

**③ Regular apt updates** — the ordinary upgrade, with held packages honoured and shown,
dependencies nested under the package that drags them in, and kept-back updates named.
Package lists that were never downloaded are reported as such, not as "up to date".

**Vendor sources** — which repository each browser, mail client and editor would update
from. A distribution that ships a vendor pin file (Pi-Desktop does) also gets a
**Repair sources** button that copies its own file back into place.

**④ Builds** — packages a distribution builds from source, one `build.json` each
(download over https, checked against a sha256 when `build.json` gives one; build as a
systemd user unit; install). Hidden when there are none.

One **Apply Selected** button runs whatever is ticked.

## Install

```sh
git clone https://github.com/defcom5-rockchip/pro-updates
cd pro-updates
bash install-pro-updates.sh          # builds the .deb (needs dpkg-dev, debhelper) and installs it
```

Or build it yourself with `dpkg-buildpackage -b -us -uc` and `sudo apt install
../pro-updates_1.5.0_all.deb`. `sudo apt remove pro-updates` takes it away again. The
installer also removes a 1.x install from `/usr/local`, which would otherwise shadow it.

Audit first, change nothing:

```sh
pro-updates --check
```

## Safety

- **The window's root work goes through one helper**, `/usr/libexec/pro-updates/pro-updates-helper`,
  started with `pkexec` under its own polkit action (`io.github.defcom5-rockchip.pro-updates.helper`),
  which asks for your password each time (nothing is remembered). It accepts a fixed set of
  commands (refresh, upgrade, install a local .deb, hold/unhold, install flatpak, switch named
  hosts to https, restore the vendor pin file), accepts only package names that are exactly
  one installed package (apt would otherwise expand them as patterns), checks host names and
  paths, installs a root-owned copy of a local .deb, and never runs a shell. apt's output also
  goes to `/var/log/pro-updates.log`, and apt finishes even if the window is closed. The
  terminal tool uses `sudo`; a system-wide Flatpak update follows Flatpak's own polkit rules
  (by default no password for updating apps that are already installed).
- **apt never removes a package** from the window (`--no-remove`: apt stops instead). The
  only removal anywhere is the terminal tool's offer to remove the VLC .debs after installing
  the Flathub VLC, where apt shows the list and asks.
- apt waits up to five minutes for a running update (the daily job) instead of failing,
  keeps your changed config files (`--force-confdef --force-confold`), and every failure is
  reported with its exit code.
- Held packages are never upgraded. "Hold back" holds are recorded, shown separately and
  can be released; holds the system made cannot be released through the helper. A hold also
  stops automatic security updates for that package, and it stays when Pro Updates is
  removed (release it first, or `sudo apt-mark unhold NAME`).
- Flathub is added **for your user only, and only after asking**. Name-guessed Flathub
  matches start unticked; a Flathub app installs alongside the .deb, it does not replace it.
- `/etc/pro-updates/pinned` (and `~/.config/pro-updates/pinned`) list packages that are
  never offered a Flathub swap, for hardware-tuned builds.
- One job at a time: everything is greyed out while one runs.

## Network

Nothing runs in the background: no timer, no autostart. When you open it, it makes DNS
lookups of the update hosts it lists and asks your Flatpak remotes (if any) for updates.
Applying contacts your apt sources; Flathub only after you agree; the Builds section
contacts `api.github.com` and the download URL only when a `build.json` asks for it.

## Design notes

**Unticking an apt package is best-effort; `apt-mark hold` is what actually sticks.**
apt upgrades any dependency that merely *happens* to be upgradable, and exact-version pins
bind in both directions — bumping a `-data` package can drag its parent up with it. So the
tool nests dependencies under their master and, whenever your selection is partial, asks
apt what it will *really* do and prints the answer before applying.

Attempting to model apt's resolver statically was tried and abandoned: a dependency graph
built from `Depends`/`Pre-Depends` agreed with apt on 11 of 64 packages. apt is the oracle.

**Secure transport by default.** Package files must come over `https`, `file:`, `cdrom:`
or `copy:`; updates from a plaintext source are skipped and named, and the rest go ahead.
"Allow http" is there for a LAN mirror or a caching proxy such as apt-cacher-ng. This is a
*privacy* measure, not an integrity one: apt already verifies every package against a
GPG-signed `Release` file, so HTTP cannot get a tampered package past it. What HTTP does
leak is which packages and versions you fetch.

## Requirements

Debian/Ubuntu with `apt`, `python3-gi` + `gir1.2-gtk-3.0`, `python3-apt` and `pkexec`
(the package depends on them). `flatpak` for the Flatpak sections (installed on first use
if you agree), and the Ubuntu Pro client for section ①.

## Tests

```sh
python3 -m unittest discover -s tests     # the root helper, without root
```

## Related

[ByteBender](https://github.com/defcom5-rockchip/ByteBender) rebuilds fixes that are
published only through ESM from public upstream patches, and publishes them to
`ppa:defcom5-rockchip/security`.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Canonical. Ubuntu and Ubuntu Pro are trademarks of
Canonical Ltd.
