# Pro Updates

An update centre for Ubuntu that is honest about what Ubuntu Pro is holding back — and
applies everything you *can* get for free.

Ubuntu ships security fixes for Universe and Multiverse packages to `esm.ubuntu.com`,
behind an Ubuntu Pro subscription. Those updates never appear in `apt list --upgradable`,
because the repository isn't in your sources until the machine is attached. They are
invisible to `apt`, to `unattended-upgrades`, and to the desktop updater. The only place
they surface is `pro security-status`, and there they are shown but not installable.

Pro Updates reads that list, tells you exactly what is being withheld, and — where a free
remedy exists — offers it.

```
23 gated  ·  0 fixable free  ·  11 flatpak  ·  64 regular  ·  1 held ✓
```

## What it does

**① Gated fixes** — the Universe/ESM security updates Ubuntu paywalls. For each one it
looks for a free remedy: a curated Flathub mapping for known apps, or a strict Flathub
lookup for the rest. Packages with no remedy are listed plainly as such rather than
quietly dropped.

**② Flatpak updates** — every pending ref, in both `--user` and `--system` scopes, each
with its own checkbox. Scope matters: a `--user`-only update silently skips everything
installed system-wide.

**③ Regular apt updates** — the ordinary upgrade, with `apt-mark hold` honoured and
displayed, and with dependencies nested under the package that drags them in.

One **Apply Selected** button runs whatever is ticked. Flatpak user installs need no root;
apt runs through `pkexec`.

## Install

```sh
git clone https://github.com/defcom5-rockchip/pro-updates
cd pro-updates
bash install-pro-updates.sh
```

Installs `pro-updates` and `pro-updates-gui` to `/usr/local/bin`, plus a desktop launcher
and icon. Idempotent — re-run it to upgrade. `bash install-pro-updates.sh --uninstall`
reverses it.

Audit first, change nothing:

```sh
pro-updates --check
```

## Design notes

**Unticking an apt package is best-effort; `apt-mark hold` is what actually sticks.**
apt upgrades any dependency that merely *happens* to be upgradable, and exact-version pins
bind in both directions — bumping a `-data` package can drag its parent up with it. So the
tool nests dependencies under their master and, whenever your selection is partial, asks
apt what it will *really* do and prints the answer before applying. If apt intends to touch
something you unticked, you are told, not surprised.

Attempting to model apt's resolver statically was tried and abandoned: a dependency graph
built from `Depends`/`Pre-Depends` agreed with apt on 11 of 64 packages. apt is the oracle.

**Secure transport is required.** Package files must come over `https`, `file:`, `cdrom:`
or `copy:`. A plaintext source is reported and refused. Note this is a *privacy* measure,
not an integrity one: apt already verifies every package against a GPG-signed `Release`
file, so HTTP cannot get a tampered package past it. What HTTP does leak is which packages
and versions you fetch — a precise inventory of which CVEs you have not patched yet.

The output pane shows the host, its resolved A/AAAA records, file count and byte total for
every source involved, so you can see where the bytes come from.

## What it does not do

- It does not unlock ESM. Gated packages with no free remedy stay gated. The tool is
  honest about that rather than pretending otherwise.
- It never removes a package. The GUI has no removal path at all.
- It does not touch held packages.

## Requirements

Debian/Ubuntu with `apt`. `python3-gi` + `gir1.2-gtk-3.0` for the GUI, `flatpak` for the
Flatpak sections, `python3-apt` for dependency nesting (without it the package list is
flat), and `ubuntu-pro-client` for section ①. All are installed by the installer where
available; each degrades gracefully when absent, so it runs on plain Debian too.

## Related

[ByteBender](https://github.com/defcom5-rockchip/ByteBender) reproduces the ESM-gated fixes
themselves from public sources, and publishes them to `ppa:defcom5-rockchip/security`. Pro
Updates reports what is gated; ByteBender is one way to un-gate it.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
