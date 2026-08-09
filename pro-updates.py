#!/usr/bin/env python3
"""
Pro Updates — one update centre for Ubuntu that is honest about what
Ubuntu Pro is holding back.

Three sections, each with its own y/N:
  1) GATED FIXES  — the universe/ESM security fixes Ubuntu paywalls behind Pro,
                    remedied FREE from the vendors: a curated map (VLC, Chromium)
                    + a DYNAMIC Flathub lookup for any other gated app, + a note
                    for 7-Zip. No Pro, no token.
  2) FLATPAK      — update the sandboxed apps you already have.
  3) REGULAR APT  — the normal `apt update && apt upgrade` (free, always was).

  pro-updates            run all three, prompting before each action
  pro-updates --check    audit everything, change nothing (safe)

SAFETY (learned the hard way): never removes shared libs, never uses `-y` on a
removal, never runs `autoremove`. `apt upgrade` (regular section) never removes
packages, so it's the only place -y is used.
"""
# Copyright (C) 2026 defcom5-rockchip
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version. See <https://www.gnu.org/licenses/> for the full text.

import configparser, json, os, shutil, subprocess, sys

__version__ = "1.1"

O="\033[38;5;208m"; B="\033[1m"; D="\033[2m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; X="\033[0m"

def run(cmd):  return subprocess.run(cmd, capture_output=True, text=True)
def have(c):   return shutil.which(c) is not None
def sudo(cmd): return subprocess.run((["sudo"] + cmd) if os.geteuid() else cmd)
def human(n):
    n=float(n or 0)
    for u in ("B","K","M","G"):
        if n<1024: return f"{n:.0f}{u}"
        n/=1024
    return f"{n:.1f}T"
def yes(p):
    try:    return input(f"{O}{p}{X} ").strip().lower() in ("y","yes")
    except (EOFError,KeyboardInterrupt): print(); return False

# Shared with the GUI: ~/.config/pro-updates/config.ini
CONFIG_PATH = os.path.expanduser("~/.config/pro-updates/config.ini")
def allow_plaintext():
    cp = configparser.ConfigParser()
    try: cp.read(CONFIG_PATH)
    except Exception: return False
    return cp.getboolean("policy", "allow_plaintext", fallback=False)

SECURE = ("https://", "file:", "cdrom:", "copy:", "mirror+file:")
def apt_source_hosts():
    """Hosts apt would fetch from, per its own --print-uris."""
    r = run(["apt-get", "-y", "--print-uris", "upgrade"])
    hosts = set()
    for line in r.stdout.splitlines():
        if not line.startswith("'"): continue
        try: url = line[1:line.index("'", 1)]
        except ValueError: continue
        if "://" in url: hosts.add(url.split("/")[0] + "//" + url.split("/")[2])
    return sorted(hosts)

def free_fix(name):
    """Is this ESM-gated package already fixed, or fixable, from a FREE repo?

    pro security-status compares the installed version against the ESM index, and a
    community rebuild is deliberately versioned BELOW Ubuntu's ~esmN so that official
    updates always supersede it. The consequence is that pro keeps listing the package
    as gated forever, even once you are patched. So say so explicitly rather than
    letting section 1 imply there is no remedy.

    Returns (state, origin) where state is 'installed' or 'available', else (None, None).
    Keyed on repository origin, so it works for any third-party repo, not just ours."""
    try:
        import apt, apt_pkg
        cache = apt.Cache()
        pkg = cache[name]
    except Exception:
        return None, None
    inst = pkg.installed
    if inst is None: return None, None

    def third_party(v):
        for o in v.origins:
            if o.site and "esm.ubuntu.com" in o.site: return None   # the paywalled one
            if o.origin in ("Ubuntu", "") or not o.origin: continue  # the plain archive
            return o.origin
        return None

    src = third_party(inst)
    if src: return "installed", src                    # already running a free fix
    best = None
    for v in pkg.versions:
        o = third_party(v)
        if o and apt_pkg.version_compare(v.version, inst.version) > 0:
            if best is None or apt_pkg.version_compare(v.version, best[0]) > 0:
                best = (v.version, o)
    if best: return "available", best[1]
    return None, None

def held():
    """Set of apt-held packages — never to be removed, never upgraded."""
    return set(run(["apt-mark","showhold"]).stdout.split())

FLATHUB = "https://flathub.org/repo/flathub.flatpakrepo"
def ensure_flatpak():
    if not have("flatpak"):
        print(f"{Y}flatpak isn't installed — one-time `sudo apt install flatpak`.{X}")
        if not yes("Install flatpak now? [y/N]"): return False
        if sudo(["apt-get","install","-y","flatpak"]).returncode: return False
    run(["flatpak","remote-add","--user","--if-not-exists","flathub",FLATHUB])
    return have("flatpak")

# ---- section 1: gated ESM fixes + free remedies (curated + dynamic Flathub) ----
CURATED = {"vlc": "org.videolan.VLC", "chromium": "org.chromium.Chromium"}

def is_app_pkg(n):
    n=n.lower()
    if n.startswith(("lib","python3-","gir1.2-")): return False
    if any(n.endswith(s) for s in ("-common","-data","-doc","-dev","-dbg","-l10n")): return False
    return True
def app_base(n): return n.lower().split("-")[0]

def flatpak_match(base):
    """Ask Flathub for a REAL app whose id's final segment == this package base.
    Strict on purpose: loose substring matching suggested Ghidra for 'gh'. Never that again."""
    if not have("flatpak") or len(base) < 3: return None
    r=run(["flatpak","search","--columns=application","--",base])
    if r.returncode: return None
    for line in r.stdout.splitlines():
        appid=line.strip(); low=appid.lower()
        if not appid or "." not in appid: continue
        # skip runtimes / SDK / locale / debug — not installable apps
        if any(x in low for x in (".platform",".sdk",".locale",".debug",".sources","baseapp")): continue
        if low.rsplit(".",1)[-1] == base:   # e.g. org.videolan.VLC -> "vlc" == base
            return appid
    return None

def gated_section(check):
    if not have("pro"):
        print(f"{G}● Gated fixes: none — no Ubuntu Pro tier here (Debian model, all free).{X}\n"); return
    try: data=json.loads(run(["pro","security-status","--format","json"]).stdout)
    except (json.JSONDecodeError, ValueError):
        print(f"{R}● Gated fixes: couldn't read pro security-status.{X}\n"); return
    gated=[p for p in data.get("packages",[]) if p.get("service_name") in ("esm-apps","esm-infra")]
    if not gated:
        print(f"{G}● Gated fixes: none — not missing any universe/ESM fixes.{X}\n"); return

    bases, libs = {}, []
    for p in gated:
        nm=p["package"]
        if is_app_pkg(nm): bases.setdefault(app_base(nm),[]).append(nm)
        else: libs.append(nm)

    remedies={}
    for base in bases:
        if base in CURATED:           remedies[base]=("flatpak", CURATED[base])
        elif base in ("7zip","p7zip"):remedies[base]=("note","7-Zip 25.x — Debian free / 7-zip.org (manual)")
        else:
            m=flatpak_match(base)
            remedies[base]=("suggest", m) if m else ("none", None)

    tot=sum(p.get("download_size",0) for p in gated)
    print(f"{O}● Gated fixes (universe/ESM): {len(gated)} pkg{X} {D}({human(tot)}) — free-remedy plan:{X}")
    for base in sorted(bases):
        kind,val=remedies[base]; n=len(bases[base])
        if   kind=="flatpak": print(f"  {G}▸ {base}{X} → Flathub {val}  {D}(replaces {n}){X}")
        elif kind=="suggest": print(f"  {G}▸ {base}{X} → Flathub {val}?  {D}(auto-found match — confirm){X}")
        elif kind=="note":    print(f"  {Y}▸ {base}{X} → {val}")
        else:
            state, origin = free_fix(bases[base][0])
            if state == "installed":
                print(f"  {G}▸ {base}{X} → {G}already fixed free{X} from {origin} "
                      f"{D}— pro still lists it; ignore that entry{X}")
            elif state == "available":
                print(f"  {G}▸ {base}{X} → {G}fix available free{X} from {origin} "
                      f"{D}— plain `apt upgrade` installs it{X}")
            else:
                print(f"  {Y}▸ {base}{X} → no Flathub match {D}(rebuild from source, or Pro){X}")
    if libs:
        print(f"  {D}+ {len(libs)} pure lib(s) — no app swap: {', '.join(sorted(libs)[:6])}{'…' if len(libs)>6 else ''}{X}")
    print()
    if check: return

    installs=[(b,v) for b,(k,v) in remedies.items() if k in ("flatpak","suggest") and v]
    if installs and yes(f"Install {len(installs)} patched app(s) from Flathub? [y/N]"):
        if ensure_flatpak():
            for base,appid in installs:
                print(f"{D}flatpak install --user flathub {appid}{X}")
                subprocess.run(["flatpak","install","--user","-y","flathub",appid])
            print(f"{G}installed — sandboxed, patched, no Pro.{X}")
            # SAFE removal ONLY for VLC (known-exclusive set); never for dynamic apps or shared libs
            if "vlc" in bases:
                h=held()
                old=[p for p in bases["vlc"] if p not in h]   # NEVER remove a held package
                skipped=[p for p in bases["vlc"] if p in h]
                if skipped: print(f"{D}(skipping held: {', '.join(skipped)}){X}")
                if old:
                    print(f"{Y}Old vulnerable VLC debs still on disk.{X} {D}(no -y — apt shows the list & asks; no autoremove){X}")
                    if yes(f"Remove {len(old)} VLC-only deb(s)? [y/N]"):
                        sudo(["apt-get","remove"]+old)
            print()

# ---- section 2: flatpak updates ----
def flatpak_updates():
    """Pending updates per SCOPE. A bare --columns=application list repeats the same
    id once per branch, and a --user-only update silently skips system installs."""
    out=[]
    for scope in ("user","system"):
        r=run(["flatpak","remote-ls","--"+scope,"--updates","--columns=ref"])
        if r.returncode: continue
        for line in r.stdout.splitlines():
            ref=line.split("\t")[0].strip()
            if ref.count("/")!=3: continue
            kind,appid,arch,branch=ref.split("/")
            out.append({"ref":ref,"scope":scope,"kind":kind,"appid":appid,"branch":branch})
    return out

def flatpak_section(check):
    if not have("flatpak"): return
    ups=flatpak_updates()
    if not ups:
        print(f"{G}● Flatpak apps: all up to date.{X}\n"); return
    n_user=sum(1 for u in ups if u["scope"]=="user")
    print(f"{O}● Flatpak updates available: {len(ups)}{X} {D}({n_user} user · {len(ups)-n_user} system){X}")
    for u in ups:
        print(f"    {u['appid']}  {u['branch']}  {D}[{u['scope']} · {'app' if u['kind']=='app' else 'runtime'}]{X}")
    print()
    if check: return
    if yes(f"Update {len(ups)} Flatpak ref(s) now? [y/N]"):
        for scope in ("user","system"):
            if any(u["scope"]==scope for u in ups):
                subprocess.run(["flatpak","update","--"+scope,"-y"])
        print(f"{G}flatpaks updated.{X}\n")

# ---- section 3: regular apt (at the end) ----
def apt_section(check):
    lines=run(["apt-get","-s","upgrade"]).stdout.splitlines()
    inst=[l.split()[1] for l in lines if l.startswith("Inst ")]
    sec=sum(1 for l in lines if l.startswith("Inst ") and "security" in l.lower())
    print(f"{O}● Regular apt updates: {len(inst)}{X} {D}({sec} security-flagged){X}")
    for l in lines:
        if l.startswith("Inst "): print(f"    {l.split()[1]}")
    if not inst: print(f"    {G}up to date.{X}")
    h=held()
    if h:
        print(f"  {G}✓ {len(h)} package(s) HELD and respected — never upgraded:{X} {D}{', '.join(sorted(h))}{X}")
    print(f"  {D}(list from current cache; applying runs `apt update` first){X}\n")
    bad = [h for h in apt_source_hosts() if not h.startswith(SECURE)]
    if bad:
        if allow_plaintext():
            print(f"  {Y}⚠ plaintext source(s): {', '.join(bad)} — allowed by your policy{X}")
        else:
            print(f"  {R}⛔ plaintext source(s): {', '.join(bad)}{X}")
            print(f"  {D}   https-only policy is in force; the apt section is refused.{X}")
            print(f"  {D}   Change it in the GUI, or set allow_plaintext=yes in {CONFIG_PATH}{X}\n")
            return
    if check: return
    if inst and yes("Run the regular update now (apt update && apt upgrade)? [y/N]"):
        sudo(["apt-get","update"])
        sudo(["apt-get","upgrade","-y"])   # upgrade NEVER removes packages, so -y is safe here
        print(f"{G}apt upgrade done.{X}\n")

def main():
    if "--version" in sys.argv: print(f"pro-updates {__version__}"); return 0
    check="--check" in sys.argv
    print(f"\n{O}{B}  Pro Updates {__version__} {X}{D}— one-stop: gated free-fixes · flatpaks · regular apt{X}\n")
    if not have("apt-get"): print("Debian/Ubuntu (apt) only."); return 1
    gated_section(check)    # 1 — the special sauce
    flatpak_section(check)  # 2 — keep sandboxed apps current
    apt_section(check)      # 3 — the regular updates, at the end
    if check: print(f"{D}--check: audit only, nothing was changed.{X}")
    return 0

if __name__=="__main__":
    try: rc=main()
    except KeyboardInterrupt: print(); rc=130
    if "--check" not in sys.argv and sys.stdin.isatty():
        try: input(f"\n{D}Press Enter to close…{X}")
        except (EOFError,KeyboardInterrupt): pass
    sys.exit(rc)
