#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Pro Updates — the updates on an apt-based system in one terminal run, including
what the Ubuntu Pro client says is published only through Ubuntu Pro (ESM).

Three sections, each with its own y/N:
  1) UBUNTU PRO (ESM) — universe fixes Canonical publishes only to Ubuntu Pro
                    subscribers, with any free remedy: a Flathub build (curated,
                    or a name match to confirm), a newer version in another
                    configured repository, a note for 7-Zip. Needs the Ubuntu Pro
                    client; without it the section says "not checked".
  2) FLATPAK      — update the Flatpak apps you already have.
  3) REGULAR APT  — the normal `apt update && apt upgrade`.

  pro-updates            run all three, prompting before each action
  pro-updates --check    audit everything, change nothing (reads the network:
                         DNS, and Flathub if a remote is configured)

SAFETY: apt never removes a package here (--no-remove; the one exception is the
VLC .debs after a Flathub VLC install, where apt shows the list and asks), never
runs `autoremove`, waits for a running update instead of failing, and keeps your
changed config files. Held packages are never upgraded.

Not affiliated with or endorsed by Canonical. Ubuntu and Ubuntu Pro are
trademarks of Canonical Ltd.
"""
# Copyright (C) 2026 defcom5-rockchip
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version. See <https://www.gnu.org/licenses/> for the full text.

import configparser, glob, json, os, re, shutil, subprocess, sys, time

__version__ = "1.5.0"
if "--version" in sys.argv:             # answer before any scan: this used to hang under sudo
    print(f"pro-updates {__version__}"); raise SystemExit(0)

O="\033[38;5;208m"; B="\033[1m"; D="\033[2m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; X="\033[0m"

class _Failed:
    def __init__(self, rc, err): self.returncode, self.stdout, self.stderr = rc, "", err

# Output is parsed, so every command runs in the C locale; nothing may hang the scan.
C_ENV = dict(os.environ, LC_ALL="C")
def run(cmd, timeout=120):
    try: return subprocess.run(cmd, capture_output=True, text=True, env=C_ENV, timeout=timeout)
    except FileNotFoundError: return _Failed(127, f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired: return _Failed(124, f"{cmd[0]}: timed out after {timeout} s")
def have(c):   return shutil.which(c) is not None
def sudo(cmd): return subprocess.run((["sudo"] + cmd) if os.geteuid() else cmd).returncode
def human(n):
    n=float(n or 0)
    for u in ("B","K","M","G"):
        if n<1024: return f"{n:.0f}{u}"
        n/=1024
    return f"{n:.1f}T"
def yes(p):
    try:    return input(f"{O}{p}{X} ").strip().lower() in ("y","yes")
    except (EOFError,KeyboardInterrupt): print(); return False
FAILURES = []
def failed(what, rc):
    FAILURES.append(what)
    print(f"{R}✗ {what} failed (exit code {rc}).{X}\n")

# apt: never remove, wait for a running update (the daily job) instead of failing,
# keep changed config files without asking.
APT_OPTS = ["-o", "DPkg::Lock::Timeout=300",
            "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
APT_ENV = ["env", "DEBIAN_FRONTEND=noninteractive"]

# Shared with the GUI: ~/.config/pro-updates/config.ini
CONFIG_PATH = os.path.expanduser("~/.config/pro-updates/config.ini")
def allow_plaintext():
    cp = configparser.ConfigParser()
    try: cp.read(CONFIG_PATH)
    except Exception: return False
    return cp.getboolean("policy", "allow_plaintext", fallback=False)

SECURE = ("https://", "file:", "cdrom:", "copy:", "mirror+file:")
def is_secure(url): return url.startswith(SECURE)

def print_uris(cmd):
    """{package: url} for what apt would download, per its own --print-uris."""
    out = {}
    for line in run(cmd).stdout.splitlines():
        if not line.startswith("'"): continue
        try: end = line.index("'", 1)
        except ValueError: continue
        rest = line[end + 1:].split()
        if rest: out[rest[0].split("_")[0]] = line[1:end]
    return out

def host_of(url):
    m = re.match(r"([a-z+]+://(?:[^@/]*@)?[^/]+)", url)
    return m.group(1) if m else url

def sources_files_with(host):
    """Which apt source files mention this host over http."""
    hits = []
    for path in ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*.sources") \
                                          + glob.glob("/etc/apt/sources.list.d/*.list"):
        try:
            with open(path, errors="replace") as fh:
                if ("http://" + host.split("://", 1)[-1]) in fh.read(): hits.append(path)
        except OSError: pass
    return hits

def lists_state():
    """(never_downloaded, age_in_seconds) of apt's package lists."""
    rel = glob.glob("/var/lib/apt/lists/*_InRelease") + glob.glob("/var/lib/apt/lists/*_Release")
    if not rel or not glob.glob("/var/lib/apt/lists/*_Packages*"): return True, None
    # apt sets a Release file's mtime to the server's date: use when it was written (ctime)
    # and the stamps a successful update leaves (the window's helper, apt's daily job)
    marks = [os.path.getctime(f) for f in rel]
    for stamp in ("/var/lib/pro-updates/last-refresh", "/var/lib/apt/periodic/update-success-stamp",
                  "/var/lib/apt/periodic/update-stamp"):
        try: marks.append(os.path.getmtime(stamp))
        except OSError: pass
    return False, max(0, time.time() - max(marks))

def split_by_transport(pkgs):
    """(go_ahead, skipped) under the https-only policy: a package whose own download, or a
    dependency's, comes from a plaintext host is skipped and named; the rest go ahead.
    Returns go_ahead=None when what is left still needs a plaintext download."""
    if allow_plaintext() or not pkgs: return list(pkgs), {}
    def insecure(sel):
        uris = print_uris(["apt-get","-y","--print-uris","install","--only-upgrade","--"]+sel) if sel else {}
        return {p: host_of(u) for p,u in uris.items() if not is_secure(u)}
    bad = insecure(pkgs)
    skipped = {p: bad[p.split(":")[0]] for p in pkgs if p.split(":")[0] in bad}
    go = [p for p in pkgs if p not in skipped]
    if go and insecure(go):    # a plaintext dependency: find the packages that need it
        for p in list(go):
            own = insecure([p])
            if own: skipped[p] = ", ".join(sorted(set(own.values()))); go.remove(p)
        if go and insecure(go): return None, skipped
    return go, skipped

def free_fix(name):
    """Does this ESM-listed package come, or could it come, from another repository?

    pro security-status compares the installed version against the ESM index, and a
    community rebuild is deliberately versioned BELOW Ubuntu's ~esmN so that official
    updates always supersede it, so pro keeps listing such a package. Whether that
    other repository's build carries the fix is NOT checked; the output says so.

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
            if o.site and "esm.ubuntu.com" in o.site: return None   # the subscription archive
            if o.origin in ("Ubuntu", "") or not o.origin: continue  # the plain archive
            return o.origin
        return None

    src = third_party(inst)
    if src: return "installed", src
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

def our_holds():
    """Holds made by the GUI's "Hold back" (recorded by its helper)."""
    try:
        with open("/var/lib/pro-updates/holds") as fh: return {l.strip() for l in fh if l.strip()}
    except OSError: return set()

FLATHUB = "https://flathub.org/repo/flathub.flatpakrepo"
def ensure_flatpak():
    if not have("flatpak"):
        print(f"{Y}flatpak isn't installed — one-time `sudo apt install flatpak`.{X}")
        if not yes("Install flatpak now? [y/N]"): return False
        rc = sudo(APT_ENV + ["apt-get","install","-y","--no-remove"] + APT_OPTS + ["--","flatpak"])
        if rc: failed("installing flatpak", rc); return False
    remotes = run(["flatpak","remotes","--user","--columns=name"]).stdout.split()
    if "flathub" not in remotes:
        print(f"{D}Flathub will be added for your user only. Flatpak and GNOME Software then also check "
              f"flathub.org for updates to these apps.{X}")
        if not yes("Add Flathub for your user? [y/N]"): return False
        r = run(["flatpak","remote-add","--user","--if-not-exists","flathub",FLATHUB], timeout=120)
        if r.returncode: failed("adding Flathub", r.returncode); return False
    return True

# ---- section 1: ESM-only fixes + free remedies (curated + dynamic Flathub) ----
# Chromium is deliberately absent: a Flathub build replaces a distribution's
# hardware-tuned one (and cannot use a vendor GPU blob).
CURATED = {"vlc": "org.videolan.VLC"}

def load_pinned():
    """Packages the image owner has PINNED — never offer a Flathub/generic swap for
    them. Used to protect hardware-tuned builds (a generic Flathub build loses
    hardware video decode). Read from /etc/pro-updates/pinned and
    ~/.config/pro-updates/pinned; one package name per line, '#' comments. Only
    blocks the *remedy swap* — normal apt security upgrades from the pinned build's
    own repository still flow."""
    pinned = set()
    for p in ("/etc/pro-updates/pinned",
              os.path.expanduser("~/.config/pro-updates/pinned")):
        try:
            with open(p) as fh:
                for line in fh:
                    s = line.split("#", 1)[0].strip()
                    if s: pinned.add(s)
        except OSError:
            pass
    return pinned

PINNED = load_pinned()

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
        print(f"{Y}● Ubuntu Pro (ESM): not checked — the Ubuntu Pro client isn't installed, so universe "
              f"fixes published only through Ubuntu Pro can't be listed.{X}\n"); return
    r=run(["pro","security-status","--format","json"])
    try: data=json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        print(f"{R}● Ubuntu Pro (ESM): not checked — couldn't read `pro security-status`.{X}\n"); return
    gated=[p for p in data.get("packages",[]) if p.get("service_name") in ("esm-apps","esm-infra")]
    if not gated:
        print(f"{G}● Ubuntu Pro (ESM): no installed package has an ESM-only fix.{X}\n"); return

    bases, libs = {}, []
    for p in gated:
        nm=p["package"]
        if is_app_pkg(nm): bases.setdefault(app_base(nm),[]).append(nm)
        else: libs.append(nm)

    remedies={}
    for base in bases:
        if base in PINNED:            remedies[base]=("pinned", None)
        elif base in CURATED:         remedies[base]=("flatpak", CURATED[base])
        elif base in ("7zip","p7zip"):remedies[base]=("note","7-Zip 25.x — Debian / 7-zip.org (manual)")
        else:
            m=flatpak_match(base)
            remedies[base]=("suggest", m) if m else ("none", None)

    tot=sum(p.get("download_size",0) for p in gated)
    print(f"{O}● Ubuntu Pro (ESM)-only fixes: {len(gated)} pkg{X} {D}({human(tot)}) — remedies:{X}")
    for base in sorted(bases):
        kind,val=remedies[base]
        if   kind=="pinned":  print(f"  {Y}▸ {base}{X} → pinned by this system — not replaced {D}(its own repository's updates still apply){X}")
        elif kind=="flatpak": print(f"  {G}▸ {base}{X} → Flathub {val}  {D}(installs alongside; the .deb stays){X}")
        elif kind=="suggest": print(f"  {G}▸ {base}{X} → Flathub {val}?  {D}(name match — check it is the same app){X}")
        elif kind=="note":    print(f"  {Y}▸ {base}{X} → {val}")
        else:
            state, origin = free_fix(bases[base][0])
            if state == "installed":
                print(f"  {G}▸ {base}{X} → installed from {origin}, not from Ubuntu "
                      f"{D}— whether that build has the fix is not checked{X}")
            elif state == "available":
                print(f"  {G}▸ {base}{X} → newer version available from {origin} "
                      f"{D}— a plain `apt upgrade` installs it; whether it has the fix is not checked{X}")
            else:
                print(f"  {Y}▸ {base}{X} → no Flathub match {D}(rebuild from source, or Ubuntu Pro){X}")
    if libs:
        print(f"  {D}+ {len(libs)} librar{'y' if len(libs)==1 else 'ies'} — no app to swap: {', '.join(sorted(libs)[:6])}{'…' if len(libs)>6 else ''}{X}")
    print()
    if check: return

    curated=[(b,v) for b,(k,v) in remedies.items() if k=="flatpak" and v]
    guessed=[(b,v) for b,(k,v) in remedies.items() if k=="suggest" and v]
    installs=list(curated)
    if curated and not yes(f"Install {len(curated)} app(s) from Flathub ({', '.join(v for _,v in curated)})? [y/N]"):
        installs=[]
    for b,v in guessed:   # a name match is only a guess: ask one by one
        if yes(f"Install {v} from Flathub for '{b}'? (name match) [y/N]"): installs.append((b,v))
    if installs and ensure_flatpak():
        bad=[]
        for base,appid in installs:
            print(f"{D}flatpak install --user flathub {appid}{X}")
            rc=subprocess.run(["flatpak","install","--user","-y","flathub",appid]).returncode
            if rc: failed(f"flatpak install {appid}", rc); bad.append(appid)
        if not bad: print(f"{G}installed (sandboxed, per user).{X}")
        # SAFE removal ONLY for VLC (known-exclusive set); never for dynamic apps or shared libs
        if "vlc" in bases and "org.videolan.VLC" not in bad and any(a=="org.videolan.VLC" for _,a in installs):
            h=held()
            old=[p for p in bases["vlc"] if p not in h]   # NEVER remove a held package
            skipped=[p for p in bases["vlc"] if p in h]
            if skipped: print(f"{D}(skipping held: {', '.join(skipped)}){X}")
            if old:
                print(f"{Y}The VLC .debs are still installed.{X} {D}(no -y — apt shows the list & asks; no autoremove){X}")
                if yes(f"Remove {len(old)} VLC-only deb(s)? [y/N]"):
                    rc=sudo(["apt-get","remove"]+APT_OPTS+["--"]+old)
                    if rc: failed("removing the VLC .debs", rc)
        print()

# ---- section 2: flatpak updates ----
def flatpak_updates():
    """Pending updates per SCOPE, plus the scopes that couldn't be checked. A bare
    --columns=application list repeats the same id once per branch, and a
    --user-only update silently skips system installs."""
    out, errors = [], []
    for scope in ("user","system"):
        r=run(["flatpak","remote-ls","--"+scope,"--updates","--columns=ref"], timeout=90)
        if r.returncode:
            err=(r.stderr or "").strip().splitlines()
            errors.append(f"{scope}: {err[-1] if err else 'failed'}"[:160]); continue
        for line in r.stdout.splitlines():
            ref=line.split("\t")[0].strip()
            if ref.count("/")!=3: continue
            kind,appid,arch,branch=ref.split("/")
            out.append({"ref":ref,"scope":scope,"kind":kind,"appid":appid,"branch":branch})
    return out, errors

def flatpak_section(check):
    if not have("flatpak"): return
    if not run(["flatpak","remotes"]).stdout.strip():
        print(f"{G}● Flatpak: no remotes configured — nothing to update.{X}\n"); return
    ups, errors = flatpak_updates()
    for e in errors: print(f"{Y}● Flatpak: couldn't check ({e}) — offline?{X}")
    if not ups:
        if not errors: print(f"{G}● Flatpak apps: all up to date.{X}")
        print(); return
    n_user=sum(1 for u in ups if u["scope"]=="user")
    print(f"{O}● Flatpak updates available: {len(ups)}{X} {D}({n_user} user · {len(ups)-n_user} system){X}")
    for u in ups:
        print(f"    {u['appid']}  {u['branch']}  {D}[{u['scope']} · {'app' if u['kind']=='app' else 'runtime'}]{X}")
    print()
    if check: return
    if yes(f"Update {len(ups)} Flatpak ref(s) now? [y/N]"):
        ok=True
        for scope in ("user","system"):
            if any(u["scope"]==scope for u in ups):
                rc=subprocess.run(["flatpak","update","--"+scope,"-y"]).returncode
                if rc: failed(f"flatpak update ({scope})", rc); ok=False
        if ok: print(f"{G}flatpaks updated.{X}\n")

# ---- section 3: regular apt (at the end) ----
def vcmp(a, b):
    try:
        import apt_pkg; apt_pkg.init_system(); return apt_pkg.version_compare(a, b)
    except Exception:
        return (a > b) - (a < b)

def upgrade_plan():
    lines=run(["apt-get","-s","upgrade"]).stdout.splitlines()
    # A pin above 1000 can make apt "upgrade" to a LOWER version; `apt-get upgrade -y`
    # then refuses the whole run, so downgrades are listed apart and never applied.
    downs=[]
    for l in lines:
        m=re.match(r"Inst (\S+) \[([^\]]+)\] \((\S+)", l)
        if m and vcmp(m.group(3), m.group(2)) < 0: downs.append(m.groups())
    down={n for n,_,_ in downs}
    inst=[l.split()[1] for l in lines if l.startswith("Inst ") and l.split()[1] not in down]
    sec=sum(1 for l in lines if l.startswith("Inst ") and "security" in l.lower() and l.split()[1] not in down)
    # `upgrade` silently skips updates that need packages added or removed: name them
    full=run(["apt-get","-s","dist-upgrade"]).stdout.splitlines()
    # an upgrade's Inst line names the installed version in brackets; a new package's does not
    kept=sorted({l.split()[1] for l in full if re.match(r"Inst \S+ \[", l)} - set(inst) - down)
    return inst, sec, kept, downs

def apt_section(check):
    empty, age = lists_state()
    if empty or (age or 0) > 86400:
        when = "have never been downloaded" if empty else f"are {int(age // 3600)} h old"
        print(f"{Y}● The package lists {when} — the list below may be missing updates.{X}")
        if not check and yes("Download them first (sudo apt-get update)? [y/N]"):
            rc=sudo(APT_ENV+["apt-get","update"]+APT_OPTS)
            if rc: failed("apt-get update", rc)
    inst, sec, kept, downs = upgrade_plan()
    print(f"{O}● Regular apt updates: {len(inst)}{X} {D}({sec} security-flagged){X}")
    for p in inst: print(f"    {p}")
    if not inst: print(f"    {G}up to date.{X}" if not lists_state()[0] else f"    {Y}unknown — no package lists.{X}")
    if downs:
        print(f"  {Y}{len(downs)} pinned downgrade(s) not applied here (a pin above 1000 asks for an older version):{X} "
              f"{D}{'; '.join(f'{n} {a} → {b}' for n,a,b in downs)} — if wanted: "
              f"sudo apt-get install --allow-downgrades {' '.join(n for n,_,_ in downs)}{X}")
    if kept:
        print(f"  {D}{len(kept)} kept back (need packages added or removed — not done here; "
              f"`sudo apt full-upgrade` shows the plan): {', '.join(kept)}{X}")
    h=held(); ours=our_holds()
    sys_h=sorted(h-ours); our_h=sorted(h&ours)
    if sys_h:
        print(f"  {G}✓ {len(sys_h)} package(s) held by the system and respected — never upgraded:{X} {D}{', '.join(sys_h)}{X}")
    if our_h:
        print(f"  {Y}{len(our_h)} held with Pro Updates' \"Hold back\" (no updates, security ones included):{X} {D}{', '.join(our_h)}{X}")
    print(f"  {D}(list from current cache; applying runs `apt update` first){X}\n")
    if inst and allow_plaintext():
        uris=print_uris(["apt-get","-y","--print-uris","install","--only-upgrade","--"]+inst)
        bad=sorted({host_of(u) for u in uris.values() if not is_secure(u)})
        if bad: print(f"  {Y}⚠ plaintext source(s): {', '.join(bad)} — allowed by your policy{X}\n")
    go, skip = split_by_transport(inst)
    if skip:
        print(f"  {R}⛔ https-only policy: skipping {len(skip)} update(s) that need a plaintext source:{X}")
        for p,hst in sorted(skip.items()):
            print(f"  {D}   {p}  ({hst}, in {', '.join(f for h in hst.split(', ') for f in sources_files_with(h)) or '?'}){X}")
        print(f"  {D}   Switch those sources to https, or allow http in the GUI / allow_plaintext=yes in {CONFIG_PATH}{X}\n")
    if go is None:
        print(f"  {R}⛔ the remaining updates still need a plaintext source together — the apt step is skipped.{X}\n")
        return
    if check or not go: return
    if yes(f"Run the regular update now ({len(go)} package(s))? [y/N]"):
        rc=sudo(APT_ENV+["apt-get","update"]+APT_OPTS)
        if rc: failed("apt-get update", rc); return
        if skip or downs:     # name the packages: a plain upgrade would include what was left out
            rc=sudo(APT_ENV+["apt-get","install","--only-upgrade","-y","--no-remove"]+APT_OPTS+["--"]+go)
        else:
            rc=sudo(APT_ENV+["apt-get","upgrade","-y","--no-remove"]+APT_OPTS)
        if rc: failed("apt upgrade", rc)
        else: print(f"{G}apt upgrade done.{X}\n")

def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__.strip()); return 0
    check="--check" in sys.argv
    if os.geteuid()==0 and os.environ.get("SUDO_USER") and not check:
        print("Run pro-updates as your normal user: it asks for your password (sudo) when it needs root, "
              "and Flatpak installs and the settings belong to your account.")
        return 1
    print(f"\n{O}{B}  Pro Updates {__version__} {X}{D}— Ubuntu Pro (ESM) status · flatpaks · regular apt{X}\n")
    if not have("apt-get"): print("Debian/Ubuntu (apt) only."); return 1
    gated_section(check)    # 1
    flatpak_section(check)  # 2
    apt_section(check)      # 3 — the regular updates, at the end
    if check: print(f"{D}--check: audit only, nothing was changed.{X}")
    if FAILURES: print(f"{R}Finished with failures: {', '.join(FAILURES)}{X}"); return 1
    return 0

if __name__=="__main__":
    try: rc=main()
    except KeyboardInterrupt: print(); rc=130
    if "--check" not in sys.argv and "--help" not in sys.argv and sys.stdin.isatty():
        try: input(f"\n{D}Press Enter to close…{X}")
        except (EOFError,KeyboardInterrupt): pass
    sys.exit(rc)
