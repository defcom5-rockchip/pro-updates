#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Pro Updates (GUI) — a GTK3 window for the updates on an apt-based system.

Sections:
  Package sources   — https-only or http-allowed policy; when the package lists
                      were last downloaded
  Vendor sources    — which repository each browser, mail client and editor
                      would update from
  ①  Ubuntu Pro (ESM) — universe fixes Canonical publishes only to Ubuntu Pro
                      subscribers, and any free remedy (a Flathub build, a newer
                      version in another configured repository). Needs the Ubuntu
                      Pro client; without it this section says "not checked".
  ②  Flatpak apps   — updates for the Flatpak apps already installed
  ③  Regular apt    — the normal apt upgrade; held packages are never upgraded
  ④  Builds         — packages this desktop builds from source (one build.json
                      per project); hidden when there are none

Root work goes through one helper (/usr/libexec/pro-updates/pro-updates-helper)
started with pkexec: fixed commands, checked arguments, no shell. apt never
removes a package from here (--no-remove). Flatpak installs are per user.

Not affiliated with or endorsed by Canonical. Ubuntu and Ubuntu Pro are
trademarks of Canonical Ltd.
"""
# Copyright (C) 2026 defcom5-rockchip
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version. See <https://www.gnu.org/licenses/> for the full text.

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk
import configparser, glob, json, os, re, shutil, socket, subprocess, threading, time, traceback

__version__ = "1.5.0"

def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def resolve(host):
    """Every A/AAAA record behind a mirror hostname — archive.ubuntu.com is a
    round-robin, so the box may talk to any of them."""
    try: infos = socket.getaddrinfo(host, None)
    except OSError as e: return [f"unresolved ({e.strerror or e})"]
    ips, seen = [], set()
    for _fam, _t, _p, _c, sa in infos:
        if sa[0] not in seen: seen.add(sa[0]); ips.append(sa[0])
    return ips

def apt_uri_hosts(pkgs):
    """Ask apt for the exact URLs it would fetch, grouped by host: (files, bytes)."""
    if not pkgs: return {}
    r = run(["apt-get", "-y", "--print-uris", "install", "--only-upgrade"] + pkgs)
    agg = {}
    for line in r.stdout.splitlines():
        if not line.startswith("'"): continue
        try: url = line[1:line.index("'", 1)]
        except ValueError: continue
        m = re.match(r"([a-z+]+)://(?:[^@/]*@)?([^/]+)", url)
        if not m: continue
        parts = line.rsplit(" ", 2)
        try: size = int(parts[-2])
        except (ValueError, IndexError): size = 0
        a = agg.setdefault(f"{m.group(1)}://{m.group(2)}", [0, 0])
        a[0] += 1; a[1] += size
    return agg

# Transport policy. file:/cdrom:/copy: are local media, nothing to intercept.
SECURE = ("https://", "file:", "cdrom:", "copy:", "mirror+file:")
def is_secure(url): return url.startswith(SECURE)

# Two supported stances, persisted in ~/.config/pro-updates/config.ini and shared
# with the CLI:
#   strict  - refuse plaintext. Right for a laptop on networks you do not control.
#   relaxed - allow http. Required for a LAN mirror or a caching proxy such as
#             apt-cacher-ng, which is plain HTTP by design and cannot be https.
CONFIG_DIR = os.path.expanduser("~/.config/pro-updates")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.ini")

def load_allow_plaintext():
    cp = configparser.ConfigParser()
    try: cp.read(CONFIG_PATH)
    except Exception: return False
    return cp.getboolean("policy", "allow_plaintext", fallback=False)

def save_allow_plaintext(value):
    cp = configparser.ConfigParser()
    try: cp.read(CONFIG_PATH)
    except Exception: pass
    if not cp.has_section("policy"): cp.add_section("policy")
    cp.set("policy", "allow_plaintext", "yes" if value else "no")
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as fh: cp.write(fh)

ALLOW_PLAINTEXT = load_allow_plaintext()

def blocked(hosts):
    """Plaintext hosts that the current policy refuses. Empty when relaxed."""
    if ALLOW_PLAINTEXT: return []
    return sorted(h for h in hosts if not is_secure(h))

def plaintext(hosts):
    """Plaintext hosts, whatever the policy — for display."""
    return sorted(h for h in hosts if not is_secure(h))

def https_works(host):
    """Never rewrite a source to https without checking the mirror serves it."""
    try:
        import urllib.request
        req = urllib.request.Request("https://" + host + "/", method="HEAD")
        with urllib.request.urlopen(req, timeout=12) as r: return r.status < 500
    except Exception: return False

def sources_files_with(host):
    """Which apt source files mention this host over http."""
    import glob
    hits = []
    for path in ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*.sources") \
                                          + glob.glob("/etc/apt/sources.list.d/*.list"):
        try:
            if ("http://" + host.split("://", 1)[-1]) in open(path, errors="replace").read():
                hits.append(path)
        except Exception: pass
    return hits

def source_lines(pkgs, flatpak_rows, gated_n):
    """Where the bytes actually come from — host, resolved IPs, count and size."""
    out = []
    for host, (n, size) in sorted(apt_uri_hosts(pkgs).items()):
        warn = ("" if is_secure(host) else
                ("   ⚠ plaintext — allowed by your policy" if ALLOW_PLAINTEXT
                 else "   ⛔ PLAINTEXT — blocked by https-only policy"))
        out.append(f"  apt      {host}   {n} file(s) · {human(size)}{warn}")
        out.append(f"           → {', '.join(resolve(host.split('://', 1)[1]))}")
    if flatpak_rows:
        urls = {}
        for line in run(["flatpak", "remotes", "--columns=name,url"]).stdout.splitlines():
            bits = line.split("\t")
            if len(bits) >= 2: urls[bits[0].strip()] = bits[1].strip()
        for origin in sorted({f.get("origin") or "flathub" for f in flatpak_rows}):
            url = urls.get(origin, "?")
            host = re.sub(r"^[a-z]+://", "", url).split("/")[0]
            n_u = sum(1 for f in flatpak_rows if f["scope"] == "user")
            out.append(f"  flatpak  {url}   {len(flatpak_rows)} ref(s) "
                       f"(user {n_u} · system {len(flatpak_rows) - n_u})  [{origin}]")
            if host and host != "?": out.append(f"           → {', '.join(resolve(host))}")
    if gated_n:
        out.append(f"  esm      https://esm.ubuntu.com   {gated_n} ESM-only pkg(s) — "
                   f"not fetched (Ubuntu Pro subscription)")
        out.append(f"           → {', '.join(resolve('esm.ubuntu.com'))}")
    return out

class _Failed:
    def __init__(self, rc, err): self.returncode, self.stdout, self.stderr = rc, "", err

# Output is parsed, so every command runs in the C locale; nothing may hang the scan.
C_ENV = dict(os.environ, LC_ALL="C")
def run(cmd, timeout=120):
    try: return subprocess.run(cmd, capture_output=True, text=True, env=C_ENV, timeout=timeout)
    except FileNotFoundError: return _Failed(127, f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired: return _Failed(124, f"{cmd[0]}: timed out after {timeout} s")
def have(c): return shutil.which(c) is not None

# Root work: one helper with fixed commands, started through pkexec (polkit shows the
# policy's message). Running from a source tree uses the copy next to this file.
HELPER = "/usr/libexec/pro-updates/pro-updates-helper"
if not os.path.exists(HELPER):
    HELPER = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pro-updates-helper")
def helper(*args): return ["pkexec", HELPER] + list(args)

# Flathub builds of gated apps. Chromium is deliberately absent: a Flathub build
# replaces a distribution's hardware-tuned one (and cannot use a vendor GPU blob).
CURATED = {"vlc": "org.videolan.VLC"}

def load_pinned():
    """Packages pinned by the image owner — never offered a Flathub/generic swap
    (protects hardware-tuned builds, where a generic replacement loses hardware
    video decode). /etc/pro-updates/pinned and ~/.config/pro-updates/pinned, one
    name per line, '#' comments. Only blocks the swap — normal apt security
    upgrades from the build's own repository still flow."""
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
FLATHUB = "https://flathub.org/repo/flathub.flatpakrepo"

def lists_state():
    """(never_downloaded, age_in_seconds) of apt's package lists. A freshly built
    image ships with empty lists: until the first `apt update`, apt knows of no
    updates and no repository for anything, which must not read as "up to date"."""
    rel = glob.glob("/var/lib/apt/lists/*_InRelease") + glob.glob("/var/lib/apt/lists/*_Release")
    if not rel or not glob.glob("/var/lib/apt/lists/*_Packages*"): return True, None
    return False, max(0, time.time() - last_refresh(rel))

def last_refresh(rel):
    """When the lists were last downloaded. apt sets each Release file's mtime to the
    server's date, so use the time the file was written (ctime) and the stamps that a
    successful update leaves: the helper's own, and apt's daily job's."""
    marks = [os.path.getctime(f) for f in rel]
    for stamp in ("/var/lib/pro-updates/last-refresh", "/var/lib/apt/periodic/update-success-stamp",
                  "/var/lib/apt/periodic/update-stamp"):
        try: marks.append(os.path.getmtime(stamp))
        except OSError: pass
    return max(marks)

def age_text(sec):
    if sec is None: return "never"
    if sec < 3600: return f"{int(sec // 60)} min ago"
    if sec < 2 * 86400: return f"{int(sec // 3600)} h ago"
    return f"{int(sec // 86400)} days ago"

# Holds made with "Hold back" are recorded by the helper, so they can be released
# again without touching the holds the system itself set.
OUR_HOLDS = "/var/lib/pro-updates/holds"
def our_holds():
    try:
        with open(OUR_HOLDS) as fh: return sorted({l.strip() for l in fh if l.strip()})
    except OSError: return []

def is_app_pkg(n):
    n = n.lower()
    if n.startswith(("lib", "python3-", "gir1.2-")): return False
    if any(n.endswith(s) for s in ("-common", "-data", "-doc", "-dev", "-dbg", "-l10n")): return False
    return True
def app_base(n): return n.lower().split("-")[0]
def flatpak_match(base):
    # strict: final id segment must EQUAL base, and skip runtimes/SDK/extensions
    # (loose substring matched Ghidra for 'gh' — never again)
    if not have("flatpak") or len(base) < 3: return None
    for line in run(["flatpak", "search", "--columns=application", "--", base]).stdout.splitlines():
        a = line.strip(); low = a.lower()
        if not a or "." not in a: continue
        if any(x in low for x in (".platform", ".sdk", ".locale", ".debug", ".sources", "baseapp")): continue
        if low.rsplit(".", 1)[-1] == base: return a
    return None
def free_fix(name):
    """Does this ESM-listed package come, or could it come, from another repository?

    pro security-status compares the installed version against the ESM index, and a
    community rebuild is deliberately versioned BELOW Ubuntu's ~esmN so that official
    updates always supersede it, so pro keeps listing such a package. Whether that
    other repository's build carries the fix is NOT checked here; the GUI says so.

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
    if src: return "installed", src                    # already running a free fix
    best = None
    for v in pkg.versions:
        o = third_party(v)
        if o and apt_pkg.version_compare(v.version, inst.version) > 0:
            if best is None or apt_pkg.version_compare(v.version, best[0]) > 0:
                best = (v.version, o)
    if best: return "available", best[1]
    return None, None

def held(): return sorted(set(run(["apt-mark", "showhold"]).stdout.split()))

def is_installed(pkg):
    """dpkg-query -W also succeeds for packages dpkg merely remembers (state 'un', 'rc')."""
    r = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", pkg])
    return r.returncode == 0 and r.stdout.startswith(("ii", "hi"))

# ── vendor sources: browsers/mail/editors must come from their vendors, never from Armbian's rebranded mirror ──
VENDOR_APPS = ["firefox", "google-chrome-stable", "chromium", "thunderbird", "code", "codium"]
VENDOR_NAMES = {"ppa.launchpadcontent.net/mozillateam": "Mozilla Team", "ppa.launchpadcontent.net/xtradeb": "xtradeb",
                "dl.google.com": "Google", "packages.microsoft.com": "Microsoft", "download.vscodium.com": "vscodium.com"}
BAD_HOSTS = ("apt.armbian.com",)

def candidate_origin(pkg):
    """(installed, candidate, origin_host, state) from apt-cache policy; state: ok | armbian | snap | none | missing."""
    out = run(["apt-cache", "policy", pkg]).stdout.splitlines()
    if not out or not any(l.startswith("  Candidate:") for l in out): return ("", "", "", "missing")
    inst = next((l.split(":", 1)[1].strip() for l in out if l.startswith("  Installed:")), "")
    cand = next((l.split(":", 1)[1].strip() for l in out if l.startswith("  Candidate:")), "")
    if cand in ("", "(none)"): return (inst, cand, "", "none")
    host, hit = "", False
    ver_line = re.compile(r"^\s*(\*\*\*\s+)?(\S+)\s+-?\d+$")      # ' *** 1.2-3 1001' / '     1.2-3 500'
    for l in out:
        m = ver_line.match(l)
        if m:
            if hit: break                                    # next version block: candidate had no URL
            hit = (m.group(2) == cand); continue
        if hit:
            u = re.search(r"https?://([^ ]+)", l)
            if u: host = u.group(1).split(" ")[0].rstrip("/"); break
    state = ("armbian" if any(b in host for b in BAD_HOSTS) else "snap" if "snap" in cand
             else "nosrc" if not host else "ok")                 # nosrc: only dpkg/status knows it — no repo will ever update it
    return (inst, cand, host, state)

def vendor_label(host):
    for k, v in VENDOR_NAMES.items():
        if k in host: return v
    return host.split("/")[0] if host else "?"

# Repair: the distribution ships its own vendor pin file and the helper copies it
# into place unchanged (one file for the image recipe and this button, never two).
VENDOR_PINS = "/usr/share/pi-desktop/apt/00-pidesktop-browsers"
VENDOR_PINS_DEST = "/etc/apt/preferences.d/00-pidesktop-browsers"
def pins_changed():
    """True when the distribution ships a pin file and the one in use differs."""
    if not os.path.isfile(VENDOR_PINS): return False
    try:
        with open(VENDOR_PINS, "rb") as a, open(VENDOR_PINS_DEST, "rb") as b: return a.read() != b.read()
    except OSError: return True

# ── ④ Pi-Desktop builds ──────────────────────────────────────────────────────
# One build.json per project. Searched in order; later duplicates (same package) win.
# Extra folders (a project share, say) come from PROUPDATES_BUILD_DIRS, colon-separated.
BUILD_DIRS = [os.path.expanduser("~/.config/pro-updates/builds"), "/usr/share/pro-updates/builds"] + \
             [d for d in os.environ.get("PROUPDATES_BUILD_DIRS", "").split(":") if d]

def load_builds():
    import glob
    found = {}
    for d in BUILD_DIRS:
        for p in sorted(glob.glob(os.path.join(d, "*.json")) + glob.glob(os.path.join(d, "*", "build.json"))):
            m = None
            try:
                with open(p) as fh: m = json.load(fh)
                if not isinstance(m, dict): raise ValueError("not a JSON object")
                for k, typ in (("source", dict), ("build", dict), ("upstream", dict), ("notes", str),
                               ("package", str), ("artifact", str), ("workdir", str), ("name", str)):
                    if k in m and not isinstance(m[k], typ):
                        raise ValueError(f'"{k}" must be ' + ("an object" if typ is dict else "text"))
                for parent, keys in (("source", ("url", "file", "sha256")), ("build", ("script", "deps", "note")),
                                     ("upstream", ("kind", "repo", "version", "tag_prefix"))):
                    for k in keys:
                        if k in m.get(parent, {}) and not isinstance(m[parent][k], str):
                            raise ValueError(f'"{parent}.{k}" must be text')
                if not isinstance(m.get("build", {}).get("args", []), list):
                    raise ValueError('"build.args" must be a list')
                if not isinstance(m.get("build", {}).get("minutes", 0), (int, float)):
                    raise ValueError('"build.minutes" must be a number')
                m["name"] = str(m.get("name") or m.get("package") or os.path.basename(os.path.dirname(p)))
                m["_dir"], m["_file"] = os.path.dirname(p), p
                found[m.get("package") or p] = m
            except Exception as e:
                nm = m.get("name") if isinstance(m, dict) and isinstance(m.get("name"), str) and m.get("name") else \
                     os.path.basename(os.path.dirname(p))
                found[p] = {"name": nm, "package": "", "_error": str(e), "_dir": os.path.dirname(p), "_file": p}
    return list(found.values())

def _expand(m, s, version=None):
    if not s: return s
    s = s.replace("{workdir}", os.path.expanduser(m.get("workdir", "~/Development/pro-updates-builds")))
    if version: s = s.replace("{version}", version)
    return os.path.expanduser(s)

def _rel(m, p):
    p = _expand(m, p)
    return p if (not p or os.path.isabs(p)) else os.path.join(m["_dir"], p)

def installed_version(pkg):
    if not pkg: return ""
    r = run(["dpkg-query", "-W", "-f=${Version}", pkg])
    return r.stdout.strip() if r.returncode == 0 else ""

def upstream_version(m):
    u = m.get("upstream")
    if not isinstance(u, dict): return ""
    k = u.get("kind")
    if k == "static": return u.get("version", "")
    if k == "github-release":
        try:
            import urllib.request
            req = urllib.request.Request(f"https://api.github.com/repos/{u['repo']}/releases/latest",
                                         headers={"User-Agent": "pro-updates", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=8) as r: tag = json.load(r).get("tag_name", "")
            pre = u.get("tag_prefix", "")
            return tag[len(pre):] if pre and tag.startswith(pre) else tag
        except Exception as e:
            return f"?  ({type(e).__name__})"
    return ""

def upstream_part(debver):
    """'9:157.0+build1-0ubuntu0.26.04.1~mt1+pd1' -> '157.0+build1' (what upstream calls it)."""
    v = debver.split(":", 1)[-1]
    return v.rsplit("-", 1)[0] if "-" in v else v

def vcmp(a, b):
    try:
        import apt_pkg; apt_pkg.init_system(); return apt_pkg.version_compare(a, b)
    except Exception:
        return (a > b) - (a < b)

def artifact_for(m):
    import glob
    pat = _rel(m, m.get("artifact", ""))
    hits = sorted(glob.glob(pat), key=os.path.getmtime) if pat else []
    return hits[-1] if hits else ""

def deb_version(path):
    return run(["dpkg-deb", "-f", path, "Version"]).stdout.strip() if path else ""

def build_row(m):
    inst = installed_version(m.get("package", ""))
    up = upstream_version(m)
    static = isinstance(m.get("upstream"), dict) and m["upstream"].get("kind") == "static"
    newer = bool(up) and not up.startswith("?") and bool(inst) and \
            (vcmp(up, inst) > 0 if static else vcmp(up, upstream_part(inst)) > 0)
    art = artifact_for(m)
    return {"m": m, "installed": inst, "upstream": up, "newer": newer,
            "artifact": art, "artifact_version": deb_version(art)}

def build_rows():
    rows = []
    for m in load_builds():
        if "_error" in m:
            rows.append({"m": m, "error": m["_error"]}); continue
        try: rows.append(build_row(m))
        except Exception as e: rows.append({"m": m, "error": f"{type(e).__name__}: {e}"})
    return rows

def dep_graph(pkgs):
    """Which packages in this upgrade set DRAG IN which others.

    An edge master -> child means: upgrading `master` requires a version of `child`
    newer than the one installed, so unticking the child on its own is a lie — apt
    upgrades it anyway. The GUI nests children under their master and lets the
    master own the tick. Needs python3-apt; without it we just return no edges and
    the list stays flat (old behaviour)."""
    forces, forced_by = {}, {}
    try:
        import apt, apt_pkg
    except ImportError:
        return forces, forced_by
    try: cache = apt.Cache()
    except Exception: return forces, forced_by
    S = set(pkgs)
    for name in pkgs:
        try: cand = cache[name].candidate
        except Exception: continue
        if cand is None: continue
        for grp in cand.get_dependencies("Depends", "PreDepends"):
            if len(grp) != 1: continue          # OR-group: an alternative may satisfy it
            dep = grp[0]
            if dep.name not in S or dep.name == name: continue
            try: inst = cache[dep.name].installed
            except Exception: continue
            if not (dep.version and inst): continue
            if apt_pkg.version_compare(dep.version, inst.version) > 0:
                forces.setdefault(name, set()).add(dep.name)
                forced_by.setdefault(dep.name, set()).add(name)
    return forces, forced_by

def downgrades(sim_lines):
    """[(name, installed, candidate)] for `Inst` lines whose candidate is older."""
    out = []
    for l in sim_lines:
        m = re.match(r"Inst (\S+) \[([^\]]+)\] \((\S+)", l)
        if m and vcmp(m.group(3), m.group(2)) < 0: out.append(m.groups())
    return out

def gated_scan(d):
    """Section ①. Without the Ubuntu Pro client nothing can be known about ESM-only
    fixes, and saying "nothing gated" would be false reassurance: say "not checked"."""
    if not have("pro"):
        d["gated_status"] = "no-pro"; return
    r = run(["pro", "security-status", "--format", "json"])
    try: j = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        d["gated_status"] = "error"; d["gated_error"] = (r.stderr or "no output").strip()[:200]; return
    d["gated_status"] = "checked"
    bases = {}
    for p in [p for p in j.get("packages", []) if p.get("service_name") in ("esm-apps", "esm-infra")]:
        nm = p["package"]
        if is_app_pkg(nm): bases.setdefault(app_base(nm), []).append(nm)
        else: d["libs"].append(nm)
    for base, pkgs in sorted(bases.items()):
        if base in PINNED:              d["gated"].append({"base": base, "pkgs": pkgs, "kind": "pinned", "appid": None})
        elif base in CURATED:           d["gated"].append({"base": base, "pkgs": pkgs, "kind": "flatpak", "appid": CURATED[base]})
        elif base in ("7zip", "p7zip"): d["gated"].append({"base": base, "pkgs": pkgs, "kind": "note", "appid": None})
        else:
            m = flatpak_match(base)
            state, origin = (None, None) if m else free_fix(pkgs[0])
            # a name-guessed Flathub match is a suggestion: shown unticked, never pre-selected
            d["gated"].append({"base": base, "pkgs": pkgs, "appid": m,
                               "kind": "suggest" if m else ("free" if state else "none"),
                               "free_state": state, "free_origin": origin})

def gather():
    d = {"gated": [], "libs": [], "apt": [], "apt_sec": 0, "flatpak": [], "flatpak_errors": [],
         "held": held(), "our_holds": our_holds()}
    d["lists_empty"], d["lists_age"] = lists_state()
    gated_scan(d)
    lines = run(["apt-get", "-s", "upgrade"]).stdout.splitlines()
    # A pin above 1000 can make apt "upgrade" to a LOWER version (a vendor build that
    # replaces a rebuild with a higher epoch). `apt-get upgrade -y` then refuses the
    # whole run, security fixes included, so downgrades are listed apart, never applied.
    d["downgrades"] = downgrades(lines)
    down = {n for n, _, _ in d["downgrades"]}
    d["apt"] = [l.split()[1] for l in lines if l.startswith("Inst ") and l.split()[1] not in down]
    d["apt_sec_names"] = {l.split()[1] for l in lines if l.startswith("Inst ") and "security" in l.lower()} - down
    d["apt_sec"] = len(d["apt_sec_names"])
    # `upgrade` never installs or removes packages, so it silently skips updates that
    # need either; name them rather than claim the system is up to date.
    full = run(["apt-get", "-s", "dist-upgrade"]).stdout.splitlines()
    # an upgrade's Inst line names the installed version in brackets; a new package's does not
    d["kept_back"] = sorted({l.split()[1] for l in full if re.match(r"Inst \S+ \[", l)} - set(d["apt"]) - down)
    d["forces"], d["forced_by"] = dep_graph(d["apt"])
    d["have_flatpak"] = have("flatpak")
    d["flatpak_remotes"] = []
    if d["have_flatpak"]:
        # (name, options) — options says "user" or "system"
        d["flatpak_remotes"] = [tuple((l.split("\t") + [""])[:2]) for l in
                                run(["flatpak", "remotes", "--columns=name,options"]).stdout.splitlines() if l.strip()]
        # per-SCOPE and per-REF: a bare `--columns=application` list shows the same id
        # several times (one per branch) with no way to tell the rows apart, and
        # updating only --user silently skips everything installed system-wide.
        for scope in ("user", "system"):
            r = run(["flatpak", "remote-ls", "--" + scope, "--updates", "--columns=ref"], timeout=90)
            if r.returncode:
                err = (r.stderr or "").strip().splitlines()
                d["flatpak_errors"].append(f"{scope}: {err[-1] if err else 'failed'}"[:160])
                continue
            for line in r.stdout.splitlines():
                ref = line.split("\t")[0].strip()
                if ref.count("/") != 3: continue
                kind, appid, arch, branch = ref.split("/")
                d["flatpak"].append({"ref": ref, "scope": scope, "kind": kind,
                                     "appid": appid, "arch": arch, "branch": branch})
    d["builds"] = build_rows()
    d["vendors"] = [(p, *candidate_origin(p)) for p in VENDOR_APPS if is_installed(p)]
    # "vendors only" is a policy, and a system declares it by shipping the vendor pin
    # file. Elsewhere (stock Ubuntu: Firefox is a snap) only Armbian's mirror copies count.
    # With no lists downloaded every package reads "no source" — that is not a fault yet.
    d["vendor_policy"] = os.path.isfile(VENDOR_PINS)
    bad_states = (("armbian",) if not d["vendor_policy"] else
                  ("armbian", "snap", "none") if d["lists_empty"] else ("armbian", "snap", "none", "nosrc"))
    d["vendors_bad"] = [v for v in d["vendors"] if v[4] in bad_states]
    d["pins_changed"] = pins_changed()
    d["sources"] = source_lines(d["apt"], d["flatpak"], len(d["libs"]) + sum(len(g["pkgs"]) for g in d["gated"]))
    hosts = apt_uri_hosts(d["apt"])
    d["plaintext"] = plaintext(hosts)
    d["insecure"] = blocked(hosts)
    return d

def split_by_transport(pkgs):
    """(go_ahead, skipped, pulled) for an apt selection under the https-only policy.
    A selected package whose own download, or a dependency's, comes from a plaintext
    host is skipped and named; the rest go ahead. Only if what is left still needs a
    plaintext download (packages that need each other) is anything returned in
    `pulled`, and then nothing should run."""
    if ALLOW_PLAINTEXT or not pkgs: return list(pkgs), {}, {}
    def insecure(sel):
        out = {}
        for line in run(["apt-get", "-y", "--print-uris", "install", "--only-upgrade", "--"] + sel).stdout.splitlines():
            if not line.startswith("'"): continue
            try: url = line[1:line.index("'", 1)]
            except ValueError: continue
            if is_secure(url): continue
            m = re.match(r"([a-z+]+://(?:[^@/]*@)?[^/]+)", url)
            fname = line[line.index("'", 1) + 1:].split()[0] if line[line.index("'", 1) + 1:].split() else ""
            out[fname.split("_")[0]] = m.group(1) if m else url
        return out
    base = lambda p: p.split(":")[0]
    bad = insecure(pkgs)
    if not bad: return list(pkgs), {}, {}
    skipped = {p: bad[base(p)] for p in pkgs if base(p) in bad}
    go = [p for p in pkgs if p not in skipped]
    pulled = insecure(go) if go else {}
    if pulled:          # a dependency from a plaintext host: find the packages that need it, one by one
        for p in list(go):
            own = insecure([p])
            if own:
                skipped[p] = ", ".join(sorted(set(own.values()))); go.remove(p)
        pulled = insecure(go) if go else {}
    return go, skipped, pulled

class App(Gtk.Window):
    def __init__(self):
        super().__init__(title="Pro Updates")
        self.set_default_size(680, 740)
        self._css()
        hb = Gtk.HeaderBar(title="Pro Updates"); hb.set_subtitle(f"apt · Flatpak · update sources · v{__version__}")
        hb.set_show_close_button(True); self.set_titlebar(hb)
        self.refresh_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        self.refresh_btn.set_tooltip_text("Scan again (reads the current package lists; changes nothing)")
        self.refresh_btn.connect("clicked", lambda *_: self.scan()); hb.pack_start(self.refresh_btn)
        ab = Gtk.Button.new_from_icon_name("help-about-symbolic", Gtk.IconSize.BUTTON)
        ab.set_tooltip_text("About Pro Updates"); ab.connect("clicked", self.on_about); hb.pack_end(ab)
        self.busy = False          # one job at a time: every action is greyed out while one runs
        self._scanning = False
        self.connect("delete-event", self._on_close)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL); self.add(outer)
        self.summary = Gtk.Label(xalign=0); self.summary.get_style_context().add_class("summary")
        for m in ("set_margin_top", "set_margin_start", "set_margin_end"): getattr(self.summary, m)(12)
        outer.pack_start(self.summary, False, False, 0)

        sc = Gtk.ScrolledWindow(); sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for m in ("set_margin_start", "set_margin_end", "set_margin_top"): getattr(self.body, m)(12)
        sc.add(self.body)

        self.logview = Gtk.TextView(editable=False, monospace=True)
        lsc = Gtk.ScrolledWindow(); lsc.set_size_request(-1, 90); lsc.add(self.logview)

        # draggable divider — grab it to expand the output pane
        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.pack1(sc, True, False)     # sections (top): resize, don't shrink away
        paned.pack2(lsc, True, True)     # output (bottom): resize + shrink → drag to grow
        paned.set_position(430)
        outer.pack_start(paned, True, True, 0)

        bb = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        for m in ("set_margin_start", "set_margin_end", "set_margin_top", "set_margin_bottom"): getattr(bb, m)(12)
        # only shown when apt says it will re-add something you unticked: apt-mark hold
        # is the mechanism that actually makes an untick stick, and it persists.
        self.hold_btn = Gtk.Button(label="Hold back")
        self.hold_btn.set_tooltip_text("apt-mark hold: apt, including the automatic security updates, will not upgrade "
                                       "these until the hold is released (section ③ offers that)")
        self.hold_btn.connect("clicked", self.on_hold)
        self.hold_btn.set_no_show_all(True); self.hold_btn.hide()
        bb.pack_start(self.hold_btn, False, False, 0)
        self._pending_hold = []
        self.apply_btn = Gtk.Button(label="Apply Selected")
        self.apply_btn.get_style_context().add_class("suggested-action")
        self.apply_btn.connect("clicked", self.on_apply)
        bb.pack_start(self.apply_btn, False, False, 0)
        outer.pack_start(bb, False, False, 0)

        self.checks = {"gated": [], "flatpak": [], "apt": []}
        self._forces, self._forced_by = {}, {}
        self.scan()

    def _on_close(self, *_):
        """Closing while a job runs: apt and the helper finish on their own (their output
        goes to /var/log/pro-updates.log), but a Flatpak update or a build started from
        here may be cut off. Say so, and wait unless told otherwise."""
        if not self.busy: return False
        dlg = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
                                buttons=Gtk.ButtonsType.NONE, text="A job is still running")
        dlg.format_secondary_text("apt updates finish on their own if you close the window (their output goes to "
                                  "/var/log/pro-updates.log), but a Flatpak update or a build started here may be "
                                  "cut off. Wait until the output says done.")
        dlg.add_buttons("Close anyway", Gtk.ResponseType.CLOSE, "Wait", Gtk.ResponseType.CANCEL)
        dlg.set_default_response(Gtk.ResponseType.CANCEL)
        close = dlg.run() == Gtk.ResponseType.CLOSE
        dlg.destroy()
        return not close

    def on_about(self, *_):
        dlg = Gtk.AboutDialog(transient_for=self, modal=True)
        dlg.set_program_name("Pro Updates"); dlg.set_version(__version__)
        dlg.set_logo_icon_name("pro-updates")
        dlg.set_comments("See and apply apt and Flatpak updates; shows each browser's update source "
                         "and the held packages.\n\nNot affiliated with or endorsed by Canonical. "
                         "Ubuntu and Ubuntu Pro are trademarks of Canonical Ltd.")
        dlg.set_website("https://github.com/defcom5-rockchip/pro-updates")
        dlg.set_copyright("© 2026 defcom5-rockchip"); dlg.set_license_type(Gtk.License.GPL_3_0)
        dlg.run(); dlg.destroy()

    # ── one job at a time ────────────────────────────────────────────────────
    def _set_busy(self, busy):
        self.busy = busy
        self.body.set_sensitive(not busy)
        self.refresh_btn.set_sensitive(not busy)
        self.hold_btn.set_sensitive(not busy)
        if busy: self.apply_btn.set_sensitive(False)
        else: self._refresh_apply()

    def _job(self, fn):
        """Run fn in a thread as THE job: everything is greyed out until it ends,
        a traceback lands in the output pane, and a rescan follows."""
        if self.busy or self._scanning:
            self.logln("busy — wait for the current job to finish"); return
        self._set_busy(True)
        def guarded():
            try: fn()
            except Exception:
                self.logln("💥 internal error — the job stopped here:")
                for ln in traceback.format_exc().rstrip().splitlines(): self.logln("   " + ln)
            finally:
                GLib.idle_add(self._job_done)
        threading.Thread(target=guarded, daemon=True).start()

    def _job_done(self):
        self.busy = False
        self.scan()

    def step(self, label, cmd):
        """One command of a job; True when it worked. Reports failures plainly."""
        rc = self.stream(cmd)
        if rc == 0: return True
        # pkexec(1): 126 = the dialog was dismissed; 127 = not authorised or pkexec failed
        why = ({126: "the password dialog was dismissed", 127: "not authorised, or pkexec failed"}.get(rc, f"exit code {rc}")
               if cmd[:1] == ["pkexec"] else f"exit code {rc}")
        self.logln(f"❌ {label} failed — {why}")
        return False

    def _css(self):
        # follow GNOME's dark/light preference: GTK3 apps don't pick up color-scheme on their own
        try:
            from gi.repository import Gio
            scheme = Gio.Settings.new("org.gnome.desktop.interface").get_string("color-scheme")
            st = Gtk.Settings.get_default()
            if scheme == "prefer-dark":
                # GTK 3.24.5x renders the theme NAME "Adwaita-dark" as light (no such theme dir; the builtin fallback is
                # the light variant). "Adwaita" + prefer-dark is the combination that actually produces the dark Adwaita.
                if st.get_property("gtk-theme-name") in ("Adwaita-dark", "Adwaita"): st.set_property("gtk-theme-name", "Adwaita")
                st.set_property("gtk-application-prefer-dark-theme", True)
        except Exception: pass
        css = b".summary{font-size:15px;font-weight:bold;}"
        p = Gtk.CssProvider(); p.load_from_data(css)
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), p, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def logln(self, s):
        def _():
            b = self.logview.get_buffer(); b.insert(b.get_end_iter(), s + "\n")
            self.logview.scroll_to_mark(b.get_insert(), 0, False, 0, 0)
        GLib.idle_add(_)

    def _section(self, title):
        f = Gtk.Frame(label=title)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        for m in ("set_margin_start", "set_margin_end", "set_margin_top", "set_margin_bottom"): getattr(box, m)(8)
        f.add(box); self.body.pack_start(f, False, False, 0); return box

    def _checklist(self, parent, label, rows):
        """Collapsed expander holding one ticked checkbox per row, plus all/none.
        rows = [(display_text, {attr: value, ...}), …]. Returns the checkbox list.
        Used by BOTH the flatpak and apt sections so they behave the same: anything
        you don't want updated, you untick individually."""
        exp = Gtk.Expander(label=label)
        lst = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        lst.set_margin_start(14); lst.set_margin_top(4)
        boxes = []
        row = Gtk.Box(spacing=6)
        b_all, b_none = Gtk.Button(label="all"), Gtk.Button(label="none")
        b_all.connect("clicked", lambda *_: [c.set_active(True) for c in boxes])
        b_none.connect("clicked", lambda *_: [c.set_active(False) for c in boxes])
        row.pack_start(b_all, False, False, 0); row.pack_start(b_none, False, False, 0)
        lst.pack_start(row, False, False, 0)
        for text, attrs, indent in rows:
            cb = Gtk.CheckButton(label=text); cb.set_active(True)
            if indent: cb.set_margin_start(18 * indent)
            for k, v in attrs.items(): setattr(cb, k, v)
            boxes.append(cb); lst.pack_start(cb, False, False, 0)
        exp.add(lst); parent.pack_start(exp, False, False, 0)
        return boxes

    def _apt_rows(self, d):
        """Flat list -> tree: a package that drags others in owns them as indented
        children. Shared children are shown once, under the first master to claim
        them, and the label names the others."""
        forces, forced_by = d["forces"], d["forced_by"]
        rows, seen = [], set()

        def emit(name, depth, parent=None):
            if name in seen or depth > 8: return
            seen.add(name)
            label = ("└─ " if depth else "") + name
            if name in d["apt_sec_names"]: label += "   [security]"
            others = sorted(forced_by.get(name, set()) - {parent})
            if others: label += "   (also needed by " + ", ".join(others) + ")"
            rows.append((label, {"pkgname": name}, depth))
            for child in sorted(forces.get(name, ())): emit(child, depth + 1, name)

        for name in d["apt"]:
            if name not in forced_by: emit(name, 0)   # roots: free to untick
        for name in d["apt"]: emit(name, 0)           # anything left (dependency cycles)
        return rows

    def _on_policy(self, widget):
        global ALLOW_PLAINTEXT
        ALLOW_PLAINTEXT = widget.get_active()      # the "Allow http" button is the one wired up
        save_allow_plaintext(ALLOW_PLAINTEXT)
        self.logln("policy: " + ("plaintext sources ALLOWED (local mirror / caching proxy)"
                                 if ALLOW_PLAINTEXT else "https required — plaintext will be refused"))
        self.scan()

    def _rewrite_sources(self, hosts):
        """http:// -> https:// in the apt source files, but only for mirrors that
        actually answer over https. The helper backs the files up first."""
        def work():
            targets = []
            for h in hosts:
                name = h.split("://", 1)[-1]
                if not https_works(name):
                    self.logln(f"  {name}: does NOT serve https — leaving it alone"); continue
                files = sources_files_with(h)
                if not files:
                    self.logln(f"  {name}: serves https but no source file matched"); continue
                targets.append(name)
                self.logln(f"  {name}: https OK → {', '.join(files)}")
            if not targets:
                self.logln("nothing to rewrite."); return
            self.logln("rewriting sources (password)…")
            self.step("switch to https", helper("https-sources", *targets))
        self._job(work)

    def _refresh_apply(self):
        """Nothing ticked anywhere -> nothing to apply. Grey the button out rather
        than leaving a live-looking control that would be a no-op."""
        if self.busy or self._scanning:
            self.apply_btn.set_sensitive(False); return
        n = (sum(1 for c in self.checks["gated"] if c.get_active())
             + sum(1 for c in self.checks["flatpak"] if c.get_active())
             + sum(1 for c in self.checks["apt"] if c.get_active()))
        self.apply_btn.set_sensitive(n > 0)
        self.apply_btn.set_label("Apply Selected" if n else "Nothing to apply")

    def _relock(self, boxes):
        """Sensitivity fixpoint: a child stays ticked and locked while ANY master that
        drags it in is ticked. Iterated — the graph nests several levels deep
        (sssd -> sssd-ad -> sssd-common -> libnss-sss)."""
        for _pass in range(12):
            changed = False
            for name, cb in boxes.items():
                pulled = any(boxes[m].get_active() for m in self._forced_by.get(name, ()) if m in boxes)
                if cb.get_sensitive() == pulled:
                    cb.set_sensitive(not pulled); changed = True
                if pulled and not cb.get_active():
                    cb.set_active(True); changed = True
            if not changed: break

    def _on_toggle(self, cb=None):
        """Untick a master and its whole branch goes with it — except any child that a
        DIFFERENT still-ticked package also needs. Re-tick it and the branch comes back."""
        if getattr(self, "_syncing", False): return
        self._syncing = True
        try:
            boxes = {c.pkgname: c for c in self.checks["apt"]}
            if cb is not None and hasattr(cb, "pkgname"):
                want = cb.get_active()
                for _round in range(3):     # re-run: a shared child may only be released
                    seen = set()            # once a sibling further down has been unticked
                    stack = list(self._forces.get(cb.pkgname, ()))
                    while stack:
                        name = stack.pop()
                        if name in seen: continue
                        seen.add(name)
                        child = boxes.get(name)
                        if child is None: continue
                        if want:
                            if not child.get_active(): child.set_active(True)
                        elif child.get_active() and not any(
                                boxes[m].get_active() for m in self._forced_by.get(name, ()) if m in boxes):
                            child.set_active(False)
                        stack.extend(self._forces.get(name, ()))
            self._relock(boxes)
        finally:
            self._syncing = False
        self._refresh_apply()
        self._schedule_preflight()

    def _schedule_preflight(self):
        """The nesting above is a readable approximation. apt's resolver is the only
        authority — it also weighs Breaks, exact-version pins in BOTH directions, and
        it upgrades any dependency that merely happens to be upgradable. So after the
        dust settles, ask apt what this selection really does and say so out loud."""
        self._pf_gen = getattr(self, "_pf_gen", 0) + 1
        gen = self._pf_gen
        GLib.timeout_add(700, lambda: (self._run_preflight(gen), False)[1])

    def _run_preflight(self, gen):
        if gen != self._pf_gen: return                       # superseded by a later click
        sel = [c.pkgname for c in self.checks["apt"] if c.get_active()]
        if not sel or len(sel) == len(self.checks["apt"]): return
        def work():
            sim = run(["apt-get", "-s", "install", "--only-upgrade"] + sel)
            if gen != self._pf_gen: return                   # user clicked again meanwhile
            plans = {l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Inst ")}
            extra = sorted(plans - set(sel))
            removes = sorted(l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Remv "))
            self.logln(f"apt check ({len(sel)} selected): " + (
                "nothing extra — selection is exact ✓" if not extra and not removes else
                ("will ALSO upgrade " + ", ".join(extra) if extra else "") +
                ("  |  would REMOVE " + ", ".join(removes) + " — Apply stops instead" if removes else "")))
            if extra:
                self.logln("   → unticking can't stop these. \"Hold back\" pins them with apt-mark hold.")
            GLib.idle_add(self._offer_hold, [p for p in extra if is_installed(p)])   # new installs cannot be held
        threading.Thread(target=work, daemon=True).start()

    def _offer_hold(self, pkgs):
        self._pending_hold = pkgs
        if pkgs:
            self.hold_btn.set_label(f"Hold back {len(pkgs)}")
            self.hold_btn.show()
        else:
            self.hold_btn.hide()

    def on_hold(self, *_):
        pkgs = list(self._pending_hold)
        if not pkgs: return
        def work():
            self.logln("apt-mark hold (password): " + ", ".join(pkgs))
            if self.step("hold", helper("hold", *pkgs)):
                self.logln("held — apt, including automatic security updates, will not upgrade them. "
                           "Section ③ offers to release them again.")
        self._job(work)

    def on_unhold(self, pkgs):
        def work():
            self.logln("releasing holds made by Pro Updates (password): " + ", ".join(pkgs))
            if self.step("release holds", helper("unhold", *pkgs)): self.logln("released.")
        self._job(work)

    def on_refresh_lists(self, *_):
        def work():
            self.logln("downloading the package lists (password)…")
            if self.step("apt update", helper("refresh")): self.logln("package lists updated.")
        self._job(work)

    def scan(self):
        if self._scanning or self.busy: return
        self._scanning = True
        self.body.set_sensitive(False); self.refresh_btn.set_sensitive(False); self.apply_btn.set_sensitive(False)
        self.logln("scanning…")
        def work():
            try: d = gather()
            except Exception:
                tb = traceback.format_exc()
                GLib.idle_add(self._scan_failed, tb); return
            GLib.idle_add(self.populate, d)
        threading.Thread(target=work, daemon=True).start()

    def _scan_failed(self, tb):
        self._scanning = False
        for c in self.body.get_children(): self.body.remove(c)     # nothing stale may be applied
        self.checks = {"gated": [], "flatpak": [], "apt": []}
        self._offer_hold([])
        self.summary.set_text("Scan failed — see the output below; Refresh tries again")
        self.logln("💥 scan failed:")
        for ln in tb.rstrip().splitlines(): self.logln("   " + ln)
        self._set_busy(False)

    def populate(self, d):
        """Show a scan. Whatever goes wrong while building the sections, the window
        never stays greyed out: the error is logged and Refresh works again."""
        try:
            self._populate(d)
        except Exception:
            for c in self.body.get_children(): self.body.remove(c)
            self.checks = {"gated": [], "flatpak": [], "apt": []}
            self.summary.set_text("Could not show the scan — see the output below; Refresh tries again")
            self._offer_hold([])
            self.logln("💥 could not show the scan:")
            for ln in traceback.format_exc().rstrip().splitlines(): self.logln("   " + ln)
        finally:
            self._scanning = False
            self._set_busy(False)

    def _populate(self, d):
        self._scanning = False
        for c in self.body.get_children(): self.body.remove(c)
        self.checks = {"gated": [], "flatpak": [], "apt": []}
        n_gated = sum(len(g["pkgs"]) for g in d["gated"]) + len(d["libs"])
        gated_txt = (f"{n_gated} Pro-only (ESM)" if d["gated_status"] == "checked" else "Pro-only (ESM): not checked")
        apt_txt = "package lists not downloaded" if d["lists_empty"] else f"{len(d['apt'])} apt"
        self.summary.set_text(f"{apt_txt}  ·  {len(d['flatpak'])} flatpak  ·  {gated_txt}  ·  {len(d['held'])} held"
                              + (f"  ·  ⛔ {len(d['vendors_bad'])} from the wrong source" if d.get("vendors_bad") else ""))

        s = self._section("Package sources — transport policy")
        rb_strict = Gtk.RadioButton.new_with_label_from_widget(
            None, "Require https  —  refuse plaintext sources (recommended)")
        rb_relaxed = Gtk.RadioButton.new_with_label_from_widget(
            rb_strict, "Allow http  —  for a LAN mirror or caching proxy (apt-cacher-ng)")
        (rb_relaxed if ALLOW_PLAINTEXT else rb_strict).set_active(True)
        rb_relaxed.connect("toggled", self._on_policy)
        s.pack_start(rb_strict, False, False, 0)
        s.pack_start(rb_relaxed, False, False, 0)
        note = Gtk.Label(xalign=0)
        note.set_markup("<small><i>apt verifies every package against a GPG-signed Release file, so "
                        "http cannot get a tampered package past it. What http leaks is <b>which</b> "
                        "packages and versions you fetch. A caching proxy is plain http by design and "
                        "cannot be https — hence the second option.</i></small>")
        note.set_line_wrap(True); s.pack_start(note, False, False, 0)
        if d.get("plaintext"):
            row = Gtk.Box(spacing=8)
            lbl = Gtk.Label(xalign=0)
            lbl.set_markup("<small>plaintext in use: <tt>" +
                           GLib.markup_escape_text(", ".join(d["plaintext"])) + "</tt></small>")
            row.pack_start(lbl, False, False, 0)
            btn = Gtk.Button(label="Switch these to https")
            btn.set_tooltip_text("Rewrites http:// to https:// in the apt source files, "
                                 "after checking each mirror actually serves https")
            btn.connect("clicked", lambda *_: self._rewrite_sources(d["plaintext"]))
            row.pack_start(btn, False, False, 0)
            s.pack_start(row, False, False, 0)
        row = Gtk.Box(spacing=8)
        lbl = Gtk.Label(xalign=0)
        if d["lists_empty"]:
            lbl.set_markup("<b>Package lists: not downloaded yet</b> — until they are, no update can be seen")
        else:
            lbl.set_markup(f"<small>Package lists downloaded {age_text(d['lists_age'])}</small>")
        lbl.set_line_wrap(True); row.pack_start(lbl, False, False, 0)
        btn = Gtk.Button(label="Download package lists" if d["lists_empty"] else "Refresh lists")
        btn.set_tooltip_text("apt update (asks for your password)")
        btn.connect("clicked", self.on_refresh_lists)
        row.pack_start(btn, False, False, 0); s.pack_start(row, False, False, 0)

        # vendor sources: who the browsers/mail/editors would update from, live from apt's candidate
        if d.get("vendors"):
            vs = self._section("Vendor sources — browsers, mail and editors update from their vendors")
            heldset = set(d["held"])
            for pkg, inst, cand, host, state in d["vendors"]:
                l = Gtk.Label(xalign=0); l.set_line_wrap(True)
                if state == "nosrc" and d["lists_empty"]:
                    mark, src = "·", "<i>not known until the package lists are downloaded</i>"
                elif state == "snap" and not d["vendor_policy"]:
                    mark, src = "·", "Ubuntu (transitional package for the snap)"
                else:
                    mark = {"ok": "✓", "armbian": "⛔", "snap": "⛔", "none": "⛔", "nosrc": "⚠", "missing": "·"}[state]
                    src = {"armbian": "<b>Armbian's rebranded mirror</b>", "snap": "<b>Ubuntu snap shim</b>",
                           "none": "<b>no candidate — a negative pin is poisoning it</b>",
                           "nosrc": "<b>no update source configured</b> (installed from a repo that is gone; add the vendor's)"}.get(state, GLib.markup_escape_text(vendor_label(host)))
                held = "   <i>held (personal build)</i>" if pkg in heldset else ""
                l.set_markup(f"{mark}  <b>{GLib.markup_escape_text(pkg)}</b>  ←  {src}   <small><tt>{GLib.markup_escape_text(cand)}</tt></small>{held}")
                vs.pack_start(l, False, False, 0)
            # Repair only exists where the distribution ships its pin file, and only shows when needed
            if os.path.isfile(VENDOR_PINS) and (d["vendors_bad"] or d["pins_changed"]):
                warn = Gtk.Label(xalign=0); warn.set_line_wrap(True)
                warn.set_markup("<small><i>" + ("The vendor pin file was changed or removed. " if d["pins_changed"] else
                                "A browser would update from the wrong source. ") +
                                "Repair restores the system's own pin file (Armbian at 1, the vendors at 1001), "
                                "drops Armbian's desktop component and downloads the lists. Backups go to "
                                "/var/backups/pro-updates.</i></small>")
                vs.pack_start(warn, False, False, 0)
                row = Gtk.Box(spacing=8)
                btn = Gtk.Button(label="Repair sources")
                btn.set_tooltip_text(f"asks for your password; copies {VENDOR_PINS} to {VENDOR_PINS_DEST}")
                btn.connect("clicked", lambda *_: self._repair_sources())
                row.pack_start(btn, False, False, 0); vs.pack_start(row, False, False, 0)

        s = self._section("①  Universe fixes published only through Ubuntu Pro (ESM)")
        if d["gated_status"] == "no-pro":
            l = Gtk.Label(xalign=0); l.set_line_wrap(True)
            l.set_markup("<b>Not checked</b> — the Ubuntu Pro client isn't installed, so universe fixes that "
                         "Canonical publishes only through Ubuntu Pro (ESM) can't be listed here.")
            s.pack_start(l, False, False, 0)
        elif d["gated_status"] == "error":
            l = Gtk.Label(xalign=0); l.set_line_wrap(True)
            l.set_markup("<b>Not checked</b> — <tt>pro security-status</tt> gave no usable answer: "
                         f"<small>{GLib.markup_escape_text(d.get('gated_error', ''))}</small>")
            s.pack_start(l, False, False, 0)
        elif not d["gated"] and not d["libs"]:
            s.pack_start(Gtk.Label(label="None — no installed package has an ESM-only fix.", xalign=0), False, False, 0)
        for g in d["gated"]:
            if g["kind"] in ("flatpak", "suggest"):
                guess = g["kind"] == "suggest"
                cb = Gtk.CheckButton(label=f"{g['base']}  →  Flathub {g['appid']}"
                                           + ("  (name match — check it is the same app)" if guess else "")
                                           + "   installs alongside; the .deb stays")
                cb.set_active(not guess); cb.appid = g["appid"]
                cb.connect("toggled", lambda *_: self._refresh_apply())
                self.checks["gated"].append(cb); s.pack_start(cb, False, False, 0)
            elif g["kind"] == "pinned":
                lbl = Gtk.Label(xalign=0)
                lbl.set_markup(f"•  <b>{GLib.markup_escape_text(g['base'])}</b>  →  "
                               f"<b>pinned</b> by this system — not replaced"
                               f"  <small><i>(its own repository's updates still apply)</i></small>")
                lbl.set_line_wrap(True); s.pack_start(lbl, False, False, 0)
            elif g["kind"] == "note":
                s.pack_start(Gtk.Label(label="•  7-Zip 25.x  →  Debian / 7-zip.org (manual)", xalign=0), False, False, 0)
            elif g["kind"] == "free":
                lbl = Gtk.Label(xalign=0)
                origin = GLib.markup_escape_text(g["free_origin"])
                if g["free_state"] == "installed":
                    lbl.set_markup(f"•  <b>{GLib.markup_escape_text(g['base'])}</b>  →  installed from <b>{origin}</b>, "
                                   f"not from Ubuntu  <small><i>(whether that build has the fix is not checked)</i></small>")
                else:
                    lbl.set_markup(f"•  <b>{GLib.markup_escape_text(g['base'])}</b>  →  newer version available from "
                                   f"<b>{origin}</b>  <small><i>(a plain apt upgrade installs it — see section ③; "
                                   f"whether it has the fix is not checked)</i></small>")
                lbl.set_line_wrap(True); s.pack_start(lbl, False, False, 0)
            else:
                s.pack_start(Gtk.Label(label=f"•  {g['base']}  →  no Flathub match (rebuild from source)", xalign=0), False, False, 0)
        if d["libs"]:
            s.pack_start(Gtk.Label(label=f"+  {len(d['libs'])} libraries — no app to swap", xalign=0), False, False, 0)

        s = self._section("②  Flatpak app updates")
        if d["flatpak"]:
            n_user = sum(1 for f in d["flatpak"] if f["scope"] == "user")
            n_sys = len(d["flatpak"]) - n_user
            scope_note = f"{n_user} user" + (f" · {n_sys} system" if n_sys else "")
            hdr = Gtk.Label(xalign=0)
            hdr.set_markup(f"<b>{len(d['flatpak'])}</b> update(s) available   <small>({scope_note})</small>")
            s.pack_start(hdr, False, False, 0)
            rows = [(f"{f['appid']}  {f['branch']}   [{f['scope']} · {'app' if f['kind'] == 'app' else 'runtime'}]",
                     {"ref": f["ref"], "scope": f["scope"]}, 0) for f in d["flatpak"]]
            self.checks["flatpak"] = self._checklist(s, "choose apps", rows)
            for cb in self.checks["flatpak"]: cb.connect("toggled", lambda *_: self._refresh_apply())
        elif not d["have_flatpak"]:
            s.pack_start(Gtk.Label(label="Flatpak isn't installed.", xalign=0), False, False, 0)
        elif not d["flatpak_remotes"]:
            s.pack_start(Gtk.Label(label="No Flatpak remotes are configured — nothing to update.", xalign=0), False, False, 0)
        elif not d["flatpak_errors"]:
            s.pack_start(Gtk.Label(label="All Flatpaks up to date.", xalign=0), False, False, 0)
        if d["flatpak_errors"]:
            l = Gtk.Label(xalign=0); l.set_line_wrap(True)
            l.set_markup("⚠ <b>Couldn't check</b> (offline?): <small>" +
                         GLib.markup_escape_text("; ".join(d["flatpak_errors"])) + "</small>")
            s.pack_start(l, False, False, 0)

        s = self._section("③  Regular apt updates")
        if d["apt"]:
            hdr = Gtk.Label(xalign=0)
            hdr.set_markup(f"<b>{len(d['apt'])}</b> update(s) available   <small>({d['apt_sec']} security)</small>")
            s.pack_start(hdr, False, False, 0)
            self.checks["apt"] = self._checklist(s, "choose packages", self._apt_rows(d))
            self._forces, self._forced_by = d["forces"], d["forced_by"]
            for cb in self.checks["apt"]: cb.connect("toggled", self._on_toggle)
            self._syncing = True
            try: self._relock({c.pkgname: c for c in self.checks["apt"]})
            finally: self._syncing = False
            if d["forced_by"]:
                note = Gtk.Label(xalign=0)
                note.set_markup(f"<small><i>{len(d['forced_by'])} package(s) are nested under the one that "
                                f"requires them — apt would upgrade them regardless, so they follow their "
                                f"master's tick. Untick the master to hold the whole branch back.</i></small>")
                note.set_line_wrap(True); s.pack_start(note, False, False, 0)
        elif d["lists_empty"]:
            l = Gtk.Label(xalign=0); l.set_line_wrap(True)
            l.set_markup("<b>Unknown</b> — the package lists haven't been downloaded yet. "
                         "Use <i>Download package lists</i> above.")
            s.pack_start(l, False, False, 0)
        else:
            s.pack_start(Gtk.Label(label=f"System up to date (lists from {age_text(d['lists_age'])}).", xalign=0), False, False, 0)
        self._downgrades = [n for n, _, _ in d["downgrades"]]
        if d["downgrades"]:
            l = Gtk.Label(xalign=0); l.set_line_wrap(True)
            l.set_markup(f"<small><i>{len(d['downgrades'])} pinned downgrade(s) not applied here — a pin above 1000 "
                         f"asks apt to replace them with an older version: " +
                         GLib.markup_escape_text("; ".join(f"{n} {a} → {b}" for n, a, b in d["downgrades"])) +
                         ". If that is what you want: <tt>sudo apt-get install --allow-downgrades "
                         + GLib.markup_escape_text(" ".join(self._downgrades)) + "</tt></i></small>")
            s.pack_start(l, False, False, 0)
        if d["kept_back"]:
            l = Gtk.Label(xalign=0); l.set_line_wrap(True)
            l.set_markup(f"<small><i>{len(d['kept_back'])} kept back — they need packages added or removed, which "
                         f"this window never does (use <tt>sudo apt full-upgrade</tt> after reading its plan): "
                         f"{GLib.markup_escape_text(', '.join(d['kept_back']))}</i></small>")
            s.pack_start(l, False, False, 0)
        if d["held"]:
            ours = [p for p in d["held"] if p in set(d["our_holds"])]
            system = [p for p in d["held"] if p not in set(d["our_holds"])]
            if system:
                l = Gtk.Label(xalign=0)
                l.set_markup(f"<i>✓ {len(system)} held by the system &amp; respected — never upgraded: "
                             f"{GLib.markup_escape_text(', '.join(system))}</i>")
                l.set_line_wrap(True); s.pack_start(l, False, False, 0)
            if ours:
                row = Gtk.Box(spacing=8)
                l = Gtk.Label(xalign=0); l.set_line_wrap(True)
                l.set_markup(f"<i>{len(ours)} held by you (Hold back) — no updates, security ones included: "
                             f"{GLib.markup_escape_text(', '.join(ours))}</i>")
                row.pack_start(l, False, False, 0)
                btn = Gtk.Button(label="Release")
                btn.set_tooltip_text("apt-mark unhold for the holds made here (asks for your password)")
                btn.connect("clicked", lambda *_: self.on_unhold(ours))
                row.pack_start(btn, False, False, 0); s.pack_start(row, False, False, 0)

        if d.get("builds"):
            s = self._section("④  Builds from source")
            self._builds_section(s, d["builds"])

        self._offer_hold([])          # stale offer must not survive a rescan
        self.body.show_all(); self._set_busy(False); self.logln("ready.")
        for line in d.get("sources", []): self.logln(line)
        if d.get("insecure"):
            self.logln("⛔ POLICY: https-only. Updates from these plaintext source(s) will be skipped:")
            self.logln("   (packages are still GPG-signed and hash-verified over http — what plaintext")
            self.logln("    leaks is WHICH packages and versions you fetch, not their integrity.)")
            for h in d["insecure"]:
                files = sources_files_with(h)
                self.logln(f"     {h}   in {', '.join(files) if files else '?'}")
            self.logln("   fix: \"Switch these to https\" under Package sources, or allow http there.")

    def _repair_sources(self):
        def work():
            self.logln("vendor sources: repairing (password)…")
            if not self.step("repair sources", helper("repair-pins")): return
            for pkg in VENDOR_APPS:
                if not is_installed(pkg): continue
                inst, cand, host, state = candidate_origin(pkg)
                self.logln(f"   {pkg:22} ← {vendor_label(host) if state == 'ok' else state.upper():16} {cand}")
        self._job(work)

    # ── ④ builds ────────────────────────────────────────────────────────────
    def _builds_section(self, s, rows):
        if not rows:
            lbl = Gtk.Label(xalign=0)
            lbl.set_markup("<i>No build.json found. Looked in: " + GLib.markup_escape_text(", ".join(BUILD_DIRS)) + "</i>")
            lbl.set_line_wrap(True); s.pack_start(lbl, False, False, 0); return
        for r in rows:
            # one malformed manifest costs its own row, never the whole window
            try:
                s.pack_start(self._build_row_box(r), False, False, 0)
            except Exception as e:
                head = Gtk.Label(xalign=0); head.set_line_wrap(True)
                head.set_markup(f"<b>{GLib.markup_escape_text(str(r['m'].get('name', '?')))}</b>  —  bad build.json: "
                                f"<i>{GLib.markup_escape_text(type(e).__name__ + ': ' + str(e))}</i>")
                s.pack_start(head, False, False, 0)

    def _build_row_box(self, r):
        m = r["m"]; box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2); box.set_margin_bottom(6)
        head = Gtk.Label(xalign=0); head.set_line_wrap(True)
        if "error" in r:
            head.set_markup(f"<b>{GLib.markup_escape_text(m['name'])}</b>  —  bad build.json: "
                            f"<i>{GLib.markup_escape_text(r['error'])}</i>")
            box.pack_start(head, False, False, 0); return box
        inst = r["installed"] or "not installed"; up = r["upstream"] or "—"
        mark = "   <b>⬆ newer upstream</b>" if r["newer"] else ("   ✓ current" if r["installed"] and r["upstream"] and not r["upstream"].startswith("?") else "")
        head.set_markup(f"<b>{GLib.markup_escape_text(m['name'])}</b>   <small>installed <tt>{GLib.markup_escape_text(inst)}</tt>"
                        f"  ·  upstream <tt>{GLib.markup_escape_text(up)}</tt></small>{mark}")
        box.pack_start(head, False, False, 0)
        if r["artifact"]:
            a = Gtk.Label(xalign=0)
            a.set_markup(f"<small>built: <tt>{GLib.markup_escape_text(r['artifact_version'])}</tt>  "
                         f"<i>{GLib.markup_escape_text(os.path.basename(r['artifact']))}</i></small>")
            box.pack_start(a, False, False, 0)
        bb = Gtk.Box(spacing=6)
        src = (m.get("source") or {}).get("url", ""); bld = m.get("build") or {}
        b_dl = Gtk.Button(label="Download source"); b_dl.set_sensitive(bool(src) and bool(r["upstream"]) and not r["upstream"].startswith("?"))
        b_dl.set_tooltip_text(_expand(m, src, r["upstream"]) if src else "no source URL in build.json")
        b_dl.connect("clicked", lambda _b, m=m, v=r["upstream"]: self._b_download(m, v))
        b_bu = Gtk.Button(label="Build"); b_bu.set_sensitive(bool(bld.get("script")) and not bld.get("manual"))
        b_bu.set_tooltip_text(("manual: " if bld.get("manual") else "") + (bld.get("note") or _rel(m, bld.get("script", "")) or "no build script"))
        b_bu.connect("clicked", lambda _b, m=m: self._b_build(m))
        b_in = Gtk.Button(label="Install" + (" + hold" if m.get("hold") else "")); b_in.set_sensitive(bool(r["artifact"]))
        b_in.set_tooltip_text(r["artifact"] or "nothing built yet")
        b_in.connect("clicked", lambda _b, m=m, a=r["artifact"]: self._b_install(m, a))
        for b in (b_dl, b_bu, b_in): bb.pack_start(b, False, False, 0)
        box.pack_start(bb, False, False, 0)
        if m.get("notes"):
            n = Gtk.Label(xalign=0); n.set_markup(f"<small><i>{GLib.markup_escape_text(m['notes'])}</i></small>")
            n.set_line_wrap(True); box.pack_start(n, False, False, 0)
        return box

    def _b_download(self, m, version):
        srcm = m.get("source") if isinstance(m.get("source"), dict) else {}
        url = _expand(m, srcm.get("url", ""), version)
        name = _expand(m, srcm.get("file", "") or os.path.basename(url), version)
        want = (srcm.get("sha256") or "").strip().lower()
        wd = _expand(m, "{workdir}"); dest = os.path.join(wd, os.path.basename(name))
        def work():
            if not url.startswith("https://"):
                self.logln(f"④ refusing a non-https download: {url}"); return
            os.makedirs(wd, exist_ok=True)
            self.logln(f"④ download {url}\n   → {dest}")
            # https only, redirects included
            if not self.step("download", ["curl", "-fL", "--proto", "=https", "--proto-redir", "=https",
                                          "--retry", "3", "--progress-bar", "-o", dest, url]): return
            sha = run(["sha256sum", dest]).stdout.split()[0] if have("sha256sum") else "?"
            self.logln(f"   {human(os.path.getsize(dest))}  sha256 {sha}")
            if want and sha != want:
                os.remove(dest)
                self.logln(f"❌ checksum mismatch — expected {want}; the file was deleted")
            elif want:
                self.logln("   ✓ matches the sha256 in build.json")
            else:
                self.logln("   (build.json has no sha256 — compare this with the project's published checksum)")
        self._job(work)

    def _b_build(self, m):
        bld = m.get("build") if isinstance(m.get("build"), dict) else {}
        script = _rel(m, bld.get("script", "")); args = [_expand(m, str(a)) for a in bld.get("args", [])]
        unit = "pro-updates-build-" + re.sub(r"[^a-z0-9]+", "-", (m.get("package") or "pkg").lower()) + "-" + str(int(GLib.get_real_time() // 1000000))
        def work():
            if not os.path.exists(script): self.logln(f"④ build script missing: {script}"); return
            deps = _rel(m, bld.get("deps", ""))
            if deps and os.path.exists(deps): self.logln(f"④ build deps installer available (sudo, once): {deps}")
            self.logln(f"④ build {m['name']} as systemd user unit {unit}" + (f"  (~{bld['minutes']} min)" if bld.get("minutes") else "")
                       + " — other actions wait until it ends")
            self.logln(f"   bash {script} {' '.join(args)}")
            self.step("build", ["systemd-run", "--user", "--unit=" + unit, "--collect", "--wait", "--pipe", "--quiet",
                                "-p", "Nice=5", "-p", "WorkingDirectory=" + m["_dir"], "/bin/bash", script] + args)
            art = artifact_for(m)
            self.logln("   artifact: " + (art if art else "none found (check the log above)"))
        self._job(work)

    def _b_install(self, m, artifact):
        pkg = m.get("package", "")
        def work():
            if not artifact or not os.path.exists(artifact): self.logln("④ nothing to install"); return
            self.logln(f"④ install {os.path.basename(artifact)} (password)…")
            sim = run(["apt-get", "-s", "install", "--", artifact])
            removes = sorted(l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Remv "))
            if removes: self.logln("⚠ apt would remove " + ", ".join(removes) + " — it will stop instead (nothing is removed here)")
            args = [artifact] + ([pkg] if m.get("hold") and pkg else [])
            if self.step("install", helper("install-deb", *args)):
                self.logln("④ installed: " + (installed_version(pkg) or "?") + (" (held)" if m.get("hold") else ""))
        self._job(work)

    def stream(self, cmd):
        """Run cmd, copy its output into the pane, return its exit code."""
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        except Exception as e:
            self.logln(f"  error: {e}")
            return 1
        # keep reading to the end whatever happens: a reader that stops would leave the
        # command blocked on a full pipe
        for line in p.stdout:
            try: self.logln("  " + line.rstrip())
            except Exception: pass
        return p.wait()

    def _flathub_ok(self):
        """Flathub is added for this user only, and only after saying what it means."""
        remotes = ([tuple((l.split("\t") + [""])[:2]) for l in
                    run(["flatpak", "remotes", "--columns=name,options"]).stdout.splitlines() if l.strip()]
                   if have("flatpak") else [])
        if any(n == "flathub" and "user" in o for n, o in remotes):
            return True
        dlg = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION,
                                buttons=Gtk.ButtonsType.NONE, text="Add Flathub for your account?")
        dlg.format_secondary_text("The Flatpak apps come from flathub.org. Once Flathub is added, Flatpak and "
                                  "GNOME Software also check flathub.org for updates to them. It is added for "
                                  "your user only, not system-wide.")
        dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Add Flathub", Gtk.ResponseType.OK)
        ok = dlg.run() == Gtk.ResponseType.OK
        dlg.destroy()
        return ok

    def on_apply(self, *_):
        gated = [cb.appid for cb in self.checks["gated"] if cb.get_active()]
        flat_sel = [(cb.scope, cb.ref) for cb in self.checks["flatpak"] if cb.get_active()]
        flat_tot = {sc: sum(1 for cb in self.checks["flatpak"] if cb.scope == sc) for sc in ("user", "system")}
        apt_pkgs = [cb.pkgname for cb in self.checks["apt"] if cb.get_active()]
        # with a pinned downgrade pending, `apt-get upgrade` would refuse the whole run: name the packages instead
        apt_all = bool(apt_pkgs) and len(apt_pkgs) == len(self.checks["apt"]) and not getattr(self, "_downgrades", [])
        if gated and not self._flathub_ok():
            self.logln("cancelled — nothing was changed."); return

        def worker():
            failed = []
            if gated:
                ok = True
                if not have("flatpak"):
                    self.logln("installing flatpak (password)…")
                    ok = self.step("install flatpak", helper("install-flatpak"))
                if ok:
                    ok = self.step("add Flathub (user)", ["flatpak", "remote-add", "--user", "--if-not-exists", "flathub", FLATHUB])
                for appid in (gated if ok else []):
                    self.logln(f"flatpak install {appid} …")
                    if not self.step(f"flatpak install {appid}", ["flatpak", "install", "--user", "-y", "flathub", appid]):
                        failed.append(appid)
                if not ok: failed.append("Flathub")
            for scope in ("user", "system"):
                refs = [r for sc, r in flat_sel if sc == scope]
                if not refs: continue
                # whole scope selected -> plain update; otherwise name the exact refs,
                # so an unticked app is left alone instead of swept up by a blanket update.
                whole = len(refs) == flat_tot[scope]
                self.logln(f"flatpak [{scope}]: updating {len(refs)} ref(s)"
                           + ("" if whole else " (selected only)")
                           + (" — Flatpak's own permission rules apply" if scope == "system" else "") + " …")
                if not self.step(f"flatpak update ({scope})", ["flatpak", "update", "--" + scope, "-y"] + ([] if whole else refs)):
                    failed.append(f"flatpak {scope}")
            # NB: a local copy. Rebinding the enclosing `apt_pkgs` here would make the
            # name local to worker() for its whole body, and the read above it would
            # then raise UnboundLocalError before the apt phase ever started.
            pkgs = list(apt_pkgs)
            whole = apt_all
            if pkgs:
                pkgs, skipped, pulled = split_by_transport(pkgs)
                if skipped:
                    whole = False
                    self.logln("⛔ https-only: skipping " + ", ".join(f"{p} ({h})" for p, h in sorted(skipped.items())))
                if pulled:
                    self.logln("⛔ https-only: your selection needs " + ", ".join(f"{p} ({h})" for p, h in sorted(pulled.items()))
                               + " from a plaintext source — the apt phase is skipped. Untick what needs it, "
                               "switch the source to https, or allow http.")
                    pkgs = []; failed.append("apt (plaintext source)")
            if pkgs:
                if not whole:
                    # last line of defence: ask apt what it would ACTUALLY do with this
                    # selection, and name anything unticked it still intends to upgrade.
                    sim = run(["apt-get", "-s", "install", "--only-upgrade", "--"] + pkgs)
                    plans = {l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Inst ")}
                    extra = sorted(plans - set(pkgs))
                    removes = sorted(l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Remv "))
                    if extra: self.logln("⚠ apt will also upgrade (required by your selection): " + ", ".join(extra))
                    if removes: self.logln("⚠ apt would remove " + ", ".join(removes) + " — it will stop instead (nothing is removed here)")
                    if not extra and not removes: self.logln("pre-flight: selection is exact — nothing else pulled in ✓")
                self.logln(f"apt: updating the lists, then {'all' if whole else len(pkgs)} package(s) (password — holds honoured)…")
                if not self.step("apt", helper("upgrade-all") if whole else helper("upgrade", *pkgs)):
                    failed.append("apt")
            self.logln("✅ done." if not failed else "❌ finished with failures: " + ", ".join(failed))

        self._job(worker)

if __name__ == "__main__":
    # Wayland app-id = program name; matching it to pro-updates.desktop lets GNOME show the launcher icon for the running window
    GLib.set_prgname("pro-updates"); GLib.set_application_name("Pro Updates")
    Gtk.Window.set_default_icon_name("pro-updates")
    w = App(); w.connect("destroy", Gtk.main_quit); w.show_all(); Gtk.main()
