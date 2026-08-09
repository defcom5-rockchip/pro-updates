#!/usr/bin/env python3
"""
Pro Updates (GUI) — a GTK3 update centre for Ubuntu.

Three checkboxed sections:
  ① Gated fixes   — universe/ESM security fixes remedied FREE from Flathub
                    (curated VLC/Chromium + dynamic Flathub lookup; 7-Zip note)
  ② Flatpak apps  — update the sandboxed apps you already have
  ③ Regular apt   — the normal apt upgrade (HOLDS honored + shown)

One "Apply Selected" button. flatpak installs run per-user (no root); apt runs
via pkexec (graphical password). Honors apt holds. SAFETY: the GUI never removes
packages — that stays in the guarded CLI tool.
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
import configparser, json, os, re, shutil, socket, subprocess, threading

__version__ = "1.1"

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
        out.append(f"  esm      https://esm.ubuntu.com   {gated_n} gated pkg(s) — "
                   f"NOT fetched, needs a Pro subscription")
        out.append(f"           → {', '.join(resolve('esm.ubuntu.com'))}")
    return out

def run(cmd):
    try: return subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        class R: returncode = 1; stdout = ""; stderr = ""
        return R()
def have(c): return shutil.which(c) is not None

CURATED = {"vlc": "org.videolan.VLC", "chromium": "org.chromium.Chromium"}
FLATHUB = "https://flathub.org/repo/flathub.flatpakrepo"

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

def held(): return sorted(set(run(["apt-mark", "showhold"]).stdout.split()))

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

def gather():
    d = {"gated": [], "libs": [], "apt": [], "apt_sec": 0, "flatpak": [], "held": held()}
    if have("pro"):
        try: j = json.loads(run(["pro", "security-status", "--format", "json"]).stdout)
        except Exception: j = {}
        bases = {}
        for p in [p for p in j.get("packages", []) if p.get("service_name") in ("esm-apps", "esm-infra")]:
            nm = p["package"]
            if is_app_pkg(nm): bases.setdefault(app_base(nm), []).append(nm)
            else: d["libs"].append(nm)
        for base, pkgs in sorted(bases.items()):
            if base in CURATED:            d["gated"].append({"base": base, "pkgs": pkgs, "kind": "flatpak", "appid": CURATED[base]})
            elif base in ("7zip", "p7zip"):d["gated"].append({"base": base, "pkgs": pkgs, "kind": "note", "appid": None})
            else:
                m = flatpak_match(base)
                state, origin = (None, None) if m else free_fix(pkgs[0])
                d["gated"].append({"base": base, "pkgs": pkgs, "appid": m,
                                   "kind": "flatpak" if m else ("free" if state else "none"),
                                   "free_state": state, "free_origin": origin})
    lines = run(["apt-get", "-s", "upgrade"]).stdout.splitlines()
    d["apt"] = [l.split()[1] for l in lines if l.startswith("Inst ")]
    d["apt_sec_names"] = {l.split()[1] for l in lines if l.startswith("Inst ") and "security" in l.lower()}
    d["apt_sec"] = len(d["apt_sec_names"])
    d["forces"], d["forced_by"] = dep_graph(d["apt"])
    if have("flatpak"):
        # per-SCOPE and per-REF: a bare `--columns=application` list shows the same id
        # several times (one per branch) with no way to tell the rows apart, and
        # updating only --user silently skips everything installed system-wide.
        for scope in ("user", "system"):
            r = run(["flatpak", "remote-ls", "--" + scope, "--updates", "--columns=ref"])
            if r.returncode: continue
            for line in r.stdout.splitlines():
                ref = line.split("\t")[0].strip()
                if ref.count("/") != 3: continue
                kind, appid, arch, branch = ref.split("/")
                d["flatpak"].append({"ref": ref, "scope": scope, "kind": kind,
                                     "appid": appid, "arch": arch, "branch": branch})
    d["sources"] = source_lines(d["apt"], d["flatpak"], len(d["libs"]) + sum(len(g["pkgs"]) for g in d["gated"]))
    hosts = apt_uri_hosts(d["apt"])
    d["plaintext"] = plaintext(hosts)
    d["insecure"] = blocked(hosts)
    return d

class App(Gtk.Window):
    def __init__(self):
        super().__init__(title="Pro Updates")
        self.set_default_size(680, 740)
        self._css()
        hb = Gtk.HeaderBar(title="Pro Updates"); hb.set_subtitle(f"free security fixes · no Ubuntu Pro · v{__version__}")
        hb.set_show_close_button(True); self.set_titlebar(hb)
        rb = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        rb.connect("clicked", lambda *_: self.scan()); hb.pack_start(rb)

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
        self.hold_btn.set_tooltip_text("apt-mark hold — apt will refuse to upgrade these until you unhold them")
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

    def _css(self):
        css = b".summary{font-size:15px;font-weight:bold;color:#e85020;}"
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
        actually answer over https. Backs the files up first."""
        def worker():
            targets = []
            for h in hosts:
                name = h.split("://", 1)[-1]
                if not https_works(name):
                    self.logln(f"  {name}: does NOT serve https — leaving it alone"); continue
                files = sources_files_with(h)
                if not files:
                    self.logln(f"  {name}: serves https but no source file matched"); continue
                targets.append((name, files))
                self.logln(f"  {name}: https OK → {', '.join(files)}")
            if not targets:
                self.logln("nothing to rewrite."); return
            script = "set -e\n"
            for name, files in targets:
                for f in files:
                    script += f'cp -n "{f}" "{f}.bak-proupdates" || true\n'
                    script += f'sed -i "s|http://{name}|https://{name}|g" "{f}"\n'
            script += "apt-get update\n"
            self.logln("rewriting sources (pkexec)…")
            self.stream(["pkexec", "/bin/sh", "-c", script])
            GLib.idle_add(self.scan)
        threading.Thread(target=worker, daemon=True).start()

    def _refresh_apply(self):
        """Nothing ticked anywhere -> nothing to apply. Grey the button out rather
        than leaving a live-looking control that would be a no-op."""
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
                ("  |  will REMOVE " + ", ".join(removes) if removes else "")))
            if extra:
                self.logln(f"   → unticking can't stop these. \"Hold back\" pins them with apt-mark hold.")
            GLib.idle_add(self._offer_hold, extra)
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
        self.hold_btn.set_sensitive(False)
        def work():
            self.logln("apt-mark hold (pkexec): " + ", ".join(pkgs))
            self.stream(["pkexec", "/usr/bin/apt-mark", "hold"] + pkgs)
            self.logln("held — apt will now refuse to upgrade them. Undo with: sudo apt-mark unhold " + " ".join(pkgs))
            GLib.idle_add(self.hold_btn.set_sensitive, True)
            GLib.idle_add(self.scan)
        threading.Thread(target=work, daemon=True).start()

    def scan(self):
        self.logln("scanning…")
        threading.Thread(target=lambda: GLib.idle_add(self.populate, gather()), daemon=True).start()

    def populate(self, d):
        for c in self.body.get_children(): self.body.remove(c)
        self.checks = {"gated": [], "flatpak": [], "apt": []}
        n_free = sum(1 for g in d["gated"] if g["kind"] == "flatpak")
        n_gated = sum(len(g["pkgs"]) for g in d["gated"]) + len(d["libs"])
        self.summary.set_text(f"{n_gated} gated  ·  {n_free} fixable free  ·  "
                              f"{len(d['flatpak'])} flatpak  ·  {len(d['apt'])} regular  ·  {len(d['held'])} held ✓")

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

        s = self._section("①  Gated fixes — free from the vendors (no Ubuntu Pro)")
        if not d["gated"] and not d["libs"]:
            s.pack_start(Gtk.Label(label="Nothing gated — you're clear.", xalign=0), False, False, 0)
        for g in d["gated"]:
            if g["kind"] == "flatpak":
                cb = Gtk.CheckButton(label=f"{g['base']}  →  Flathub {g['appid']}   (replaces {len(g['pkgs'])})")
                cb.set_active(True); cb.appid = g["appid"]
                cb.connect("toggled", lambda *_: self._refresh_apply())
                self.checks["gated"].append(cb); s.pack_start(cb, False, False, 0)
            elif g["kind"] == "note":
                s.pack_start(Gtk.Label(label="•  7-Zip 25.x  →  Debian / 7-zip.org (manual)", xalign=0), False, False, 0)
            elif g["kind"] == "free":
                lbl = Gtk.Label(xalign=0)
                if g["free_state"] == "installed":
                    lbl.set_markup(f"•  <b>{GLib.markup_escape_text(g['base'])}</b>  →  "
                                   f"<b>already fixed free</b> from {GLib.markup_escape_text(g['free_origin'])}"
                                   f"  <small><i>(pro still lists it — ignore that entry)</i></small>")
                else:
                    lbl.set_markup(f"•  <b>{GLib.markup_escape_text(g['base'])}</b>  →  "
                                   f"<b>fix available free</b> from {GLib.markup_escape_text(g['free_origin'])}"
                                   f"  <small><i>(a plain apt upgrade installs it — see section ③)</i></small>")
                lbl.set_line_wrap(True); s.pack_start(lbl, False, False, 0)
            else:
                s.pack_start(Gtk.Label(label=f"•  {g['base']}  →  no Flathub match (rebuild from source)", xalign=0), False, False, 0)
        if d["libs"]:
            s.pack_start(Gtk.Label(label=f"+  {len(d['libs'])} pure libs — no app swap", xalign=0), False, False, 0)

        s = self._section("②  Flatpak app updates")
        if d["flatpak"]:
            n_user = sum(1 for f in d["flatpak"] if f["scope"] == "user")
            n_sys = len(d["flatpak"]) - n_user
            scope_note = f"{n_user} user" + (f" · {n_sys} system — asks for a password" if n_sys else "")
            hdr = Gtk.Label(xalign=0)
            hdr.set_markup(f"<b>{len(d['flatpak'])}</b> update(s) available   <small>({scope_note})</small>")
            s.pack_start(hdr, False, False, 0)
            rows = [(f"{f['appid']}  {f['branch']}   [{f['scope']} · {'app' if f['kind'] == 'app' else 'runtime'}]",
                     {"ref": f["ref"], "scope": f["scope"]}, 0) for f in d["flatpak"]]
            self.checks["flatpak"] = self._checklist(s, "choose apps", rows)
            for cb in self.checks["flatpak"]: cb.connect("toggled", lambda *_: self._refresh_apply())
        else:
            s.pack_start(Gtk.Label(label="All Flatpaks up to date.", xalign=0), False, False, 0)

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
        else:
            s.pack_start(Gtk.Label(label="System up to date.", xalign=0), False, False, 0)
        if d["held"]:
            l = Gtk.Label(xalign=0)
            l.set_markup(f"<i>✓ {len(d['held'])} held &amp; respected — never upgraded: {GLib.markup_escape_text(', '.join(d['held']))}</i>")
            l.set_line_wrap(True); s.pack_start(l, False, False, 0)

        self._refresh_apply()
        self._offer_hold([])          # stale offer must not survive a rescan
        self.body.show_all(); self.logln("ready.")
        for line in d.get("sources", []): self.logln(line)
        if d.get("insecure"):
            self.logln("⛔ POLICY: https-only. Plaintext source(s) below will NOT be used.")
            self.logln("   (packages are still GPG-signed and hash-verified over http — what plaintext")
            self.logln("    leaks is WHICH packages and versions you fetch, not their integrity.)")
            for h in d["insecure"]: self.logln(f"     {h}")
            self.logln("   fix: sudo sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources"
                       " && sudo apt update")

    def stream(self, cmd):
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in p.stdout: self.logln("  " + line.rstrip())
            p.wait()
        except Exception as e:
            self.logln(f"  error: {e}")

    def on_apply(self, *_):
        gated = [cb.appid for cb in self.checks["gated"] if cb.get_active()]
        flat_sel = [(cb.scope, cb.ref) for cb in self.checks["flatpak"] if cb.get_active()]
        flat_tot = {sc: sum(1 for cb in self.checks["flatpak"] if cb.scope == sc) for sc in ("user", "system")}
        apt_pkgs = [cb.pkgname for cb in self.checks["apt"] if cb.get_active()]
        apt_all = bool(apt_pkgs) and len(apt_pkgs) == len(self.checks["apt"])
        self.apply_btn.set_sensitive(False)

        def worker():
            if gated:
                if not have("flatpak"):
                    self.logln("installing flatpak (pkexec)…")
                    self.stream(["pkexec", "/usr/bin/apt-get", "install", "-y", "flatpak"])
                run(["flatpak", "remote-add", "--user", "--if-not-exists", "flathub", FLATHUB])
                for appid in gated:
                    self.logln(f"flatpak install {appid} …")
                    self.stream(["flatpak", "install", "--user", "-y", "flathub", appid])
            for scope in ("user", "system"):
                refs = [r for sc, r in flat_sel if sc == scope]
                if not refs: continue
                # whole scope selected -> plain update; otherwise name the exact refs,
                # so an unticked app is left alone instead of swept up by a blanket update.
                whole = len(refs) == flat_tot[scope]
                self.logln(f"flatpak [{scope}]: updating {len(refs)} ref(s)"
                           + ("" if whole else " (selected only)")
                           + (" — password prompt" if scope == "system" else "") + " …")
                self.stream(["flatpak", "update", "--" + scope, "-y"] + ([] if whole else refs))
            # NB: a local copy. Rebinding the enclosing `apt_pkgs` here would make the
            # name local to worker() for its whole body, and the read above it would
            # then raise UnboundLocalError before the apt phase ever started.
            pkgs = list(apt_pkgs)
            if pkgs:
                bad = sorted(h for h in apt_uri_hosts(pkgs) if not is_secure(h))
                if bad:
                    self.logln("⛔ REFUSING the apt phase — plaintext source(s): " + ", ".join(bad))
                    self.logln("   policy is https-only. Fix the sources, hit refresh, and re-apply:")
                    self.logln("   sudo sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources"
                               " && sudo apt update")
                    pkgs = []
            if pkgs:
                if not apt_all:
                    # last line of defence: ask apt what it would ACTUALLY do with this
                    # selection, and name anything unticked it still intends to upgrade.
                    sim = run(["apt-get", "-s", "install", "--only-upgrade"] + pkgs)
                    plans = {l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Inst ")}
                    extra = sorted(plans - set(pkgs))
                    removes = sorted(l.split()[1] for l in sim.stdout.splitlines() if l.startswith("Remv "))
                    if extra: self.logln("⚠ apt will also upgrade (required by your selection): " + ", ".join(extra))
                    if removes: self.logln("⚠ apt will REMOVE: " + ", ".join(removes))
                    if not extra and not removes: self.logln("pre-flight: selection is exact — nothing else pulled in ✓")
                self.logln(f"apt: upgrading {len(pkgs)} package(s) (pkexec — holds honored)…")
                inner = ("apt-get update && apt-get upgrade -y" if apt_all
                         else "apt-get update && apt-get install --only-upgrade -y " + " ".join(pkgs))
                self.stream(["pkexec", "/bin/sh", "-c", "export DEBIAN_FRONTEND=noninteractive; " + inner])
            self.logln("✅ done.")

        def guarded():
            # a bare thread that raises just dies: no error, no "done.", button stuck.
            # surface the traceback in the output pane instead of losing it to stderr.
            try:
                worker()
            except Exception:
                import traceback
                self.logln("💥 internal error — the run stopped here:")
                for ln in traceback.format_exc().rstrip().splitlines(): self.logln("   " + ln)
            finally:
                GLib.idle_add(self.scan)   # the rescan re-enables it only if work remains

        threading.Thread(target=guarded, daemon=True).start()

if __name__ == "__main__":
    w = App(); w.connect("destroy", Gtk.main_quit); w.show_all(); Gtk.main()
