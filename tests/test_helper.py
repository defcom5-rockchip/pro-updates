# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for pro-updates-helper that need no root: apt and dpkg never change anything
(the helper's run() is replaced by a recorder), and every path points into a temp dir.
The "is it installed" check asks the real dpkg-query of the build machine for bash and
coreutils (essential packages), and nothing else.

    python3 -m unittest discover -s tests
"""
import importlib.machinery, importlib.util, os, subprocess, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
loader = importlib.machinery.SourceFileLoader("helper", os.path.join(HERE, "..", "pro-updates-helper"))
spec = importlib.util.spec_from_loader("helper", loader)
H = importlib.util.module_from_spec(spec)
loader.exec_module(H)
REAL_INSTALLED = H.installed_names


def slurp(path):
    with open(path) as fh: return fh.read()


def spit(path, text):
    with open(path, "w") as fh: fh.write(text)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.calls = []
        self.rc = 0
        self.saved = {k: getattr(H, k) for k in ("run", "installed_names", "system_holds", "codename", "source_files",
                                                 "known_to_dpkg", "LOG")}
        H.run = lambda cmd: (self.calls.append(cmd), self.rc)[1]
        H.installed_names = H.valid_names          # the real check is tested on its own below
        H.system_holds = lambda: set()
        H.known_to_dpkg = lambda name: True
        H.STATE = os.path.join(t, "lib")
        H.HOLDS = os.path.join(H.STATE, "holds")
        H.REFRESHED = os.path.join(H.STATE, "last-refresh")
        H.STAGE = os.path.join(t, "stage")
        H.BACKUPS = os.path.join(t, "backups")
        H.SOURCES_DIR = os.path.join(t, "sources.list.d"); os.makedirs(H.SOURCES_DIR)
        H.PREFS_DIR = os.path.join(t, "preferences.d"); os.makedirs(H.PREFS_DIR)
        H.VENDOR_PINS = os.path.join(t, "share", "00-pidesktop-browsers")
        H.VENDOR_PINS_DEST = os.path.join(H.PREFS_DIR, "00-pidesktop-browsers")
        H.codename = lambda: "resolute"
        H.source_files = lambda: [os.path.join(H.SOURCES_DIR, n) for n in sorted(os.listdir(H.SOURCES_DIR))]

    def tearDown(self):
        for k, v in self.saved.items(): setattr(H, k, v)
        self.tmp.cleanup()

    def die_code(self, fn, *args):
        with self.assertRaises(SystemExit) as cm:
            fn(*args)
        return cm.exception.code


class Names(Base):
    def test_good_names(self):
        for n in ("bluez", "libpng16-16t64", "g++", "libstdc++6", "gir1.2-gtk-3.0", "libc6:arm64"):
            self.assertEqual(H.valid_names([n]), [n])

    def test_bad_names_never_reach_apt(self):
        for n in ("x; rm -rf /", "--allow-unauthenticated", "-y", "--", "Foo", "a", "a b", "$(id)", "x'y",
                  "../x", "", "bash\n", "lib*", "l?", "[a]x"):
            self.assertEqual(self.die_code(H.valid_names, [n]), 2, repr(n))
        self.assertEqual(self.calls, [])

    def test_installed_check_stops_apt_regex_expansion(self):
        H.installed_names = REAL_INSTALLED
        self.assertEqual(H.installed_names(["bash", "coreutils"]), ["bash", "coreutils"])
        # apt-get/apt-mark would expand these as regular expressions; dpkg-query does not
        for n in ("bas.", "l.", "coreutil.+", "no-such-package-pu"):
            self.assertEqual(self.die_code(H.installed_names, [n]), 2, n)

    def test_upgrade_argv(self):
        self.assertEqual(H.cmd_upgrade(["bluez", "sudo"]), 0)
        self.assertEqual(self.calls[0][:2], [H.APT_GET, "update"])
        up = self.calls[1]
        self.assertEqual(up[:5], [H.APT_GET, "install", "--only-upgrade", "-y", "--no-remove"])
        self.assertIn("DPkg::Lock::Timeout=300", up)
        self.assertIn("Dpkg::Options::=--force-confold", up)
        self.assertEqual(up[up.index("--"):], ["--", "bluez", "sudo"])
        self.assertTrue(os.path.exists(H.REFRESHED))

    def test_upgrade_stops_when_update_fails(self):
        self.rc = 100
        self.assertEqual(H.cmd_upgrade(["bluez"]), 100)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(os.path.exists(H.REFRESHED))

    def test_upgrade_all_never_removes(self):
        H.cmd_upgrade_all([])
        self.assertIn("--no-remove", self.calls[1])


class Holds(Base):
    def test_hold_records_and_unhold_only_ours(self):
        self.assertEqual(H.cmd_hold(["bluez"]), 0)
        self.assertEqual(self.calls[-1], [H.APT_MARK, "hold", "--", "bluez"])
        self.assertEqual(H.read_holds(), ["bluez"])
        # a hold the system made (mpv, say) cannot be released through the helper
        self.assertEqual(self.die_code(H.cmd_unhold, ["mpv"]), 2)
        self.assertEqual(H.cmd_unhold(["bluez"]), 0)
        self.assertEqual(self.calls[-1], [H.APT_MARK, "unhold", "--", "bluez"])
        self.assertEqual(H.read_holds(), [])

    def test_holding_a_system_hold_does_not_make_it_ours(self):
        H.system_holds = lambda: {"mpv"}
        self.assertEqual(H.cmd_hold(["mpv", "bluez"]), 0)
        self.assertEqual(H.read_holds(), ["bluez"])
        self.assertEqual(self.die_code(H.cmd_unhold, ["mpv"]), 2)

    def test_unhold_of_a_vanished_package_only_cleans_the_record(self):
        H.cmd_hold(["bluez", "gone-pkg"]); self.calls.clear()
        H.known_to_dpkg = lambda name: name != "gone-pkg"
        self.assertEqual(H.cmd_unhold(["gone-pkg"]), 0)
        self.assertEqual(self.calls, [])                    # apt-mark would expand the name as a pattern
        self.assertEqual(H.read_holds(), ["bluez"])

    def test_failed_hold_is_not_recorded(self):
        self.rc = 1
        H.cmd_hold(["bluez"])
        self.assertEqual(H.read_holds(), [])


class Deb(Base):
    def make_deb(self, name):
        root = os.path.join(self.tmp.name, "pkg"); os.makedirs(os.path.join(root, "DEBIAN"), exist_ok=True)
        spit(os.path.join(root, "DEBIAN", "control"),
             f"Package: {name}\nVersion: 1.0\nArchitecture: all\nMaintainer: t <t@example.org>\nDescription: t\n")
        out = os.path.join(self.tmp.name, f"{name}_1.0_all.deb")
        subprocess.run(["dpkg-deb", "--root-owner-group", "-b", root, out], check=True, capture_output=True)
        return out

    def test_install_deb_checks_path_and_package_on_a_staged_copy(self):
        deb = self.make_deb("hello-pu")
        self.assertEqual(self.die_code(H.cmd_install_deb, ["relative.deb"]), 2)
        self.assertEqual(self.die_code(H.cmd_install_deb, ["/etc/passwd"]), 2)
        self.assertEqual(self.die_code(H.cmd_install_deb, [deb, "other-pkg"]), 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(H.cmd_install_deb([deb, "hello-pu"]), 0)
        installed = self.calls[0][-1]
        self.assertEqual(self.calls[0][-2], "--")
        self.assertTrue(installed.startswith(H.STAGE + os.sep), installed)      # the copy, not the user's file
        self.assertEqual(os.path.basename(installed), os.path.basename(deb))
        self.assertEqual(os.listdir(H.STAGE), [])                              # staging dir removed
        self.assertIn("--no-remove", self.calls[0])
        self.assertEqual(self.calls[1], [H.APT_MARK, "hold", "--", "hello-pu"])

    def test_install_deb_refuses_symlinks_to_other_files_and_fifos(self):
        secret = os.path.join(self.tmp.name, "secret"); spit(secret, "s"); os.chmod(secret, 0o600)
        link = os.path.join(self.tmp.name, "evil.deb"); os.symlink(secret, link)
        self.assertEqual(self.die_code(H.cmd_install_deb, [link]), 2)       # resolves to a non-.deb
        fifo = os.path.join(self.tmp.name, "pipe.deb"); os.mkfifo(fifo)
        self.assertEqual(self.die_code(H.cmd_install_deb, [fifo]), 2)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(H.STAGE) and os.listdir(H.STAGE))


class Https(Base):
    def test_rewrites_only_that_host_and_backs_up(self):
        f = os.path.join(H.SOURCES_DIR, "armbian.sources")
        spit(f, "Types: deb\nURIs: http://apt.armbian.com\nSuites: resolute\n"
                "# http://apt.armbian.com.example.org stays\nURIs: http://other.example.org/x\n")
        os.chmod(f, 0o644)
        self.assertEqual(H.cmd_https_sources(["apt.armbian.com"]), 0)
        text = slurp(f)
        self.assertIn("URIs: https://apt.armbian.com\n", text)
        self.assertIn("http://apt.armbian.com.example.org", text)
        self.assertIn("http://other.example.org/x", text)
        self.assertEqual(os.stat(f).st_mode & 0o777, 0o644)
        bdirs = os.listdir(H.BACKUPS)
        self.assertEqual(len(bdirs), 1)
        self.assertIn("http://apt.armbian.com\n", slurp(os.path.join(H.BACKUPS, bdirs[0], "armbian.sources")))
        self.assertEqual(self.calls[-1][:2], [H.APT_GET, "update"])

    def test_failed_update_restores_the_files(self):
        f = os.path.join(H.SOURCES_DIR, "ubuntu.sources")
        spit(f, "URIs: http://ports.ubuntu.com/\n")
        self.rc = 100
        self.assertEqual(H.cmd_https_sources(["ports.ubuntu.com"]), 100)
        self.assertEqual(slurp(f), "URIs: http://ports.ubuntu.com/\n")

    def test_symlinked_source_keeps_its_link(self):
        real = os.path.join(self.tmp.name, "real.sources")
        spit(real, "URIs: http://ports.ubuntu.com/\n")
        link = os.path.join(H.SOURCES_DIR, "ubuntu.sources")
        os.symlink(real, link)
        self.assertEqual(H.cmd_https_sources(["ports.ubuntu.com"]), 0)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(slurp(real), "URIs: https://ports.ubuntu.com/\n")

    def test_bad_hosts(self):
        for h in ("apt.armbian.com/evil", "a b", "-x", "host|sed", "", "http://x", "apt.armbian.com\n"):
            self.assertEqual(self.die_code(H.cmd_https_sources, [h]), 2, repr(h))


class Pins(Base):
    def test_repair_copies_shipped_file_and_drops_component(self):
        os.makedirs(os.path.dirname(H.VENDOR_PINS))
        spit(H.VENDOR_PINS, "Package: chromium\nPin: release o=LP-PPA-xtradeb-apps\nPin-Priority: 1001\n")
        for n in ("armbian-desktops", "pidesktop-browsers"):
            spit(os.path.join(H.PREFS_DIR, n), "old\n")
        src = os.path.join(H.SOURCES_DIR, "armbian.sources")
        spit(src, "Types: deb\nComponents: main resolute-utils resolute-desktop\n")
        self.assertEqual(H.cmd_repair_pins([]), 0)
        self.assertEqual(slurp(H.VENDOR_PINS_DEST), slurp(H.VENDOR_PINS))
        self.assertEqual(sorted(os.listdir(H.PREFS_DIR)), ["00-pidesktop-browsers"])
        self.assertIn("Components: main resolute-utils\n", slurp(src))
        self.assertEqual(self.calls[-1][:2], [H.APT_GET, "update"])

    def test_component_edge_cases(self):
        f = H.drop_desktop_component
        self.assertEqual(f("Components: resolute-desktop\n", "resolute"), "Components: resolute-desktop\n")  # never empty
        self.assertEqual(f("components: main resolute-desktop\n", "resolute"), "components: main\n")
        self.assertEqual(f("Components: resolute-desktop main\n", "resolute"), "Components: main\n")
        self.assertEqual(f("Components: main\n", "resolute"), "Components: main\n")
        self.assertEqual(f("Components: main resolute-desktop", "resolute"), "Components: main")

    def test_no_pin_file_no_repair(self):
        self.assertEqual(self.die_code(H.cmd_repair_pins, []), 2)


class Log(Base):
    def test_full_log_disk_never_stops_a_job(self):
        H.run = self.saved["run"]
        H.LOG = "/dev/full"                                  # every write fails with ENOSPC
        fchmod = H.os.fchmod
        H.os.fchmod = lambda fd, mode: None                  # as a normal user, fchmod on /dev/full is EPERM
        try:
            log = H._log_open()
            self.assertIsNotNone(log, "the log must open, so the write-error path is what gets tested")
            log.close()
            # buffered writes to /dev/full only fail when the buffer is flushed at close
            self.assertEqual(H.run(["sh", "-c", "for i in $(seq 1 5000); do echo line $i; done"]), 0)
            self.assertEqual(H.LAST[-1], "line 5000")
        finally:
            H.os.fchmod = fchmod

    def test_a_failing_log_write_is_dropped_not_raised(self):
        class Broken:
            closed = False
            def write(self, data): raise OSError(28, "No space left on device")
            def close(self): self.closed = True
        log = Broken()
        self.assertIsNone(H._log_write(log, b"x"))
        self.assertTrue(log.closed)
        self.assertIsNone(H._log_write(None, b"x"))


class Outlive(unittest.TestCase):
    def test_parent_death_signal_is_cancelled(self):
        """pkexec's PR_SET_PDEATHSIG must not survive into the helper (closing the window
        would SIGTERM it mid-run)."""
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        code = ("import ctypes, importlib.machinery, importlib.util;"
                "libc=ctypes.CDLL(None); libc.prctl(1, 15, 0, 0, 0);"
                f"l=importlib.machinery.SourceFileLoader('h', {os.path.join(HERE, '..', 'pro-updates-helper')!r});"
                "s=importlib.util.spec_from_loader('h', l); h=importlib.util.module_from_spec(s); l.exec_module(h);"
                "h.outlive_the_window(); v=ctypes.c_int(); libc.prctl(2, ctypes.byref(v), 0, 0, 0); print(v.value)")
        out = subprocess.run(["python3", "-c", code], capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "0")
        self.assertTrue(libc)


class Pipe(unittest.TestCase):
    def test_closed_window_does_not_kill_the_command(self):
        """The window's end of the pipe closes mid-run: the command must still finish."""
        code = ("import importlib.machinery, importlib.util, sys;"
                f"l=importlib.machinery.SourceFileLoader('h', {os.path.join(HERE, '..', 'pro-updates-helper')!r});"
                "s=importlib.util.spec_from_loader('h', l); h=importlib.util.module_from_spec(s); l.exec_module(h);"
                "h.LOG='/nonexistent/pu.log';"
                "rc=h.run(['sh','-c','for i in $(seq 1 2000); do echo line $i; done; touch \"$0\"', sys.argv[1]]);"
                "open(sys.argv[1]+'.rc','w').write(str(rc))")
        with tempfile.TemporaryDirectory() as t:
            done = os.path.join(t, "done")
            p = subprocess.Popen(["python3", "-c", code, done], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p.stdout.readline(); p.stdout.close()          # read one line, then go away
            p.wait(timeout=30)
            self.assertTrue(os.path.exists(done), "the command was killed when the reader went away")
            self.assertEqual(slurp(done + ".rc"), "0")


if __name__ == "__main__":
    unittest.main()
