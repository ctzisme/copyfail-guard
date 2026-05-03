import unittest
from pathlib import Path

from copyfail_guard.detector import EXIT_CODES, Verdict, detect
from copyfail_guard.system import SystemContext

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(name: str, release: str, *, is_linux: bool = True) -> SystemContext:
    return SystemContext(
        root=FIXTURES / name,
        uname_release=release,
        is_linux=is_linux,
    )


class DetectVerdictMatrixTests(unittest.TestCase):
    """One row per scenario in the planned verdict matrix."""

    def test_ubuntu_default_is_vulnerable(self):
        r = detect(_ctx("ubuntu2404", "6.8.0-50-generic"))
        self.assertEqual(r.verdict, Verdict.VULNERABLE)
        self.assertEqual(r.exit_code, 1)
        self.assertEqual(r.distro.family, "debian")
        self.assertTrue(r.module.loaded)
        self.assertFalse(r.module.builtin)
        self.assertEqual(r.kernel_class.patched_threshold, "6.12.85")

    def test_ubuntu_mitigated_with_install_false(self):
        r = detect(_ctx("ubuntu2404-mitigated", "6.8.0-50-generic"))
        self.assertEqual(r.verdict, Verdict.MITIGATED)
        self.assertEqual(r.exit_code, 0)
        self.assertEqual(r.module.blacklist.method, "install_false")
        # Should NOT include the weak-blacklist note.
        self.assertFalse(any("more robust" in n for n in r.notes))

    def test_ubuntu_kernel_above_threshold_is_patched(self):
        # 6.6.137 is the patched threshold of the 6.6 branch — but our fixture's lib/modules
        # dir is named 6.8.0-50-generic, so we have to pretend uname says 6.6.137. We'll
        # craft a scenario with a fixture that reports a patched release.
        # Quick reuse: use ubuntu2404-patched fixture which has only modules.dep entry but
        # we'll claim the running kernel is 6.6.200.
        r = detect(
            SystemContext(
                root=FIXTURES / "ubuntu2404-patched",
                uname_release="6.6.200-generic",
                is_linux=True,
            )
        )
        # ubuntu2404-patched fixture has the dep entry under 6.8.0-50-generic, so for
        # release 6.6.200 the loadable check returns False (different modules dir).
        # That yields not_applicable. Let's instead set up a temp fixture.

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text(
                "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04\n"
            )
            (base / "proc").mkdir()
            (base / "proc" / "modules").write_text("ext4 999 1 - Live 0\n")
            mod_dir = base / "lib" / "modules" / "6.6.200-generic"
            mod_dir.mkdir(parents=True)
            (mod_dir / "modules.dep").write_text("kernel/crypto/algif_aead.ko:\n")
            (mod_dir / "modules.builtin").write_text("")
            r = detect(SystemContext(root=base, uname_release="6.6.200-generic", is_linux=True))
            self.assertEqual(r.verdict, Verdict.PATCHED)
            self.assertEqual(r.exit_code, 0)

    def test_builtin_kernel_is_unmitigable(self):
        r = detect(_ctx("builtin-kernel", "6.8.0-builtin"))
        self.assertEqual(r.verdict, Verdict.UNMITIGABLE_BUILTIN)
        self.assertEqual(r.exit_code, 1)
        self.assertTrue(r.module.builtin)
        self.assertFalse(r.module.loadable)
        self.assertTrue(any("compiled into the kernel" in n for n in r.notes))

    def test_no_module_is_not_applicable(self):
        r = detect(_ctx("no-module", "6.8.0-stripped"))
        self.assertEqual(r.verdict, Verdict.NOT_APPLICABLE)
        self.assertEqual(r.exit_code, 0)

    def test_non_linux_is_unknown(self):
        r = detect(_ctx("ubuntu2404", "6.8.0-50-generic", is_linux=False))
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.exit_code, 2)

    def test_unparseable_release_is_unknown(self):
        ctx = SystemContext(root=FIXTURES / "ubuntu2404", uname_release="garbage", is_linux=True)
        r = detect(ctx)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.exit_code, 2)

    def test_kernel_below_coverage_is_unknown(self):
        ctx = SystemContext(
            root=FIXTURES / "ubuntu2404", uname_release="3.10.0-1160.el7", is_linux=True
        )
        r = detect(ctx)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.exit_code, 2)
        self.assertTrue(any("outside the CVE-2026-31431 coverage table" in n for n in r.notes))

    def test_weak_blacklist_emits_note(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=debian\n")
            (base / "etc" / "modprobe.d").mkdir()
            (base / "etc" / "modprobe.d" / "site.conf").write_text("blacklist algif_aead\n")
            (base / "proc").mkdir()
            (base / "proc" / "modules").write_text("")
            mod = base / "lib" / "modules" / "6.8.0"
            mod.mkdir(parents=True)
            (mod / "modules.dep").write_text("kernel/crypto/algif_aead.ko:\n")
            (mod / "modules.builtin").write_text("")
            r = detect(SystemContext(root=base, uname_release="6.8.0", is_linux=True))
            self.assertEqual(r.verdict, Verdict.MITIGATED)
            self.assertTrue(any("more robust" in n for n in r.notes))

    def test_container_emits_note(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            (base / ".dockerenv").touch()
            (base / "proc").mkdir()
            (base / "proc" / "modules").write_text("algif_aead 16384 0 - Live 0\n")
            mod = base / "lib" / "modules" / "6.8.0"
            mod.mkdir(parents=True)
            (mod / "modules.dep").write_text("kernel/crypto/algif_aead.ko:\n")
            (mod / "modules.builtin").write_text("")
            r = detect(SystemContext(root=base, uname_release="6.8.0", is_linux=True))
            self.assertEqual(r.verdict, Verdict.VULNERABLE)
            self.assertTrue(r.in_container)
            self.assertTrue(any("inside a container" in n for n in r.notes))


class ExitCodeContractTests(unittest.TestCase):
    def test_user_promised_codes(self):
        self.assertEqual(EXIT_CODES[Verdict.PATCHED], 0)
        self.assertEqual(EXIT_CODES[Verdict.MITIGATED], 0)
        self.assertEqual(EXIT_CODES[Verdict.NOT_APPLICABLE], 0)
        self.assertEqual(EXIT_CODES[Verdict.VULNERABLE], 1)
        self.assertEqual(EXIT_CODES[Verdict.UNMITIGABLE_BUILTIN], 1)
        self.assertEqual(EXIT_CODES[Verdict.UNKNOWN], 2)


if __name__ == "__main__":
    unittest.main()
