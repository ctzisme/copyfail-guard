import unittest
from pathlib import Path

from copyfail_guard.modules import (
    BlacklistResult,
    find_blacklist,
    gather_status,
    is_builtin,
    is_in_container,
    is_in_sysfs,
    is_loadable,
    is_loaded,
)
from copyfail_guard.system import SystemContext

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(name: str, release: str) -> SystemContext:
    return SystemContext(
        root=FIXTURES / name,
        uname_release=release,
        is_linux=False,  # avoid the live `modprobe --showconfig` path
    )


class IsLoadedTests(unittest.TestCase):
    def test_ubuntu_has_module_loaded(self):
        self.assertTrue(is_loaded(_ctx("ubuntu2404", "6.8.0-50-generic")))

    def test_mitigated_has_module_unloaded(self):
        self.assertFalse(is_loaded(_ctx("ubuntu2404-mitigated", "6.8.0-50-generic")))

    def test_substring_match_does_not_false_positive(self):
        # /proc/modules has 'af_alg' but not 'algif_aead' as the row name in mitigated fixture.
        # Confirm we match on first whitespace-delimited token, not substring.
        self.assertFalse(is_loaded(_ctx("ubuntu2404-mitigated", "6.8.0-50-generic")))

    def test_missing_proc_modules_returns_false(self):
        self.assertFalse(is_loaded(_ctx("nonexistent", "any")))


class IsInSysfsTests(unittest.TestCase):
    def test_present(self):
        self.assertTrue(is_in_sysfs(_ctx("ubuntu2404", "6.8.0-50-generic")))

    def test_absent(self):
        self.assertFalse(is_in_sysfs(_ctx("no-module", "6.8.0-stripped")))


class IsBuiltinTests(unittest.TestCase):
    def test_builtin_kernel(self):
        self.assertTrue(is_builtin(_ctx("builtin-kernel", "6.8.0-builtin")))

    def test_loadable_kernel_not_builtin(self):
        self.assertFalse(is_builtin(_ctx("ubuntu2404", "6.8.0-50-generic")))

    def test_no_module_at_all(self):
        self.assertFalse(is_builtin(_ctx("no-module", "6.8.0-stripped")))


class IsLoadableTests(unittest.TestCase):
    def test_ubuntu_has_ko(self):
        self.assertTrue(is_loadable(_ctx("ubuntu2404", "6.8.0-50-generic")))

    def test_xz_compressed_ko(self):
        # Fedora ships .ko.xz — must still match.
        self.assertTrue(is_loadable(_ctx("fedora41", "6.11.4-301.fc41.x86_64")))

    def test_zst_compressed_ko(self):
        self.assertTrue(is_loadable(_ctx("sles16", "6.4.0-150600.23.42-default")))

    def test_builtin_kernel_has_no_ko(self):
        self.assertFalse(is_loadable(_ctx("builtin-kernel", "6.8.0-builtin")))

    def test_stripped_kernel_has_no_ko(self):
        self.assertFalse(is_loadable(_ctx("no-module", "6.8.0-stripped")))


class FindBlacklistTests(unittest.TestCase):
    def test_no_blacklist_in_default_ubuntu(self):
        r = find_blacklist(_ctx("ubuntu2404", "6.8.0-50-generic"))
        self.assertFalse(r.blacklisted)
        self.assertIsNone(r.method)

    def test_install_false_is_strong_mitigation(self):
        r = find_blacklist(_ctx("ubuntu2404-mitigated", "6.8.0-50-generic"))
        self.assertTrue(r.blacklisted)
        self.assertEqual(r.method, "install_false")
        self.assertIn("cve-2026-31431-copyfail-guard.conf", r.config_file)

    def test_plain_blacklist_directive(self):
        # Construct an ad-hoc fixture for "blacklist algif_aead" only
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "etc" / "modprobe.d"
            d.mkdir(parents=True)
            (d / "site.conf").write_text("blacklist algif_aead\n")
            ctx = SystemContext(root=Path(tmp), uname_release="x", is_linux=False)
            r = find_blacklist(ctx)
            self.assertTrue(r.blacklisted)
            self.assertEqual(r.method, "blacklist")

    def test_inline_comment_is_stripped(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "etc" / "modprobe.d"
            d.mkdir(parents=True)
            (d / "x.conf").write_text("install algif_aead /bin/false  # CVE-2026-31431\n")
            ctx = SystemContext(root=Path(tmp), uname_release="x", is_linux=False)
            r = find_blacklist(ctx)
            self.assertTrue(r.blacklisted)
            self.assertEqual(r.method, "install_false")

    def test_install_redirect_to_unrelated_command_still_flagged(self):
        # `install algif_aead /sbin/some_other` is not /bin/false but still overrides default load.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "etc" / "modprobe.d"
            d.mkdir(parents=True)
            (d / "x.conf").write_text("install algif_aead /sbin/log_attempt\n")
            ctx = SystemContext(root=Path(tmp), uname_release="x", is_linux=False)
            r = find_blacklist(ctx)
            self.assertTrue(r.blacklisted)
            self.assertEqual(r.method, "install_redirect")


class FindBlacklistShowconfigTests(unittest.TestCase):
    """Cover the live-system path: ``modprobe --showconfig`` is authoritative
    when it succeeds — we must NOT also scan conf dirs (that would let a stale
    .conf in a directory modprobe ignores produce a false positive)."""

    def _runner_returning(self, stdout: str, returncode: int = 0):
        import subprocess

        def runner(args, **_kwargs):
            return subprocess.CompletedProcess(
                args=args, returncode=returncode, stdout=stdout, stderr=""
            )

        return runner

    def test_showconfig_says_no_blacklist_overrides_dir_scan(self):
        # Context: root=/ + is_linux=True triggers the showconfig path.
        # If showconfig returns no rules, find_blacklist must report False
        # even if a stray conf file would suggest otherwise.
        ctx = SystemContext(
            root=Path("/"),
            uname_release="6.8.0-test",
            runner=self._runner_returning("# nothing relevant here\n"),
            is_linux=True,
        )
        r = find_blacklist(ctx, "algif_aead")
        self.assertFalse(r.blacklisted)
        self.assertIsNone(r.method)

    def test_showconfig_finds_install_false(self):
        ctx = SystemContext(
            root=Path("/"),
            uname_release="6.8.0-test",
            runner=self._runner_returning("install algif_aead /bin/false\n"),
            is_linux=True,
        )
        r = find_blacklist(ctx, "algif_aead")
        self.assertTrue(r.blacklisted)
        self.assertEqual(r.method, "install_false")


class GatherStatusTests(unittest.TestCase):
    def test_combined(self):
        s = gather_status(_ctx("ubuntu2404", "6.8.0-50-generic"))
        self.assertTrue(s.loaded)
        self.assertFalse(s.builtin)
        self.assertTrue(s.loadable)
        self.assertTrue(s.in_sysfs)
        self.assertFalse(s.blacklist.blacklisted)


class IsInContainerTests(unittest.TestCase):
    def test_dockerenv_marker(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".dockerenv").touch()
            ctx = SystemContext(root=Path(tmp), uname_release="x", is_linux=False)
            self.assertTrue(is_in_container(ctx))

    def test_cgroup_marker(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "proc" / "1"
            proc.mkdir(parents=True)
            (proc / "cgroup").write_text("0::/docker/abc123\n")
            ctx = SystemContext(root=Path(tmp), uname_release="x", is_linux=False)
            self.assertTrue(is_in_container(ctx))

    def test_clean_root_is_not_container(self):
        ctx = _ctx("ubuntu2404", "6.8.0-50-generic")
        self.assertFalse(is_in_container(ctx))


class BlacklistResultDataclassTests(unittest.TestCase):
    def test_immutable(self):
        r = BlacklistResult(True, "install_false", "/etc/x.conf")
        with self.assertRaises(Exception):
            r.blacklisted = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
