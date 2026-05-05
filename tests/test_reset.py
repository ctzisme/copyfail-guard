import tempfile
import unittest
from pathlib import Path

from copyfail_guard.fixer import AUDIT_LOG, CONF_DIR, CONF_FILENAME, apply_reset
from copyfail_guard.system import SystemContext


def _ctx(tmp: Path, *, geteuid=lambda: 0, is_linux: bool = True) -> SystemContext:
    return SystemContext(
        root=tmp,
        uname_release="6.8.0-50-generic",
        geteuid=geteuid,
        is_linux=is_linux,
    )


def _write_conf(base: Path) -> Path:
    conf = base / CONF_DIR / CONF_FILENAME
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("install algif_aead /bin/false\n")
    return conf


class ResetHappyPathTests(unittest.TestCase):
    def test_removes_conf_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            conf = _write_conf(base)
            r = apply_reset(_ctx(base))
            self.assertTrue(r.success)
            self.assertTrue(r.removed)
            self.assertFalse(conf.exists())

    def test_appends_audit_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_conf(base)
            apply_reset(_ctx(base))
            log = base / AUDIT_LOG
            self.assertTrue(log.is_file())
            self.assertIn("reset", log.read_text())

    def test_idempotent_when_file_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            r = apply_reset(_ctx(base))
            self.assertTrue(r.success)
            self.assertFalse(r.removed)

    def test_idempotent_second_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_conf(base)
            apply_reset(_ctx(base))
            r2 = apply_reset(_ctx(base))
            self.assertTrue(r2.success)
            self.assertFalse(r2.removed)

    def test_path_field_matches_conf_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            r = apply_reset(_ctx(base))
            self.assertIn(CONF_FILENAME, r.path)


class ResetDryRunTests(unittest.TestCase):
    def test_dry_run_does_not_remove_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            conf = _write_conf(base)
            r = apply_reset(_ctx(base), dry_run=True)
            self.assertTrue(r.success)
            self.assertTrue(r.dry_run)
            self.assertTrue(r.removed)   # would remove
            self.assertTrue(conf.exists())  # not actually removed

    def test_dry_run_when_absent_reports_not_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            r = apply_reset(_ctx(base), dry_run=True)
            self.assertTrue(r.success)
            self.assertFalse(r.removed)

    def test_dry_run_writes_no_audit_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_conf(base)
            apply_reset(_ctx(base), dry_run=True)
            self.assertFalse((base / AUDIT_LOG).exists())


class ResetPrecheckTests(unittest.TestCase):
    def test_non_linux_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = apply_reset(_ctx(Path(tmp), is_linux=False))
            self.assertFalse(r.success)
            self.assertIn("Linux", r.error or "")

    def test_container_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / ".dockerenv").touch()
            r = apply_reset(_ctx(base))
            self.assertFalse(r.success)
            self.assertIn("container", r.error or "")

    def test_non_root_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            r = apply_reset(_ctx(base, geteuid=lambda: 1000))
            self.assertFalse(r.success)
            self.assertIn("root", r.error or "")

    def test_non_root_with_dry_run_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            r = apply_reset(_ctx(base, geteuid=lambda: 1000), dry_run=True)
            self.assertTrue(r.success)


if __name__ == "__main__":
    unittest.main()
