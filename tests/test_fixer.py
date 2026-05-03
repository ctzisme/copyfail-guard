import subprocess
import unittest
from pathlib import Path

from copyfail_guard.fixer import (
    AUDIT_LOG,
    CONF_BODY,
    CONF_DIR,
    CONF_FILENAME,
    apply_fix,
)
from copyfail_guard.system import SystemContext


class FakeRunner:
    """Records subprocess.run-style calls and returns canned responses."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        return subprocess.CompletedProcess(
            args=args, returncode=self.returncode, stdout=self.stdout, stderr=self.stderr
        )


def _ctx(tmp: Path, *, runner=None, geteuid=lambda: 0, is_linux: bool = True) -> SystemContext:
    return SystemContext(
        root=tmp,
        uname_release="6.8.0-50-generic",
        runner=runner if runner is not None else FakeRunner(),
        geteuid=geteuid,
        is_linux=is_linux,
    )


class ApplyFixHappyPathTests(unittest.TestCase):
    def test_writes_conf_with_expected_body(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\nID_LIKE=debian\n")

            runner = FakeRunner(returncode=0)
            r = apply_fix(_ctx(base, runner=runner))

            self.assertTrue(r.success)
            self.assertFalse(r.dry_run)
            conf = base / CONF_DIR / CONF_FILENAME
            self.assertTrue(conf.is_file())
            self.assertEqual(conf.read_text(), CONF_BODY)
            # File mode should be world-readable.
            self.assertEqual(conf.stat().st_mode & 0o777, 0o644)

    def test_calls_modprobe_remove(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            runner = FakeRunner(returncode=0)
            apply_fix(_ctx(base, runner=runner))
            self.assertEqual(runner.calls, [["modprobe", "-r", "algif_aead"]])

    def test_audit_log_is_appended(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            apply_fix(_ctx(base))
            log = base / AUDIT_LOG
            self.assertTrue(log.is_file())
            self.assertIn("fix applied", log.read_text())

    def test_idempotent_second_run(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            apply_fix(_ctx(base))
            r2 = apply_fix(_ctx(base))
            self.assertTrue(r2.success)
            already = [a for a in r2.actions if a.type == "write_blacklist"][0]
            self.assertIn("already present", already.description)


class DryRunTests(unittest.TestCase):
    def test_no_files_written(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            runner = FakeRunner()
            r = apply_fix(_ctx(base, runner=runner), dry_run=True)
            self.assertTrue(r.dry_run)
            self.assertTrue(r.success)
            self.assertFalse((base / CONF_DIR / CONF_FILENAME).exists())
            self.assertFalse((base / AUDIT_LOG).exists())
            self.assertEqual(runner.calls, [])
            for a in r.actions:
                if a.type == "precheck":
                    continue
                self.assertFalse(a.executed, f"{a.type} should not have executed in dry-run")


class PrecheckRefusalTests(unittest.TestCase):
    def test_non_linux_refuses(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            r = apply_fix(_ctx(Path(tmp), is_linux=False))
            self.assertFalse(r.success)
            self.assertFalse((Path(tmp) / CONF_DIR / CONF_FILENAME).exists())

    def test_container_refuses(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / ".dockerenv").touch()
            r = apply_fix(_ctx(base))
            self.assertFalse(r.success)
            self.assertTrue(any("container" in (a.error or "") for a in r.actions))

    def test_non_root_refuses_unless_dry_run(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            r = apply_fix(_ctx(base, geteuid=lambda: 1000))
            self.assertFalse(r.success)

    def test_non_root_with_dry_run_succeeds(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            r = apply_fix(_ctx(base, geteuid=lambda: 1000), dry_run=True)
            self.assertTrue(r.success)


class RmmodFailureTests(unittest.TestCase):
    def test_rmmod_failure_on_loaded_module_records_failure(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            (base / "proc").mkdir()
            (base / "proc" / "modules").write_text("algif_aead 16384 1 - Live 0\n")
            runner = FakeRunner(returncode=1, stderr="Module is in use")
            r = apply_fix(_ctx(base, runner=runner))
            self.assertFalse(r.success)
            rm = [a for a in r.actions if a.type == "rmmod"][0]
            self.assertFalse(rm.success)
            self.assertIn("in use", rm.error)
            self.assertTrue(any("still loaded" in n for n in r.notes))

    def test_rmmod_failure_when_not_loaded_is_ok(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\n")
            (base / "proc").mkdir()
            (base / "proc" / "modules").write_text("ext4 999 1 - Live 0\n")
            runner = FakeRunner(returncode=1, stderr="not loaded")
            r = apply_fix(_ctx(base, runner=runner))
            self.assertTrue(r.success)
            rm = [a for a in r.actions if a.type == "rmmod"][0]
            self.assertTrue(rm.success)


if __name__ == "__main__":
    unittest.main()
