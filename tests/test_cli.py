import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FIXTURES = ROOT / "tests" / "fixtures"


def run_cli(*args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "copyfail_guard", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


class DetectExitCodeTests(unittest.TestCase):
    def test_vulnerable_fixture_exits_1(self):
        r = run_cli("--root", str(FIXTURES / "ubuntu2404"), "detect")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("VULNERABLE", r.stdout)

    def test_mitigated_fixture_exits_0(self):
        r = run_cli("--root", str(FIXTURES / "ubuntu2404-mitigated"), "detect")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("MITIGATED", r.stdout)

    def test_builtin_fixture_exits_1(self):
        r = run_cli("--root", str(FIXTURES / "builtin-kernel"), "detect")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("kernel upgrade required", r.stdout.lower())

    def test_no_module_fixture_exits_0(self):
        r = run_cli("--root", str(FIXTURES / "no-module"), "detect")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOT APPLICABLE", r.stdout)

    def test_default_subcommand_is_detect(self):
        r = run_cli("--root", str(FIXTURES / "ubuntu2404"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("VULNERABLE", r.stdout)


class JsonOutputTests(unittest.TestCase):
    def test_json_is_parseable(self):
        r = run_cli("--root", str(FIXTURES / "ubuntu2404"), "--json", "detect")
        self.assertEqual(r.returncode, 1)
        d = json.loads(r.stdout)
        self.assertEqual(d["verdict"], "vulnerable")
        self.assertEqual(d["exit_code"], 1)

    def test_json_for_each_distro_fixture(self):
        for name, expected_family, release in [
            ("ubuntu2404", "debian", "6.8.0-50-generic"),
            ("rhel10", "rhel", "6.12.0-55.el10.x86_64"),
            ("fedora41", "fedora", "6.11.4-301.fc41.x86_64"),
            ("sles16", "suse", "6.4.0-150600.23.42-default"),
        ]:
            with self.subTest(name=name):
                r = run_cli("--root", str(FIXTURES / name), "--json", "detect")
                d = json.loads(r.stdout)
                self.assertEqual(d["distribution"]["family"], expected_family)
                self.assertEqual(d["kernel"]["release"], release)


class QuietModeTests(unittest.TestCase):
    def test_quiet_emits_single_line(self):
        r = run_cli("--root", str(FIXTURES / "ubuntu2404"), "--quiet", "detect")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(len(r.stdout.strip().splitlines()), 1)
        self.assertIn("VULNERABLE", r.stdout)


class FixDryRunTests(unittest.TestCase):
    def test_dry_run_writes_nothing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "etc").mkdir()
            (base / "etc" / "os-release").write_text("ID=ubuntu\nID_LIKE=debian\n")
            r = run_cli("--root", str(base), "--dry-run", "fix")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("dry-run", r.stdout)
            self.assertFalse((base / "etc" / "modprobe.d").exists())

    def test_fix_against_root_without_dry_run_refuses(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            r = run_cli("--root", tmp, "fix")
            self.assertEqual(r.returncode, 2)
            self.assertIn("refusing", r.stderr)


class HelpTests(unittest.TestCase):
    def test_help_exits_0(self):
        r = run_cli("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("copyfail-guard", r.stdout)
        self.assertIn("detect", r.stdout)
        self.assertIn("fix", r.stdout)

    def test_version_flag(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("copyfail-guard", r.stdout)


if __name__ == "__main__":
    unittest.main()
