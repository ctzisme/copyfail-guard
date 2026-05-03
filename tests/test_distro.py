import unittest
from pathlib import Path

from copyfail_guard.distro import (
    detect_distro,
    parse_os_release,
    upgrade_command,
)

FIXTURES = Path(__file__).parent / "fixtures"


class ParseOsReleaseTests(unittest.TestCase):
    def test_strips_quotes_and_handles_unquoted(self):
        text = '''
ID=ubuntu
NAME="Ubuntu"
VERSION_ID="24.04"
PRETTY_NAME='Ubuntu 24.04 LTS'
'''
        d = parse_os_release(text)
        self.assertEqual(d["ID"], "ubuntu")
        self.assertEqual(d["NAME"], "Ubuntu")
        self.assertEqual(d["VERSION_ID"], "24.04")
        self.assertEqual(d["PRETTY_NAME"], "Ubuntu 24.04 LTS")

    def test_skips_blank_and_comment(self):
        text = "\n# comment\n\nID=fedora\n"
        d = parse_os_release(text)
        self.assertEqual(d, {"ID": "fedora"})

    def test_malformed_lines_are_ignored(self):
        text = "ID=debian\nnot a key=value pair\n=value\n"
        d = parse_os_release(text)
        self.assertEqual(d, {"ID": "debian"})


class DetectDistroTests(unittest.TestCase):
    def test_ubuntu_fixture(self):
        info = detect_distro(FIXTURES / "ubuntu2404")
        self.assertIsNotNone(info)
        self.assertEqual(info.id, "ubuntu")
        self.assertEqual(info.id_like, ("debian",))
        self.assertEqual(info.version_id, "24.04")
        self.assertEqual(info.family, "debian")
        self.assertIn("Ubuntu", info.pretty_name)

    def test_rhel_fixture(self):
        info = detect_distro(FIXTURES / "rhel10")
        self.assertEqual(info.id, "rhel")
        self.assertEqual(info.id_like, ("fedora",))
        self.assertEqual(info.family, "rhel")
        self.assertEqual(info.version_id, "10.1")

    def test_fedora_fixture(self):
        info = detect_distro(FIXTURES / "fedora41")
        self.assertEqual(info.id, "fedora")
        self.assertEqual(info.family, "fedora")

    def test_sles_fixture(self):
        info = detect_distro(FIXTURES / "sles16")
        self.assertEqual(info.id, "sles")
        self.assertEqual(info.id_like, ("suse",))
        self.assertEqual(info.family, "suse")

    def test_missing_root_returns_none(self):
        self.assertIsNone(detect_distro(FIXTURES / "nonexistent"))

    def test_unknown_id_with_known_id_like(self):
        # Synthesize a one-off os-release on the fly via a tmpdir-equivalent.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            etc = Path(tmp) / "etc"
            etc.mkdir()
            (etc / "os-release").write_text(
                'ID=somedistro\nID_LIKE="ubuntu debian"\nVERSION_ID="1.0"\n'
            )
            info = detect_distro(Path(tmp))
            self.assertEqual(info.family, "debian")

    def test_unknown_id_and_id_like(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            etc = Path(tmp) / "etc"
            etc.mkdir()
            (etc / "os-release").write_text("ID=arch\nVERSION_ID=rolling\n")
            info = detect_distro(Path(tmp))
            self.assertEqual(info.family, "unknown")


class UpgradeCommandTests(unittest.TestCase):
    def test_each_family_has_a_command(self):
        for family in ("debian", "rhel", "fedora", "suse"):
            cmd = upgrade_command(family)
            self.assertTrue(cmd)
            self.assertIn("sudo", cmd)

    def test_unknown_family_returns_generic_advice(self):
        cmd = upgrade_command("unknown")
        self.assertIn("CVE-2026-31431", cmd)


if __name__ == "__main__":
    unittest.main()
