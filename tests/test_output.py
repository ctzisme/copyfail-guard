import json
import unittest
from pathlib import Path

from copyfail_guard.detector import detect
from copyfail_guard.output import (
    FixAction,
    FixResult,
    detection_to_dict,
    fix_to_dict,
    render_detection_json,
    render_detection_text,
    render_fix_json,
    render_fix_text,
)
from copyfail_guard.system import SystemContext

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(name: str, release: str) -> SystemContext:
    return SystemContext(root=FIXTURES / name, uname_release=release, is_linux=True)


class DetectionRenderTests(unittest.TestCase):
    def test_json_is_valid_and_has_expected_keys(self):
        r = detect(_ctx("ubuntu2404", "6.8.0-50-generic"))
        s = render_detection_json(r)
        d = json.loads(s)
        self.assertEqual(d["cve"], "CVE-2026-31431")
        self.assertEqual(d["verdict"], "vulnerable")
        self.assertEqual(d["exit_code"], 1)
        self.assertEqual(d["distribution"]["family"], "debian")
        self.assertEqual(d["kernel"]["upstream"], "6.8.0")
        self.assertEqual(d["kernel"]["branch"], "6.12")
        self.assertEqual(d["kernel"]["patched_threshold"], "6.12.85")
        self.assertTrue(d["module"]["loaded"])
        self.assertFalse(d["mitigation"]["blacklisted"])
        types = [a["type"] for a in d["recommended_actions"]]
        self.assertEqual(types, ["mitigate", "upgrade", "reboot"])

    def test_text_includes_label_and_distro_and_command(self):
        r = detect(_ctx("ubuntu2404", "6.8.0-50-generic"))
        s = render_detection_text(r)
        self.assertIn("VULNERABLE", s)
        self.assertIn("Ubuntu", s)
        self.assertIn("6.8.0-50-generic", s)
        self.assertIn("apt-get", s)
        self.assertIn("Reboot", s)

    def test_mitigated_text_omits_mitigate_action(self):
        r = detect(_ctx("ubuntu2404-mitigated", "6.8.0-50-generic"))
        s = render_detection_text(r)
        self.assertIn("MITIGATED", s)
        self.assertNotIn("Apply mitigation now", s)
        self.assertIn("permanent fix", s)

    def test_builtin_text_emphasizes_upgrade(self):
        r = detect(_ctx("builtin-kernel", "6.8.0-builtin"))
        s = render_detection_text(r)
        self.assertIn("kernel upgrade required", s.lower())
        self.assertIn("mitigation alone is insufficient", s)

    def test_unknown_text_renders_without_actions(self):
        ctx = SystemContext(root=FIXTURES / "ubuntu2404", uname_release="garbage", is_linux=True)
        r = detect(ctx)
        s = render_detection_text(r)
        self.assertIn("UNKNOWN", s)
        self.assertNotIn("Recommended actions", s)

    def test_dict_round_trips_through_json(self):
        r = detect(_ctx("rhel10", "6.12.0-55.el10.x86_64"))
        d1 = detection_to_dict(r)
        d2 = json.loads(json.dumps(d1))
        self.assertEqual(d1, d2)


class FixRenderTests(unittest.TestCase):
    def _result(self, *, success=True, dry_run=False) -> FixResult:
        return FixResult(
            success=success,
            dry_run=dry_run,
            actions=(
                FixAction(
                    type="write_blacklist",
                    description="Wrote modprobe blacklist",
                    executed=not dry_run,
                    success=success,
                    target="/etc/modprobe.d/cve-2026-31431-copyfail-guard.conf",
                ),
                FixAction(
                    type="rmmod",
                    description="Unloaded algif_aead",
                    executed=not dry_run,
                    success=success,
                    target="algif_aead",
                ),
            ),
            upgrade_command="sudo apt-get update && sudo apt-get install --only-upgrade linux-image-generic",
            notes=(),
        )

    def test_json_shape(self):
        d = json.loads(render_fix_json(self._result(dry_run=True)))
        self.assertTrue(d["dry_run"])
        self.assertEqual(d["cve"], "CVE-2026-31431")
        self.assertEqual(len(d["actions"]), 2)
        self.assertFalse(d["actions"][0]["executed"])

    def test_text_shows_dry_run_marker(self):
        s = render_fix_text(self._result(dry_run=True))
        self.assertIn("dry-run", s)

    def test_text_shows_failure(self):
        s = render_fix_text(self._result(success=False))
        self.assertIn("FAILED", s)

    def test_fix_dict_round_trips(self):
        r = self._result()
        d1 = fix_to_dict(r)
        d2 = json.loads(json.dumps(d1))
        self.assertEqual(d1, d2)


if __name__ == "__main__":
    unittest.main()
