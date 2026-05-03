import unittest

from copyfail_guard.kernel import (
    Classification,
    KernelVersion,
    Verdict,
    classify,
    parse_release,
)


class ParseReleaseTests(unittest.TestCase):
    def test_ubuntu_generic(self):
        kv = parse_release("6.8.0-50-generic")
        self.assertEqual((kv.major, kv.minor, kv.patch), (6, 8, 0))
        self.assertEqual(kv.suffix, "50-generic")
        self.assertEqual(kv.upstream, "6.8.0")

    def test_rhel_dotted_suffix(self):
        kv = parse_release("5.14.0-503.el9_5.x86_64")
        self.assertEqual(kv.tuple, (5, 14, 0))
        self.assertEqual(kv.suffix, "503.el9_5.x86_64")

    def test_suse_dotted_suffix(self):
        kv = parse_release("6.4.0-150600.23.42-default")
        self.assertEqual(kv.tuple, (6, 4, 0))

    def test_plain_three_component(self):
        kv = parse_release("6.6.137")
        self.assertEqual(kv.tuple, (6, 6, 137))
        self.assertEqual(kv.suffix, "")

    def test_two_component_falls_back_to_zero_patch(self):
        kv = parse_release("7.0-rc3")
        self.assertEqual(kv.tuple, (7, 0, 0))
        self.assertEqual(kv.suffix, "rc3")

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_release(""))
        self.assertIsNone(parse_release(None))
        self.assertIsNone(parse_release("not-a-version"))


class ClassifyTests(unittest.TestCase):
    def _kv(self, *parts: int, suffix: str = "") -> KernelVersion:
        major, minor, patch = (*parts, 0, 0, 0)[:3]
        raw = ".".join(str(p) for p in parts)
        if suffix:
            raw += "-" + suffix
        return KernelVersion(major=major, minor=minor, patch=patch, suffix=suffix, raw=raw)

    def test_below_floor_is_unknown(self):
        self.assertEqual(classify(self._kv(3, 18, 0)).verdict, Verdict.UNKNOWN_BRANCH)
        self.assertEqual(classify(self._kv(4, 13, 999)).verdict, Verdict.UNKNOWN_BRANCH)

    def test_5_10_branch_boundaries(self):
        self.assertEqual(classify(self._kv(5, 10, 253)).verdict, Verdict.IN_RANGE)
        self.assertEqual(classify(self._kv(5, 10, 254)).verdict, Verdict.PATCHED)
        self.assertEqual(classify(self._kv(5, 10, 999)).verdict, Verdict.PATCHED)

    def test_5_15_branch_boundaries(self):
        self.assertEqual(classify(self._kv(5, 15, 203)).verdict, Verdict.IN_RANGE)
        self.assertEqual(classify(self._kv(5, 15, 204)).verdict, Verdict.PATCHED)

    def test_6_6_branch_boundaries(self):
        self.assertEqual(classify(self._kv(6, 6, 136)).verdict, Verdict.IN_RANGE)
        c = classify(self._kv(6, 6, 137))
        self.assertEqual(c.verdict, Verdict.PATCHED)
        self.assertEqual(c.branch, "6.6")
        self.assertEqual(c.patched_threshold, "6.6.137")

    def test_arc_start_includes_first_version(self):
        # 6.7.0 is the start of the 6.7-6.12 arc, fixed at 6.12.85.
        c = classify(self._kv(6, 7, 0))
        self.assertEqual(c.verdict, Verdict.IN_RANGE)
        self.assertEqual(c.branch, "6.12")
        self.assertEqual(c.patched_threshold, "6.12.85")

    def test_arc_middle_non_lts_branch_still_vulnerable(self):
        # 5.13 is non-LTS; never received a backport. Should be IN_RANGE.
        self.assertEqual(classify(self._kv(5, 13, 19)).verdict, Verdict.IN_RANGE)

    def test_6_19_arc(self):
        self.assertEqual(classify(self._kv(6, 19, 11)).verdict, Verdict.IN_RANGE)
        self.assertEqual(classify(self._kv(6, 19, 12)).verdict, Verdict.PATCHED)

    def test_7_0_rc_is_vulnerable(self):
        kv = KernelVersion(major=7, minor=0, patch=0, suffix="rc3", raw="7.0.0-rc3")
        self.assertEqual(classify(kv).verdict, Verdict.IN_RANGE)

    def test_7_0_final_is_patched(self):
        self.assertEqual(classify(self._kv(7, 0, 0)).verdict, Verdict.PATCHED)

    def test_far_future_is_patched(self):
        self.assertEqual(classify(self._kv(8, 5, 0)).verdict, Verdict.PATCHED)

    def test_classification_dataclass_frozen(self):
        c = Classification(Verdict.PATCHED, "6.6", "6.6.137")
        with self.assertRaises(Exception):
            c.verdict = Verdict.IN_RANGE  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
