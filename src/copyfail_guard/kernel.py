"""Kernel version parsing and CVE-2026-31431 vulnerability classification.

The vulnerability data here comes from NVD's CVE-2026-31431 entry. Each entry
in :data:`VULNERABLE_ARCS` describes one upstream stable arc:

    (arc_start_inclusive, vulnerable_up_to_inclusive, fixed_at_inclusive)

A version v is in the vulnerable range when ``arc_start <= v <= vulnerable_up_to``.
A version on the fix's own minor branch (e.g. 6.6.x) is patched when ``v >= fixed_at``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

VersionTuple = tuple[int, int, int]

VULNERABLE_ARCS: list[tuple[VersionTuple, VersionTuple, VersionTuple]] = [
    ((4, 14, 0), (5, 10, 253), (5, 10, 254)),
    ((5, 11, 0), (5, 15, 203), (5, 15, 204)),
    ((5, 16, 0), (6, 1, 169), (6, 1, 170)),
    ((6, 2, 0), (6, 6, 136), (6, 6, 137)),
    ((6, 7, 0), (6, 12, 84), (6, 12, 85)),
    ((6, 13, 0), (6, 18, 21), (6, 18, 22)),
    ((6, 19, 0), (6, 19, 11), (6, 19, 12)),
]

# Versions from this point on are assumed to carry the fix forward.
ASSUMED_PATCHED_FROM: VersionTuple = (7, 0, 0)

# Versions strictly older than this are not assessed by this tool.
COVERAGE_FLOOR: VersionTuple = (4, 14, 0)


class Verdict(str, Enum):
    PATCHED = "patched"
    IN_RANGE = "in_range"
    UNKNOWN_BRANCH = "unknown_branch"


@dataclass(frozen=True)
class KernelVersion:
    major: int
    minor: int
    patch: int
    suffix: str
    raw: str

    @property
    def tuple(self) -> VersionTuple:
        return (self.major, self.minor, self.patch)

    @property
    def upstream(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class Classification:
    verdict: Verdict
    branch: str | None
    patched_threshold: str | None


_RELEASE_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+.](.*))?$")


def parse_release(release: str | None) -> KernelVersion | None:
    """Parse a ``uname -r`` style string. Returns ``None`` if it doesn't look like one."""
    if not release:
        return None
    m = _RELEASE_RE.match(release.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    suffix = m.group(4) or ""
    return KernelVersion(major=major, minor=minor, patch=patch, suffix=suffix, raw=release)


def classify(kv: KernelVersion) -> Classification:
    """Decide whether *kv* falls in the CVE-2026-31431 vulnerable range."""
    v = kv.tuple

    if v == (7, 0, 0):
        rc = re.search(r"rc(\d+)", kv.suffix, re.IGNORECASE) if kv.suffix else None
        if rc and 1 <= int(rc.group(1)) <= 6:
            return Classification(Verdict.IN_RANGE, "7.0-rc", "7.0")
        return Classification(Verdict.PATCHED, "7.0", "7.0")

    if v < COVERAGE_FLOOR:
        return Classification(Verdict.UNKNOWN_BRANCH, None, None)
    if v > ASSUMED_PATCHED_FROM:
        return Classification(Verdict.PATCHED, None, None)

    for arc_start, vuln_max, fixed_at in VULNERABLE_ARCS:
        branch = f"{fixed_at[0]}.{fixed_at[1]}"
        threshold = f"{fixed_at[0]}.{fixed_at[1]}.{fixed_at[2]}"
        # On the fix's own minor branch and at/after the fix point.
        if (kv.major, kv.minor) == (fixed_at[0], fixed_at[1]) and v >= fixed_at:
            return Classification(Verdict.PATCHED, branch, threshold)
        if arc_start <= v <= vuln_max:
            return Classification(Verdict.IN_RANGE, branch, threshold)

    return Classification(Verdict.UNKNOWN_BRANCH, None, None)
