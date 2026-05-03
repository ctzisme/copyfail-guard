"""Linux distribution detection and per-family kernel upgrade hints.

Parses ``/etc/os-release`` (POSIX shell-style key=value, optionally quoted) and
maps the distribution to one of four supported families:

- ``debian``  — Debian, Ubuntu, and derivatives
- ``rhel``    — RHEL, Rocky, AlmaLinux, CentOS Stream
- ``fedora``  — Fedora
- ``suse``    — openSUSE Leap, Tumbleweed, SLES

Anything else maps to ``"unknown"`` and gets a generic remediation message.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")

_FAMILY_BY_ID = {
    "debian": "debian",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "rhel": "rhel",
    "redhat": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "centos": "rhel",
    "ol": "rhel",
    "oracle": "rhel",
    "fedora": "fedora",
    "sles": "suse",
    "sled": "suse",
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
}

# When ID isn't recognized, fall back to ID_LIKE.
_FAMILY_BY_ID_LIKE = {
    "debian": "debian",
    "ubuntu": "debian",
    "rhel": "rhel",
    "fedora": "fedora",
    "centos": "rhel",
    "suse": "suse",
    "opensuse": "suse",
}


@dataclass(frozen=True)
class DistroInfo:
    id: str
    id_like: tuple[str, ...]
    version_id: str
    pretty_name: str
    family: str  # one of: debian, rhel, fedora, suse, unknown


_KV_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def parse_os_release(text: str) -> dict[str, str]:
    """Parse ``/etc/os-release`` text into a flat dict, handling quoted values."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key, raw_value = m.group(1), m.group(2)
        try:
            tokens = shlex.split(raw_value, posix=True)
            value = tokens[0] if tokens else ""
        except ValueError:
            value = raw_value.strip().strip('"').strip("'")
        out[key] = value
    return out


def _family_from(distro_id: str, id_like: tuple[str, ...]) -> str:
    if distro_id in _FAMILY_BY_ID:
        return _FAMILY_BY_ID[distro_id]
    for like in id_like:
        if like in _FAMILY_BY_ID_LIKE:
            return _FAMILY_BY_ID_LIKE[like]
    return "unknown"


def detect_distro(root: Path) -> DistroInfo | None:
    """Read os-release under *root* and return :class:`DistroInfo`, or ``None`` if absent."""
    for rel in OS_RELEASE_PATHS:
        p = root / rel
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            data = parse_os_release(text)
            distro_id = data.get("ID", "").lower()
            id_like_raw = data.get("ID_LIKE", "")
            id_like = tuple(t.lower() for t in id_like_raw.split() if t)
            return DistroInfo(
                id=distro_id,
                id_like=id_like,
                version_id=data.get("VERSION_ID", ""),
                pretty_name=data.get("PRETTY_NAME", "") or data.get("NAME", ""),
                family=_family_from(distro_id, id_like),
            )
    return None
