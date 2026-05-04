"""Kernel module signal collection for CVE-2026-31431 (the ``algif_aead`` module).

Four independent signals plus a synthesizing helper:

- :func:`is_loaded` — appears as a row in ``/proc/modules``
- :func:`is_builtin` — listed in ``/lib/modules/<release>/modules.builtin``
- :func:`is_loadable` — has a ``.ko[.xz|.zst]`` line in ``modules.dep``
- :func:`find_blacklist` — ``install <name> /bin/false`` or ``blacklist <name>`` in
  modprobe config (uses ``modprobe --showconfig`` when on the live system, falls
  back to scanning ``/etc/modprobe.d/``, ``/run/modprobe.d/``, ``/usr/lib/modprobe.d/``,
  ``/lib/modprobe.d/`` in that order).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .system import SystemContext

MODULE_NAME = "algif_aead"

CONF_DIRS = (
    "etc/modprobe.d",
    "run/modprobe.d",
    "usr/lib/modprobe.d",
    "lib/modprobe.d",
)


@dataclass(frozen=True)
class BlacklistResult:
    blacklisted: bool
    method: str | None  # "install_false" | "blacklist" | None
    config_file: str | None  # absolute or fixture-relative path string


@dataclass(frozen=True)
class ModuleStatus:
    name: str
    loaded: bool
    builtin: bool
    loadable: bool
    in_sysfs: bool
    blacklist: BlacklistResult


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def is_loaded(ctx: SystemContext, name: str = MODULE_NAME) -> bool:
    """True if *name* has an entry in ``/proc/modules``."""
    text = _read_text(ctx.under_root("proc/modules"))
    if not text:
        return False
    for line in text.splitlines():
        first = line.split(None, 1)[0] if line.strip() else ""
        if first == name:
            return True
    return False


def is_in_sysfs(ctx: SystemContext, name: str = MODULE_NAME) -> bool:
    """True if ``/sys/module/<name>/`` exists (loaded *or* built-in)."""
    return ctx.under_root("sys/module", name).is_dir()


def _modules_dir(ctx: SystemContext) -> Path:
    return ctx.under_root("lib/modules", ctx.uname_release)


_KO_RE = re.compile(r"/([^/]+)\.ko(?:\.[a-z0-9]+)?(?::|$)")


def is_builtin(ctx: SystemContext, name: str = MODULE_NAME) -> bool:
    """True if *name* is listed in ``modules.builtin`` for the running kernel."""
    text = _read_text(_modules_dir(ctx) / "modules.builtin")
    if not text:
        return False
    for line in text.splitlines():
        m = _KO_RE.search(line)
        if m and m.group(1) == name:
            return True
    return False


def is_loadable(ctx: SystemContext, name: str = MODULE_NAME) -> bool:
    """True if a ``<name>.ko[.xz|.zst]`` entry exists in ``modules.dep``."""
    text = _read_text(_modules_dir(ctx) / "modules.dep")
    if not text:
        return False
    for line in text.splitlines():
        head = line.split(":", 1)[0]
        m = _KO_RE.search(head + ":")
        if m and m.group(1) == name:
            return True
    return False


def _scan_conf_dirs(ctx: SystemContext, name: str) -> BlacklistResult:
    install_re = re.compile(rf"^\s*install\s+{re.escape(name)}\s+(\S+)")
    blacklist_re = re.compile(rf"^\s*blacklist\s+{re.escape(name)}\s*$")
    for sub in CONF_DIRS:
        d = ctx.under_root(sub)
        if not d.is_dir():
            continue
        for conf in sorted(d.glob("*.conf")):
            text = _read_text(conf)
            if not text:
                continue
            for raw in text.splitlines():
                line = raw.split("#", 1)[0]
                m = install_re.match(line)
                if m:
                    target = m.group(1)
                    if target in ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true"):
                        return BlacklistResult(True, "install_false", str(conf))
                    return BlacklistResult(True, "install_redirect", str(conf))
                if blacklist_re.match(line):
                    return BlacklistResult(True, "blacklist", str(conf))
    return BlacklistResult(False, None, None)


def find_blacklist(ctx: SystemContext, name: str = MODULE_NAME) -> BlacklistResult:
    """Detect a modprobe-level block for *name*.

    Prefers ``modprobe --showconfig`` when running against the real root, since
    that resolves include directives and override precedence correctly. Falls back
    to scanning the conf directories under :attr:`SystemContext.root` for fixture
    or rescue scenarios.
    """
    if ctx.root == Path("/") and ctx.is_linux:
        try:
            r = ctx.runner(
                ["modprobe", "--showconfig"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if r.returncode == 0 and r.stdout:
                install_re = re.compile(rf"^\s*install\s+{re.escape(name)}\s+(\S+)", re.MULTILINE)
                m = install_re.search(r.stdout)
                if m:
                    target = m.group(1)
                    if target in ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true"):
                        return BlacklistResult(True, "install_false", None)
                    return BlacklistResult(True, "install_redirect", None)
                if re.search(rf"^\s*blacklist\s+{re.escape(name)}\s*$", r.stdout, re.MULTILINE):
                    return BlacklistResult(True, "blacklist", None)
                # modprobe ran successfully and reported no blacklist for this module.
                # Trust that — modprobe knows about include directives and override
                # precedence, and a stray .conf in a directory it doesn't read would
                # not actually block module loading at runtime.
                return BlacklistResult(False, None, None)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    # modprobe binary unavailable or errored — fall back to scanning conf dirs.
    return _scan_conf_dirs(ctx, name)


def gather_status(ctx: SystemContext, name: str = MODULE_NAME) -> ModuleStatus:
    """Run all four signal collectors and return a combined :class:`ModuleStatus`."""
    return ModuleStatus(
        name=name,
        loaded=is_loaded(ctx, name),
        builtin=is_builtin(ctx, name),
        loadable=is_loadable(ctx, name),
        in_sysfs=is_in_sysfs(ctx, name),
        blacklist=find_blacklist(ctx, name),
    )


def is_in_container(ctx: SystemContext) -> bool:
    """Heuristic: are we running inside a container?

    Triggers on ``/.dockerenv`` or container markers in ``/proc/1/cgroup``.
    """
    if ctx.under_root(".dockerenv").exists():
        return True
    cgroup_text = _read_text(ctx.under_root("proc/1/cgroup"))
    if cgroup_text:
        for marker in ("docker", "containerd", "/lxc/", "kubepods"):
            if marker in cgroup_text:
                return True
    return False
