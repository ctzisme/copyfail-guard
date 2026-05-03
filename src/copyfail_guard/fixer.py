"""Apply the CVE-2026-31431 mitigation: blacklist ``algif_aead`` and unload it.

The fix is intentionally minimal — it does **not** call any package manager. It only:

1. Atomically writes ``/etc/modprobe.d/cve-2026-31431-copyfail-guard.conf`` with
   ``install algif_aead /bin/false``.
2. Calls ``modprobe -r algif_aead`` to drop the running module (best-effort).
3. Appends an audit line to ``/var/log/copyfail-guard.log``.

The recommended kernel upgrade command is returned in :class:`FixResult` so the
CLI layer can print it for the user; this module never executes it.
"""

from __future__ import annotations

import datetime
import os
import subprocess
import tempfile
from pathlib import Path

from .distro import detect_distro, upgrade_command
from .modules import MODULE_NAME, is_in_container, is_loaded
from .output import FixAction, FixResult
from .system import SystemContext

CONF_FILENAME = "cve-2026-31431-copyfail-guard.conf"
CONF_DIR = "etc/modprobe.d"
AUDIT_LOG = "var/log/copyfail-guard.log"

CONF_BODY = """\
# Mitigation for CVE-2026-31431 (Copy Fail) installed by copyfail-guard.
# Remove this file and reboot once the kernel has been upgraded to a fixed version.
install algif_aead /bin/false
"""


def _conf_path(ctx: SystemContext) -> Path:
    return ctx.under_root(CONF_DIR, CONF_FILENAME)


def _audit_path(ctx: SystemContext) -> Path:
    return ctx.under_root(AUDIT_LOG)


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically (same-fs rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(prefix=".copyfail-guard-", dir=str(path.parent))
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def _audit(ctx: SystemContext, line: str) -> bool:
    """Best-effort append to the audit log; failures are non-fatal."""
    log = _audit_path(ctx)
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a", encoding="utf-8") as f:
            ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            f.write(f"{ts} {line}\n")
        return True
    except OSError:
        return False


def apply_fix(ctx: SystemContext, *, dry_run: bool = False) -> FixResult:
    """Run the mitigation and return a structured :class:`FixResult`."""
    actions: list[FixAction] = []
    notes: list[str] = []

    distro = detect_distro(ctx.root)
    upgrade = upgrade_command(distro.family) if distro else upgrade_command("unknown")

    # ---- Pre-checks -------------------------------------------------------
    if not ctx.is_linux:
        actions.append(
            FixAction(
                type="precheck",
                description="Verify host is Linux",
                executed=True,
                success=False,
                error="Host is not Linux; nothing to do.",
            )
        )
        return FixResult(False, dry_run, tuple(actions), upgrade, ())

    if is_in_container(ctx):
        actions.append(
            FixAction(
                type="precheck",
                description="Verify host is not a container",
                executed=True,
                success=False,
                error="Running inside a container; mitigate on the host kernel instead.",
            )
        )
        return FixResult(False, dry_run, tuple(actions), upgrade, ())

    if not dry_run and ctx.geteuid() != 0:
        actions.append(
            FixAction(
                type="precheck",
                description="Verify root privileges",
                executed=True,
                success=False,
                error="Must run as root (or rerun with --dry-run to preview steps).",
            )
        )
        return FixResult(False, dry_run, tuple(actions), upgrade, ())

    actions.append(
        FixAction(
            type="precheck",
            description="Pre-flight checks (Linux, host, root)",
            executed=True,
            success=True,
        )
    )

    # ---- Step 1: write blacklist conf ------------------------------------
    conf = _conf_path(ctx)
    target_str = str(conf)
    already_present = False
    try:
        already_present = conf.read_text(encoding="utf-8") == CONF_BODY
    except (OSError, UnicodeDecodeError):
        already_present = False

    if dry_run:
        actions.append(
            FixAction(
                type="write_blacklist",
                description=(
                    "Would write modprobe blacklist (already present)"
                    if already_present
                    else "Would write modprobe blacklist"
                ),
                executed=False,
                success=True,
                target=target_str,
            )
        )
    elif already_present:
        actions.append(
            FixAction(
                type="write_blacklist",
                description="Modprobe blacklist already present (no change)",
                executed=True,
                success=True,
                target=target_str,
            )
        )
    else:
        try:
            _atomic_write(conf, CONF_BODY)
            actions.append(
                FixAction(
                    type="write_blacklist",
                    description="Wrote modprobe blacklist",
                    executed=True,
                    success=True,
                    target=target_str,
                )
            )
        except OSError as e:
            actions.append(
                FixAction(
                    type="write_blacklist",
                    description="Failed to write modprobe blacklist",
                    executed=True,
                    success=False,
                    target=target_str,
                    error=str(e),
                )
            )
            return FixResult(False, dry_run, tuple(actions), upgrade, tuple(notes))

    # ---- Step 2: unload running module ------------------------------------
    was_loaded = is_loaded(ctx)
    if dry_run:
        actions.append(
            FixAction(
                type="rmmod",
                description=(
                    f"Would unload {MODULE_NAME}" if was_loaded
                    else f"Would attempt to unload {MODULE_NAME} (not currently loaded)"
                ),
                executed=False,
                success=True,
                target=MODULE_NAME,
            )
        )
    else:
        try:
            r = ctx.runner(
                ["modprobe", "-r", MODULE_NAME],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if r.returncode == 0:
                actions.append(
                    FixAction(
                        type="rmmod",
                        description=f"Unloaded {MODULE_NAME}",
                        executed=True,
                        success=True,
                        target=MODULE_NAME,
                    )
                )
            else:
                stderr = (r.stderr or "").strip()
                if not was_loaded:
                    actions.append(
                        FixAction(
                            type="rmmod",
                            description=f"{MODULE_NAME} was not loaded; nothing to unload",
                            executed=True,
                            success=True,
                            target=MODULE_NAME,
                        )
                    )
                else:
                    actions.append(
                        FixAction(
                            type="rmmod",
                            description=f"Failed to unload {MODULE_NAME}",
                            executed=True,
                            success=False,
                            target=MODULE_NAME,
                            error=stderr or f"exit code {r.returncode}",
                        )
                    )
                    notes.append(
                        f"{MODULE_NAME} is still loaded; another process may be using it. "
                        "The blacklist will prevent re-loading after reboot."
                    )
        except FileNotFoundError:
            actions.append(
                FixAction(
                    type="rmmod",
                    description="modprobe binary not found; skipping unload",
                    executed=True,
                    success=False,
                    target=MODULE_NAME,
                    error="modprobe not in PATH",
                )
            )
        except subprocess.TimeoutExpired:
            actions.append(
                FixAction(
                    type="rmmod",
                    description=f"Timeout while unloading {MODULE_NAME}",
                    executed=True,
                    success=False,
                    target=MODULE_NAME,
                    error="modprobe -r timed out after 10s",
                )
            )

    # ---- Step 3: audit log -----------------------------------------------
    if dry_run:
        actions.append(
            FixAction(
                type="audit_log",
                description="Would append audit record",
                executed=False,
                success=True,
                target=str(_audit_path(ctx)),
            )
        )
    else:
        ok = _audit(ctx, "fix applied: install algif_aead /bin/false")
        actions.append(
            FixAction(
                type="audit_log",
                description="Appended audit record" if ok else "Could not write audit log",
                executed=True,
                success=ok,
                target=str(_audit_path(ctx)),
            )
        )

    success = all(a.success for a in actions if a.executed) or dry_run
    return FixResult(success, dry_run, tuple(actions), upgrade, tuple(notes))
