"""Text and JSON formatters for :class:`DetectionResult` and :class:`FixResult`.

Text goes to stdout when invoked from the CLI; JSON also goes to stdout. Logs and
warnings are the CLI's responsibility (stderr) — this module only renders payloads.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .detector import DetectionResult, Verdict

CVE_ID = "CVE-2026-31431"
CVE_NICKNAME = "Copy Fail"


VERDICT_LABELS = {
    Verdict.PATCHED: "PATCHED",
    Verdict.MITIGATED: "MITIGATED",
    Verdict.VULNERABLE: "VULNERABLE",
    Verdict.UNMITIGABLE_BUILTIN: "VULNERABLE (kernel upgrade required)",
    Verdict.NOT_APPLICABLE: "NOT APPLICABLE",
    Verdict.UNKNOWN: "UNKNOWN",
}


# ---------------------------------------------------------------------------
# Detection rendering
# ---------------------------------------------------------------------------


def detection_to_dict(r: DetectionResult) -> dict:
    """Render a :class:`DetectionResult` as a JSON-serializable dict."""
    distro = None
    if r.distro is not None:
        distro = {
            "id": r.distro.id,
            "version_id": r.distro.version_id,
            "pretty_name": r.distro.pretty_name,
            "family": r.distro.family,
        }

    kernel = None
    if r.kernel is not None:
        kernel = {
            "release": r.kernel.raw,
            "upstream": r.kernel.upstream,
        }
        if r.kernel_class is not None:
            kernel["branch"] = r.kernel_class.branch
            kernel["patched_threshold"] = r.kernel_class.patched_threshold

    module = None
    if r.module is not None:
        module = {
            "name": r.module.name,
            "loaded": r.module.loaded,
            "builtin": r.module.builtin,
            "loadable": r.module.loadable,
            "in_sysfs": r.module.in_sysfs,
        }
    mitigation = None
    if r.module is not None:
        mitigation = {
            "blacklisted": r.module.blacklist.blacklisted,
            "method": r.module.blacklist.method,
            "config_file": r.module.blacklist.config_file,
        }

    actions = _recommended_actions(r)

    return {
        "cve": CVE_ID,
        "verdict": r.verdict.value,
        "exit_code": r.exit_code,
        "in_container": r.in_container,
        "distribution": distro,
        "kernel": kernel,
        "module": module,
        "mitigation": mitigation,
        "recommended_actions": actions,
        "notes": list(r.notes),
    }


def _recommended_actions(r: DetectionResult) -> list[dict]:
    actions: list[dict] = []
    if r.verdict == Verdict.VULNERABLE:
        actions.append({"type": "mitigate", "command": "sudo copyfail-guard fix"})
        if r.upgrade_command:
            actions.append({"type": "upgrade", "command": r.upgrade_command})
        actions.append({"type": "reboot"})
    elif r.verdict == Verdict.UNMITIGABLE_BUILTIN:
        if r.upgrade_command:
            actions.append({"type": "upgrade", "command": r.upgrade_command})
        actions.append({"type": "reboot"})
    elif r.verdict == Verdict.MITIGATED:
        if r.upgrade_command:
            actions.append({"type": "upgrade", "command": r.upgrade_command})
        actions.append({"type": "reboot"})
    return actions


def render_detection_json(r: DetectionResult) -> str:
    return json.dumps(detection_to_dict(r), indent=2, sort_keys=False)


def render_detection_text(r: DetectionResult) -> str:
    label = VERDICT_LABELS[r.verdict]
    lines = [f"[copyfail-guard] {CVE_ID} ({CVE_NICKNAME}) — {label}"]

    if r.distro is not None:
        lines.append(f"  Distribution: {r.distro.pretty_name or r.distro.id}  ({r.distro.family} family)")
    else:
        lines.append("  Distribution: (unknown)")

    if r.kernel is not None:
        kernel_line = f"  Kernel:       {r.kernel.raw}"
        if r.kernel_class is not None and r.kernel_class.branch is not None:
            if r.kernel_class.patched_threshold:
                kernel_line += f"  (branch {r.kernel_class.branch}, fixed at {r.kernel_class.patched_threshold})"
            else:
                kernel_line += f"  (branch {r.kernel_class.branch})"
        lines.append(kernel_line)
    else:
        lines.append("  Kernel:       (could not parse)")

    if r.module is not None:
        m = r.module
        if m.builtin:
            mod_state = "built into kernel image"
        elif m.loaded:
            mod_state = "loaded as .ko"
        elif m.loadable:
            mod_state = "loadable .ko present (not currently loaded)"
        else:
            mod_state = "not present"
        lines.append(f"  Module:       algif_aead — {mod_state}")

        if m.blacklist.blacklisted:
            method_label = {
                "install_false": "install /bin/false",
                "install_redirect": "install (custom redirect)",
                "blacklist": "blacklist (weak)",
            }.get(m.blacklist.method or "", m.blacklist.method or "")
            mit_line = f"  Mitigation:   {method_label}"
            if m.blacklist.config_file:
                mit_line += f" — {m.blacklist.config_file}"
            lines.append(mit_line)
        else:
            lines.append("  Mitigation:   none")

    if r.in_container:
        lines.append("  Environment:  container")

    actions = _recommended_actions(r)
    if r.verdict == Verdict.VULNERABLE:
        lines.append("")
        lines.append("Recommended actions:")
        lines.append("  1. Apply mitigation now:")
        lines.append("       sudo copyfail-guard fix")
        if r.upgrade_command:
            lines.append("  2. Upgrade kernel:")
            lines.append(f"       {r.upgrade_command}")
            lines.append("  3. Reboot")
        else:
            lines.append("  2. Reboot")
    elif r.verdict == Verdict.UNMITIGABLE_BUILTIN:
        lines.append("")
        lines.append("Recommended actions (mitigation alone is insufficient):")
        if r.upgrade_command:
            lines.append("  1. Upgrade kernel:")
            lines.append(f"       {r.upgrade_command}")
        lines.append("  2. Reboot")
    elif r.verdict == Verdict.MITIGATED:
        lines.append("")
        lines.append("Mitigation in place. Plan a kernel upgrade for a permanent fix:")
        if r.upgrade_command:
            lines.append(f"  {r.upgrade_command}")

    if r.notes:
        lines.append("")
        lines.append("Notes:")
        for n in r.notes:
            lines.append(f"  - {n}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fix rendering
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FixAction:
    type: str
    description: str
    executed: bool
    success: bool
    error: str | None = None
    target: str | None = None


@dataclass(frozen=True)
class FixResult:
    success: bool
    dry_run: bool
    actions: tuple[FixAction, ...]
    upgrade_command: str | None
    notes: tuple[str, ...]


def fix_to_dict(r: FixResult) -> dict:
    return {
        "cve": CVE_ID,
        "success": r.success,
        "dry_run": r.dry_run,
        "actions": [
            {
                "type": a.type,
                "description": a.description,
                "executed": a.executed,
                "success": a.success,
                "error": a.error,
                "target": a.target,
            }
            for a in r.actions
        ],
        "recommended_followup": (
            [{"type": "upgrade", "command": r.upgrade_command}, {"type": "reboot"}]
            if r.upgrade_command
            else []
        ),
        "notes": list(r.notes),
    }


def render_fix_json(r: FixResult) -> str:
    return json.dumps(fix_to_dict(r), indent=2, sort_keys=False)


def render_fix_text(r: FixResult) -> str:
    header = "[copyfail-guard] fix"
    if r.dry_run:
        header += " (dry-run)"
    header += " — " + ("OK" if r.success else "FAILED")
    lines = [header]

    for a in r.actions:
        if not a.executed:
            prefix = "  [skip]"
        elif a.success:
            prefix = "  [ ok ]"
        else:
            prefix = "  [fail]"
        line = f"{prefix} {a.description}"
        if a.target:
            line += f"  [{a.target}]"
        if a.error:
            line += f"  — {a.error}"
        lines.append(line)

    if r.upgrade_command:
        lines.append("")
        lines.append("Next steps for a permanent fix:")
        lines.append(f"  1. {r.upgrade_command}")
        lines.append("  2. Reboot")

    if r.notes:
        lines.append("")
        lines.append("Notes:")
        for n in r.notes:
            lines.append(f"  - {n}")

    return "\n".join(lines)
