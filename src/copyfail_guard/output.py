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


def _kernel_upgrade_note(r: DetectionResult) -> str:
    """Generic prose hint asking the user to update the kernel to a patched version."""
    threshold = r.kernel_class.patched_threshold if r.kernel_class else None
    if threshold:
        return (
            f"Update the kernel on this system to {threshold} or later (whatever your "
            "distribution ships once it has integrated the CVE-2026-31431 fix), then reboot."
        )
    return (
        "Update the kernel to a CVE-2026-31431-patched version using your "
        "distribution's normal update mechanism, then reboot."
    )


def _recommended_actions(r: DetectionResult) -> list[dict]:
    actions: list[dict] = []
    if r.verdict == Verdict.VULNERABLE:
        actions.append({"type": "mitigate", "command": "sudo copyfail-guard fix"})
        actions.append({"type": "upgrade_kernel", "note": _kernel_upgrade_note(r)})
    elif r.verdict in (Verdict.UNMITIGABLE_BUILTIN, Verdict.MITIGATED):
        actions.append({"type": "upgrade_kernel", "note": _kernel_upgrade_note(r)})
    return actions


def render_detection_json(r: DetectionResult) -> str:
    return json.dumps(detection_to_dict(r), indent=2, sort_keys=False)


def render_detection_text(r: DetectionResult) -> str:
    label = VERDICT_LABELS[r.verdict]
    lines = [f"[copyfail-guard] {CVE_ID} ({CVE_NICKNAME}) — {label}"]

    if r.distro is not None:
        lines.append(
            f"  Distribution: {r.distro.pretty_name or r.distro.id}  ({r.distro.family} family)"
        )
    else:
        lines.append("  Distribution: (unknown)")

    if r.kernel is not None:
        kernel_line = f"  Kernel:       {r.kernel.raw}"
        if r.kernel_class is not None and r.kernel_class.branch is not None:
            if r.kernel_class.patched_threshold:
                kernel_line += (
                    f"  (branch {r.kernel_class.branch},"
                    f" fixed at {r.kernel_class.patched_threshold})"
                )
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

    upgrade_note = _kernel_upgrade_note(r)
    if r.verdict == Verdict.VULNERABLE:
        lines.append("")
        lines.append("Recommended actions:")
        lines.append("  1. Apply mitigation now:")
        lines.append("       sudo copyfail-guard fix")
        lines.append("  2. Update the kernel for a permanent fix:")
        lines.append(f"       {upgrade_note}")
    elif r.verdict == Verdict.UNMITIGABLE_BUILTIN:
        lines.append("")
        lines.append("Recommended action (mitigation alone is insufficient):")
        lines.append(f"  {upgrade_note}")
    elif r.verdict == Verdict.MITIGATED:
        lines.append("")
        lines.append("Mitigation in place. For a permanent fix:")
        lines.append(f"  {upgrade_note}")

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
        "recommended_followup": [
            {
                "type": "upgrade_kernel",
                "note": (
                    "Mitigation is temporary. Update the kernel to a CVE-2026-31431-patched "
                    "version using your distribution's normal update mechanism, then reboot."
                ),
            }
        ],
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

    if r.success and not any(a.type == "precheck" and not a.success for a in r.actions):
        lines.append("")
        lines.append("Next step for a permanent fix:")
        lines.append(
            "  Update the kernel to a CVE-2026-31431-patched version using your "
            "distribution's normal update mechanism, then reboot."
        )

    if r.notes:
        lines.append("")
        lines.append("Notes:")
        for n in r.notes:
            lines.append(f"  - {n}")

    return "\n".join(lines)
