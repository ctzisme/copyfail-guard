"""Combine kernel, module, and distro signals into a single CVE-2026-31431 verdict.

Decision order (first match wins):

1. Not Linux or unparseable kernel release             → ``unknown``        (exit 2)
2. Kernel version outside the assessed coverage table  → ``unknown``        (exit 2)
3. Kernel version is at/after the patched threshold    → ``patched``        (exit 0)
4. Kernel in vulnerable range + module is built-in     → ``unmitigable_builtin`` (exit 1)
5. Kernel in vulnerable range + module not present     → ``not_applicable`` (exit 0)
6. Kernel in vulnerable range + modprobe block present → ``mitigated``      (exit 0)
7. Otherwise (in range, loadable, no block)            → ``vulnerable``     (exit 1)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .distro import DistroInfo, detect_distro, upgrade_command
from .kernel import Classification, KernelVersion
from .kernel import Verdict as KernelVerdict
from .kernel import classify, parse_release
from .modules import ModuleStatus, gather_status, is_in_container
from .system import SystemContext


class Verdict(str, Enum):
    PATCHED = "patched"
    MITIGATED = "mitigated"
    VULNERABLE = "vulnerable"
    UNMITIGABLE_BUILTIN = "unmitigable_builtin"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


EXIT_CODES: dict[Verdict, int] = {
    Verdict.PATCHED: 0,
    Verdict.MITIGATED: 0,
    Verdict.NOT_APPLICABLE: 0,
    Verdict.VULNERABLE: 1,
    Verdict.UNMITIGABLE_BUILTIN: 1,
    Verdict.UNKNOWN: 2,
}


@dataclass(frozen=True)
class DetectionResult:
    verdict: Verdict
    exit_code: int
    distro: DistroInfo | None
    kernel: KernelVersion | None
    kernel_class: Classification | None
    module: ModuleStatus | None
    in_container: bool
    upgrade_command: str | None
    notes: tuple[str, ...] = field(default_factory=tuple)


def _make(
    verdict: Verdict,
    *,
    distro: DistroInfo | None = None,
    kernel: KernelVersion | None = None,
    kernel_class: Classification | None = None,
    module: ModuleStatus | None = None,
    in_container: bool = False,
    upgrade_command: str | None = None,
    notes: list[str] | None = None,
) -> DetectionResult:
    return DetectionResult(
        verdict=verdict,
        exit_code=EXIT_CODES[verdict],
        distro=distro,
        kernel=kernel,
        kernel_class=kernel_class,
        module=module,
        in_container=in_container,
        upgrade_command=upgrade_command,
        notes=tuple(notes or ()),
    )


def detect(ctx: SystemContext) -> DetectionResult:
    """Run the full detection pipeline against *ctx* and return a verdict."""
    notes: list[str] = []

    distro = detect_distro(ctx.root)
    upgrade = upgrade_command(distro.family) if distro else upgrade_command("unknown")

    if not ctx.is_linux:
        notes.append("Not running on Linux; this CVE only affects the Linux kernel.")
        return _make(Verdict.UNKNOWN, distro=distro, notes=notes)

    kv = parse_release(ctx.uname_release)
    if kv is None:
        notes.append(f"Could not parse kernel release {ctx.uname_release!r}.")
        return _make(Verdict.UNKNOWN, distro=distro, notes=notes)

    in_container = is_in_container(ctx)
    if in_container:
        notes.append(
            "Running inside a container; the kernel and modules belong to the host. "
            "Run copyfail-guard on the host to mitigate."
        )

    kc = classify(kv)

    if kc.verdict == KernelVerdict.UNKNOWN_BRANCH:
        notes.append(
            f"Kernel {kv.upstream} is outside the CVE-2026-31431 coverage table; manual review needed."
        )
        return _make(
            Verdict.UNKNOWN,
            distro=distro,
            kernel=kv,
            kernel_class=kc,
            in_container=in_container,
            notes=notes,
        )

    module = gather_status(ctx)

    if kc.verdict == KernelVerdict.PATCHED:
        return _make(
            Verdict.PATCHED,
            distro=distro,
            kernel=kv,
            kernel_class=kc,
            module=module,
            in_container=in_container,
            notes=notes,
        )

    # Kernel is IN_RANGE.
    if module.builtin:
        notes.append(
            "algif_aead is compiled into the kernel image; modprobe-level mitigation is "
            "ineffective. The only fix is to upgrade the kernel and reboot."
        )
        return _make(
            Verdict.UNMITIGABLE_BUILTIN,
            distro=distro,
            kernel=kv,
            kernel_class=kc,
            module=module,
            in_container=in_container,
            upgrade_command=upgrade,
            notes=notes,
        )

    if not module.loadable:
        notes.append(
            "Kernel is in the vulnerable range, but algif_aead is not available as a "
            "loadable module on this system; this CVE does not apply here."
        )
        return _make(
            Verdict.NOT_APPLICABLE,
            distro=distro,
            kernel=kv,
            kernel_class=kc,
            module=module,
            in_container=in_container,
            notes=notes,
        )

    if module.blacklist.blacklisted:
        if module.blacklist.method == "blacklist":
            notes.append(
                "Mitigation uses a 'blacklist' directive. 'install algif_aead /bin/false' is "
                "more robust because it cannot be bypassed by explicit modprobe."
            )
        return _make(
            Verdict.MITIGATED,
            distro=distro,
            kernel=kv,
            kernel_class=kc,
            module=module,
            in_container=in_container,
            upgrade_command=upgrade,
            notes=notes,
        )

    return _make(
        Verdict.VULNERABLE,
        distro=distro,
        kernel=kv,
        kernel_class=kc,
        module=module,
        in_container=in_container,
        upgrade_command=upgrade,
        notes=notes,
    )
