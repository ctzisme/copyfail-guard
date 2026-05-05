"""Command-line entry point for copyfail-guard.

Subcommands:
    detect   — read-only diagnostic (default if none given)
    fix      — apply mitigation (write blacklist, unload module)

Exit codes:
    0  — system is safe (patched / mitigated / not applicable / fix succeeded)
    1  — system is vulnerable (verdict: vulnerable or unmitigable_builtin)
    2  — error (could not determine state, refused due to preconditions, etc.)

Output streams:
    stdout — verdict line, JSON, fix result
    stderr — diagnostic messages, warnings
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

from . import __version__
from .detector import EXIT_CODES, detect
from .fixer import apply_fix, apply_reset
from .output import (
    VERDICT_LABELS,
    render_detection_json,
    render_detection_text,
    render_fix_json,
    render_fix_text,
    render_reset_json,
    render_reset_text,
)
from .system import SystemContext


def _infer_uname_release(root: Path) -> str | None:
    """If a fixture root contains exactly one ``lib/modules/<X>``, return ``<X>``."""
    mod_dir = root / "lib" / "modules"
    if not mod_dir.is_dir():
        return None
    entries = [p.name for p in mod_dir.iterdir() if p.is_dir()]
    if len(entries) == 1:
        return entries[0]
    return None


def _noop_runner(args, **_kwargs):
    """Stand-in subprocess runner for fixture mode — never executes anything real."""
    return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="")


def build_context(args: argparse.Namespace) -> SystemContext:
    """Build a :class:`SystemContext` from parsed CLI arguments."""
    root_str = getattr(args, "root", "/")
    if root_str and root_str != "/":
        root = Path(root_str).resolve()
        release = (
            args.uname_release
            or _infer_uname_release(root)
            or (os.uname().release if hasattr(os, "uname") else "")
        )
        return SystemContext(
            root=root,
            uname_release=release,
            runner=_noop_runner,
            geteuid=lambda: 0,
            is_linux=True,
        )

    return SystemContext(
        root=Path("/"),
        uname_release=(args.uname_release or (os.uname().release if hasattr(os, "uname") else "")),
        runner=subprocess.run,
        geteuid=getattr(os, "geteuid", lambda: 0),
        is_linux=platform.system() == "Linux",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="copyfail-guard",
        description="Detect and mitigate CVE-2026-31431 (Copy Fail) on Linux.",
    )
    p.add_argument("--json", action="store_true", help="emit a JSON document on stdout")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print actions without changing anything (only meaningful for fix)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress prose; emit only the one-line verdict (no effect with --json)",
    )
    p.add_argument(
        "--root",
        default="/",
        help="alternate root directory; primarily for testing or rescue mode",
    )
    p.add_argument(
        "--uname-release",
        default=None,
        help="override the kernel release string (testing/forensics)",
    )
    p.add_argument("--version", action="version", version=f"copyfail-guard {__version__}")

    sub = p.add_subparsers(dest="command")
    sub.add_parser("detect", help="check system status (default)")
    sub.add_parser("fix", help="apply modprobe-level mitigation")
    sub.add_parser("reset", help="remove the modprobe conf file installed by fix")
    return p


def _run_detect(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    result = detect(ctx)

    if args.json:
        sys.stdout.write(render_detection_json(result) + "\n")
    elif args.quiet:
        sys.stdout.write(
            f"[copyfail-guard] CVE-2026-31431 — {VERDICT_LABELS[result.verdict]} "
            f"(exit={result.exit_code})\n"
        )
    else:
        sys.stdout.write(render_detection_text(result) + "\n")

    return EXIT_CODES[result.verdict]


def _run_fix(args: argparse.Namespace) -> int:
    if args.root != "/" and not args.dry_run:
        sys.stderr.write("error: refusing to run fix against a custom --root without --dry-run.\n")
        return 2

    ctx = build_context(args)
    result = apply_fix(ctx, dry_run=args.dry_run)

    if args.json:
        sys.stdout.write(render_fix_json(result) + "\n")
    else:
        sys.stdout.write(render_fix_text(result) + "\n")

    return 0 if result.success else 2


def _run_reset(args: argparse.Namespace) -> int:
    if args.root != "/" and not args.dry_run:
        sys.stderr.write(
            "error: refusing to run reset against a custom --root without --dry-run.\n"
        )
        return 2

    ctx = build_context(args)
    result = apply_reset(ctx, dry_run=args.dry_run)

    if args.json:
        sys.stdout.write(render_reset_json(result) + "\n")
    else:
        sys.stdout.write(render_reset_text(result) + "\n")

    return 0 if result.success else 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "detect"
    if command == "fix":
        return _run_fix(args)
    if command == "reset":
        return _run_reset(args)
    return _run_detect(args)


if __name__ == "__main__":
    sys.exit(main())
