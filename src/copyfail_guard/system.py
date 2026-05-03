"""Dependency injection container for filesystem, subprocess, and identity calls.

The detector and fixer never read ``/proc``, ``/etc``, or call ``subprocess.run`` directly.
They go through a :class:`SystemContext`. In production the context points at the real
``/`` and the real subprocess; tests construct one with ``root=`` pointing at a fixture
tree and ``runner=`` set to a recorder.
"""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True)
class SystemContext:
    root: Path = field(default_factory=lambda: Path("/"))
    uname_release: str = field(
        default_factory=lambda: os.uname().release if hasattr(os, "uname") else ""
    )
    runner: Runner = subprocess.run
    geteuid: Callable[[], int] = field(default_factory=lambda: getattr(os, "geteuid", lambda: 0))
    is_linux: bool = field(default_factory=lambda: platform.system() == "Linux")

    def under_root(self, *parts: str) -> Path:
        """Resolve a path under :attr:`root`, stripping leading ``/`` from each component."""
        cleaned = [p.lstrip("/") for p in parts]
        return self.root.joinpath(*cleaned)


def default_context() -> SystemContext:
    """Return a :class:`SystemContext` bound to the real running system."""
    return SystemContext()
