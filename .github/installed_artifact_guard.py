"""Reject source-checkout imports during installed-wheel release tests."""

import importlib.util
import sysconfig
from pathlib import Path

import pytest

MODULE = "mudraid"


def pytest_sessionstart(session):
    spec = importlib.util.find_spec(MODULE)
    roots = {Path(sysconfig.get_path(key)).resolve() for key in ("purelib", "platlib")}
    if (
        spec is None
        or spec.origin is None
        or not any(Path(spec.origin).resolve().is_relative_to(root) for root in roots)
    ):
        raise pytest.UsageError(
            f"Installed artifact required: {MODULE} resolved to "
            f"{getattr(spec, 'origin', None)!r}, outside this environment's site-packages"
        )
