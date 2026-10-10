from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from mcp_hub.errors import AccessDenied, HubError, NotFound, ValidationFailed
from mcp_hub.plugins.sample.paths import resolve_safe, validate_relative


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "root"
    (r / "a").mkdir(parents=True)
    (r / "a" / "f.txt").write_text("x")
    return r


def test_ok(root: Path) -> None:
    assert resolve_safe(root, "a/f.txt") == (root / "a" / "f.txt").resolve()
    assert resolve_safe(root, "") == root.resolve()
    assert resolve_safe(root, "./a\\f.txt") == (root / "a" / "f.txt").resolve()


@pytest.mark.parametrize(
    "bad",
    [
        "..",
        "../x",
        "a/../../x",
        "a\\..\\..\\x",
        "/etc/passwd",
        "\\Windows",
        "\\\\server\\share",
        "//server/share",
        "C:\\Windows",
        "C:file",
        "f.txt:stream",
        "a/CON",
        "nul.txt",
        "COM1",
        "lpt9.log",
        "a/f.txt.",
        "a/f.txt ",
    ],
)
def test_rejected(root: Path, bad: str) -> None:
    with pytest.raises(AccessDenied):
        resolve_safe(root, bad)


def test_nul_byte(root: Path) -> None:
    with pytest.raises(ValidationFailed):
        validate_relative("a\x00b")


def test_missing(root: Path) -> None:
    with pytest.raises(NotFound):
        resolve_safe(root, "nope")


def test_symlink_escape(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    link = root / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        if sys.platform == "win32":
            import subprocess

            r = subprocess.run(  # noqa: S603
                ["cmd", "/c", "mklink", "/J", str(link), str(outside)],  # noqa: S607
                capture_output=True,
                check=False,
            )
            if r.returncode != 0:
                pytest.skip("cannot create symlink or junction")
        else:
            pytest.skip("cannot create symlink")
    with pytest.raises(HubError):
        resolve_safe(root, "link/secret.txt")
    with pytest.raises(HubError):
        resolve_safe(root, "link")
