"""Filesystem sandbox guard. Deny by default: anything unusual is rejected, not normalised."""

from __future__ import annotations

import re
from pathlib import Path

from mcp_hub.errors import AccessDenied, NotFound, ValidationFailed

_WINDOWS_DEVICE = re.compile(r"^(con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])$", re.I)


def validate_relative(rel: str) -> list[str]:
    """Return safe path components or raise. Pure string checks, no filesystem access."""
    if "\x00" in rel:
        raise ValidationFailed("Path contains a NUL byte.")
    if rel.startswith(("\\\\", "//")) or rel.startswith(("/", "\\")):
        raise AccessDenied("Absolute paths are not allowed.")
    if ":" in rel:
        raise AccessDenied("Drive letters and alternate data streams are not allowed.")
    parts = [p for p in re.split(r"[\\/]", rel) if p not in ("", ".")]
    for part in parts:
        if part == "..":
            raise AccessDenied("Parent directory references are not allowed.")
        if part != part.rstrip(" ."):
            raise AccessDenied("Path components must not end with a dot or space.")
        stem = part.split(".", 1)[0]
        if _WINDOWS_DEVICE.match(stem):
            raise AccessDenied("Reserved device names are not allowed.")
    return parts


def resolve_safe(root: Path, rel: str) -> Path:
    """Resolve `rel` under `root`, following symlinks, and require the result stays inside root."""
    parts = validate_relative(rel)
    root_resolved = root.resolve(strict=True)
    candidate = root_resolved.joinpath(*parts)
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        raise NotFound("No such file or directory.") from None
    except OSError:
        raise AccessDenied("Path cannot be resolved.") from None
    if not resolved.is_relative_to(root_resolved):
        raise AccessDenied("Path escapes the allowed root.")
    return resolved
