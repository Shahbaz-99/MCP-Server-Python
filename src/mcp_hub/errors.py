"""Error taxonomy. `ToolError` messages are safe to show to the model; never put secrets in them."""

from __future__ import annotations


class HubError(Exception):
    """Base class. `code` is a stable machine-readable identifier used in metrics and audit logs."""

    code = "internal_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigError(HubError):
    code = "config_error"


class ValidationFailed(HubError):
    code = "invalid_input"


class AccessDenied(HubError):
    code = "access_denied"


class NotFound(HubError):
    code = "not_found"


class UpstreamError(HubError):
    code = "upstream_error"


class LimitExceeded(HubError):
    code = "limit_exceeded"


class ToolTimeout(HubError):
    code = "timeout"


def to_public_message(exc: BaseException) -> tuple[str, str]:
    """Map any exception to (code, message) safe for a tool error. Unknown errors are masked."""
    if isinstance(exc, HubError):
        return exc.code, exc.message
    return HubError.code, "Internal error. See server logs."
