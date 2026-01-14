"""Structured error handling for Scrut DFIR CLI."""

import sys
from typing import TYPE_CHECKING, Any, NoReturn

from scrut.models.error import ErrorCode, StructuredError

if TYPE_CHECKING:
    pass


class ScrutError(Exception):
    """Base exception for Scrut errors.

    Wraps a StructuredError for consistent error handling.
    """

    def __init__(
        self,
        code: str,
        message: str,
        remediation: str,
        retryable: bool = False,
        context: dict[str, Any] | None = None,
    ):
        self.error = StructuredError(
            code=code,
            message=message,
            remediation=remediation,
            retryable=retryable,
            context=context,
        )
        super().__init__(message)

    def to_structured(self) -> StructuredError:
        """Convert to StructuredError."""
        return self.error

    def to_structured_error(self) -> dict:
        """Convert to JSON-serializable dict for output."""
        return self.error.model_dump(mode="json", exclude_none=True)


class TargetNotFoundError(ScrutError):
    """Target not found error."""

    def __init__(self, target_id: str):
        super().__init__(
            code=ErrorCode.TARGET_NOT_FOUND,
            message=f"Target with ID {target_id} not found",
            remediation="Run 'scrut target list' to see available targets",
            retryable=False,
            context={"target_id": target_id},
        )


class CaseNotFoundError(ScrutError):
    """Case not found error."""

    def __init__(self, case_id: str | None = None):
        message = f"Case with ID {case_id} not found" if case_id else "No active case found"
        super().__init__(
            code=ErrorCode.CASE_NOT_FOUND,
            message=message,
            remediation="Run 'scrut case init' to create a new case or 'scrut case list' to see existing cases",
            retryable=False,
            context={"case_id": case_id} if case_id else None,
        )


class ParseError(ScrutError):
    """Parse error."""

    def __init__(self, message: str, artifact_path: str | None = None):
        super().__init__(
            code=ErrorCode.PARSE_ERROR,
            message=message,
            remediation="Check the artifact file for corruption or unsupported format",
            retryable=False,
            context={"artifact_path": artifact_path} if artifact_path else None,
        )


class ValidationError(ScrutError):
    """Validation error."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(
            code=ErrorCode.VALIDATION_ERROR,
            message=message,
            remediation="Check the input parameters and try again",
            retryable=False,
            context={"field": field} if field else None,
        )


class UnsupportedArtifactError(ScrutError):
    """Unsupported artifact type error."""

    def __init__(self, artifact_type: str, supported: list[str]):
        super().__init__(
            code=ErrorCode.UNSUPPORTED_ARTIFACT,
            message=f"Artifact type '{artifact_type}' is not supported",
            remediation=f"Supported types: {', '.join(supported)}",
            retryable=False,
            context={"artifact_type": artifact_type, "supported": supported},
        )


class HashMismatchError(ScrutError):
    """Hash mismatch error."""

    def __init__(self, expected: str, actual: str, path: str):
        super().__init__(
            code=ErrorCode.HASH_MISMATCH,
            message=f"Hash mismatch for {path}",
            remediation="The file may have been modified or corrupted. Re-acquire the evidence.",
            retryable=False,
            context={"expected": expected, "actual": actual, "path": path},
        )


class IOError(ScrutError):
    """I/O error."""

    def __init__(self, message: str, path: str | None = None):
        super().__init__(
            code=ErrorCode.IO_ERROR,
            message=message,
            remediation="Check file permissions and path accessibility",
            retryable=True,
            context={"path": path} if path else None,
        )


def handle_error(error: ScrutError | Exception, exit_code: int = 1) -> NoReturn:
    """Handle an error by outputting it and exiting.

    Args:
        error: The error to handle
        exit_code: Exit code to use
    """
    from scrut.cli.output import output_error

    if isinstance(error, ScrutError):
        output_error(error.to_structured())
    else:
        structured = StructuredError(
            code=ErrorCode.INTERNAL_ERROR,
            message=str(error),
            remediation="This is an unexpected error. Please report it.",
            retryable=False,
            context={"type": type(error).__name__},
        )
        output_error(structured)

    sys.exit(exit_code)


def create_error(
    code: str,
    message: str,
    remediation: str,
    retryable: bool = False,
    context: dict[str, Any] | None = None,
) -> StructuredError:
    """Create a structured error.

    Args:
        code: Error code
        message: Human-readable message
        remediation: Suggested fix
        retryable: Whether retry may succeed
        context: Additional context

    Returns:
        StructuredError instance
    """
    return StructuredError(
        code=code,
        message=message,
        remediation=remediation,
        retryable=retryable,
        context=context,
    )
