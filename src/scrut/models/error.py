"""Structured error model for Scrut DFIR CLI."""

from typing import Any

from pydantic import BaseModel, Field


class StructuredError(BaseModel):
    """Structured error response format.

    All errors emitted by Scrut follow this schema to enable
    programmatic error handling and provide actionable remediation.
    """

    code: str = Field(
        ...,
        pattern=r"^[A-Z][A-Z0-9_]*$",
        description="Error code (e.g., TARGET_NOT_FOUND)",
        examples=[
            "TARGET_NOT_FOUND",
            "PARSE_ERROR",
            "INVALID_FORMAT",
            "PERMISSION_DENIED",
            "UNSUPPORTED_ARTIFACT",
            "HASH_MISMATCH",
            "TIMEOUT",
            "RESOURCE_EXHAUSTED",
        ],
    )

    message: str = Field(
        ...,
        description="Human-readable error message",
    )

    remediation: str = Field(
        ...,
        description="Suggested fix or next step",
    )

    retryable: bool = Field(
        ...,
        description="Whether retry may succeed",
    )

    context: dict[str, Any] | None = Field(
        default=None,
        description="Additional context (target_id, path, etc.)",
    )

    model_config = {"extra": "forbid"}


class ErrorCode:
    """Standard error codes for Scrut."""

    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    CASE_NOT_FOUND = "CASE_NOT_FOUND"
    PARSE_ERROR = "PARSE_ERROR"
    INVALID_FORMAT = "INVALID_FORMAT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED_ARTIFACT = "UNSUPPORTED_ARTIFACT"
    HASH_MISMATCH = "HASH_MISMATCH"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    IO_ERROR = "IO_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
