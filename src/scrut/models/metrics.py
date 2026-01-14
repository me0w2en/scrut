"""Observability metrics models for Scrut DFIR CLI."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class StepMetrics(BaseModel):
    """Observability metrics for a command or step.

    Every command invocation emits these metrics to stderr
    for observability and debugging.
    """

    run_id: UUID = Field(
        ...,
        description="Correlation ID for this run",
    )

    step_name: str = Field(
        ...,
        description="Step identifier (e.g., 'parse_evtx', 'case_init')",
    )

    duration_ms: int = Field(
        ...,
        ge=0,
        description="Execution time in milliseconds",
    )

    records_processed: int = Field(
        default=0,
        ge=0,
        description="Number of records processed",
    )

    records_output: int = Field(
        default=0,
        ge=0,
        description="Number of records emitted",
    )

    bytes_read: int = Field(
        default=0,
        ge=0,
        description="Bytes read from input",
    )

    bytes_written: int = Field(
        default=0,
        ge=0,
        description="Bytes written to output",
    )

    warnings: int = Field(
        default=0,
        ge=0,
        description="Warning count",
    )

    errors: int = Field(
        default=0,
        ge=0,
        description="Error count",
    )

    skipped: int = Field(
        default=0,
        ge=0,
        description="Skipped record count",
    )

    model_config = {"extra": "forbid"}


class RunMetadata(BaseModel):
    """Metadata for a command run.

    Captures environment and version information for reproducibility.
    """

    run_id: UUID = Field(
        ...,
        description="Unique identifier for this run",
    )

    command: str = Field(
        ...,
        description="Full command that was executed",
    )

    scrut_version: str = Field(
        ...,
        description="Scrut CLI version",
    )

    started_at: datetime = Field(
        ...,
        description="ISO-8601 start timestamp",
    )

    completed_at: datetime | None = Field(
        default=None,
        description="ISO-8601 completion timestamp",
    )

    exit_code: int | None = Field(
        default=None,
        description="Process exit code",
    )

    metrics: StepMetrics | None = Field(
        default=None,
        description="Execution metrics",
    )

    model_config = {"extra": "forbid"}
