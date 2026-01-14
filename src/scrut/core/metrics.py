"""Run ID generation and metrics collection for Scrut DFIR CLI."""

import time
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from scrut import __version__
from scrut.models.metrics import RunMetadata, StepMetrics


def generate_run_id() -> UUID:
    """Generate a unique run ID.

    Returns:
        UUID v4 for run correlation
    """
    return uuid4()


class MetricsCollector:
    """Collects metrics for a command or step execution."""

    def __init__(self, run_id: UUID | None = None, step_name: str = "unknown"):
        self.run_id = run_id or generate_run_id()
        self.step_name = step_name
        self.start_time: float | None = None
        self.end_time: float | None = None

        self.records_processed = 0
        self.records_output = 0
        self.bytes_read = 0
        self.bytes_written = 0
        self.warnings = 0
        self.errors = 0
        self.skipped = 0

    def start(self) -> None:
        """Mark the start of execution."""
        self.start_time = time.perf_counter()

    def stop(self) -> None:
        """Mark the end of execution."""
        self.end_time = time.perf_counter()

    @property
    def duration_ms(self) -> int:
        """Get execution duration in milliseconds."""
        if self.start_time is None:
            return 0
        end = self.end_time or time.perf_counter()
        return int((end - self.start_time) * 1000)

    def add_records_processed(self, count: int = 1) -> None:
        """Increment records processed counter."""
        self.records_processed += count

    def add_records_output(self, count: int = 1) -> None:
        """Increment records output counter."""
        self.records_output += count

    def add_bytes_read(self, count: int) -> None:
        """Increment bytes read counter."""
        self.bytes_read += count

    def add_bytes_written(self, count: int) -> None:
        """Increment bytes written counter."""
        self.bytes_written += count

    def add_warning(self) -> None:
        """Increment warning counter."""
        self.warnings += 1

    def add_error(self) -> None:
        """Increment error counter."""
        self.errors += 1

    def add_skipped(self, count: int = 1) -> None:
        """Increment skipped counter."""
        self.skipped += count

    def to_step_metrics(self) -> StepMetrics:
        """Convert to StepMetrics model."""
        return StepMetrics(
            run_id=self.run_id,
            step_name=self.step_name,
            duration_ms=self.duration_ms,
            records_processed=self.records_processed,
            records_output=self.records_output,
            bytes_read=self.bytes_read,
            bytes_written=self.bytes_written,
            warnings=self.warnings,
            errors=self.errors,
            skipped=self.skipped,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return self.to_step_metrics().model_dump(mode="json")


class RunContext:
    """Context for a command run with metadata and metrics."""

    def __init__(self, command: str, run_id: UUID | None = None):
        self.run_id = run_id or generate_run_id()
        self.command = command
        self.started_at = datetime.now(UTC)
        self.completed_at: datetime | None = None
        self.exit_code: int | None = None
        self.metrics = MetricsCollector(run_id=self.run_id, step_name=command)

    def complete(self, exit_code: int = 0) -> None:
        """Mark the run as complete."""
        self.completed_at = datetime.now(UTC)
        self.exit_code = exit_code
        self.metrics.stop()

    def to_run_metadata(self) -> RunMetadata:
        """Convert to RunMetadata model."""
        return RunMetadata(
            run_id=self.run_id,
            command=self.command,
            scrut_version=__version__,
            started_at=self.started_at,
            completed_at=self.completed_at,
            exit_code=self.exit_code,
            metrics=self.metrics.to_step_metrics() if self.completed_at else None,
        )


@contextmanager
def collect_metrics(
    step_name: str, run_id: UUID | None = None
) -> Generator[MetricsCollector, None, None]:
    """Context manager for collecting metrics.

    Usage:
        with collect_metrics("parse_evtx") as metrics:
            for record in parse():
                metrics.add_records_processed()
                yield record
                metrics.add_records_output()

    Args:
        step_name: Name of the step being executed
        run_id: Optional run ID for correlation

    Yields:
        MetricsCollector instance
    """
    collector = MetricsCollector(run_id=run_id, step_name=step_name)
    collector.start()
    try:
        yield collector
    finally:
        collector.stop()
