"""Logging and progress utilities for Scrut DFIR CLI.

All progress and log output goes to stderr to keep stdout clean
for machine-readable results (JSON/JSONL).
"""

import json
import sys
import time
from datetime import UTC, datetime
from typing import Any, Literal

_verbose = False
_quiet = False
_log_format: Literal["text", "json"] = "text"


def set_verbose(verbose: bool) -> None:
    """Set verbose mode."""
    global _verbose
    _verbose = verbose


def set_quiet(quiet: bool) -> None:
    """Set quiet mode."""
    global _quiet
    _quiet = quiet


def configure_logging(
    log_format: Literal["text", "json"] = "text",
    quiet: bool = False,
) -> None:
    """Configure logging settings.

    Args:
        log_format: Output format for log messages
        quiet: Suppress progress output
    """
    global _log_format, _quiet
    _log_format = log_format
    _quiet = quiet


def log(
    message: str,
    level: Literal["debug", "info", "warning", "error"] = "info",
    **context: Any,
) -> None:
    """Log a message to stderr.

    Args:
        message: Log message
        level: Log level
        **context: Additional context to include
    """
    if _quiet and level in ("debug", "info"):
        return

    if level == "debug" and not _verbose:
        return

    if _log_format == "json":
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
            **context,
        }
        print(json.dumps(log_entry), file=sys.stderr)
    else:
        prefix = f"[{level.upper()}]" if level != "info" else ""
        if prefix:
            print(f"{prefix} {message}", file=sys.stderr)
        else:
            print(message, file=sys.stderr)


def debug(message: str, **context: Any) -> None:
    """Log a debug message."""
    log(message, level="debug", **context)


def info(message: str, **context: Any) -> None:
    """Log an info message."""
    log(message, level="info", **context)


def warning(message: str, **context: Any) -> None:
    """Log a warning message."""
    log(message, level="warning", **context)


def error(message: str, **context: Any) -> None:
    """Log an error message."""
    log(message, level="error", **context)


class ProgressReporter:
    """Reports progress to stderr.

    Used for long-running operations to show progress and ETA.
    """

    def __init__(
        self,
        total: int | None = None,
        description: str = "Processing",
        unit: str = "records",
    ):
        self.total = total
        self.description = description
        self.unit = unit
        self.current = 0
        self.start_time = time.perf_counter()
        self._last_update = 0.0

    def update(self, amount: int = 1) -> None:
        """Update progress by amount.

        Args:
            amount: Number of items processed
        """
        if _quiet:
            return

        self.current += amount

        now = time.perf_counter()
        if now - self._last_update < 0.1:  # Max 10 updates/second
            return
        self._last_update = now

        self._print_progress()

    def _print_progress(self) -> None:
        """Print current progress to stderr."""
        elapsed = time.perf_counter() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0

        if self.total:
            percentage = (self.current / self.total) * 100
            eta_seconds = (self.total - self.current) / rate if rate > 0 else 0
            eta_str = _format_duration(eta_seconds)

            if _log_format == "json":
                progress = {
                    "description": self.description,
                    "current": self.current,
                    "total": self.total,
                    "percentage": round(percentage, 1),
                    "rate": round(rate, 1),
                    "unit": self.unit,
                    "eta_seconds": round(eta_seconds, 1),
                }
                print(json.dumps({"progress": progress}), file=sys.stderr)
            else:
                print(
                    f"\r{self.description}: {self.current}/{self.total} "
                    f"({percentage:.1f}%) - {rate:.1f} {self.unit}/s - ETA: {eta_str}",
                    end="",
                    file=sys.stderr,
                )
        else:
            if _log_format == "json":
                progress = {
                    "description": self.description,
                    "current": self.current,
                    "rate": round(rate, 1),
                    "unit": self.unit,
                }
                print(json.dumps({"progress": progress}), file=sys.stderr)
            else:
                print(
                    f"\r{self.description}: {self.current} {self.unit} "
                    f"({rate:.1f} {self.unit}/s)",
                    end="",
                    file=sys.stderr,
                )

    def finish(self) -> None:
        """Mark progress as complete."""
        if _quiet:
            return

        elapsed = time.perf_counter() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0

        if _log_format == "json":
            complete = {
                "description": self.description,
                "total": self.current,
                "duration_seconds": round(elapsed, 2),
                "rate": round(rate, 1),
                "unit": self.unit,
            }
            print(json.dumps({"complete": complete}), file=sys.stderr)
        else:
            print(
                f"\n{self.description}: Complete - {self.current} {self.unit} "
                f"in {_format_duration(elapsed)} ({rate:.1f} {self.unit}/s)",
                file=sys.stderr,
            )


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
