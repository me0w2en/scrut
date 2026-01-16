"""Output formatting for Scrut CLI.

Implements JSON, JSONL, and human-readable output modes.
stdout contains only machine-readable results.
stderr carries progress, logs, and diagnostics.
"""

import json
import sys
from collections.abc import Iterator
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel

OutputFormat = Literal["json", "jsonl", "human"]

_output_format: OutputFormat = "json"


def set_output_format(format: OutputFormat) -> None:
    """Set the global output format."""
    global _output_format
    _output_format = format


def get_output_format() -> OutputFormat:
    """Get the current output format."""
    return _output_format


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for Scrut types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, BaseModel):
            return obj.model_dump(mode="json")
        return super().default(obj)


def output_json(data: Any, file: Any = None) -> None:
    """Output data as JSON to stdout.

    Args:
        data: Data to output (dict, list, or Pydantic model)
        file: Output file (defaults to stdout)
    """
    if file is None:
        file = sys.stdout

    if isinstance(data, BaseModel):
        output = data.model_dump(mode="json")
    else:
        output = data

    json.dump(output, file, cls=JSONEncoder, ensure_ascii=False)
    file.write("\n")
    file.flush()


def output_jsonl(records: Iterator[Any], file: Any = None) -> None:
    """Output records as JSONL (one JSON object per line) to stdout.

    Args:
        records: Iterator of records (dicts or Pydantic models)
        file: Output file (defaults to stdout)
    """
    if file is None:
        file = sys.stdout

    for record in records:
        if isinstance(record, BaseModel):
            output = record.model_dump(mode="json")
        else:
            output = record
        json.dump(output, file, cls=JSONEncoder, ensure_ascii=False)
        file.write("\n")
        file.flush()


def output_human(data: Any, title: str | None = None, file: Any = None) -> None:
    """Output data in human-readable format to stdout.

    Args:
        data: Data to output
        title: Optional title for the output
        file: Output file (defaults to stdout)
    """
    if file is None:
        file = sys.stdout

    if title:
        file.write(f"\n{title}\n")
        file.write("=" * len(title) + "\n\n")

    if isinstance(data, BaseModel):
        data = data.model_dump(mode="json")

    if isinstance(data, dict):
        _format_dict(data, file)
    elif isinstance(data, list):
        _format_list(data, file)
    else:
        file.write(str(data) + "\n")

    file.flush()


def output_human_table(
    records: list[dict[str, Any]],
    columns: list[str] | None = None,
    title: str | None = None,
    file: Any = None,
    max_width: int = 50,
) -> None:
    """Output records as a human-readable table.

    Args:
        records: List of record dictionaries
        columns: Columns to display (auto-detect if None)
        title: Optional title for the table
        file: Output file (defaults to stdout)
        max_width: Maximum column width
    """
    if file is None:
        file = sys.stdout

    if not records:
        file.write("No records.\n")
        return

    if title:
        file.write(f"\n{title}\n")
        file.write("=" * len(title) + "\n\n")

    if columns is None:
        columns = _auto_detect_columns(records)

    widths = {col: len(col) for col in columns}
    for record in records[:100]:
        for col in columns:
            value = _get_nested_value(record, col)
            widths[col] = min(max_width, max(widths[col], len(str(value))))

    header = " | ".join(col.ljust(widths[col])[:widths[col]] for col in columns)
    file.write(header + "\n")
    file.write("-" * len(header) + "\n")

    for record in records:
        row = []
        for col in columns:
            value = _get_nested_value(record, col)
            value_str = str(value) if value is not None else ""
            if len(value_str) > widths[col]:
                value_str = value_str[: widths[col] - 3] + "..."
            row.append(value_str.ljust(widths[col]))
        file.write(" | ".join(row) + "\n")

    file.write(f"\nTotal: {len(records)} records\n")
    file.flush()


def _auto_detect_columns(records: list[dict[str, Any]]) -> list[str]:
    """Auto-detect best columns for display based on record type."""
    if not records:
        return []

    first = records[0]

    if "data" in first and isinstance(first["data"], dict):
        data = first["data"]

        if "event_id" in data:
            return ["timestamp", "data.event_id", "data.channel", "data.record_number"]

        if "executable_name" in data:
            return [
                "timestamp",
                "data.executable_name",
                "data.run_count",
                "data.last_run_time",
            ]

        if "key_path" in data:
            return ["data.key_path", "data.value_name", "data.value_type", "data.value_data"]

    return list(first.keys())[:6]


def _get_nested_value(record: dict[str, Any], key: str) -> Any:
    """Get a nested value using dot notation (e.g., 'data.event_id')."""
    parts = key.split(".")
    value = record
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def _format_dict(data: dict[str, Any], file: Any, indent: int = 0) -> None:
    """Format a dictionary for human-readable output."""
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            file.write(f"{prefix}{key}:\n")
            _format_dict(value, file, indent + 1)
        elif isinstance(value, list):
            file.write(f"{prefix}{key}:\n")
            _format_list(value, file, indent + 1)
        else:
            file.write(f"{prefix}{key}: {value}\n")


def _format_list(data: list[Any], file: Any, indent: int = 0) -> None:
    """Format a list for human-readable output."""
    prefix = "  " * indent
    for i, item in enumerate(data):
        if isinstance(item, dict):
            file.write(f"{prefix}[{i}]:\n")
            _format_dict(item, file, indent + 1)
        else:
            file.write(f"{prefix}- {item}\n")


def output(data: Any, format: OutputFormat | None = None, **kwargs: Any) -> None:
    """Output data in the specified format.

    Args:
        data: Data to output
        format: Output format (uses global if not specified)
        **kwargs: Additional arguments passed to format-specific function
    """
    if format is None:
        format = _output_format

    if format == "json":
        output_json(data, **kwargs)
    elif format == "jsonl":
        if not hasattr(data, "__iter__") or isinstance(data, (dict, str)):
            output_json(data, **kwargs)
        else:
            output_jsonl(iter(data), **kwargs)
    elif format == "human":
        output_human(data, **kwargs)
    else:
        output_json(data, **kwargs)


def output_error(error: Any, file: Any = None) -> None:
    """Output an error to stdout in the current format.

    Errors are output to stdout (not stderr) for programmatic handling.
    """
    output(error, file=file)


def output_pagination(
    has_more: bool,
    cursor: str | None = None,
    total_estimated: int | None = None,
    file: Any = None,
) -> None:
    """Output pagination metadata.

    Args:
        has_more: Whether more results are available
        cursor: Cursor for next page
        total_estimated: Estimated total record count
        file: Output file (defaults to stdout)
    """
    pagination = {"_pagination": {"has_more": has_more}}

    if cursor:
        pagination["_pagination"]["cursor"] = cursor

    if total_estimated is not None:
        pagination["_pagination"]["total_estimated"] = total_estimated

    output_json(pagination, file=file)


class OutputFormatter:
    """Encapsulates output formatting for commands."""

    def __init__(self, format: OutputFormat = "json"):
        """Initialize formatter with specified format.

        Args:
            format: Output format (json, jsonl, human)
        """
        self.format = format
        self._buffer: list[dict[str, Any]] = []

    def output(self, data: Any) -> None:
        """Output data in the configured format.

        Args:
            data: Data to output to stdout
        """
        if self.format == "human":
            if isinstance(data, BaseModel):
                self._buffer.append(data.model_dump(mode="json"))
            elif isinstance(data, dict):
                self._buffer.append(data)
            else:
                output_human(data)
        else:
            output(data, format=self.format)

    def error(self, error: Any) -> None:
        """Output error in the configured format.

        Args:
            error: Error data to output to stdout
        """
        output_error(error)

    def stream(self, records: Iterator[Any]) -> None:
        """Stream records in JSONL format.

        Args:
            records: Iterator of records
        """
        if self.format == "human":
            record_list = []
            for record in records:
                if isinstance(record, BaseModel):
                    record_list.append(record.model_dump(mode="json"))
                else:
                    record_list.append(record)
            output_human_table(record_list)
        else:
            output_jsonl(records)

    def flush_table(self, title: str | None = None) -> None:
        """Flush buffered records as a table (for human format).

        Args:
            title: Optional title for the table
        """
        if self._buffer and self.format == "human":
            output_human_table(self._buffer, title=title)
            self._buffer = []

    def is_human(self) -> bool:
        """Check if output format is human-readable."""
        return self.format == "human"

    def pagination(
        self,
        has_more: bool,
        cursor: str | None = None,
        total_estimated: int | None = None,
        records_returned: int = 0,
    ) -> None:
        """Output pagination metadata.

        Args:
            has_more: Whether more results are available
            cursor: Cursor for next page
            total_estimated: Estimated total record count
            records_returned: Number of records returned
        """
        if self.format == "human":
            import sys
            sys.stderr.write(f"\nRecords returned: {records_returned}")
            if total_estimated:
                sys.stderr.write(f" of ~{total_estimated}")
            if has_more and cursor:
                sys.stderr.write(f"\nMore results available. Use --cursor {cursor}")
            sys.stderr.write("\n")
        else:
            output_pagination(has_more, cursor, total_estimated)
