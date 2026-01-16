"""Pagination utilities for large result sets.

Provides cursor-based pagination for streaming parse results to enable
LLM agents to process outputs without token overflow.
"""

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class PaginationState:
    """State for cursor-based pagination."""

    offset: int
    timestamp_cursor: datetime | None = None
    record_id_cursor: str | None = None
    total_estimated: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "o": self.offset,
            "t": self.timestamp_cursor.isoformat() if self.timestamp_cursor else None,
            "r": self.record_id_cursor,
            "n": self.total_estimated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PaginationState":
        """Create from dictionary."""
        timestamp = None
        if data.get("t"):
            timestamp = datetime.fromisoformat(data["t"])
        return cls(
            offset=data.get("o", 0),
            timestamp_cursor=timestamp,
            record_id_cursor=data.get("r"),
            total_estimated=data.get("n"),
        )


class CursorGenerator:
    """Generates and decodes pagination cursors."""

    @staticmethod
    def encode(state: PaginationState) -> str:
        """Encode pagination state to opaque cursor string.

        Args:
            state: Pagination state to encode

        Returns:
            Base64-encoded cursor string
        """
        data = state.to_dict()
        json_str = json.dumps(data, separators=(",", ":"))
        return base64.urlsafe_b64encode(json_str.encode()).decode()

    @staticmethod
    def decode(cursor: str) -> PaginationState:
        """Decode cursor string to pagination state.

        Args:
            cursor: Base64-encoded cursor string

        Returns:
            PaginationState object

        Raises:
            ValueError: If cursor is invalid
        """
        try:
            json_str = base64.urlsafe_b64decode(cursor).decode()
            data = json.loads(json_str)
            return PaginationState.from_dict(data)
        except Exception as e:
            raise ValueError(f"Invalid cursor: {e}")

    @staticmethod
    def create_next_cursor(
        current_offset: int,
        last_timestamp: datetime | None,
        last_record_id: str | None,
        total_estimated: int | None = None,
    ) -> str:
        """Create a cursor for the next page.

        Args:
            current_offset: Current record offset (records processed so far)
            last_timestamp: Timestamp of last record
            last_record_id: ID of last record
            total_estimated: Estimated total record count

        Returns:
            Encoded cursor string
        """
        state = PaginationState(
            offset=current_offset,
            timestamp_cursor=last_timestamp,
            record_id_cursor=last_record_id,
            total_estimated=total_estimated,
        )
        return CursorGenerator.encode(state)


@dataclass
class PaginationResult:
    """Result metadata for paginated responses."""

    has_more: bool
    cursor: str | None = None
    offset: int = 0
    limit: int | None = None
    total_estimated: int | None = None
    records_returned: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result = {
            "has_more": self.has_more,
            "records_returned": self.records_returned,
        }
        if self.cursor:
            result["cursor"] = self.cursor
        if self.offset > 0:
            result["offset"] = self.offset
        if self.limit:
            result["limit"] = self.limit
        if self.total_estimated is not None:
            result["total_estimated"] = self.total_estimated
        return result


class Paginator:
    """Handles pagination logic for parse results."""

    def __init__(
        self,
        limit: int | None = None,
        offset: int = 0,
        cursor: str | None = None,
    ) -> None:
        """Initialize paginator.

        Args:
            limit: Maximum records to return
            offset: Starting offset
            cursor: Cursor from previous page
        """
        self.limit = limit
        self.offset = offset
        self.cursor_state: PaginationState | None = None

        if cursor:
            self.cursor_state = CursorGenerator.decode(cursor)
            self.offset = self.cursor_state.offset

        self.records_processed = 0
        self.records_output = 0
        self.last_timestamp: datetime | None = None
        self.last_record_id: str | None = None

    def should_skip(self, record_index: int) -> bool:
        """Check if record should be skipped based on offset.

        Args:
            record_index: Current record index

        Returns:
            True if record should be skipped
        """
        return record_index < self.offset

    def should_stop(self) -> bool:
        """Check if pagination limit has been reached.

        Returns:
            True if limit reached
        """
        if self.limit is None:
            return False
        return self.records_output >= self.limit

    def record_output(
        self,
        timestamp: datetime | None = None,
        record_id: str | None = None,
    ) -> None:
        """Record that a record was output.

        Args:
            timestamp: Record timestamp
            record_id: Record ID
        """
        self.records_output += 1
        self.records_processed += 1
        self.last_timestamp = timestamp
        self.last_record_id = record_id

    def get_result(self, total_available: int | None = None) -> PaginationResult:
        """Get pagination result metadata.

        Args:
            total_available: Total records available (if known)

        Returns:
            PaginationResult with metadata
        """
        has_more = False
        next_cursor = None

        if self.limit and self.records_output >= self.limit:
            has_more = True
            next_cursor = CursorGenerator.create_next_cursor(
                current_offset=self.offset + self.records_output,
                last_timestamp=self.last_timestamp,
                last_record_id=self.last_record_id,
                total_estimated=total_available,
            )

        return PaginationResult(
            has_more=has_more,
            cursor=next_cursor,
            offset=self.offset,
            limit=self.limit,
            total_estimated=total_available,
            records_returned=self.records_output,
        )


def parse_time_filter(value: str | None) -> datetime | None:
    """Parse a time filter value to datetime.

    Supports:
    - ISO-8601 format: 2026-01-14T00:00:00Z
    - Relative format: 7d, 24h, 30m (days, hours, minutes ago)

    Args:
        value: Time filter string

    Returns:
        Datetime or None if not specified
    """
    if not value:
        return None

    if value.endswith("d"):
        days = int(value[:-1])
        from datetime import timedelta, timezone
        return datetime.now(timezone.utc) - timedelta(days=days)
    elif value.endswith("h"):
        hours = int(value[:-1])
        from datetime import timedelta, timezone
        return datetime.now(timezone.utc) - timedelta(hours=hours)
    elif value.endswith("m"):
        minutes = int(value[:-1])
        from datetime import timedelta, timezone
        return datetime.now(timezone.utc) - timedelta(minutes=minutes)
    else:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
