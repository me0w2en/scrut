"""Windows Notifications parser.

Parses Windows notification database to track application notifications
and user interactions, useful for understanding user activity timeline.

Location:
- %LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase.db
- %LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\appdb.dat
"""

import json
import sqlite3
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"


def _filetime_to_datetime(filetime: int | str | None) -> datetime | None:
    """Convert Windows FILETIME to datetime."""
    if filetime is None:
        return None
    # Handle string inputs from SQLite
    if isinstance(filetime, str):
        try:
            filetime = int(filetime)
        except ValueError:
            return None
    if filetime == 0 or filetime < 0:
        return None
    try:
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return None
        timestamp = (filetime - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (OSError, ValueError, OverflowError):
        return None


@dataclass
class Notification:
    """A Windows notification record."""

    notification_id: str
    handler_id: str
    app_name: str
    title: str
    body: str
    payload: str
    arrival_time: datetime | None
    expiry_time: datetime | None
    notification_type: str
    badge_value: str = ""
    tag: str = ""
    group: str = ""


@dataclass
class NotificationHandler:
    """A notification handler (app) registration."""

    handler_id: str
    primary_id: str  # Usually AppUserModelId
    handler_type: str
    created_time: datetime | None
    modified_time: datetime | None
    settings: dict[str, Any] | None = None


class NotificationsParser:
    """Parser for Windows notifications database."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.notifications: list[Notification] = []
        self.handlers: list[NotificationHandler] = []
        self._parse()

    def _parse(self) -> None:
        """Parse notifications database."""
        if len(self.data) < 100:
            return

        # Check if SQLite database
        if self.data[:16] == b"SQLite format 3\x00":
            self._parse_sqlite()
        else:
            self._parse_binary()

    def _parse_sqlite(self) -> None:
        """Parse SQLite notifications database."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
            tmp.write(self.data)
            tmp_path = tmp.name

        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row

            self._parse_handlers_table(conn)
            self._parse_notifications_table(conn)

            conn.close()
        except sqlite3.Error:
            pass
        finally:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass

    def _parse_handlers_table(self, conn: sqlite3.Connection) -> None:
        """Parse NotificationHandler table."""
        try:
            cursor = conn.execute("""
                SELECT
                    RecordId,
                    PrimaryId,
                    HandlerType,
                    CreatedTime,
                    ModifiedTime,
                    WNSId,
                    WNFEventName
                FROM NotificationHandler
            """)

            for row in cursor:
                handler = NotificationHandler(
                    handler_id=str(row["RecordId"]) if row["RecordId"] else "",
                    primary_id=row["PrimaryId"] or "",
                    handler_type=row["HandlerType"] or "",
                    created_time=_filetime_to_datetime(row["CreatedTime"]) if row["CreatedTime"] else None,
                    modified_time=_filetime_to_datetime(row["ModifiedTime"]) if row["ModifiedTime"] else None,
                )
                self.handlers.append(handler)
        except sqlite3.Error:
            pass

    def _parse_notifications_table(self, conn: sqlite3.Connection) -> None:
        """Parse Notification table."""
        try:
            cursor = conn.execute("""
                SELECT
                    Id,
                    HandlerId,
                    Type,
                    Payload,
                    Tag,
                    "Group",
                    ExpiryTime,
                    ArrivalTime,
                    PayloadType,
                    BootId
                FROM Notification
            """)

            handler_lookup = {h.handler_id: h.primary_id for h in self.handlers}

            for row in cursor:
                handler_id = str(row["HandlerId"]) if row["HandlerId"] else ""
                app_name = handler_lookup.get(handler_id, "")

                # Parse payload (usually XML or JSON)
                payload = ""
                title = ""
                body = ""

                if row["Payload"]:
                    payload_data = row["Payload"]
                    if isinstance(payload_data, bytes):
                        try:
                            payload = payload_data.decode("utf-8")
                        except UnicodeDecodeError:
                            payload = payload_data.decode("utf-16-le", errors="replace")
                    else:
                        payload = str(payload_data)

                    # Try to extract title and body from XML
                    title, body = self._extract_notification_content(payload)

                notification = Notification(
                    notification_id=str(row["Id"]) if row["Id"] else "",
                    handler_id=handler_id,
                    app_name=app_name,
                    title=title,
                    body=body,
                    payload=payload[:500] if len(payload) > 500 else payload,
                    arrival_time=_filetime_to_datetime(row["ArrivalTime"]) if row["ArrivalTime"] else None,
                    expiry_time=_filetime_to_datetime(row["ExpiryTime"]) if row["ExpiryTime"] else None,
                    notification_type=row["Type"] or "",
                    tag=row["Tag"] or "",
                    group=row["Group"] or "",
                )
                self.notifications.append(notification)
        except sqlite3.Error:
            pass

    def _extract_notification_content(self, payload: str) -> tuple[str, str]:
        """Extract title and body from notification payload."""
        import re

        title = ""
        body = ""

        # Try XML format
        title_match = re.search(r"<text[^>]*>([^<]+)</text>", payload, re.IGNORECASE)
        if title_match:
            title = title_match.group(1)

        texts = re.findall(r"<text[^>]*>([^<]+)</text>", payload, re.IGNORECASE)
        if len(texts) > 1:
            body = texts[1]

        # Try JSON format
        if not title:
            try:
                data = json.loads(payload)
                if isinstance(data, dict):
                    title = data.get("title", data.get("Title", ""))
                    body = data.get("body", data.get("Body", data.get("message", "")))
            except json.JSONDecodeError:
                pass

        return title, body

    def _parse_binary(self) -> None:
        """Parse binary notification data (appdb.dat)."""
        # This is a simplified parser for binary format
        # The actual format is more complex

        # Look for notification patterns
        import re

        # Find app IDs (usually contains underscores and exclamation marks)
        app_pattern = re.compile(
            rb"([A-Za-z0-9_\.\-]+![A-Za-z0-9_\.\-]+)",
        )

        for match in app_pattern.finditer(self.data):
            try:
                app_id = match.group(1).decode("ascii")
                if len(app_id) > 5:
                    self.handlers.append(
                        NotificationHandler(
                            handler_id=str(match.start()),
                            primary_id=app_id,
                            handler_type="app",
                            created_time=None,
                            modified_time=None,
                        )
                    )
            except Exception:
                pass


@ParserRegistry.register
class NotificationsFileParser(BaseParser):
    """Parser for Windows notifications database."""

    name: ClassVar[str] = "notifications"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "notifications",
        "windows_notifications",
        "wpndatabase",
        "appdb",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize notifications parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse notifications database."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse notifications from bytes."""
        parser = NotificationsParser(data)

        record_index = 0

        for notification in parser.notifications:
            record_data: dict[str, Any] = {
                "notification_id": notification.notification_id,
                "notification_type": notification.notification_type,
                "source_file": filename,
            }

            if notification.handler_id:
                record_data["handler_id"] = notification.handler_id
            if notification.app_name:
                record_data["app_name"] = notification.app_name
            if notification.title:
                record_data["title"] = notification.title
            if notification.body:
                record_data["body"] = notification.body
            if notification.tag:
                record_data["tag"] = notification.tag
            if notification.group:
                record_data["group"] = notification.group
            if notification.arrival_time:
                record_data["arrival_time"] = notification.arrival_time.isoformat()
            if notification.expiry_time:
                record_data["expiry_time"] = notification.expiry_time.isoformat()
            if notification.payload and len(notification.payload) < 500:
                record_data["payload_preview"] = notification.payload

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "notification",
                notification.notification_id,
                notification.handler_id,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=notification.arrival_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        for handler in parser.handlers:
            record_data = {
                "record_type": "notification_handler",
                "handler_id": handler.handler_id,
                "primary_id": handler.primary_id,
                "handler_type": handler.handler_type,
                "source_file": filename,
            }

            if handler.created_time:
                record_data["created_time"] = handler.created_time.isoformat()
            if handler.modified_time:
                record_data["modified_time"] = handler.modified_time.isoformat()

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "notification_handler",
                handler.handler_id,
                handler.primary_id,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=handler.created_time or handler.modified_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        if parser.notifications or parser.handlers:
            summary_data = {
                "summary": True,
                "notification_count": len(parser.notifications),
                "handler_count": len(parser.handlers),
                "source_file": filename,
            }

            apps = set()
            for n in parser.notifications:
                if n.app_name:
                    apps.add(n.app_name)
            for h in parser.handlers:
                if h.primary_id:
                    apps.add(h.primary_id)
            summary_data["unique_apps"] = list(apps)[:20]

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("notifications_summary", filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=summary_data,
                evidence_ref=evidence_ref,
            )
