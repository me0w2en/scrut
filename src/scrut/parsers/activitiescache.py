r"""ActivitiesCache (Windows Timeline) parser.

Parses the Windows Timeline database to track user activities
including application usage, file access, and web browsing.

Locations:
- %LOCALAPPDATA%\ConnectedDevicesPlatform\<user>\ActivitiesCache.db
- %LOCALAPPDATA%\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db

Introduced in Windows 10 version 1803.
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

# Activity types
ACTIVITY_TYPES = {
    2: "Notification",
    3: "Copy/Paste",
    5: "App Usage",
    6: "App Usage (URI)",
    10: "App Activation",
    11: "App Usage (Blob)",
    12: "App Usage (Phone)",
    15: "Cloud File Access",
    16: "App Usage (Blob)",
}

# Activity status
ACTIVITY_STATUS = {
    1: "Active",
    2: "Updated",
    3: "Deleted",
    4: "Ignored",
}


def _filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME to datetime."""
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


def _unix_to_datetime(unix_ts: int) -> datetime | None:
    """Convert Unix timestamp to datetime."""
    if unix_ts == 0:
        return None
    try:
        return datetime.fromtimestamp(unix_ts, tz=UTC)
    except (OSError, ValueError):
        return None


@dataclass
class Activity:
    """A single activity record."""

    activity_id: str
    app_id: str
    activity_type: int
    activity_type_name: str
    start_time: datetime | None
    end_time: datetime | None
    last_modified: datetime | None
    expiration_time: datetime | None
    payload: dict[str, Any]
    platform: str = ""
    display_text: str = ""
    description: str = ""
    app_activity_id: str = ""
    clipboard_data: str = ""
    is_local_only: bool = False
    etag: str = ""
    package_id: str = ""
    status: int = 0


class ActivitiesCacheParser:
    """Parser for ActivitiesCache.db SQLite database."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.activities: list[Activity] = []
        self._parse()

    def _parse(self) -> None:
        """Parse ActivitiesCache.db database."""
        # SQLite requires a file, create a temporary one
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
            tmp.write(self.data)
            tmp_path = tmp.name

        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row

            # Parse Activity table
            self._parse_activity_table(conn)

            # Parse ActivityOperation table (pending sync operations)
            self._parse_activity_operation_table(conn)

            conn.close()
        except sqlite3.Error:
            pass
        finally:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass

    def _parse_activity_table(self, conn: sqlite3.Connection) -> None:
        """Parse the Activity table."""
        try:
            cursor = conn.execute("""
                SELECT
                    Id,
                    AppId,
                    ActivityType,
                    StartTime,
                    EndTime,
                    LastModifiedTime,
                    ExpirationTime,
                    Payload,
                    Priority,
                    IsLocalOnly,
                    PlatformDeviceId,
                    CreatedInCloud,
                    ETag,
                    PackageIdHash,
                    ActivityStatus
                FROM Activity
            """)

            for row in cursor:
                self._process_activity_row(row)
        except sqlite3.Error:
            # Table might not exist or have different schema
            pass

    def _parse_activity_operation_table(self, conn: sqlite3.Connection) -> None:
        """Parse the ActivityOperation table."""
        try:
            cursor = conn.execute("""
                SELECT
                    Id,
                    AppId,
                    ActivityType,
                    StartTime,
                    EndTime,
                    LastModifiedTime,
                    ExpirationTime,
                    Payload
                FROM ActivityOperation
            """)

            for row in cursor:
                self._process_activity_row(row, is_operation=True)
        except sqlite3.Error:
            pass

    def _process_activity_row(
        self, row: sqlite3.Row, is_operation: bool = False
    ) -> None:
        """Process a single activity row."""
        try:
            activity_id = str(row["Id"]) if row["Id"] else ""
            app_id = row["AppId"] or ""
            activity_type = row["ActivityType"] or 0

            # Parse timestamps
            start_time = None
            end_time = None
            last_modified = None
            expiration_time = None

            if row["StartTime"]:
                start_time = _unix_to_datetime(row["StartTime"])
            if row["EndTime"]:
                end_time = _unix_to_datetime(row["EndTime"])
            if row["LastModifiedTime"]:
                last_modified = _unix_to_datetime(row["LastModifiedTime"])
            if row["ExpirationTime"]:
                expiration_time = _unix_to_datetime(row["ExpirationTime"])

            # Parse payload (JSON blob)
            payload = {}
            display_text = ""
            description = ""
            app_activity_id = ""

            if row["Payload"]:
                payload_data = row["Payload"]
                if isinstance(payload_data, bytes):
                    try:
                        payload = json.loads(payload_data.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        payload = {"raw": payload_data.hex()[:200]}
                elif isinstance(payload_data, str):
                    try:
                        payload = json.loads(payload_data)
                    except json.JSONDecodeError:
                        payload = {"raw": payload_data[:200]}

                # Extract useful fields from payload
                if isinstance(payload, dict):
                    display_text = payload.get("displayText", "")
                    description = payload.get("description", "")
                    app_activity_id = payload.get("appActivityId", "")

            # Get optional fields safely
            is_local_only = False
            etag = ""
            package_id = ""
            status = 0

            try:
                is_local_only = bool(row["IsLocalOnly"]) if "IsLocalOnly" in row.keys() else False
                etag = row["ETag"] if "ETag" in row.keys() else ""
                package_id = row["PackageIdHash"] if "PackageIdHash" in row.keys() else ""
                status = row["ActivityStatus"] if "ActivityStatus" in row.keys() else 0
            except (KeyError, IndexError):
                pass

            activity = Activity(
                activity_id=activity_id,
                app_id=app_id,
                activity_type=activity_type,
                activity_type_name=ACTIVITY_TYPES.get(activity_type, f"Unknown({activity_type})"),
                start_time=start_time,
                end_time=end_time,
                last_modified=last_modified,
                expiration_time=expiration_time,
                payload=payload,
                display_text=display_text,
                description=description,
                app_activity_id=app_activity_id,
                is_local_only=is_local_only,
                etag=etag or "",
                package_id=package_id or "",
                status=status or 0,
            )

            self.activities.append(activity)
        except Exception:
            pass

    def _parse_app_id(self, app_id: str) -> dict[str, str]:
        """Parse AppId to extract application information."""
        result = {
            "raw": app_id,
            "platform": "",
            "app_name": "",
            "package": "",
        }

        if not app_id:
            return result

        # AppId format can be:
        # - Platform_Package!AppId
        # - {GUID}!AppId
        # - x_exe_path

        if "!" in app_id:
            parts = app_id.split("!", 1)
            result["platform"] = parts[0]
            result["app_name"] = parts[1] if len(parts) > 1 else ""

            # Further parse platform
            if "_" in parts[0]:
                platform_parts = parts[0].split("_", 1)
                result["platform"] = platform_parts[0]
                result["package"] = platform_parts[1] if len(platform_parts) > 1 else ""
        elif app_id.startswith("x_"):
            # Executable path format
            result["platform"] = "Win32"
            result["app_name"] = app_id[2:].replace("_", "\\")

        return result


@ParserRegistry.register
class ActivitiesCacheFileParser(BaseParser):
    """Parser for Windows Timeline (ActivitiesCache.db)."""

    name: ClassVar[str] = "activitiescache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "activitiescache",
        "activities_cache",
        "windows_timeline",
        "timeline",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize ActivitiesCache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse ActivitiesCache.db file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse ActivitiesCache from bytes."""
        parser = ActivitiesCacheParser(data)

        record_index = 0
        for activity in parser.activities:
            record_data: dict[str, Any] = {
                "activity_id": activity.activity_id,
                "app_id": activity.app_id,
                "activity_type": activity.activity_type,
                "activity_type_name": activity.activity_type_name,
            }

            # Parse app_id for more details
            app_info = parser._parse_app_id(activity.app_id)
            if app_info["platform"]:
                record_data["platform"] = app_info["platform"]
            if app_info["app_name"]:
                record_data["app_name"] = app_info["app_name"]
            if app_info["package"]:
                record_data["package"] = app_info["package"]

            # Add timestamps
            if activity.start_time:
                record_data["start_time"] = activity.start_time.isoformat()
            if activity.end_time:
                record_data["end_time"] = activity.end_time.isoformat()
                # Calculate duration
                if activity.start_time:
                    duration = (activity.end_time - activity.start_time).total_seconds()
                    record_data["duration_seconds"] = int(duration)
            if activity.last_modified:
                record_data["last_modified"] = activity.last_modified.isoformat()

            # Add display info
            if activity.display_text:
                record_data["display_text"] = activity.display_text
            if activity.description:
                record_data["description"] = activity.description
            if activity.app_activity_id:
                record_data["app_activity_id"] = activity.app_activity_id

            # Add payload if meaningful
            if activity.payload and activity.payload != {}:
                # Only include non-empty, non-raw payloads
                if not ("raw" in activity.payload and len(activity.payload) == 1):
                    record_data["payload"] = activity.payload

            # Status
            if activity.status:
                record_data["status"] = ACTIVITY_STATUS.get(
                    activity.status, f"Unknown({activity.status})"
                )

            record_data["is_local_only"] = activity.is_local_only

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "activity", activity.activity_id, activity.app_id
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=activity.start_time or activity.last_modified,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
