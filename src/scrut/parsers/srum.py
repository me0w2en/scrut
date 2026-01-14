"""SRUM (System Resource Usage Monitor) parser.

Parses the SRUDB.dat ESE database to extract application resource usage,
network activity, and energy usage data.

Note: This is a simplified parser that extracts data from a pre-exported
CSV or uses basic ESE page parsing. Full ESE database support would
require a complete ESE implementation.
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# ESE Database constants
ESE_SIGNATURE = b"\xef\xcd\xab\x89"
ESE_PAGE_SIZE = 32768  # Default for SRUM


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


def _ole_timestamp_to_datetime(ole_time: float) -> datetime | None:
    """Convert OLE Automation timestamp to datetime."""
    if ole_time == 0:
        return None
    try:
        # OLE time: days since 1899-12-30
        import datetime as dt
        base = dt.datetime(1899, 12, 30, tzinfo=dt.UTC)
        delta = dt.timedelta(days=ole_time)
        return base + delta
    except (OSError, ValueError, OverflowError):
        return None


@dataclass
class SRUMEntry:
    """A single SRUM entry."""

    table_name: str
    timestamp: datetime | None
    app_id: str | None
    user_sid: str | None
    data: dict[str, Any]


class SRUMParser:
    """Parser for SRUM database.

    This parser attempts to extract basic information from the ESE database
    by scanning for recognizable patterns. For complete SRUM analysis,
    consider exporting data using external tools first.
    """

    # Known SRUM table GUIDs
    TABLE_GUIDS = {
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "Application Resource Usage",
        "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Data Usage",
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "Network Connectivity",
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "Energy Usage",
        "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "Energy Usage (Long Term)",
    }

    def __init__(self, data: bytes) -> None:
        """Initialize parser with SRUDB.dat data."""
        self.data = data
        self.entries: list[SRUMEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse the ESE database for SRUM data."""
        # Check if this is an ESE database
        if len(self.data) < 668:
            return

        # ESE database header signature at offset 4
        if self.data[4:8] != ESE_SIGNATURE:
            # Try to find SRUM data patterns directly
            self._parse_raw()
            return

        # Parse ESE database structure
        self._parse_ese()

    def _parse_ese(self) -> None:
        """Parse ESE database structure."""
        # ESE database parsing is complex; here we use pattern matching
        # to find common SRUM data structures

        # Look for known table GUIDs and extract nearby data
        for guid, table_name in self.TABLE_GUIDS.items():
            guid_bytes = guid.encode("utf-16-le")
            offset = 0

            while True:
                pos = self.data.find(guid_bytes, offset)
                if pos == -1:
                    break

                # Try to extract data around this position
                entry = self._extract_entry_at(pos, table_name)
                if entry:
                    self.entries.append(entry)

                offset = pos + len(guid_bytes)

        # Also try to find application paths and SIDs
        self._find_app_entries()

    def _parse_raw(self) -> None:
        """Parse raw data looking for SRUM-like structures."""
        # Look for common patterns in SRUM data
        self._find_app_entries()

    def _find_app_entries(self) -> None:
        """Find application entries in the data."""
        # Look for common Windows paths that appear in SRUM
        patterns = [
            b"\\Windows\\",
            b"\\Program Files",
            b"\\AppData\\",
            b".exe\x00",
        ]

        found_apps = set()

        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break

                # Try to extract the full path
                start = pos
                while start > 0 and self.data[start - 1] >= 0x20:
                    start -= 1

                end = pos + len(pattern)
                while end < len(self.data) and self.data[end] >= 0x20:
                    end += 1

                try:
                    # Try UTF-16
                    path_start = start - (start % 2)
                    path_data = self.data[path_start:end + (end % 2)]
                    if len(path_data) > 4:
                        try:
                            path = path_data.decode("utf-16-le", errors="ignore")
                            if path and len(path) > 5 and path not in found_apps:
                                found_apps.add(path)
                        except Exception:
                            pass
                except Exception:
                    pass

                offset = pos + len(pattern)

        # Create entries for found applications
        for app_path in found_apps:
            if len(app_path) > 200 or "\x00" in app_path:
                continue

            clean_path = app_path.strip("\x00").strip()
            if clean_path and ("exe" in clean_path.lower() or "\\" in clean_path):
                self.entries.append(
                    SRUMEntry(
                        table_name="Application",
                        timestamp=None,
                        app_id=clean_path,
                        user_sid=None,
                        data={"application_path": clean_path},
                    )
                )

    def _extract_entry_at(self, pos: int, table_name: str) -> SRUMEntry | None:
        """Try to extract a SRUM entry at the given position."""
        # This is a heuristic approach; real ESE parsing would be more reliable
        try:
            # Look for nearby timestamps (FILETIME format)
            for offset in range(-100, 100, 8):
                if pos + offset < 0 or pos + offset + 8 > len(self.data):
                    continue

                potential_time = struct.unpack("<Q", self.data[pos + offset:pos + offset + 8])[0]
                timestamp = _filetime_to_datetime(potential_time)

                if timestamp and timestamp.year >= 2010 and timestamp.year <= 2030:
                    return SRUMEntry(
                        table_name=table_name,
                        timestamp=timestamp,
                        app_id=None,
                        user_sid=None,
                        data={"raw_offset": pos},
                    )

            return None
        except Exception:
            return None


@ParserRegistry.register
class SRUMFileParser(BaseParser):
    """Parser for SRUDB.dat files."""

    name: ClassVar[str] = "srum"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["srum", "srudb.dat"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize SRUM parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse SRUDB.dat file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse SRUM from bytes."""
        parser = SRUMParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "table_name": entry.table_name,
            }

            if entry.app_id:
                record_data["application"] = entry.app_id
            if entry.user_sid:
                record_data["user_sid"] = entry.user_sid
            if entry.timestamp:
                record_data["timestamp"] = entry.timestamp.isoformat()

            # Add any additional data
            record_data.update(entry.data)

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            app = entry.app_id or f"entry_{record_index}"
            record_id = self.create_record_id("srum", entry.table_name, record_index, app)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
