"""Recycle Bin parser for deleted file tracking.

Parses Windows Recycle Bin files ($I, $R, INFO2) to extract
information about deleted files.
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

# $I file version
RECYCLE_BIN_V1 = 1  # Vista, 7, 8
RECYCLE_BIN_V2 = 2  # Windows 10+

# INFO2 signature
INFO2_SIGNATURE = b"\x05\x00\x00\x00"


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


@dataclass
class RecycleBinEntry:
    """A single Recycle Bin entry."""

    filename: str  # $I filename (e.g., $IABCDEF.txt)
    original_path: str
    file_size: int
    deleted_time: datetime | None
    version: int
    user_sid: str = ""


class RecycleBinIParser:
    """Parser for $I files (Windows Vista+)."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser with $I file data."""
        self.data = data
        self.filename = filename
        self.entry: RecycleBinEntry | None = None
        self._parse()

    def _parse(self) -> None:
        """Parse $I file structure."""
        if len(self.data) < 28:
            return

        # Version (8 bytes, but only first is meaningful)
        version = struct.unpack("<Q", self.data[0:8])[0]

        if version == 1:
            self._parse_v1()
        elif version == 2:
            self._parse_v2()
        else:
            # Try v2 format as fallback
            self._parse_v2()

    def _parse_v1(self) -> None:
        """Parse version 1 format (Vista/7/8)."""
        if len(self.data) < 28:
            return

        # File size (8 bytes at offset 8)
        file_size = struct.unpack("<Q", self.data[8:16])[0]

        # Deletion time (8 bytes at offset 16)
        deletion_time = _filetime_to_datetime(
            struct.unpack("<Q", self.data[16:24])[0]
        )

        # Path length in characters (4 bytes at offset 24)
        path_len = struct.unpack("<I", self.data[24:28])[0]

        # Path (UTF-16LE, starting at offset 28)
        path = ""
        if path_len > 0 and 28 + path_len * 2 <= len(self.data):
            try:
                path = self.data[28:28 + path_len * 2].decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                pass

        if path:
            self.entry = RecycleBinEntry(
                filename=self.filename,
                original_path=path,
                file_size=file_size,
                deleted_time=deletion_time,
                version=1,
            )

    def _parse_v2(self) -> None:
        """Parse version 2 format (Windows 10+)."""
        if len(self.data) < 28:
            return

        # File size (8 bytes at offset 8)
        file_size = struct.unpack("<Q", self.data[8:16])[0]

        # Deletion time (8 bytes at offset 16)
        deletion_time = _filetime_to_datetime(
            struct.unpack("<Q", self.data[16:24])[0]
        )

        # Path length in bytes (4 bytes at offset 24)
        path_byte_len = struct.unpack("<I", self.data[24:28])[0]

        # Path (UTF-16LE, starting at offset 28)
        path = ""
        if path_byte_len > 0 and 28 + path_byte_len <= len(self.data):
            try:
                path = self.data[28:28 + path_byte_len].decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                pass

        if path:
            self.entry = RecycleBinEntry(
                filename=self.filename,
                original_path=path,
                file_size=file_size,
                deleted_time=deletion_time,
                version=2,
            )


class INFO2Parser:
    """Parser for INFO2 files (Windows XP and earlier)."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with INFO2 file data."""
        self.data = data
        self.entries: list[RecycleBinEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse INFO2 file structure."""
        if len(self.data) < 20:
            return

        # Check header
        if self.data[0:4] != INFO2_SIGNATURE:
            return

        # Record size (4 bytes at offset 12)
        record_size = struct.unpack("<I", self.data[12:16])[0]

        if record_size == 0 or record_size > 1024:
            record_size = 800  # Default for Unicode paths

        # Skip header (20 bytes)
        offset = 20

        record_num = 0
        while offset + record_size <= len(self.data):
            record = self._parse_record(self.data[offset:offset + record_size], record_num)
            if record:
                self.entries.append(record)

            offset += record_size
            record_num += 1

    def _parse_record(self, data: bytes, index: int) -> RecycleBinEntry | None:
        """Parse a single INFO2 record."""
        if len(data) < 280:
            return None

        # ANSI path (260 bytes at offset 4)
        ansi_path = ""
        try:
            path_data = data[4:264]
            null_pos = path_data.find(b"\x00")
            if null_pos > 0:
                ansi_path = path_data[:null_pos].decode("cp1252", errors="replace")
        except Exception:
            pass

        # Drive number (4 bytes at offset 264)
        drive_num = struct.unpack("<I", data[264:268])[0]

        # Deletion time (8 bytes at offset 268)
        deletion_time = _filetime_to_datetime(
            struct.unpack("<Q", data[268:276])[0]
        )

        # File size (4 bytes at offset 276)
        file_size = struct.unpack("<I", data[276:280])[0]

        # Unicode path (520 bytes at offset 280, if present)
        unicode_path = ""
        if len(data) >= 800:
            try:
                path_data = data[280:800]
                null_pos = 0
                for i in range(0, len(path_data) - 1, 2):
                    if path_data[i:i + 2] == b"\x00\x00":
                        null_pos = i
                        break
                if null_pos > 0:
                    unicode_path = path_data[:null_pos].decode("utf-16-le")
            except Exception:
                pass

        path = unicode_path or ansi_path

        if path:
            return RecycleBinEntry(
                filename=f"D{drive_num}{index}",
                original_path=path,
                file_size=file_size,
                deleted_time=deletion_time,
                version=0,  # XP format
            )

        return None


class RecycleBinParser:
    """High-level Recycle Bin parser."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename
        self.entries: list[RecycleBinEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse based on filename/content."""
        fname = self.filename.lower()

        if fname.startswith("$i"):
            # $I file
            parser = RecycleBinIParser(self.data, self.filename)
            if parser.entry:
                self.entries.append(parser.entry)
        elif fname == "info2" or fname.endswith("info2"):
            # INFO2 file
            parser = INFO2Parser(self.data)
            self.entries.extend(parser.entries)
        elif len(self.data) >= 4:
            # Try to detect format
            if self.data[0:4] == INFO2_SIGNATURE:
                parser = INFO2Parser(self.data)
                self.entries.extend(parser.entries)
            else:
                # Try $I format
                parser = RecycleBinIParser(self.data, self.filename)
                if parser.entry:
                    self.entries.append(parser.entry)


@ParserRegistry.register
class RecycleBinFileParser(BaseParser):
    """Parser for Recycle Bin files."""

    name: ClassVar[str] = "recyclebin"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "recyclebin",
        "$i",
        "info2",
        "$recycle.bin",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Recycle Bin parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Recycle Bin file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse Recycle Bin from bytes."""
        parser = RecycleBinParser(data, filename)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "filename": entry.filename,
                "original_path": entry.original_path,
                "file_size": entry.file_size,
                "version": entry.version,
            }

            if entry.deleted_time:
                record_data["deleted_time"] = entry.deleted_time.isoformat()
            if entry.user_sid:
                record_data["user_sid"] = entry.user_sid

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("recyclebin", entry.filename, entry.original_path)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.deleted_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
