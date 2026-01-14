"""$UsnJrnl ($J) parser for NTFS change journal.

Parses the NTFS USN Journal to track file system changes including
file creation, deletion, rename, and modification events.
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

# USN record versions
USN_RECORD_V2 = 2
USN_RECORD_V3 = 3
USN_RECORD_V4 = 4

# USN reason flags
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_INDEXABLE_CHANGE = 0x00004000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_COMPRESSION_CHANGE = 0x00020000
USN_REASON_ENCRYPTION_CHANGE = 0x00040000
USN_REASON_OBJECT_ID_CHANGE = 0x00080000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_TRANSACTED_CHANGE = 0x00400000
USN_REASON_INTEGRITY_CHANGE = 0x00800000
USN_REASON_CLOSE = 0x80000000

# Source info flags
USN_SOURCE_DATA_MANAGEMENT = 0x00000001
USN_SOURCE_AUXILIARY_DATA = 0x00000002
USN_SOURCE_REPLICATION_MANAGEMENT = 0x00000004
USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT = 0x00000008

# File attribute flags
FILE_ATTR_READONLY = 0x00000001
FILE_ATTR_HIDDEN = 0x00000002
FILE_ATTR_SYSTEM = 0x00000004
FILE_ATTR_DIRECTORY = 0x00000010
FILE_ATTR_ARCHIVE = 0x00000020
FILE_ATTR_DEVICE = 0x00000040
FILE_ATTR_NORMAL = 0x00000080
FILE_ATTR_TEMPORARY = 0x00000100
FILE_ATTR_SPARSE_FILE = 0x00000200
FILE_ATTR_REPARSE_POINT = 0x00000400
FILE_ATTR_COMPRESSED = 0x00000800
FILE_ATTR_OFFLINE = 0x00001000
FILE_ATTR_NOT_CONTENT_INDEXED = 0x00002000
FILE_ATTR_ENCRYPTED = 0x00004000


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


def _get_reason_flags(reason: int) -> list[str]:
    """Convert reason flags to list of names."""
    flags = []
    if reason & USN_REASON_DATA_OVERWRITE:
        flags.append("DATA_OVERWRITE")
    if reason & USN_REASON_DATA_EXTEND:
        flags.append("DATA_EXTEND")
    if reason & USN_REASON_DATA_TRUNCATION:
        flags.append("DATA_TRUNCATION")
    if reason & USN_REASON_NAMED_DATA_OVERWRITE:
        flags.append("NAMED_DATA_OVERWRITE")
    if reason & USN_REASON_NAMED_DATA_EXTEND:
        flags.append("NAMED_DATA_EXTEND")
    if reason & USN_REASON_NAMED_DATA_TRUNCATION:
        flags.append("NAMED_DATA_TRUNCATION")
    if reason & USN_REASON_FILE_CREATE:
        flags.append("FILE_CREATE")
    if reason & USN_REASON_FILE_DELETE:
        flags.append("FILE_DELETE")
    if reason & USN_REASON_EA_CHANGE:
        flags.append("EA_CHANGE")
    if reason & USN_REASON_SECURITY_CHANGE:
        flags.append("SECURITY_CHANGE")
    if reason & USN_REASON_RENAME_OLD_NAME:
        flags.append("RENAME_OLD_NAME")
    if reason & USN_REASON_RENAME_NEW_NAME:
        flags.append("RENAME_NEW_NAME")
    if reason & USN_REASON_INDEXABLE_CHANGE:
        flags.append("INDEXABLE_CHANGE")
    if reason & USN_REASON_BASIC_INFO_CHANGE:
        flags.append("BASIC_INFO_CHANGE")
    if reason & USN_REASON_HARD_LINK_CHANGE:
        flags.append("HARD_LINK_CHANGE")
    if reason & USN_REASON_COMPRESSION_CHANGE:
        flags.append("COMPRESSION_CHANGE")
    if reason & USN_REASON_ENCRYPTION_CHANGE:
        flags.append("ENCRYPTION_CHANGE")
    if reason & USN_REASON_OBJECT_ID_CHANGE:
        flags.append("OBJECT_ID_CHANGE")
    if reason & USN_REASON_REPARSE_POINT_CHANGE:
        flags.append("REPARSE_POINT_CHANGE")
    if reason & USN_REASON_STREAM_CHANGE:
        flags.append("STREAM_CHANGE")
    if reason & USN_REASON_TRANSACTED_CHANGE:
        flags.append("TRANSACTED_CHANGE")
    if reason & USN_REASON_INTEGRITY_CHANGE:
        flags.append("INTEGRITY_CHANGE")
    if reason & USN_REASON_CLOSE:
        flags.append("CLOSE")
    return flags


def _get_file_attributes(attrs: int) -> list[str]:
    """Convert file attributes to list of names."""
    flags = []
    if attrs & FILE_ATTR_READONLY:
        flags.append("READONLY")
    if attrs & FILE_ATTR_HIDDEN:
        flags.append("HIDDEN")
    if attrs & FILE_ATTR_SYSTEM:
        flags.append("SYSTEM")
    if attrs & FILE_ATTR_DIRECTORY:
        flags.append("DIRECTORY")
    if attrs & FILE_ATTR_ARCHIVE:
        flags.append("ARCHIVE")
    if attrs & FILE_ATTR_COMPRESSED:
        flags.append("COMPRESSED")
    if attrs & FILE_ATTR_ENCRYPTED:
        flags.append("ENCRYPTED")
    if attrs & FILE_ATTR_SPARSE_FILE:
        flags.append("SPARSE")
    if attrs & FILE_ATTR_REPARSE_POINT:
        flags.append("REPARSE")
    return flags


@dataclass
class UsnRecord:
    """A single USN Journal record."""

    record_length: int
    major_version: int
    minor_version: int
    file_reference: int
    parent_reference: int
    usn: int
    timestamp: datetime | None
    reason: int
    source_info: int
    security_id: int
    file_attributes: int
    filename: str

    @property
    def file_record_number(self) -> int:
        """Get the MFT record number."""
        return self.file_reference & 0x0000FFFFFFFFFFFF

    @property
    def file_sequence_number(self) -> int:
        """Get the file sequence number."""
        return (self.file_reference >> 48) & 0xFFFF

    @property
    def parent_record_number(self) -> int:
        """Get the parent MFT record number."""
        return self.parent_reference & 0x0000FFFFFFFFFFFF

    @property
    def is_directory(self) -> bool:
        """Check if this is a directory."""
        return bool(self.file_attributes & FILE_ATTR_DIRECTORY)


class UsnJrnlParser:
    """Parser for $UsnJrnl:$J data."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with $J data."""
        self.data = data

    def parse(self) -> Iterator[UsnRecord]:
        """Parse all USN records from the journal."""
        offset = 0
        data_len = len(self.data)

        while offset < data_len - 8:
            # Skip null/sparse regions
            if self.data[offset:offset + 8] == b"\x00" * 8:
                # Find next non-null region (page aligned)
                next_offset = offset + 8
                while next_offset < data_len - 8:
                    if self.data[next_offset:next_offset + 4] != b"\x00\x00\x00\x00":
                        break
                    next_offset += 4096  # Skip by page size
                offset = next_offset
                continue

            # Read record length
            if offset + 4 > data_len:
                break

            record_length = struct.unpack("<I", self.data[offset:offset + 4])[0]

            # Validate record length
            if record_length < 60 or record_length > 65536:
                # Try to find next valid record
                offset += 8
                continue

            if offset + record_length > data_len:
                break

            record_data = self.data[offset:offset + record_length]

            # Parse based on version
            major_version = struct.unpack("<H", record_data[4:6])[0]
            minor_version = struct.unpack("<H", record_data[6:8])[0]

            record = None
            if major_version == USN_RECORD_V2:
                record = self._parse_v2(record_data)
            elif major_version == USN_RECORD_V3:
                record = self._parse_v3(record_data)
            elif major_version == USN_RECORD_V4:
                record = self._parse_v4(record_data)

            if record:
                yield record

            # Move to next record (8-byte aligned)
            offset += (record_length + 7) & ~7

    def _parse_v2(self, data: bytes) -> UsnRecord | None:
        """Parse USN_RECORD_V2 structure."""
        if len(data) < 60:
            return None

        record_length = struct.unpack("<I", data[0:4])[0]
        major_version = struct.unpack("<H", data[4:6])[0]
        minor_version = struct.unpack("<H", data[6:8])[0]
        file_reference = struct.unpack("<Q", data[8:16])[0]
        parent_reference = struct.unpack("<Q", data[16:24])[0]
        usn = struct.unpack("<Q", data[24:32])[0]
        timestamp = _filetime_to_datetime(struct.unpack("<Q", data[32:40])[0])
        reason = struct.unpack("<I", data[40:44])[0]
        source_info = struct.unpack("<I", data[44:48])[0]
        security_id = struct.unpack("<I", data[48:52])[0]
        file_attributes = struct.unpack("<I", data[52:56])[0]
        filename_length = struct.unpack("<H", data[56:58])[0]
        filename_offset = struct.unpack("<H", data[58:60])[0]

        # Extract filename
        filename = ""
        if filename_offset > 0 and filename_offset + filename_length <= len(data):
            try:
                filename = data[filename_offset:filename_offset + filename_length].decode(
                    "utf-16-le"
                )
            except UnicodeDecodeError:
                filename = "<decode error>"

        return UsnRecord(
            record_length=record_length,
            major_version=major_version,
            minor_version=minor_version,
            file_reference=file_reference,
            parent_reference=parent_reference,
            usn=usn,
            timestamp=timestamp,
            reason=reason,
            source_info=source_info,
            security_id=security_id,
            file_attributes=file_attributes,
            filename=filename,
        )

    def _parse_v3(self, data: bytes) -> UsnRecord | None:
        """Parse USN_RECORD_V3 structure (128-bit file references)."""
        if len(data) < 76:
            return None

        record_length = struct.unpack("<I", data[0:4])[0]
        major_version = struct.unpack("<H", data[4:6])[0]
        minor_version = struct.unpack("<H", data[6:8])[0]

        # V3 uses 128-bit file references
        file_ref_low = struct.unpack("<Q", data[8:16])[0]
        file_ref_high = struct.unpack("<Q", data[16:24])[0]
        parent_ref_low = struct.unpack("<Q", data[24:32])[0]
        parent_ref_high = struct.unpack("<Q", data[32:40])[0]

        usn = struct.unpack("<Q", data[40:48])[0]
        timestamp = _filetime_to_datetime(struct.unpack("<Q", data[48:56])[0])
        reason = struct.unpack("<I", data[56:60])[0]
        source_info = struct.unpack("<I", data[60:64])[0]
        security_id = struct.unpack("<I", data[64:68])[0]
        file_attributes = struct.unpack("<I", data[68:72])[0]
        filename_length = struct.unpack("<H", data[72:74])[0]
        filename_offset = struct.unpack("<H", data[74:76])[0]

        filename = ""
        if filename_offset > 0 and filename_offset + filename_length <= len(data):
            try:
                filename = data[filename_offset:filename_offset + filename_length].decode(
                    "utf-16-le"
                )
            except UnicodeDecodeError:
                filename = "<decode error>"

        return UsnRecord(
            record_length=record_length,
            major_version=major_version,
            minor_version=minor_version,
            file_reference=file_ref_low,
            parent_reference=parent_ref_low,
            usn=usn,
            timestamp=timestamp,
            reason=reason,
            source_info=source_info,
            security_id=security_id,
            file_attributes=file_attributes,
            filename=filename,
        )

    def _parse_v4(self, data: bytes) -> UsnRecord | None:
        """Parse USN_RECORD_V4 structure."""
        # V4 is similar to V3 with additional extent information
        return self._parse_v3(data)


@ParserRegistry.register
class UsnJrnlFileParser(BaseParser):
    """Parser for $UsnJrnl:$J files."""

    name: ClassVar[str] = "usnjrnl"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["usnjrnl", "$j", "$usnjrnl"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize USN Journal parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse $UsnJrnl:$J file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse USN Journal from bytes."""
        parser = UsnJrnlParser(data)

        record_index = 0
        for record in parser.parse():
            record_data: dict[str, Any] = {
                "usn": record.usn,
                "filename": record.filename,
                "file_record_number": record.file_record_number,
                "file_sequence_number": record.file_sequence_number,
                "parent_record_number": record.parent_record_number,
                "is_directory": record.is_directory,
                "reason_flags": _get_reason_flags(record.reason),
                "file_attributes": _get_file_attributes(record.file_attributes),
                "timestamp": record.timestamp.isoformat() if record.timestamp else None,
            }

            # Add source info if present
            if record.source_info:
                sources = []
                if record.source_info & USN_SOURCE_DATA_MANAGEMENT:
                    sources.append("DATA_MANAGEMENT")
                if record.source_info & USN_SOURCE_AUXILIARY_DATA:
                    sources.append("AUXILIARY_DATA")
                if record.source_info & USN_SOURCE_REPLICATION_MANAGEMENT:
                    sources.append("REPLICATION_MANAGEMENT")
                if sources:
                    record_data["source_info"] = sources

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("usnjrnl", record.usn, record.filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=record.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
