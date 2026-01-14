"""$MFT (Master File Table) parser for NTFS forensics.

Parses the NTFS Master File Table to extract file metadata,
timestamps, and file system structure information.
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

# MFT Constants
MFT_RECORD_SIZE = 1024
MFT_SIGNATURE = b"FILE"
BAAD_SIGNATURE = b"BAAD"

# Attribute types
ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0

# File attribute flags
FILE_ATTR_READONLY = 0x0001
FILE_ATTR_HIDDEN = 0x0002
FILE_ATTR_SYSTEM = 0x0004
FILE_ATTR_DIRECTORY = 0x0010
FILE_ATTR_ARCHIVE = 0x0020
FILE_ATTR_DEVICE = 0x0040
FILE_ATTR_NORMAL = 0x0080
FILE_ATTR_TEMPORARY = 0x0100
FILE_ATTR_SPARSE = 0x0200
FILE_ATTR_REPARSE = 0x0400
FILE_ATTR_COMPRESSED = 0x0800
FILE_ATTR_OFFLINE = 0x1000
FILE_ATTR_NOT_INDEXED = 0x2000
FILE_ATTR_ENCRYPTED = 0x4000

# Filename namespace
FN_POSIX = 0
FN_WIN32 = 1
FN_DOS = 2
FN_WIN32_DOS = 3


def _filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME to datetime."""
    if filetime == 0 or filetime < 0:
        return None
    try:
        # FILETIME: 100-nanosecond intervals since 1601-01-01
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return None
        timestamp = (filetime - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (OSError, ValueError, OverflowError):
        return None


def _get_file_flags(flags: int) -> list[str]:
    """Convert file attribute flags to list of names."""
    result = []
    if flags & FILE_ATTR_READONLY:
        result.append("READONLY")
    if flags & FILE_ATTR_HIDDEN:
        result.append("HIDDEN")
    if flags & FILE_ATTR_SYSTEM:
        result.append("SYSTEM")
    if flags & FILE_ATTR_DIRECTORY:
        result.append("DIRECTORY")
    if flags & FILE_ATTR_ARCHIVE:
        result.append("ARCHIVE")
    if flags & FILE_ATTR_COMPRESSED:
        result.append("COMPRESSED")
    if flags & FILE_ATTR_ENCRYPTED:
        result.append("ENCRYPTED")
    if flags & FILE_ATTR_SPARSE:
        result.append("SPARSE")
    if flags & FILE_ATTR_REPARSE:
        result.append("REPARSE")
    return result


@dataclass
class StandardInformation:
    """$STANDARD_INFORMATION attribute data."""

    created: datetime | None
    modified: datetime | None
    mft_modified: datetime | None
    accessed: datetime | None
    flags: int
    owner_id: int
    security_id: int
    usn: int


@dataclass
class FileName:
    """$FILE_NAME attribute data."""

    parent_ref: int
    parent_seq: int
    created: datetime | None
    modified: datetime | None
    mft_modified: datetime | None
    accessed: datetime | None
    alloc_size: int
    real_size: int
    flags: int
    name: str
    namespace: int


@dataclass
class DataAttribute:
    """$DATA attribute info."""

    name: str
    resident: bool
    size: int
    allocated_size: int


@dataclass
class MFTEntry:
    """Parsed MFT entry."""

    record_number: int
    sequence: int
    flags: int
    used_size: int
    allocated_size: int
    base_record: int
    is_valid: bool
    is_directory: bool
    is_deleted: bool
    standard_info: StandardInformation | None
    filenames: list[FileName]
    data_streams: list[DataAttribute]

    @property
    def primary_name(self) -> str | None:
        """Get the primary filename (WIN32 preferred)."""
        if not self.filenames:
            return None
        # Prefer WIN32 or WIN32_DOS namespace
        for fn in self.filenames:
            if fn.namespace in (FN_WIN32, FN_WIN32_DOS):
                return fn.name
        return self.filenames[0].name


class MFTParser:
    """Parser for raw $MFT file."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with MFT data."""
        self.data = data
        self.record_size = MFT_RECORD_SIZE

    def _apply_fixup(self, record: bytearray) -> bool:
        """Apply fixup array to MFT record."""
        if len(record) < 48:
            return False

        # Get fixup offset and count
        fixup_offset = struct.unpack("<H", record[4:6])[0]
        fixup_count = struct.unpack("<H", record[6:8])[0]

        if fixup_offset >= len(record) or fixup_count == 0:
            return False

        # Get fixup signature
        if fixup_offset + 2 > len(record):
            return False
        signature = record[fixup_offset:fixup_offset + 2]

        # Apply fixups at end of each sector
        for i in range(1, fixup_count):
            sector_end = i * 512 - 2
            if sector_end + 2 > len(record):
                break
            if fixup_offset + 2 + i * 2 > len(record):
                break

            # Verify signature matches
            if record[sector_end:sector_end + 2] != signature:
                return False

            # Replace with actual value
            fixup_value = record[fixup_offset + 2 + (i - 1) * 2:fixup_offset + 2 + i * 2]
            record[sector_end:sector_end + 2] = fixup_value

        return True

    def _parse_standard_information(self, data: bytes) -> StandardInformation | None:
        """Parse $STANDARD_INFORMATION attribute."""
        if len(data) < 48:
            return None

        created = _filetime_to_datetime(struct.unpack("<Q", data[0:8])[0])
        modified = _filetime_to_datetime(struct.unpack("<Q", data[8:16])[0])
        mft_modified = _filetime_to_datetime(struct.unpack("<Q", data[16:24])[0])
        accessed = _filetime_to_datetime(struct.unpack("<Q", data[24:32])[0])
        flags = struct.unpack("<I", data[32:36])[0]

        owner_id = 0
        security_id = 0
        usn = 0

        if len(data) >= 72:
            owner_id = struct.unpack("<I", data[48:52])[0]
            security_id = struct.unpack("<I", data[52:56])[0]
            usn = struct.unpack("<Q", data[64:72])[0]

        return StandardInformation(
            created=created,
            modified=modified,
            mft_modified=mft_modified,
            accessed=accessed,
            flags=flags,
            owner_id=owner_id,
            security_id=security_id,
            usn=usn,
        )

    def _parse_filename(self, data: bytes) -> FileName | None:
        """Parse $FILE_NAME attribute."""
        if len(data) < 66:
            return None

        parent_ref = struct.unpack("<Q", data[0:8])[0]
        parent_entry = parent_ref & 0x0000FFFFFFFFFFFF
        parent_seq = (parent_ref >> 48) & 0xFFFF

        created = _filetime_to_datetime(struct.unpack("<Q", data[8:16])[0])
        modified = _filetime_to_datetime(struct.unpack("<Q", data[16:24])[0])
        mft_modified = _filetime_to_datetime(struct.unpack("<Q", data[24:32])[0])
        accessed = _filetime_to_datetime(struct.unpack("<Q", data[32:40])[0])

        alloc_size = struct.unpack("<Q", data[40:48])[0]
        real_size = struct.unpack("<Q", data[48:56])[0]
        flags = struct.unpack("<I", data[56:60])[0]

        name_length = data[64]
        namespace = data[65]

        if len(data) < 66 + name_length * 2:
            return None

        try:
            name = data[66:66 + name_length * 2].decode("utf-16-le")
        except UnicodeDecodeError:
            name = "<decode error>"

        return FileName(
            parent_ref=parent_entry,
            parent_seq=parent_seq,
            created=created,
            modified=modified,
            mft_modified=mft_modified,
            accessed=accessed,
            alloc_size=alloc_size,
            real_size=real_size,
            flags=flags,
            name=name,
            namespace=namespace,
        )

    def _parse_data_attr(self, attr_data: bytes, name_offset: int, name_length: int) -> DataAttribute | None:
        """Parse $DATA attribute header."""
        if len(attr_data) < 16:
            return None

        non_resident = attr_data[8] != 0

        name = ""
        if name_length > 0 and name_offset > 0:
            name_start = name_offset
            name_end = name_start + name_length * 2
            if name_end <= len(attr_data):
                try:
                    name = attr_data[name_start:name_end].decode("utf-16-le")
                except UnicodeDecodeError:
                    pass

        if non_resident:
            if len(attr_data) < 64:
                return None
            alloc_size = struct.unpack("<Q", attr_data[40:48])[0]
            real_size = struct.unpack("<Q", attr_data[48:56])[0]
        else:
            if len(attr_data) < 24:
                return None
            real_size = struct.unpack("<I", attr_data[16:20])[0]
            alloc_size = real_size

        return DataAttribute(
            name=name if name else "$DATA",
            resident=not non_resident,
            size=real_size,
            allocated_size=alloc_size,
        )

    def parse_record(self, offset: int) -> MFTEntry | None:
        """Parse a single MFT record at the given offset."""
        if offset + self.record_size > len(self.data):
            return None

        record = bytearray(self.data[offset:offset + self.record_size])

        signature = bytes(record[:4])
        if signature == BAAD_SIGNATURE:
            return None
        if signature != MFT_SIGNATURE:
            return None

        if not self._apply_fixup(record):
            return None

        # Parse header
        # Offset 16-18: Sequence number
        # Offset 18-20: Link count
        # Offset 20-22: First attribute offset
        # Offset 22-24: Flags
        # Offset 24-28: Used size
        # Offset 28-32: Allocated size
        # Offset 32-40: Base record reference

        sequence = struct.unpack("<H", record[16:18])[0]
        first_attr = struct.unpack("<H", record[20:22])[0]
        flags = struct.unpack("<H", record[22:24])[0]
        used_size = struct.unpack("<I", record[24:28])[0]
        alloc_size = struct.unpack("<I", record[28:32])[0]
        base_ref = struct.unpack("<Q", record[32:40])[0]

        is_valid = True
        is_directory = (flags & 0x02) != 0
        is_deleted = (flags & 0x01) == 0

        standard_info = None
        filenames: list[FileName] = []
        data_streams: list[DataAttribute] = []

        pos = first_attr
        while pos < used_size and pos + 4 <= len(record):
            attr_type = struct.unpack("<I", record[pos:pos + 4])[0]

            if attr_type == 0xFFFFFFFF:
                break

            if pos + 8 > len(record):
                break

            attr_len = struct.unpack("<I", record[pos + 4:pos + 8])[0]
            if attr_len == 0 or pos + attr_len > len(record):
                break

            attr_data = record[pos:pos + attr_len]

            # Get name offset and length for named attributes
            name_length = attr_data[9] if len(attr_data) > 9 else 0
            name_offset = struct.unpack("<H", attr_data[10:12])[0] if len(attr_data) > 11 else 0

            # Resident flag at offset 8
            non_resident = attr_data[8] if len(attr_data) > 8 else 0

            # Get content offset and length
            if non_resident:
                content_offset = 0
                content_length = 0
            else:
                if len(attr_data) >= 24:
                    content_length = struct.unpack("<I", attr_data[16:20])[0]
                    content_offset = struct.unpack("<H", attr_data[20:22])[0]
                else:
                    content_offset = 0
                    content_length = 0

            if attr_type == ATTR_STANDARD_INFORMATION and not non_resident:
                if content_offset > 0 and content_offset + content_length <= len(attr_data):
                    si_data = attr_data[content_offset:content_offset + content_length]
                    standard_info = self._parse_standard_information(bytes(si_data))

            elif attr_type == ATTR_FILE_NAME and not non_resident:
                if content_offset > 0 and content_offset + content_length <= len(attr_data):
                    fn_data = attr_data[content_offset:content_offset + content_length]
                    fn = self._parse_filename(bytes(fn_data))
                    if fn:
                        filenames.append(fn)

            elif attr_type == ATTR_DATA:
                da = self._parse_data_attr(bytes(attr_data), name_offset, name_length)
                if da:
                    data_streams.append(da)

            pos += attr_len

        record_number = offset // self.record_size

        return MFTEntry(
            record_number=record_number,
            sequence=sequence,
            flags=flags,
            used_size=used_size,
            allocated_size=alloc_size,
            base_record=base_ref & 0x0000FFFFFFFFFFFF,
            is_valid=is_valid,
            is_directory=is_directory,
            is_deleted=is_deleted,
            standard_info=standard_info,
            filenames=filenames,
            data_streams=data_streams,
        )

    def parse_all(self) -> Iterator[MFTEntry]:
        """Parse all MFT records."""
        num_records = len(self.data) // self.record_size

        for i in range(num_records):
            offset = i * self.record_size
            entry = self.parse_record(offset)
            if entry and (entry.standard_info or entry.filenames):
                yield entry


@ParserRegistry.register
class MFTFileParser(BaseParser):
    """Parser for $MFT files."""

    name: ClassVar[str] = "mft"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["mft", "$mft"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize MFT parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse $MFT file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse $MFT from bytes."""
        parser = MFTParser(data)

        for entry in parser.parse_all():
            if not entry.standard_info and not entry.filenames:
                continue

            primary_name = entry.primary_name or f"<MFT Entry {entry.record_number}>"
            parent_ref = None
            if entry.filenames:
                parent_ref = entry.filenames[0].parent_ref

            record_data: dict[str, Any] = {
                "record_number": entry.record_number,
                "sequence": entry.sequence,
                "filename": primary_name,
                "parent_record": parent_ref,
                "is_directory": entry.is_directory,
                "is_deleted": entry.is_deleted,
                "flags": _get_file_flags(entry.standard_info.flags if entry.standard_info else 0),
            }

            # Add timestamps from $STANDARD_INFORMATION
            if entry.standard_info:
                si = entry.standard_info
                record_data["si_created"] = si.created.isoformat() if si.created else None
                record_data["si_modified"] = si.modified.isoformat() if si.modified else None
                record_data["si_mft_modified"] = si.mft_modified.isoformat() if si.mft_modified else None
                record_data["si_accessed"] = si.accessed.isoformat() if si.accessed else None
                record_data["usn"] = si.usn

            # Add timestamps from $FILE_NAME (for timestomping detection)
            if entry.filenames:
                fn = entry.filenames[0]
                record_data["fn_created"] = fn.created.isoformat() if fn.created else None
                record_data["fn_modified"] = fn.modified.isoformat() if fn.modified else None
                record_data["fn_mft_modified"] = fn.mft_modified.isoformat() if fn.mft_modified else None
                record_data["fn_accessed"] = fn.accessed.isoformat() if fn.accessed else None
                record_data["file_size"] = fn.real_size
                record_data["allocated_size"] = fn.alloc_size

            if entry.data_streams:
                ads = [ds.name for ds in entry.data_streams if ds.name != "$DATA"]
                if ads:
                    record_data["alternate_data_streams"] = ads

            timestamp = None
            if entry.standard_info and entry.standard_info.modified:
                timestamp = entry.standard_info.modified
            elif entry.filenames and entry.filenames[0].modified:
                timestamp = entry.filenames[0].modified

            evidence_ref = self.create_evidence_ref(
                record_offset=entry.record_number * MFT_RECORD_SIZE,
                record_index=entry.record_number,
            )

            fname = entry.filenames[0].name if entry.filenames else f"entry_{entry.record_number}"
            record_id = self.create_record_id("mft", entry.record_number, fname)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )
