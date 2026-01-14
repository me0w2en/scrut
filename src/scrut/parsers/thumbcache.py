"""Windows Thumbnail Cache parser.

Parses Windows thumbnail cache files to identify images/files
that were viewed, even if the original files have been deleted.

Locations:
- %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\thumbcache_*.db
- %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\iconcache_*.db
- %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\thumbcache_idx.db

Cache sizes:
- thumbcache_16.db (16x16 icons)
- thumbcache_32.db (32x32 icons)
- thumbcache_48.db (48x48 icons)
- thumbcache_96.db (96x96 thumbnails)
- thumbcache_256.db (256x256 thumbnails)
- thumbcache_1024.db (1024x1024 thumbnails)
- thumbcache_sr.db (scaling ratio thumbnails)
- thumbcache_wide.db (wide/landscape thumbnails)
- thumbcache_exif.db (EXIF rotation thumbnails)
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

# Thumbcache file signature
THUMBCACHE_SIGNATURE = b"CMMM"
THUMBCACHE_VISTA_SIGNATURE = b"IMMM"

# Cache entry types
CACHE_TYPES = {
    0: "Unknown",
    1: "BMP",
    2: "JPEG",
    3: "PNG",
}


@dataclass
class ThumbnailEntry:
    """A thumbnail cache entry."""

    cache_entry_hash: str
    data_size: int
    data_offset: int
    header_checksum: int
    data_checksum: int
    identifier: str
    extension: str
    padding_size: int
    has_thumbnail: bool


@dataclass
class ThumbnailIndexEntry:
    """A thumbnail index entry (from thumbcache_idx.db)."""

    entry_hash: str
    flags: int
    cache_entry_offset: int
    last_modified: datetime | None
    identifier: str


class ThumbcacheParser:
    """Parser for Windows thumbnail cache files."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename.lower()
        self.entries: list[ThumbnailEntry] = []
        self.index_entries: list[ThumbnailIndexEntry] = []
        self.header: dict[str, Any] = {}
        self._parse()

    def _parse(self) -> None:
        """Parse thumbnail cache file."""
        if len(self.data) < 24:
            return

        # Determine file type
        if "idx" in self.filename:
            self._parse_index()
        else:
            self._parse_cache()

    def _parse_cache(self) -> None:
        """Parse thumbcache_*.db file."""
        # Check signature
        sig = self.data[:4]
        if sig not in [THUMBCACHE_SIGNATURE, THUMBCACHE_VISTA_SIGNATURE]:
            return

        try:
            # Parse header
            # Offset 0: Signature (4 bytes)
            # Offset 4: Version (4 bytes)
            # Offset 8: Type (4 bytes) - cache size type
            # Offset 12: First cache entry offset (4 bytes)
            # Offset 16: First available cache entry offset (4 bytes)
            # Offset 20: Number of cache entries (4 bytes)

            self.header["signature"] = sig.decode("ascii", errors="replace")
            self.header["version"] = struct.unpack("<I", self.data[4:8])[0]
            self.header["cache_type"] = struct.unpack("<I", self.data[8:12])[0]

            if sig == THUMBCACHE_SIGNATURE:
                # Windows 7+ format
                first_entry = struct.unpack("<I", self.data[12:16])[0]
                entry_count = struct.unpack("<I", self.data[20:24])[0]
            else:
                # Vista format
                first_entry = struct.unpack("<I", self.data[16:20])[0]
                entry_count = struct.unpack("<I", self.data[12:16])[0]

            self.header["first_entry_offset"] = first_entry
            self.header["entry_count"] = entry_count

            # Parse entries
            offset = first_entry
            parsed_count = 0

            while offset < len(self.data) - 24 and parsed_count < min(entry_count, 10000):
                entry = self._parse_cache_entry(offset)
                if entry is None:
                    break

                self.entries.append(entry)
                parsed_count += 1

                # Move to next entry
                entry_size = 32 + entry.padding_size + entry.data_size
                # Align to 8 bytes
                entry_size = (entry_size + 7) & ~7
                offset += entry_size

                if entry_size == 0:
                    break

        except struct.error:
            pass

    def _parse_cache_entry(self, offset: int) -> ThumbnailEntry | None:
        """Parse a single cache entry."""
        if offset + 32 > len(self.data):
            return None

        try:
            # Entry header structure:
            # Offset 0: Signature "CMMM" (4 bytes)
            # Offset 4: Entry size (4 bytes)
            # Offset 8: Entry hash (8 bytes)
            # Offset 16: Extension (4 bytes, null-padded)
            # Offset 20: Identifier string size (4 bytes)
            # Offset 24: Padding size (4 bytes)
            # Offset 28: Data size (4 bytes)

            sig = self.data[offset : offset + 4]
            if sig != THUMBCACHE_SIGNATURE:
                return None

            entry_size = struct.unpack("<I", self.data[offset + 4 : offset + 8])[0]
            entry_hash = struct.unpack("<Q", self.data[offset + 8 : offset + 16])[0]
            extension = self.data[offset + 16 : offset + 20].decode("ascii", errors="replace").rstrip("\x00")
            identifier_size = struct.unpack("<I", self.data[offset + 20 : offset + 24])[0]
            padding_size = struct.unpack("<I", self.data[offset + 24 : offset + 28])[0]
            data_size = struct.unpack("<I", self.data[offset + 28 : offset + 32])[0]

            # Extract identifier if present
            identifier = ""
            if identifier_size > 0 and offset + 32 + identifier_size <= len(self.data):
                try:
                    identifier = self.data[offset + 32 : offset + 32 + identifier_size].decode(
                        "utf-16-le", errors="replace"
                    ).rstrip("\x00")
                except Exception:
                    pass

            # Calculate checksums (header and data)
            header_checksum = 0
            data_checksum = 0

            return ThumbnailEntry(
                cache_entry_hash=f"{entry_hash:016x}",
                data_size=data_size,
                data_offset=offset + 32 + padding_size,
                header_checksum=header_checksum,
                data_checksum=data_checksum,
                identifier=identifier,
                extension=extension,
                padding_size=padding_size,
                has_thumbnail=data_size > 0,
            )

        except struct.error:
            return None

    def _parse_index(self) -> None:
        """Parse thumbcache_idx.db file."""
        if len(self.data) < 24:
            return

        try:
            # Index file header
            # Offset 0: Signature (4 bytes)
            # Offset 4: Version (4 bytes)
            # Offset 8-24: Unknown/reserved
            # Offset 24: First entry offset

            sig = self.data[:4]
            if sig not in [THUMBCACHE_SIGNATURE, THUMBCACHE_VISTA_SIGNATURE]:
                return

            self.header["signature"] = sig.decode("ascii", errors="replace")
            self.header["version"] = struct.unpack("<I", self.data[4:8])[0]

            # Parse index entries
            offset = 24
            while offset < len(self.data) - 32:
                entry = self._parse_index_entry(offset)
                if entry is None:
                    break

                self.index_entries.append(entry)
                offset += 32  # Fixed size index entries

                if len(self.index_entries) > 50000:
                    break

        except struct.error:
            pass

    def _parse_index_entry(self, offset: int) -> ThumbnailIndexEntry | None:
        """Parse a single index entry."""
        if offset + 32 > len(self.data):
            return None

        try:
            # Index entry structure (32 bytes):
            # Offset 0: Entry hash (8 bytes)
            # Offset 8: Flags (4 bytes)
            # Offset 12: Cache entry offset (4 bytes)
            # Offset 16: Last modified time (8 bytes, FILETIME)
            # Offset 24: Reserved (8 bytes)

            entry_hash = struct.unpack("<Q", self.data[offset : offset + 8])[0]
            flags = struct.unpack("<I", self.data[offset + 8 : offset + 12])[0]
            cache_offset = struct.unpack("<I", self.data[offset + 12 : offset + 16])[0]
            modified_time = struct.unpack("<Q", self.data[offset + 16 : offset + 24])[0]

            # Skip empty entries
            if entry_hash == 0 and cache_offset == 0:
                return None

            # Convert FILETIME to datetime
            last_modified = None
            if modified_time > 0:
                try:
                    EPOCH_DIFF = 116444736000000000
                    if modified_time >= EPOCH_DIFF:
                        timestamp = (modified_time - EPOCH_DIFF) / 10000000
                        last_modified = datetime.fromtimestamp(timestamp, tz=UTC)
                except (OSError, ValueError, OverflowError):
                    pass

            return ThumbnailIndexEntry(
                entry_hash=f"{entry_hash:016x}",
                flags=flags,
                cache_entry_offset=cache_offset,
                last_modified=last_modified,
                identifier="",
            )

        except struct.error:
            return None


@ParserRegistry.register
class ThumbcacheFileParser(BaseParser):
    """Parser for Windows thumbnail cache files."""

    name: ClassVar[str] = "thumbcache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "thumbcache",
        "thumbnail_cache",
        "iconcache",
        "thumbcache_db",
    ]

    # Cache size mappings
    CACHE_SIZES = {
        "16": "16x16",
        "32": "32x32",
        "48": "48x48",
        "96": "96x96",
        "256": "256x256",
        "1024": "1024x1024",
        "sr": "Scaling Ratio",
        "wide": "Wide/Landscape",
        "exif": "EXIF Rotation",
        "idx": "Index",
    }

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize thumbcache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse thumbnail cache file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse thumbnail cache from bytes."""
        parser = ThumbcacheParser(data, filename)

        record_index = 0

        # Determine cache type from filename
        cache_type = "unknown"
        for key, value in self.CACHE_SIZES.items():
            if f"_{key}." in filename.lower() or f"_{key}_" in filename.lower():
                cache_type = value
                break

        # Emit cache entries
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "cache_entry_hash": entry.cache_entry_hash,
                "data_size": entry.data_size,
                "has_thumbnail": entry.has_thumbnail,
                "cache_type": cache_type,
                "source_file": filename,
            }

            if entry.identifier:
                record_data["identifier"] = entry.identifier

                # Try to extract filename from identifier
                if "\\" in entry.identifier:
                    parts = entry.identifier.split("\\")
                    record_data["original_filename"] = parts[-1]
                    record_data["original_path"] = entry.identifier

            if entry.extension:
                record_data["extension"] = entry.extension

            evidence_ref = self.create_evidence_ref(
                record_offset=entry.data_offset,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "thumbcache_entry",
                entry.cache_entry_hash,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=None,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        # Emit index entries
        for entry in parser.index_entries:
            record_data = {
                "entry_hash": entry.entry_hash,
                "flags": entry.flags,
                "cache_entry_offset": entry.cache_entry_offset,
                "record_type": "index_entry",
                "source_file": filename,
            }

            if entry.last_modified:
                record_data["last_modified"] = entry.last_modified.isoformat()

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "thumbcache_index",
                entry.entry_hash,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.last_modified,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        # Emit summary
        if parser.entries or parser.index_entries or parser.header:
            summary_data: dict[str, Any] = {
                "summary": True,
                "cache_entries": len(parser.entries),
                "index_entries": len(parser.index_entries),
                "cache_type": cache_type,
                "source_file": filename,
            }

            if parser.header:
                summary_data["header"] = parser.header

            # Count entries with thumbnails
            with_thumbnails = sum(1 for e in parser.entries if e.has_thumbnail)
            summary_data["entries_with_thumbnails"] = with_thumbnails

            # Unique identifiers
            identifiers = [e.identifier for e in parser.entries if e.identifier]
            if identifiers:
                summary_data["unique_identifiers"] = len(set(identifiers))
                summary_data["sample_identifiers"] = identifiers[:10]

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("thumbcache_summary", filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=summary_data,
                evidence_ref=evidence_ref,
            )
