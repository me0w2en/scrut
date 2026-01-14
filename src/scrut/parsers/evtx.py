"""EVTX (Windows Event Log) parser for Scrut DFIR CLI.

Custom implementation that parses EVTX files without external dependencies.
Supports parsing from file path or raw bytes (for image access).
"""

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

# Version of this parser
PARSER_VERSION = "0.2.0"

# EVTX constants
EVTX_SIGNATURE = b"ElfFile\x00"
EVTX_CHUNK_SIGNATURE = b"ElfChnk\x00"
EVTX_RECORD_SIGNATURE = b"\x2a\x2a\x00\x00"  # **\x00\x00

# BinXML token types
BINXML_EOF = 0x00
BINXML_OPEN_START_ELEMENT = 0x01
BINXML_CLOSE_START_ELEMENT = 0x02
BINXML_CLOSE_EMPTY_ELEMENT = 0x03
BINXML_END_ELEMENT = 0x04
BINXML_VALUE = 0x05
BINXML_ATTRIBUTE = 0x06
BINXML_CDATA_SECTION = 0x07
BINXML_CHAR_REF = 0x08
BINXML_ENTITY_REF = 0x09
BINXML_PI_TARGET = 0x0A
BINXML_PI_DATA = 0x0B
BINXML_TEMPLATE_INSTANCE = 0x0C
BINXML_NORMAL_SUBSTITUTION = 0x0D
BINXML_OPTIONAL_SUBSTITUTION = 0x0E
BINXML_FRAGMENT_HEADER = 0x0F

# Value types
VALUE_NULL = 0x00
VALUE_STRING = 0x01
VALUE_ANSI_STRING = 0x02
VALUE_INT8 = 0x03
VALUE_UINT8 = 0x04
VALUE_INT16 = 0x05
VALUE_UINT16 = 0x06
VALUE_INT32 = 0x07
VALUE_UINT32 = 0x08
VALUE_INT64 = 0x09
VALUE_UINT64 = 0x0A
VALUE_REAL32 = 0x0B
VALUE_REAL64 = 0x0C
VALUE_BOOL = 0x0D
VALUE_BINARY = 0x0E
VALUE_GUID = 0x0F
VALUE_SIZET = 0x10
VALUE_FILETIME = 0x11
VALUE_SYSTEMTIME = 0x12
VALUE_SID = 0x13
VALUE_HEX32 = 0x14
VALUE_HEX64 = 0x15
VALUE_BINXML = 0x21


class EvtxChunk:
    """EVTX chunk containing multiple records."""

    def __init__(self, data: bytes, offset: int) -> None:
        """Initialize chunk from raw data."""
        self.data = data
        self.offset = offset
        self._records: list[tuple[int, bytes]] = []
        self._parse()

    def _parse(self) -> None:
        """Parse chunk header and locate records."""
        if len(self.data) < 512 or self.data[:8] != EVTX_CHUNK_SIGNATURE:
            return

        # Chunk header fields (libevtx structure)
        # Offset 0-8: signature "ElfChnk\0"
        # Offset 8-16: first event record number (uint64)
        # Offset 16-24: last event record number (uint64)
        # Offset 24-32: first event record id (uint64)
        # Offset 32-40: last event record id (uint64)
        # Offset 40-44: header size (uint32, typically 128)
        # Offset 44-48: last event record data offset (uint32)
        # Offset 48-52: free space offset (uint32)
        # Offset 128+: string table, template table, records

        header_size = struct.unpack("<I", self.data[40:44])[0]
        last_record_offset = struct.unpack("<I", self.data[44:48])[0]
        free_space_offset = struct.unpack("<I", self.data[48:52])[0]

        # Records start after header (typically at offset 512 within chunk)
        # Look for record signatures
        pos = 512  # Records typically start here
        while pos < min(free_space_offset, len(self.data) - 28):
            # Check for record signature
            if self.data[pos:pos+4] == EVTX_RECORD_SIGNATURE:
                # Record header: signature (4) + size (4) + record_id (8) + timestamp (8)
                if pos + 28 <= len(self.data):
                    record_size = struct.unpack("<I", self.data[pos+4:pos+8])[0]
                    if record_size > 0 and pos + record_size <= len(self.data):
                        self._records.append((pos, self.data[pos:pos+record_size]))
                        pos += record_size
                        continue
            pos += 1

    def records(self) -> Iterator[tuple[int, bytes]]:
        """Yield (offset, data) for each record."""
        yield from self._records


class EvtxRecord:
    """Single EVTX event record."""

    def __init__(self, data: bytes, chunk_offset: int, record_offset: int) -> None:
        """Initialize record from raw data."""
        self.data = data
        self.chunk_offset = chunk_offset
        self.record_offset = record_offset
        self.record_id: int = 0
        self.timestamp: datetime | None = None
        self._event_data: dict[str, Any] = {}
        self._parse_header()

    def _parse_header(self) -> None:
        """Parse record header."""
        if len(self.data) < 28:
            return

        # Record header structure:
        # 0-4: signature (**\x00\x00)
        # 4-8: size
        # 8-16: record number
        # 16-24: timestamp (FILETIME)

        self.record_id = struct.unpack("<Q", self.data[8:16])[0]
        filetime = struct.unpack("<Q", self.data[16:24])[0]

        # Convert FILETIME to datetime
        if filetime > 0:
            try:
                # FILETIME: 100-nanosecond intervals since 1601-01-01
                unix_ts = (filetime - 116444736000000000) / 10000000
                self.timestamp = datetime.fromtimestamp(unix_ts, tz=UTC)
            except (OSError, ValueError):
                pass

    def parse_binxml(self) -> dict[str, Any]:
        """Parse BinXML content to extract event data."""
        if self._event_data:
            return self._event_data

        if len(self.data) < 28:
            return {}

        # BinXML starts after the record header (24 bytes) + copy size (4 bytes)
        binxml_start = 28
        binxml_data = self.data[binxml_start:]

        self._event_data = self._parse_binxml_simple(binxml_data)
        return self._event_data

    def _parse_binxml_simple(self, data: bytes) -> dict[str, Any]:
        """Simple BinXML parser that extracts key fields.

        This is a simplified parser that extracts common event fields
        without fully parsing the BinXML structure.
        """
        result: dict[str, Any] = {}

        try:
            # Look for common patterns in the binary data

            # Try to find EventID (usually a 2-byte value after specific patterns)
            # EventID is typically in the System/EventID element

            # Extract strings from the data
            strings = self._extract_strings(data)
            if strings:
                result["extracted_strings"] = strings

            # Look for specific field patterns
            # Provider Name often appears early
            # EventID is typically a small integer

            # Simple heuristic: look for Provider pattern
            provider_idx = data.find(b"Provider")
            if provider_idx > 0:
                # Try to extract provider name from nearby strings
                for s in strings:
                    if "Microsoft" in s or "Security" in s or "-" in s:
                        result["provider_name"] = s
                        break

            # Try to find EventID by looking for small integers after specific markers
            # This is a heuristic approach
            for i in range(0, min(200, len(data) - 2)):
                if data[i:i+1] == b'\x04' and data[i+1:i+2] in (b'\x00', b'\x01', b'\x02'):
                    # Might be EventID as uint16
                    try:
                        event_id = struct.unpack("<H", data[i+2:i+4])[0]
                        if 0 < event_id < 65535:
                            result["event_id"] = event_id
                            break
                    except Exception:
                        pass

            # Extract Channel if present
            for s in strings:
                if s.startswith("Microsoft-Windows-") or s in ("Security", "System", "Application"):
                    result["channel"] = s
                    break

        except Exception:
            pass

        return result

    def _extract_strings(self, data: bytes) -> list[str]:
        """Extract readable strings from binary data."""
        strings = []

        # Look for null-terminated UTF-16LE strings
        i = 0
        while i < len(data) - 4:
            # Check for potential string start (printable ASCII as UTF-16LE)
            if data[i+1:i+2] == b'\x00' and 0x20 <= data[i] <= 0x7e:
                # Try to read UTF-16LE string
                end = i
                while end < len(data) - 1:
                    char = data[end:end+2]
                    if char == b'\x00\x00':
                        break
                    if len(char) < 2:
                        break
                    code = struct.unpack("<H", char)[0]
                    if code > 0xFFFF or (code > 0 and code < 0x20 and code not in (9, 10, 13)):
                        break
                    end += 2

                if end > i + 4:  # Minimum string length
                    try:
                        s = data[i:end].decode("utf-16-le", errors="ignore")
                        if len(s) > 2 and s.isprintable():
                            strings.append(s)
                    except Exception:
                        pass
                    i = end
                    continue
            i += 1

        # Deduplicate while preserving order
        seen = set()
        unique_strings = []
        for s in strings:
            if s not in seen and len(s) > 2:
                seen.add(s)
                unique_strings.append(s)

        return unique_strings[:20]  # Limit to first 20 strings


@ParserRegistry.register
class EvtxParser(BaseParser):
    """Parser for Windows Event Log (EVTX) files.

    Custom implementation that parses EVTX files without external dependencies.
    Supports both file path and raw bytes input.
    """

    name: ClassVar[str] = "evtx"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["evtx"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize EVTX parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse EVTX file and yield records.

        Args:
            file_path: Path to EVTX file

        Yields:
            ParsedRecord for each event
        """
        with open(file_path, "rb") as fh:
            data = fh.read()

        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse EVTX from raw bytes.

        Args:
            data: Raw EVTX file content

        Yields:
            ParsedRecord for each event
        """
        # Verify EVTX signature
        if len(data) < 4096 or data[:8] != EVTX_SIGNATURE:
            raise ValueError("Invalid EVTX file signature")

        # Parse header
        # Offset 8-16: first chunk number
        # Offset 16-24: last chunk number
        # Offset 24-32: next record identifier
        # Offset 32-36: header size (typically 4096)
        # Offset 36-40: minor version
        # Offset 40-44: major version
        # Offset 44-48: chunk size (typically 65536)

        # EVTX file header is always 4096 bytes
        # The header_size field at offset 32 is often 128 (internal header),
        # but chunks always start at offset 4096
        header_size = 4096

        chunk_size = struct.unpack("<I", data[44:48])[0]
        if chunk_size == 0:
            chunk_size = 65536  # Default chunk size

        # Parse chunks
        chunk_offset = header_size
        record_index = 0
        all_records: list[EvtxRecord] = []

        while chunk_offset + chunk_size <= len(data):
            chunk_data = data[chunk_offset:chunk_offset + chunk_size]

            if chunk_data[:8] != EVTX_CHUNK_SIGNATURE:
                chunk_offset += chunk_size
                continue

            chunk = EvtxChunk(chunk_data, chunk_offset)

            for record_offset, record_data in chunk.records():
                record = EvtxRecord(record_data, chunk_offset, record_offset)
                if record.timestamp:
                    all_records.append(record)

            chunk_offset += chunk_size

        # Sort by timestamp for deterministic output
        all_records.sort(key=lambda r: (r.timestamp or datetime.min.replace(tzinfo=UTC), r.record_id))

        # Yield parsed records
        for record in all_records:
            try:
                parsed = self._create_parsed_record(record, record_index)
                yield parsed
                record_index += 1
            except Exception:
                record_index += 1
                continue

    def _create_parsed_record(self, record: EvtxRecord, index: int) -> ParsedRecord:
        """Create ParsedRecord from EVTX record.

        Args:
            record: EvtxRecord instance
            index: Record index

        Returns:
            ParsedRecord with event data
        """
        # Extract event data
        event_data = record.parse_binxml()

        # Normalize timestamp
        timestamp = self.normalize_timestamp(record.timestamp) if record.timestamp else None
        timestamp_original = record.timestamp.isoformat() if record.timestamp else None

        # Build record ID
        event_id = event_data.get("event_id", "unknown")
        record_id = self.create_record_id("evtx", event_id, record.record_id)

        # Add basic fields to event data
        event_data["record_number"] = record.record_id

        return ParsedRecord(
            record_id=record_id,
            schema_version="v1",
            record_type="timeline",
            timestamp=timestamp,
            timestamp_original=timestamp_original,
            data=event_data,
            evidence_ref=self.create_evidence_ref(
                record_offset=record.chunk_offset + record.record_offset,
                record_index=index,
            ),
        )


def parse_evtx(
    file_path: Path,
    target_id: UUID,
    artifact_path: str,
    source_hash: str,
    timezone_str: str = "UTC",
) -> Iterator[ParsedRecord]:
    """Convenience function to parse an EVTX file.

    Args:
        file_path: Path to EVTX file
        target_id: Target UUID
        artifact_path: Artifact path for evidence_ref
        source_hash: SHA-256 of artifact
        timezone_str: Output timezone

    Yields:
        ParsedRecord for each event
    """
    parser = EvtxParser(
        target_id=target_id,
        artifact_path=artifact_path,
        source_hash=source_hash,
        timezone_str=timezone_str,
    )
    yield from parser.parse(file_path)
