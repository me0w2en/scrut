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
PARSER_VERSION = "0.3.0"

# EVTX constants
EVTX_SIGNATURE = b"ElfFile\x00"
EVTX_CHUNK_SIGNATURE = b"ElfChnk\x00"
EVTX_RECORD_SIGNATURE = b"\x2a\x2a\x00\x00"  # **\x00\x00

# BinXML token types
BINXML_CLOSE_START_ELEMENT = 0x02
BINXML_END_ELEMENT = 0x04
BINXML_TEMPLATE_INSTANCE = 0x0C
BINXML_NORMAL_SUBSTITUTION = 0x0D
BINXML_OPTIONAL_SUBSTITUTION = 0x0E

# Value types
VALUE_NULL = 0x00
VALUE_STRING = 0x01
VALUE_UINT8 = 0x04
VALUE_UINT16 = 0x06
VALUE_UINT32 = 0x08
VALUE_UINT64 = 0x0A
VALUE_GUID = 0x0F
VALUE_FILETIME = 0x11
VALUE_SID = 0x13
VALUE_BINXML = 0x21

# "EventID" as UTF-16LE for template body scanning
_EVENTID_UTF16LE = "EventID".encode("utf-16-le")


class _TemplateInfo:
    """Parsed template definition with descriptors and EventID index."""

    __slots__ = ("descriptors", "eventid_sub_id", "total_def_size")

    def __init__(
        self,
        descriptors: list[tuple[int, int]],
        eventid_sub_id: int | None,
        total_def_size: int,
    ) -> None:
        self.descriptors = descriptors
        self.eventid_sub_id = eventid_sub_id
        self.total_def_size = total_def_size


class EvtxChunk:
    """EVTX chunk containing multiple records."""

    def __init__(self, data: bytes, offset: int) -> None:
        """Initialize chunk from raw data."""
        self.data = data
        self.offset = offset
        self._records: list[tuple[int, bytes]] = []
        self._template_cache: dict[int, _TemplateInfo] = {}
        self._parse()

    def _parse(self) -> None:
        """Parse chunk header and locate records."""
        if len(self.data) < 512 or self.data[:8] != EVTX_CHUNK_SIGNATURE:
            return

        free_space_offset = struct.unpack("<I", self.data[48:52])[0]

        pos = 512
        while pos < min(free_space_offset, len(self.data) - 28):
            if self.data[pos:pos + 4] == EVTX_RECORD_SIGNATURE:
                if pos + 28 <= len(self.data):
                    record_size = struct.unpack("<I", self.data[pos + 4:pos + 8])[0]
                    if record_size > 0 and pos + record_size <= len(self.data):
                        self._records.append((pos, self.data[pos:pos + record_size]))
                        pos += record_size
                        continue
            pos += 1

        self._build_template_cache()

    def _build_template_cache(self) -> None:
        """Parse template definitions from records and cache them."""
        for _pos, record_data in self._records:
            if len(record_data) < 48:
                continue

            # BinXML content starts at record offset 28 (after 24-byte header + 4-byte fragment header)
            # Template instance token is at record[28]
            binxml = record_data[28:]
            if len(binxml) < 10 or binxml[0] != BINXML_TEMPLATE_INSTANCE:
                continue

            # Template instance: token(1) + unknown(1) + template_id(4) + def_offset(4)
            tpl_offset = struct.unpack("<I", binxml[6:10])[0]
            if tpl_offset in self._template_cache:
                continue

            self._parse_template_at(tpl_offset)

    def _parse_template_at(self, offset: int) -> None:
        """Parse a template definition at a chunk-relative offset.

        Template definition layout:
          [0:4]     next template offset (uint32)
          [4:20]    template identifier GUID (16 bytes)
          [20:24]   element data size (uint32)
          [24:24+S] element body (S bytes, contains XML structure)
          [24+S]    number of substitution descriptors (uint32)
          [24+S+4]  descriptors (N * 4 bytes: uint16 size + uint16 type)
        """
        d = self.data
        if offset + 24 >= len(d):
            return

        elem_data_size = struct.unpack("<I", d[offset + 20:offset + 24])[0]
        if elem_data_size == 0 or offset + 24 + elem_data_size + 4 > len(d):
            return

        sub_count_pos = offset + 24 + elem_data_size
        num_subs = struct.unpack("<I", d[sub_count_pos:sub_count_pos + 4])[0]
        if num_subs < 1 or num_subs > 100:
            return

        desc_start = sub_count_pos + 4
        if desc_start + num_subs * 4 > len(d):
            return

        descriptors: list[tuple[int, int]] = []
        valid = True
        for k in range(num_subs):
            off = desc_start + k * 4
            sz = struct.unpack("<H", d[off:off + 2])[0]
            tp = struct.unpack("<H", d[off + 2:off + 4])[0]
            if (tp & 0x7F) > VALUE_BINXML:
                valid = False
                break
            descriptors.append((sz, tp & 0x7F))

        if not valid or not descriptors:
            return

        # Find the EventID substitution index by scanning the element body
        elem_body = d[offset + 24:offset + 24 + elem_data_size]
        eventid_sub_id = self._find_eventid_sub_id(elem_body)

        total_def_size = 24 + elem_data_size + 4 + num_subs * 4
        self._template_cache[offset] = _TemplateInfo(descriptors, eventid_sub_id, total_def_size)

    def _find_eventid_sub_id(self, elem_body: bytes) -> int | None:
        """Find the substitution ID for the EventID value in the template body.

        Scans the template element body for "EventID" (UTF-16LE), then finds
        the substitution token after the close-start-element (0x02) that
        represents the EventID text content (not the Qualifiers attribute).

        Substitution tokens (0x0D/0x0E) are 4 bytes: token + sub_id(2) + type(1).
        We must skip them properly to avoid interpreting their data bytes as tokens.
        """
        eid_pos = elem_body.find(_EVENTID_UTF16LE)
        if eid_pos < 0:
            return None

        # After "EventID", scan for close-start-element (0x02), then the next
        # substitution token (0x0D or 0x0E) is the EventID value.
        found_close = False
        i = eid_pos + len(_EVENTID_UTF16LE)
        limit = min(i + 80, len(elem_body) - 3)

        while i < limit:
            token = elem_body[i]
            if token in (BINXML_NORMAL_SUBSTITUTION, BINXML_OPTIONAL_SUBSTITUTION):
                if found_close:
                    sub_id = struct.unpack("<H", elem_body[i + 1:i + 3])[0]
                    return sub_id
                # Skip full substitution token: token(1) + sub_id(2) + type(1)
                i += 4
                continue
            if token == BINXML_CLOSE_START_ELEMENT:
                found_close = True
                i += 1
                continue
            if token == BINXML_END_ELEMENT:
                break
            i += 1

        return None

    def get_template(self, tpl_offset: int) -> _TemplateInfo | None:
        """Get cached template info by offset."""
        return self._template_cache.get(tpl_offset)

    def records(self) -> Iterator[tuple[int, bytes]]:
        """Yield (offset, data) for each record."""
        yield from self._records


class EvtxRecord:
    """Single EVTX event record."""

    def __init__(
        self,
        data: bytes,
        chunk_offset: int,
        record_offset: int,
        chunk: EvtxChunk | None = None,
    ) -> None:
        """Initialize record from raw data."""
        self.data = data
        self.chunk_offset = chunk_offset
        self.record_offset = record_offset
        self._chunk = chunk
        self.record_id: int = 0
        self.timestamp: datetime | None = None
        self._event_data: dict[str, Any] = {}
        self._parse_header()

    def _parse_header(self) -> None:
        """Parse record header."""
        if len(self.data) < 28:
            return

        self.record_id = struct.unpack("<Q", self.data[8:16])[0]
        filetime = struct.unpack("<Q", self.data[16:24])[0]

        if filetime > 0:
            try:
                unix_ts = (filetime - 116444736000000000) / 10000000
                self.timestamp = datetime.fromtimestamp(unix_ts, tz=UTC)
            except (OSError, ValueError):
                pass

    def parse_binxml(self) -> dict[str, Any]:
        """Parse BinXML content to extract event data."""
        if self._event_data:
            return self._event_data

        if len(self.data) < 38:
            return {}

        # Record layout: header(24) + fragment_header(4) + binxml_content
        # Template instance starts at offset 28 (after fragment header)
        binxml = self.data[28:]

        result = self._parse_with_template(binxml)

        # Extract strings for provider_name and channel
        strings = self._extract_strings(binxml)
        if strings:
            result["extracted_strings"] = strings

        for s in strings:
            if "Microsoft" in s or "Security" in s or "-" in s:
                result.setdefault("provider_name", s)
                break

        for s in strings:
            if s.startswith("Microsoft-Windows-") or s in (
                "Security", "System", "Application",
            ):
                result.setdefault("channel", s)
                break

        self._event_data = result
        return self._event_data

    def _parse_with_template(self, binxml: bytes) -> dict[str, Any]:
        """Extract event fields using BinXML template substitution parsing.

        Template instance layout (at binxml[0]):
          [0]    0x0C template instance token
          [1]    unknown byte
          [2:6]  template identifier (first 4 bytes of GUID)
          [6:10] template_def_offset (uint32, chunk-relative)

        For inline templates (first occurrence):
          [10:10+D]  template definition (D bytes, includes descriptors)
          [10+D:]    substitution values

        For referenced templates (subsequent occurrences):
          [10:14]        num_descriptors (uint32)
          [14:14+N*4]    runtime value descriptors (N * 4 bytes)
          [14+N*4:]      substitution values
        """
        result: dict[str, Any] = {}

        if len(binxml) < 10 or binxml[0] != BINXML_TEMPLATE_INSTANCE:
            return result

        tpl_offset = struct.unpack("<I", binxml[6:10])[0]

        tpl_info = self._chunk.get_template(tpl_offset) if self._chunk else None
        if not tpl_info:
            return result

        num_descs = len(tpl_info.descriptors)
        expected_inline_offset = self.record_offset + 28 + 10
        is_inline = (tpl_offset == expected_inline_offset)

        if is_inline:
            # Inline: values follow the template definition directly.
            # Use template def descriptors for sizes.
            values_start = 10 + tpl_info.total_def_size
            descriptors = tpl_info.descriptors
        else:
            # Referenced: runtime descriptor array precedes the values.
            # [10:14] = num_descriptors, [14:14+N*4] = descriptors, then values.
            desc_array_start = 14
            values_start = desc_array_start + num_descs * 4

            # Read runtime descriptors (sizes may differ from template def)
            descriptors = []
            for k in range(num_descs):
                off = desc_array_start + k * 4
                if off + 4 > len(binxml):
                    break
                rsz = struct.unpack("<H", binxml[off:off + 2])[0]
                rtp = struct.unpack("<H", binxml[off + 2:off + 4])[0]
                descriptors.append((rsz, rtp & 0x7F))

        if values_start >= len(binxml):
            return result

        # Build a map of substitution_id -> (offset_in_binxml, size, type)
        sub_values: dict[int, tuple[int, int, int]] = {}
        current = values_start
        for sub_id, (size, vtype) in enumerate(descriptors):
            if current + size > len(binxml):
                break
            sub_values[sub_id] = (current, size, vtype)
            current += size

        # Extract EventID using the known substitution ID
        if tpl_info.eventid_sub_id is not None and tpl_info.eventid_sub_id in sub_values:
            off, sz, vt = sub_values[tpl_info.eventid_sub_id]
            if sz == 2 and vt == VALUE_UINT16:
                eid = struct.unpack("<H", binxml[off:off + 2])[0]
                if 0 < eid < 65535:
                    result["event_id"] = eid

        # Extract additional System fields from substitution values
        for _sub_id, (off, sz, vt) in sub_values.items():
            if sz == 0:
                continue

            if vt == VALUE_GUID and sz == 16 and "provider_guid" not in result:
                result["provider_guid"] = _format_guid(binxml[off:off + 16])

            if vt == VALUE_UINT64 and sz == 8 and "event_record_id" not in result:
                result["event_record_id"] = struct.unpack("<Q", binxml[off:off + 8])[0]

        return result

    def _extract_strings(self, data: bytes) -> list[str]:
        """Extract readable UTF-16LE strings from binary data."""
        strings = []

        i = 0
        while i < len(data) - 4:
            if data[i + 1:i + 2] == b'\x00' and 0x20 <= data[i] <= 0x7e:
                end = i
                while end < len(data) - 1:
                    char = data[end:end + 2]
                    if char == b'\x00\x00':
                        break
                    if len(char) < 2:
                        break
                    code = struct.unpack("<H", char)[0]
                    if code > 0xFFFF or (0 < code < 0x20 and code not in (9, 10, 13)):
                        break
                    end += 2

                if end > i + 4:
                    try:
                        s = data[i:end].decode("utf-16-le", errors="ignore")
                        if len(s) > 2 and s.isprintable():
                            strings.append(s)
                    except Exception:
                        pass
                    i = end
                    continue
            i += 1

        seen: set[str] = set()
        unique: list[str] = []
        for s in strings:
            if s not in seen and len(s) > 2:
                seen.add(s)
                unique.append(s)

        return unique[:20]


def _format_guid(data: bytes) -> str:
    """Format 16 bytes as a GUID string."""
    if len(data) != 16:
        return data.hex()
    a = struct.unpack("<IHH", data[:8])
    b = data[8:10]
    c = data[10:16]
    return f"{a[0]:08x}-{a[1]:04x}-{a[2]:04x}-{b[0]:02x}{b[1]:02x}-{c.hex()}"


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
        if len(data) < 4096 or data[:8] != EVTX_SIGNATURE:
            raise ValueError("Invalid EVTX file signature")

        header_size = 4096
        chunk_size = struct.unpack("<I", data[44:48])[0]
        if chunk_size == 0:
            chunk_size = 65536

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
                record = EvtxRecord(record_data, chunk_offset, record_offset, chunk)
                if record.timestamp:
                    all_records.append(record)

            chunk_offset += chunk_size

        all_records.sort(key=lambda r: (r.timestamp or datetime.min.replace(tzinfo=UTC), r.record_id))

        for record in all_records:
            try:
                parsed = self._create_parsed_record(record, record_index)
                yield parsed
                record_index += 1
            except Exception:
                record_index += 1
                continue

    def _create_parsed_record(self, record: EvtxRecord, index: int) -> ParsedRecord:
        """Create ParsedRecord from EVTX record."""
        event_data = record.parse_binxml()

        timestamp = self.normalize_timestamp(record.timestamp) if record.timestamp else None
        timestamp_original = record.timestamp.isoformat() if record.timestamp else None

        event_id = event_data.get("event_id", "unknown")
        record_id = self.create_record_id("evtx", event_id, record.record_id)

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
