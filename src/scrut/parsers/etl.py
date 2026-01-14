r"""ETL (Event Trace Log) parser.

Parses Windows Event Trace Log files for forensic analysis
including boot/shutdown, network, and security events.

Common ETL file locations:
- %SystemRoot%\System32\WDI\LogFiles\BootCKCL.etl (Boot performance)
- %SystemRoot%\System32\WDI\LogFiles\ShutdownCKCL.etl (Shutdown)
- %SystemRoot%\System32\LogFiles\WMI\*.etl (Various WMI traces)
- %SystemRoot%\System32\SleepStudy\*.etl (Sleep/wake events)
- %SystemRoot%\Panther\setupact.log.etl (Setup activity)
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

# ETL file signature (WMI Buffer Header)
ETL_BUFFER_SIGNATURE = 0x00000000  # Buffer header starts with buffer size

# Known provider GUIDs (partial)
KNOWN_PROVIDERS = {
    "9e03f906-87d6-4e2a-aa2e-37e5bacd9ed4": "DNS Client",
    "54849625-5478-4994-a5ba-3e3b0328c30d": "Microsoft-Windows-Security-Auditing",
    "45d8cccd-539f-4b72-a8b7-5c683142609a": "Microsoft-Windows-NetworkProfile",
    "a68ca8b7-004f-d7b6-a698-07e2de0f1f5d": "Microsoft-Windows-Kernel-General",
    "b2a40f1f-a05a-4dcd-8ddd-2c5b08bf7d98": "Microsoft-Windows-TCPIP",
    "eb004a05-9b1a-11d4-9123-0050047759bc": "Microsoft-Windows-WMI",
    "331c3b3a-2005-44c2-ac5e-77220c37d6b4": "Microsoft-Windows-Kernel-Power",
    "6b6c257f-5643-43e8-8e5a-c66343dbc650": "Microsoft-Windows-Dhcp-Client",
    "43d1a55c-76d6-4f7e-995c-64c5bf32af24": "Microsoft-Windows-Kernel-Boot",
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


@dataclass
class ETLEvent:
    """A single ETL event."""

    timestamp: datetime | None
    provider_guid: str
    provider_name: str
    event_id: int
    version: int
    level: int
    opcode: int
    task: int
    keyword: int
    process_id: int
    thread_id: int
    data: bytes
    data_size: int


@dataclass
class ETLBufferHeader:
    """ETL buffer header."""

    buffer_size: int
    saved_offset: int
    current_offset: int
    reference_count: int
    timestamp: datetime | None
    sequence_number: int
    clock_type: int
    client_context: int
    flags: int
    buffer_state: int
    processor_number: int
    alignment: int


class ETLParser:
    """Parser for ETL (Event Trace Log) files."""

    # Event header flags
    EVENT_HEADER_FLAG_EXTENDED_INFO = 0x0001
    EVENT_HEADER_FLAG_PRIVATE_SESSION = 0x0002
    EVENT_HEADER_FLAG_STRING_ONLY = 0x0004
    EVENT_HEADER_FLAG_TRACE_MESSAGE = 0x0008
    EVENT_HEADER_FLAG_NO_CPUTIME = 0x0010
    EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020
    EVENT_HEADER_FLAG_64_BIT_HEADER = 0x0040
    EVENT_HEADER_FLAG_CLASSIC_HEADER = 0x0100

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.events: list[ETLEvent] = []
        self.buffers: list[ETLBufferHeader] = []
        self._parse()

    def _parse(self) -> None:
        """Parse ETL file."""
        if len(self.data) < 68:  # Minimum buffer header size
            return

        offset = 0

        while offset < len(self.data) - 68:
            try:
                buffer = self._parse_buffer_header(offset)
                if buffer is None or buffer.buffer_size == 0:
                    break

                if buffer.buffer_size > 0x100000:  # Max 1MB buffer
                    break

                self.buffers.append(buffer)

                # Parse events within buffer
                event_offset = offset + 68  # After buffer header
                buffer_end = offset + buffer.saved_offset

                while event_offset < buffer_end - 20:
                    event = self._parse_event(event_offset, buffer_end)
                    if event is None:
                        break
                    self.events.append(event)
                    event_offset += event.data_size + 68  # Event header + data

                    if len(self.events) > 100000:  # Safety limit
                        break

                offset += buffer.buffer_size
            except struct.error:
                break

    def _parse_buffer_header(self, offset: int) -> ETLBufferHeader | None:
        """Parse ETL buffer header (WMI_BUFFER_HEADER)."""
        if offset + 68 > len(self.data):
            return None

        try:
            # WMI_BUFFER_HEADER structure (simplified)
            buffer_size = struct.unpack("<I", self.data[offset : offset + 4])[0]
            saved_offset = struct.unpack("<I", self.data[offset + 4 : offset + 8])[0]
            current_offset = struct.unpack("<I", self.data[offset + 8 : offset + 12])[0]
            reference_count = struct.unpack("<I", self.data[offset + 12 : offset + 16])[0]

            # Timestamp at offset 16 (8 bytes)
            timestamp_raw = struct.unpack("<Q", self.data[offset + 16 : offset + 24])[0]
            timestamp = _filetime_to_datetime(timestamp_raw)

            sequence_number = struct.unpack("<Q", self.data[offset + 24 : offset + 32])[0]

            # Client context at offset 40
            clock_type = struct.unpack("<I", self.data[offset + 40 : offset + 44])[0]
            client_context = struct.unpack("<I", self.data[offset + 44 : offset + 48])[0]
            flags = struct.unpack("<I", self.data[offset + 48 : offset + 52])[0]
            buffer_state = struct.unpack("<I", self.data[offset + 52 : offset + 56])[0]
            processor_number = struct.unpack("<I", self.data[offset + 56 : offset + 60])[0]
            alignment = struct.unpack("<I", self.data[offset + 60 : offset + 64])[0]

            return ETLBufferHeader(
                buffer_size=buffer_size,
                saved_offset=saved_offset,
                current_offset=current_offset,
                reference_count=reference_count,
                timestamp=timestamp,
                sequence_number=sequence_number,
                clock_type=clock_type,
                client_context=client_context,
                flags=flags,
                buffer_state=buffer_state,
                processor_number=processor_number,
                alignment=alignment,
            )
        except struct.error:
            return None

    def _parse_event(
        self, offset: int, buffer_end: int
    ) -> ETLEvent | None:
        """Parse an ETL event (EVENT_HEADER structure)."""
        if offset + 68 > buffer_end:
            return None

        try:
            # EVENT_HEADER structure
            size = struct.unpack("<H", self.data[offset : offset + 2])[0]
            header_type = struct.unpack("<H", self.data[offset + 2 : offset + 4])[0]
            flags = struct.unpack("<H", self.data[offset + 4 : offset + 6])[0]
            event_property = struct.unpack("<H", self.data[offset + 6 : offset + 8])[0]
            thread_id = struct.unpack("<I", self.data[offset + 8 : offset + 12])[0]
            process_id = struct.unpack("<I", self.data[offset + 12 : offset + 16])[0]

            # Timestamp
            timestamp_raw = struct.unpack("<Q", self.data[offset + 16 : offset + 24])[0]
            timestamp = _filetime_to_datetime(timestamp_raw)

            # Provider GUID (16 bytes at offset 24)
            guid_bytes = self.data[offset + 24 : offset + 40]
            provider_guid = self._format_guid(guid_bytes)
            provider_name = KNOWN_PROVIDERS.get(provider_guid.lower(), "Unknown")

            # EVENT_DESCRIPTOR at offset 40
            event_id = struct.unpack("<H", self.data[offset + 40 : offset + 42])[0]
            version = self.data[offset + 42]
            channel = self.data[offset + 43]
            level = self.data[offset + 44]
            opcode = self.data[offset + 45]
            task = struct.unpack("<H", self.data[offset + 46 : offset + 48])[0]
            keyword = struct.unpack("<Q", self.data[offset + 48 : offset + 56])[0]

            # Extended data info at offset 56
            # User data starts after header

            data_size = size - 68 if size > 68 else 0
            data = self.data[offset + 68 : offset + 68 + data_size] if data_size > 0 else b""

            return ETLEvent(
                timestamp=timestamp,
                provider_guid=provider_guid,
                provider_name=provider_name,
                event_id=event_id,
                version=version,
                level=level,
                opcode=opcode,
                task=task,
                keyword=keyword,
                process_id=process_id,
                thread_id=thread_id,
                data=data,
                data_size=size,
            )
        except struct.error:
            return None

    def _format_guid(self, guid_bytes: bytes) -> str:
        """Format 16 bytes as a GUID string."""
        if len(guid_bytes) != 16:
            return "00000000-0000-0000-0000-000000000000"

        try:
            # GUID format: DWORD-WORD-WORD-BYTE[2]-BYTE[6]
            data1 = struct.unpack("<I", guid_bytes[0:4])[0]
            data2 = struct.unpack("<H", guid_bytes[4:6])[0]
            data3 = struct.unpack("<H", guid_bytes[6:8])[0]
            data4 = guid_bytes[8:16]

            return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[0]:02x}{data4[1]:02x}-{data4[2:].hex()}"
        except struct.error:
            return "00000000-0000-0000-0000-000000000000"


@ParserRegistry.register
class ETLFileParser(BaseParser):
    """Parser for ETL (Event Trace Log) files."""

    name: ClassVar[str] = "etl"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "etl",
        "etl_trace",
        "event_trace",
        "bootckl",
        "shutdownckl",
    ]

    # Event levels
    LEVELS = {
        0: "LogAlways",
        1: "Critical",
        2: "Error",
        3: "Warning",
        4: "Informational",
        5: "Verbose",
    }

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize ETL parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse ETL file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse ETL from bytes."""
        parser = ETLParser(data)

        record_index = 0

        for event in parser.events:
            record_data: dict[str, Any] = {
                "provider_guid": event.provider_guid,
                "provider_name": event.provider_name,
                "event_id": event.event_id,
                "version": event.version,
                "level": event.level,
                "level_name": self.LEVELS.get(event.level, f"Level{event.level}"),
                "opcode": event.opcode,
                "task": event.task,
                "process_id": event.process_id,
                "thread_id": event.thread_id,
                "source_file": filename,
            }

            # Add data preview if not too large
            if event.data and len(event.data) > 0:
                record_data["data_size"] = len(event.data)
                # Try to decode as string for preview
                try:
                    text = event.data.decode("utf-16-le").rstrip("\x00")
                    if text and len(text) < 500 and text.isprintable():
                        record_data["data_preview"] = text
                except (UnicodeDecodeError, UnicodeEncodeError):
                    try:
                        text = event.data.decode("utf-8", errors="replace").rstrip("\x00")
                        if text and len(text) < 500:
                            record_data["data_preview"] = text[:200]
                    except Exception:
                        pass

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "etl_event",
                event.provider_guid,
                event.event_id,
                record_index,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=event.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        # Emit summary record
        if parser.buffers:
            summary_data = {
                "summary": True,
                "buffer_count": len(parser.buffers),
                "event_count": len(parser.events),
                "source_file": filename,
            }

            # Get time range
            timestamps = [e.timestamp for e in parser.events if e.timestamp]
            if timestamps:
                summary_data["earliest_event"] = min(timestamps).isoformat()
                summary_data["latest_event"] = max(timestamps).isoformat()

            # Provider distribution
            providers = {}
            for event in parser.events:
                key = event.provider_name or event.provider_guid
                providers[key] = providers.get(key, 0) + 1
            summary_data["providers"] = providers

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("etl_summary", filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=summary_data,
                evidence_ref=evidence_ref,
            )
