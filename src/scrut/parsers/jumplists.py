"""Jump Lists parser for recent/frequent items tracking.

Parses Windows Jump List files (automaticDestinations-ms and customDestinations-ms)
to extract evidence of recent document access and application usage.
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry
from scrut.parsers.lnk import LnkParser

PARSER_VERSION = "0.1.0"

# OLE Compound File signatures
OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
LNK_SIGNATURE = b"\x4C\x00\x00\x00"

# Known AppIDs (subset of common applications)
KNOWN_APP_IDS = {
    "5d696d521de238c3": "Google Chrome",
    "9b9cdc69c1c24e2b": "Microsoft Edge",
    "1b4dd67f29cb1962": "Firefox",
    "cfb56c56fa0f0a54": "Windows Explorer",
    "f01b4d95cf55d32a": "Windows Explorer",
    "7e4dca80246863e3": "Control Panel",
    "1cffbe793e8a1f03": "Windows Mail",
    "5f7b5f1e01b83767": "Notepad",
    "918e0ecb43d17e23": "Notepad",
    "28c8b86deab549a1": "Internet Explorer",
    "adecfb853d77462a": "Adobe Reader",
    "a7bd71699cd38d1c": "Adobe Acrobat",
    "0a1d19afe5a80f80": "VLC Media Player",
    "e6ee34ac9913c0a9": "WinRAR",
    "4975d6798a8bdf66": "7-Zip",
    "b74736c2bd8cc8a5": "Adobe Photoshop",
    "e2a593822e01aed3": "Python",
    "d00655d2aa12ff6d": "PowerShell",
    "bcc705f705d4ee93": "Command Prompt",
    "9f5c7904de525c51": "Windows Terminal",
    "1ac14e77fa18e52c": "VS Code",
    "74d7f43c1561fc1e": "Visual Studio",
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
class OLEHeader:
    """OLE Compound File header."""

    minor_version: int = 0
    major_version: int = 0
    sector_size: int = 512
    mini_sector_size: int = 64
    num_dir_sectors: int = 0
    num_fat_sectors: int = 0
    first_dir_sector: int = 0
    first_mini_fat_sector: int = 0
    num_mini_fat_sectors: int = 0
    first_difat_sector: int = 0
    num_difat_sectors: int = 0
    difat: list[int] = field(default_factory=list)


@dataclass
class OLEDirectoryEntry:
    """OLE directory entry."""

    name: str
    entry_type: int
    color: int
    left_sibling: int
    right_sibling: int
    child: int
    clsid: bytes
    start_sector: int
    size: int


@dataclass
class JumpListEntry:
    """A single Jump List entry."""

    app_id: str
    app_name: str
    target_path: str
    target_created: datetime | None = None
    target_modified: datetime | None = None
    target_accessed: datetime | None = None
    arguments: str = ""
    working_dir: str = ""
    description: str = ""
    machine_id: str = ""
    icon_location: str = ""
    entry_id: str = ""
    file_size: int = 0


class OLECompoundFile:
    """Parser for OLE Compound Files."""

    def __init__(self, data: bytes) -> None:
        """Initialize with file data."""
        self.data = data
        self.header = OLEHeader()
        self.entries: list[OLEDirectoryEntry] = []
        self._fat: list[int] = []
        self._mini_fat: list[int] = []
        self._mini_stream: bytes = b""
        self._parse_header()

    def _parse_header(self) -> bool:
        """Parse OLE header."""
        if len(self.data) < 512:
            return False

        if self.data[0:8] != OLE_SIGNATURE:
            return False

        self.header.minor_version = struct.unpack("<H", self.data[0x18:0x1A])[0]
        self.header.major_version = struct.unpack("<H", self.data[0x1A:0x1C])[0]

        # Sector size
        sector_shift = struct.unpack("<H", self.data[0x1E:0x20])[0]
        self.header.sector_size = 1 << sector_shift

        mini_shift = struct.unpack("<H", self.data[0x20:0x22])[0]
        self.header.mini_sector_size = 1 << mini_shift

        self.header.num_dir_sectors = struct.unpack("<I", self.data[0x28:0x2C])[0]
        self.header.num_fat_sectors = struct.unpack("<I", self.data[0x2C:0x30])[0]
        self.header.first_dir_sector = struct.unpack("<I", self.data[0x30:0x34])[0]
        self.header.first_mini_fat_sector = struct.unpack("<I", self.data[0x3C:0x40])[0]
        self.header.num_mini_fat_sectors = struct.unpack("<I", self.data[0x40:0x44])[0]
        self.header.first_difat_sector = struct.unpack("<I", self.data[0x44:0x48])[0]
        self.header.num_difat_sectors = struct.unpack("<I", self.data[0x48:0x4C])[0]

        # DIFAT array in header (109 entries)
        for i in range(109):
            offset = 0x4C + i * 4
            sector = struct.unpack("<I", self.data[offset:offset + 4])[0]
            if sector != 0xFFFFFFFE:  # Not free/end
                self.header.difat.append(sector)

        # Build FAT
        self._build_fat()

        # Parse directory
        self._parse_directory()

        # Build mini stream
        if self.entries:
            root = self.entries[0]
            if root.start_sector != 0xFFFFFFFE:
                self._mini_stream = self._read_stream(
                    root.start_sector, root.size, use_mini=False
                )

        return True

    def _build_fat(self) -> None:
        """Build FAT from DIFAT."""
        sector_size = self.header.sector_size
        entries_per_sector = sector_size // 4

        for fat_sector in self.header.difat:
            offset = (fat_sector + 1) * sector_size
            if offset + sector_size > len(self.data):
                break

            for i in range(entries_per_sector):
                entry = struct.unpack(
                    "<I", self.data[offset + i * 4:offset + i * 4 + 4]
                )[0]
                self._fat.append(entry)

    def _parse_directory(self) -> None:
        """Parse directory entries."""
        sector = self.header.first_dir_sector
        sector_size = self.header.sector_size
        entries_per_sector = sector_size // 128

        visited = set()
        while sector not in (0xFFFFFFFE, 0xFFFFFFFF) and sector not in visited:
            visited.add(sector)
            offset = (sector + 1) * sector_size

            for i in range(entries_per_sector):
                entry_offset = offset + i * 128
                if entry_offset + 128 > len(self.data):
                    break

                entry_data = self.data[entry_offset:entry_offset + 128]
                entry = self._parse_dir_entry(entry_data)
                if entry:
                    self.entries.append(entry)

            if sector < len(self._fat):
                sector = self._fat[sector]
            else:
                break

    def _parse_dir_entry(self, data: bytes) -> OLEDirectoryEntry | None:
        """Parse a directory entry."""
        if len(data) < 128:
            return None

        # Name length
        name_len = struct.unpack("<H", data[0x40:0x42])[0]
        if name_len == 0:
            return None

        # Name is UTF-16LE
        try:
            name = data[0:name_len - 2].decode("utf-16-le")
        except UnicodeDecodeError:
            name = ""

        entry_type = data[0x42]
        if entry_type == 0:  # Empty
            return None

        return OLEDirectoryEntry(
            name=name,
            entry_type=entry_type,
            color=data[0x43],
            left_sibling=struct.unpack("<I", data[0x44:0x48])[0],
            right_sibling=struct.unpack("<I", data[0x48:0x4C])[0],
            child=struct.unpack("<I", data[0x4C:0x50])[0],
            clsid=data[0x50:0x60],
            start_sector=struct.unpack("<I", data[0x74:0x78])[0],
            size=struct.unpack("<Q", data[0x78:0x80])[0],
        )

    def _read_stream(
        self, start_sector: int, size: int, use_mini: bool = False
    ) -> bytes:
        """Read a stream from sectors."""
        if use_mini and self._mini_stream:
            # Read from mini stream
            result = bytearray()
            sector = start_sector
            mini_sector_size = self.header.mini_sector_size
            remaining = size
            visited = set()

            while (
                sector not in (0xFFFFFFFE, 0xFFFFFFFF)
                and remaining > 0
                and sector not in visited
            ):
                visited.add(sector)
                offset = sector * mini_sector_size
                chunk_size = min(mini_sector_size, remaining)

                if offset + chunk_size <= len(self._mini_stream):
                    result.extend(self._mini_stream[offset:offset + chunk_size])

                remaining -= chunk_size
                if sector < len(self._mini_fat):
                    sector = self._mini_fat[sector]
                else:
                    break

            return bytes(result)
        else:
            # Read from regular sectors
            result = bytearray()
            sector = start_sector
            sector_size = self.header.sector_size
            remaining = size
            visited = set()

            while (
                sector not in (0xFFFFFFFE, 0xFFFFFFFF)
                and remaining > 0
                and sector not in visited
            ):
                visited.add(sector)
                offset = (sector + 1) * sector_size
                chunk_size = min(sector_size, remaining)

                if offset + chunk_size <= len(self.data):
                    result.extend(self.data[offset:offset + chunk_size])

                remaining -= chunk_size
                if sector < len(self._fat):
                    sector = self._fat[sector]
                else:
                    break

            return bytes(result)

    def get_stream(self, name: str) -> bytes | None:
        """Get a stream by name."""
        for entry in self.entries:
            if entry.name == name and entry.entry_type == 2:  # Stream
                use_mini = entry.size < 4096
                return self._read_stream(entry.start_sector, entry.size, use_mini)
        return None

    def list_streams(self) -> list[str]:
        """List all stream names."""
        return [
            entry.name for entry in self.entries if entry.entry_type == 2  # Stream
        ]


class JumpListParser:
    """Parser for Jump List files."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser with file data."""
        self.data = data
        self.filename = filename
        self.app_id = self._extract_app_id()
        self.entries: list[JumpListEntry] = []
        self._parse()

    def _extract_app_id(self) -> str:
        """Extract AppID from filename."""
        # Filename format: {AppID}.automaticDestinations-ms
        if self.filename:
            name = Path(self.filename).stem
            parts = name.split(".")
            if parts:
                return parts[0].lower()
        return ""

    def _parse(self) -> None:
        """Parse the Jump List file."""
        if len(self.data) < 8:
            return

        # Check if OLE Compound File (automaticDestinations)
        if self.data[0:8] == OLE_SIGNATURE:
            self._parse_automatic()
        # Check for custom destinations (LNK-like)
        elif self.data[0:4] == LNK_SIGNATURE:
            self._parse_custom_lnk_based()
        else:
            # Try custom destinations format
            self._parse_custom()

    def _parse_automatic(self) -> None:
        """Parse automaticDestinations-ms file."""
        ole = OLECompoundFile(self.data)

        app_name = KNOWN_APP_IDS.get(self.app_id, "Unknown Application")

        # Each stream (except DestList) is an LNK file
        for stream_name in ole.list_streams():
            if stream_name.lower() in ("destlist", "root entry"):
                continue

            stream_data = ole.get_stream(stream_name)
            if stream_data and len(stream_data) >= 76:
                # Parse as LNK
                if stream_data[0:4] == LNK_SIGNATURE:
                    entry = self._parse_lnk_entry(stream_data, stream_name)
                    if entry:
                        entry.app_id = self.app_id
                        entry.app_name = app_name
                        self.entries.append(entry)

        # Parse DestList for additional metadata
        destlist = ole.get_stream("DestList")
        if destlist:
            self._parse_destlist(destlist)

    def _parse_destlist(self, data: bytes) -> None:
        """Parse DestList stream for entry metadata."""
        if len(data) < 32:
            return

        # Header
        version = struct.unpack("<I", data[0:4])[0]
        num_entries = struct.unpack("<I", data[4:8])[0]
        num_pinned = struct.unpack("<I", data[8:12])[0]

        # Entry size varies by version
        if version >= 3:
            entry_size = 130  # Plus variable string
        else:
            entry_size = 114

        offset = 32
        for _ in range(num_entries):
            if offset + entry_size > len(data):
                break

            # Entry ID (hash)
            entry_id = data[offset + 88:offset + 104].hex() if version >= 3 else ""

            # Access count at offset 8
            # Last access at offset 16 (FILETIME)
            if offset + 24 <= len(data):
                access_time = struct.unpack("<Q", data[offset + 16:offset + 24])[0]
                last_access = _filetime_to_datetime(access_time)

            # String length at end of fixed part
            str_offset = offset + entry_size - 4
            if str_offset + 4 <= len(data):
                str_len = struct.unpack("<H", data[str_offset:str_offset + 2])[0]
                offset = str_offset + 2 + str_len * 2
            else:
                offset += entry_size

    def _parse_custom(self) -> None:
        """Parse customDestinations-ms file."""
        # Custom format: sequence of LNK files with headers
        offset = 0
        app_name = KNOWN_APP_IDS.get(self.app_id, "Unknown Application")

        # Look for LNK signatures
        while offset < len(self.data) - 4:
            pos = self.data.find(LNK_SIGNATURE, offset)
            if pos == -1:
                break

            # Try to parse as LNK
            lnk_data = self.data[pos:]

            # Get LNK size from header if possible
            if len(lnk_data) >= 76:
                entry = self._parse_lnk_entry(lnk_data, f"entry_{len(self.entries)}")
                if entry:
                    entry.app_id = self.app_id
                    entry.app_name = app_name
                    self.entries.append(entry)

            offset = pos + 76  # Move past minimum LNK size

    def _parse_custom_lnk_based(self) -> None:
        """Parse custom destinations that start with LNK signature."""
        self._parse_custom()

    def _parse_lnk_entry(self, data: bytes, entry_id: str) -> JumpListEntry | None:
        """Parse an LNK entry from Jump List."""
        parser = LnkParser(data)
        lnk = parser.result

        if not lnk.target_path and not lnk.local_base_path:
            return None

        return JumpListEntry(
            app_id="",
            app_name="",
            target_path=lnk.target_path or lnk.local_base_path,
            target_created=lnk.created,
            target_modified=lnk.modified,
            target_accessed=lnk.accessed,
            arguments=lnk.arguments,
            working_dir=lnk.working_dir,
            description=lnk.name,
            machine_id=lnk.machine_id,
            icon_location=lnk.icon_location,
            entry_id=entry_id,
            file_size=lnk.file_size,
        )


@ParserRegistry.register
class JumpListFileParser(BaseParser):
    """Parser for Jump List files."""

    name: ClassVar[str] = "jumplist"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "jumplist",
        "automaticdestinations-ms",
        "customdestinations-ms",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Jump List parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Jump List file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse Jump List from bytes."""
        parser = JumpListParser(data, filename)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "app_id": entry.app_id,
                "app_name": entry.app_name,
                "target_path": entry.target_path,
            }

            if entry.target_created:
                record_data["target_created"] = entry.target_created.isoformat()
            if entry.target_modified:
                record_data["target_modified"] = entry.target_modified.isoformat()
            if entry.target_accessed:
                record_data["target_accessed"] = entry.target_accessed.isoformat()
            if entry.arguments:
                record_data["arguments"] = entry.arguments
            if entry.working_dir:
                record_data["working_dir"] = entry.working_dir
            if entry.description:
                record_data["description"] = entry.description
            if entry.machine_id:
                record_data["machine_id"] = entry.machine_id
            if entry.entry_id:
                record_data["entry_id"] = entry.entry_id
            if entry.file_size:
                record_data["file_size"] = entry.file_size

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("jumplist", entry.app_id, record_index, entry.target_path)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.target_modified or entry.target_accessed,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
