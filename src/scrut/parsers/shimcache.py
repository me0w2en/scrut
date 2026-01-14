"""ShimCache (AppCompatCache) parser for program execution artifacts.

Parses the Application Compatibility Cache from the SYSTEM registry hive
to extract evidence of program execution.
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
from scrut.parsers.registry import RegistryHive

PARSER_VERSION = "0.1.0"

# ShimCache signatures for different Windows versions
WINXP_MAGIC = 0xDEADBEEF
WIN2003_MAGIC = 0xBADC0FEE
WIN7_MAGIC = 0xBADC0FFE
WIN8_MAGIC = 0x00000080
WIN81_MAGIC = 0x00000080
WIN10_MAGIC = 0x00000030  # And higher


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
class ShimCacheEntry:
    """A single ShimCache entry."""

    path: str
    last_modified: datetime | None
    exec_flag: bool | None
    file_size: int | None
    data: bytes | None
    # UWP app fields (Windows 10+)
    entry_type: str = "executable"  # "executable" or "uwp_app"
    uwp_package_name: str | None = None
    uwp_publisher_id: str | None = None


class ShimCacheParser:
    """Parser for ShimCache data from SYSTEM hive."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with AppCompatCache value data."""
        self.data = data
        self.entries: list[ShimCacheEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse ShimCache entries based on format."""
        if len(self.data) < 4:
            return

        # Try to detect format
        magic = struct.unpack("<I", self.data[0:4])[0]

        if magic == WINXP_MAGIC:
            self._parse_winxp()
        elif magic == WIN2003_MAGIC:
            self._parse_win2003()
        elif magic == WIN7_MAGIC:
            self._parse_win7()
        elif magic == WIN8_MAGIC or magic == WIN10_MAGIC:
            self._parse_win8_10()
        else:
            # Try Win10 format as fallback
            self._parse_win8_10()

    def _parse_winxp(self) -> None:
        """Parse Windows XP format."""
        if len(self.data) < 400:
            return

        # XP has fixed 96 entries at offset 4
        num_entries = struct.unpack("<I", self.data[4:8])[0]
        num_entries = min(num_entries, 96)

        offset = 8
        for _ in range(num_entries):
            if offset + 552 > len(self.data):
                break

            # Entry structure:
            # Path: 528 bytes (MAX_PATH * 2 = 520 + padding)
            # Last modified: 8 bytes
            # File size: 8 bytes
            # Last update: 8 bytes

            try:
                path_data = self.data[offset:offset + 520]
                path = path_data.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                path = ""

            last_modified = _filetime_to_datetime(
                struct.unpack("<Q", self.data[offset + 528:offset + 536])[0]
            )
            file_size = struct.unpack("<Q", self.data[offset + 536:offset + 544])[0]

            if path:
                self.entries.append(
                    ShimCacheEntry(
                        path=path,
                        last_modified=last_modified,
                        exec_flag=None,
                        file_size=file_size if file_size else None,
                        data=None,
                    )
                )

            offset += 552

    def _parse_win2003(self) -> None:
        """Parse Windows 2003/Vista format."""
        if len(self.data) < 8:
            return

        num_entries = struct.unpack("<I", self.data[4:8])[0]
        offset = 8

        for _ in range(num_entries):
            if offset + 32 > len(self.data):
                break

            path_length = struct.unpack("<H", self.data[offset:offset + 2])[0]
            max_path = struct.unpack("<H", self.data[offset + 2:offset + 4])[0]

            path_offset = struct.unpack("<I", self.data[offset + 4:offset + 8])[0]

            last_modified = _filetime_to_datetime(
                struct.unpack("<Q", self.data[offset + 8:offset + 16])[0]
            )
            file_size = struct.unpack("<Q", self.data[offset + 16:offset + 24])[0]

            # Get path from offset
            if path_offset + path_length <= len(self.data):
                try:
                    path = self.data[path_offset:path_offset + path_length].decode(
                        "utf-16-le"
                    )
                except UnicodeDecodeError:
                    path = ""

                if path:
                    self.entries.append(
                        ShimCacheEntry(
                            path=path,
                            last_modified=last_modified,
                            exec_flag=None,
                            file_size=file_size if file_size else None,
                            data=None,
                        )
                    )

            offset += 32

    def _parse_win7(self) -> None:
        """Parse Windows 7 format."""
        if len(self.data) < 128:
            return

        # Skip header (128 bytes for Win7)
        num_entries = struct.unpack("<I", self.data[4:8])[0]
        offset = 128

        for _ in range(num_entries):
            if offset + 32 > len(self.data):
                break

            path_length = struct.unpack("<H", self.data[offset:offset + 2])[0]
            path_offset = struct.unpack("<I", self.data[offset + 4:offset + 8])[0]

            last_modified = _filetime_to_datetime(
                struct.unpack("<Q", self.data[offset + 8:offset + 16])[0]
            )

            # Data size and offset
            data_size = struct.unpack("<I", self.data[offset + 16:offset + 20])[0]

            # Get path
            if path_offset + path_length <= len(self.data):
                try:
                    path = self.data[path_offset:path_offset + path_length].decode(
                        "utf-16-le"
                    )
                except UnicodeDecodeError:
                    path = ""

                if path:
                    self.entries.append(
                        ShimCacheEntry(
                            path=path,
                            last_modified=last_modified,
                            exec_flag=None,
                            file_size=None,
                            data=None,
                        )
                    )

            offset += 32

    def _parse_win8_10(self) -> None:
        """Parse Windows 8/8.1/10/11 format."""
        if len(self.data) < 48:
            return

        # Win8+ uses a different header
        # Offset 0x30 (48): Signature "10ts" (0x31307473)
        # Or Win10: 0x30 header size

        # Check for Win10 Creator's Update format
        header_size = struct.unpack("<I", self.data[0:4])[0]

        if header_size == 0x34:
            # Win10 Creator's Update+
            offset = header_size
        elif header_size == 0x30:
            # Win10 pre-Creator's Update
            offset = header_size
        elif header_size == 0x80:
            # Win8/8.1
            offset = header_size
        else:
            # Try 48 as default
            offset = 48

        # Look for "10ts" signature
        while offset + 12 <= len(self.data):
            # Entry signature check
            sig = self.data[offset:offset + 4]
            if sig != b"10ts":
                break

            if offset + 12 > len(self.data):
                break

            # Entry structure:
            # 4 bytes: signature "10ts"
            # 4 bytes: unknown
            # 4 bytes: entry size (NOT including this 12-byte header)
            entry_size = struct.unpack("<I", self.data[offset + 8:offset + 12])[0]

            # Total entry size includes the 12-byte header
            total_entry_size = 12 + entry_size

            if entry_size == 0 or offset + total_entry_size > len(self.data):
                break

            entry_data = self.data[offset:offset + total_entry_size]

            # Path length at offset 12, path starts at 14
            if len(entry_data) >= 14:
                path_length = struct.unpack("<H", entry_data[12:14])[0]

                if 14 + path_length <= len(entry_data):
                    try:
                        path = entry_data[14:14 + path_length].decode("utf-16-le")
                    except UnicodeDecodeError:
                        path = ""

                    # Last modified time after path
                    lm_offset = 14 + path_length
                    last_modified = None
                    if lm_offset + 8 <= len(entry_data):
                        last_modified = _filetime_to_datetime(
                            struct.unpack("<Q", entry_data[lm_offset:lm_offset + 8])[0]
                        )

                    # Data size follows
                    data_size = 0
                    if lm_offset + 12 <= len(entry_data):
                        data_size = struct.unpack(
                            "<I", entry_data[lm_offset + 8:lm_offset + 12]
                        )[0]

                    if path:
                        # Detect UWP app entries (tab-separated format)
                        if "\t" in path and not path.startswith("C:\\"):
                            entry = self._parse_uwp_entry(path, last_modified)
                        else:
                            entry = ShimCacheEntry(
                                path=path,
                                last_modified=last_modified,
                                exec_flag=None,
                                file_size=None,
                                data=None,
                                entry_type="executable",
                            )
                        self.entries.append(entry)

            offset += total_entry_size

    def _parse_uwp_entry(
        self, raw_path: str, last_modified: datetime | None
    ) -> ShimCacheEntry:
        """Parse a UWP/Microsoft Store app entry.

        UWP entries use tab-separated format with 7 fields:
        - Field 0: Flags/version (hex)
        - Field 1: Unknown timestamp? (hex)
        - Field 2: Unknown (hex)
        - Field 3: Architecture (8664=x64, 014c=x86)
        - Field 4: Package name (e.g., Microsoft.Winget.Source)
        - Field 5: Publisher ID (e.g., 8wekyb3d8bbwe)
        - Field 6: Additional data (often empty)
        """
        parts = raw_path.split("\t")

        package_name = parts[4] if len(parts) > 4 else None
        publisher_id = parts[5] if len(parts) > 5 else None

        # Create a readable path from package info
        if package_name and publisher_id:
            display_path = f"[UWP] {package_name}_{publisher_id}"
        elif package_name:
            display_path = f"[UWP] {package_name}"
        else:
            display_path = f"[UWP] {raw_path[:50]}..."

        return ShimCacheEntry(
            path=display_path,
            last_modified=last_modified,
            exec_flag=None,
            file_size=None,
            data=None,
            entry_type="uwp_app",
            uwp_package_name=package_name,
            uwp_publisher_id=publisher_id,
        )


def parse_shimcache_from_system_hive(data: bytes) -> Iterator[ShimCacheEntry]:
    """Parse ShimCache entries from SYSTEM registry hive."""
    hive = RegistryHive(data)
    root = hive.get_root_key()

    if not root:
        return

    # Find ControlSet (Current or ControlSet001)
    control_sets = ["ControlSet001", "ControlSet002", "CurrentControlSet"]

    for cs_name in control_sets:
        cs_key = None
        for subkey in hive.get_subkeys(root):
            if subkey.name.lower() == cs_name.lower():
                cs_key = subkey
                break

        if not cs_key:
            continue

        # Navigate to AppCompatCache
        # Path: ControlSet001\Control\Session Manager\AppCompatCache
        path_parts = ["Control", "Session Manager", "AppCompatCache"]
        current = cs_key

        for part in path_parts:
            found = False
            for subkey in hive.get_subkeys(current):
                if subkey.name.lower() == part.lower():
                    current = subkey
                    found = True
                    break
            if not found:
                break
        else:
            # Found AppCompatCache key
            for value in hive.get_values(current):
                if value.name.lower() == "appcompatcache":
                    cache_data = value.raw_data
                    parser = ShimCacheParser(cache_data)
                    yield from parser.entries
                    return


@ParserRegistry.register
class ShimCacheFileParser(BaseParser):
    """Parser for ShimCache from SYSTEM hive."""

    name: ClassVar[str] = "shimcache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["shimcache", "appcompatcache"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize ShimCache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse SYSTEM hive file for ShimCache."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse ShimCache from SYSTEM hive bytes."""
        record_index = 0

        for entry in parse_shimcache_from_system_hive(data):
            record_data: dict[str, Any] = {
                "path": entry.path,
                "entry_type": entry.entry_type,
                "last_modified": (
                    entry.last_modified.isoformat() if entry.last_modified else None
                ),
            }

            if entry.exec_flag is not None:
                record_data["executed"] = entry.exec_flag
            if entry.file_size is not None:
                record_data["file_size"] = entry.file_size

            # Add UWP-specific fields
            if entry.entry_type == "uwp_app":
                if entry.uwp_package_name:
                    record_data["uwp_package_name"] = entry.uwp_package_name
                if entry.uwp_publisher_id:
                    record_data["uwp_publisher_id"] = entry.uwp_publisher_id

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("shimcache", record_index, entry.path)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.last_modified,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
