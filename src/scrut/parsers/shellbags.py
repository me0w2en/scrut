"""ShellBags parser for folder access tracking.

Parses ShellBags from USRCLASS.DAT and NTUSER.DAT registry hives
to extract evidence of folder access and browsing history.
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
from scrut.parsers.registry import RegistryHive

PARSER_VERSION = "0.1.0"

# Shell Item Types
SHELL_ITEM_ROOT_FOLDER = 0x1F
SHELL_ITEM_VOLUME = 0x20
SHELL_ITEM_FILE_ENTRY = 0x30
SHELL_ITEM_NETWORK = 0x40
SHELL_ITEM_COMPRESSED = 0x50
SHELL_ITEM_URI = 0x61
SHELL_ITEM_CONTROL_PANEL = 0x71

# Known folder GUIDs
KNOWN_FOLDER_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "3d644c9b-1fb8-4f30-9b45-f670235f79c0": "Public Downloads",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "1777f761-68ad-4d8a-87bd-30b759fa33dd": "Favorites",
    "bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968": "Links",
    "a77f5d77-2e2b-44c3-a6a2-aba601054a51": "Saved Games",
    "4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4": "Saved Pictures",
    "7d1d3a04-debb-4115-95cf-2f29da2920da": "Saved Searches",
    "56784854-c6cb-462b-8169-88e350acb882": "Contacts",
    "de92c1c7-837f-4f69-a3bb-86e631204a23": "Playlists",
    "0762d272-c50a-4bb0-a382-697dcd729b80": "Users Files",
    "ae50c081-ebd2-438a-8655-8a092e34987a": "Recent",
    "625b53c3-ab48-4ec1-ba1f-a1ef4146fc19": "Start Menu",
    "b97d20bb-f46a-4c97-ba10-5e3608430854": "Startup",
    "a63293e8-664e-48db-a079-df759e0509f7": "Templates",
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


def _dostime_to_datetime(dos_date: int, dos_time: int) -> datetime | None:
    """Convert DOS date/time to datetime."""
    if dos_date == 0:
        return None
    try:
        day = dos_date & 0x1F
        month = (dos_date >> 5) & 0x0F
        year = ((dos_date >> 9) & 0x7F) + 1980

        second = (dos_time & 0x1F) * 2
        minute = (dos_time >> 5) & 0x3F
        hour = (dos_time >> 11) & 0x1F

        if month < 1 or month > 12 or day < 1 or day > 31:
            return None
        if hour > 23 or minute > 59 or second > 59:
            return None

        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except (ValueError, OverflowError):
        return None


@dataclass
class ShellItem:
    """A single shell item from ShellBags."""

    item_type: int
    size: int
    name: str
    path: str
    modified: datetime | None = None
    accessed: datetime | None = None
    created: datetime | None = None
    mft_entry: int | None = None
    mft_sequence: int | None = None
    extension_block: dict[str, Any] = field(default_factory=dict)


@dataclass
class ShellBagEntry:
    """A ShellBag entry with full path reconstruction."""

    slot: int
    path: str
    items: list[ShellItem]
    last_write: datetime | None = None
    node_slot: int | None = None


class ShellItemParser:
    """Parser for individual shell items."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with shell item data."""
        self.data = data

    def parse(self) -> ShellItem | None:
        """Parse a single shell item."""
        if len(self.data) < 2:
            return None

        size = struct.unpack("<H", self.data[0:2])[0]
        if size < 2 or size > len(self.data):
            return None

        if size == 2:
            # Terminator
            return None

        item_data = self.data[0:size]
        if len(item_data) < 3:
            return None

        item_type = item_data[2]

        # Parse based on type
        if item_type == SHELL_ITEM_ROOT_FOLDER:
            return self._parse_root_folder(item_data)
        elif (item_type & 0x70) == SHELL_ITEM_VOLUME:
            return self._parse_volume(item_data)
        elif (item_type & 0x70) == SHELL_ITEM_FILE_ENTRY:
            return self._parse_file_entry(item_data)
        elif (item_type & 0x70) == SHELL_ITEM_NETWORK:
            return self._parse_network(item_data)
        else:
            return self._parse_generic(item_data)

    def _parse_root_folder(self, data: bytes) -> ShellItem | None:
        """Parse root folder shell item."""
        if len(data) < 20:
            return None

        # GUID starts at offset 3
        if len(data) >= 19:
            guid_bytes = data[3:19]
            guid_str = self._format_guid(guid_bytes)
            name = KNOWN_FOLDER_GUIDS.get(guid_str, f"GUID:{guid_str}")
        else:
            name = "Root Folder"

        return ShellItem(
            item_type=SHELL_ITEM_ROOT_FOLDER,
            size=len(data),
            name=name,
            path=name,
        )

    def _parse_volume(self, data: bytes) -> ShellItem | None:
        """Parse volume shell item."""
        if len(data) < 3:
            return None

        item_type = data[2]
        name = ""

        # Check for drive letter
        if item_type & 0x01:  # Has drive letter
            if len(data) >= 4:
                try:
                    # Drive letter at offset 3
                    name_data = data[3:]
                    null_pos = name_data.find(b"\x00")
                    if null_pos > 0:
                        name = name_data[:null_pos].decode("ascii", errors="replace")
                except Exception:
                    pass

        if not name:
            name = "Volume"

        return ShellItem(
            item_type=SHELL_ITEM_VOLUME,
            size=len(data),
            name=name,
            path=name,
        )

    def _parse_file_entry(self, data: bytes) -> ShellItem | None:
        """Parse file entry shell item."""
        if len(data) < 14:
            return None

        item_type = data[2]
        is_directory = bool(item_type & 0x01)
        is_unicode = bool(item_type & 0x04)

        # File size at offset 4 (4 bytes, but usually ignored in ShellBags)

        # DOS modified time at offset 8
        modified = None
        if len(data) >= 12:
            dos_date = struct.unpack("<H", data[8:10])[0]
            dos_time = struct.unpack("<H", data[10:12])[0]
            modified = _dostime_to_datetime(dos_date, dos_time)

        # File attributes at offset 12

        # Primary name starts at offset 14
        name = ""
        name_offset = 14
        if len(data) > name_offset:
            name_data = data[name_offset:]
            null_pos = name_data.find(b"\x00")
            if null_pos > 0:
                try:
                    name = name_data[:null_pos].decode("ascii", errors="replace")
                except Exception:
                    name = name_data[:null_pos].decode("utf-8", errors="replace")

        # Look for extension block
        ext_block = {}
        created = None
        accessed = None
        mft_entry = None
        mft_sequence = None
        long_name = None

        # Find extension block (signature 0x0004 at end)
        ext_offset = name_offset + len(name.encode("ascii", errors="replace")) + 1
        # Align to 2 bytes
        if ext_offset % 2:
            ext_offset += 1

        while ext_offset + 4 <= len(data):
            ext_size = struct.unpack("<H", data[ext_offset:ext_offset + 2])[0]
            if ext_size == 0 or ext_offset + ext_size > len(data):
                break

            ext_version = struct.unpack("<H", data[ext_offset + 2:ext_offset + 4])[0]

            if ext_version >= 0x03 and ext_size >= 0x16:
                # Extension block with timestamps
                ext_data = data[ext_offset:ext_offset + ext_size]

                # Created time at offset 8
                if len(ext_data) >= 16:
                    dos_date = struct.unpack("<H", ext_data[8:10])[0]
                    dos_time = struct.unpack("<H", ext_data[10:12])[0]
                    created = _dostime_to_datetime(dos_date, dos_time)

                # Accessed time at offset 12
                if len(ext_data) >= 16:
                    dos_date = struct.unpack("<H", ext_data[12:14])[0]
                    dos_time = struct.unpack("<H", ext_data[14:16])[0]
                    accessed = _dostime_to_datetime(dos_date, dos_time)

                # MFT reference if version >= 7
                if ext_version >= 0x07 and len(ext_data) >= 32:
                    mft_ref = struct.unpack("<Q", ext_data[24:32])[0]
                    mft_entry = mft_ref & 0x0000FFFFFFFFFFFF
                    mft_sequence = (mft_ref >> 48) & 0xFFFF

                # Long filename
                if ext_version >= 0x03:
                    # Unicode name offset
                    name_off = 0x16 if ext_version < 0x07 else 0x2A
                    if len(ext_data) > name_off:
                        try:
                            name_bytes = ext_data[name_off:]
                            # Find null terminator for UTF-16
                            for i in range(0, len(name_bytes) - 1, 2):
                                if name_bytes[i:i + 2] == b"\x00\x00":
                                    long_name = name_bytes[:i].decode(
                                        "utf-16-le", errors="replace"
                                    )
                                    break
                        except Exception:
                            pass

            ext_offset += ext_size

        # Use long name if available
        if long_name:
            name = long_name

        if name:
            ext_block = {
                "is_directory": is_directory,
            }
            if mft_entry is not None:
                ext_block["mft_entry"] = mft_entry
                ext_block["mft_sequence"] = mft_sequence

            return ShellItem(
                item_type=SHELL_ITEM_FILE_ENTRY,
                size=len(data),
                name=name,
                path=name,
                modified=modified,
                accessed=accessed,
                created=created,
                mft_entry=mft_entry,
                mft_sequence=mft_sequence,
                extension_block=ext_block,
            )

        return None

    def _parse_network(self, data: bytes) -> ShellItem | None:
        """Parse network location shell item."""
        if len(data) < 5:
            return None

        # Network path at offset 5
        name = ""
        if len(data) > 5:
            name_data = data[5:]
            null_pos = name_data.find(b"\x00")
            if null_pos > 0:
                try:
                    name = name_data[:null_pos].decode("ascii", errors="replace")
                except Exception:
                    pass

        if not name:
            name = "Network Location"

        return ShellItem(
            item_type=SHELL_ITEM_NETWORK,
            size=len(data),
            name=name,
            path=name,
        )

    def _parse_generic(self, data: bytes) -> ShellItem | None:
        """Parse generic shell item."""
        return ShellItem(
            item_type=data[2] if len(data) > 2 else 0,
            size=len(data),
            name=f"Unknown (0x{data[2]:02X})" if len(data) > 2 else "Unknown",
            path="",
        )

    @staticmethod
    def _format_guid(data: bytes) -> str:
        """Format GUID bytes to string."""
        if len(data) < 16:
            return ""
        # GUID format: Data1 (LE), Data2 (LE), Data3 (LE), Data4 (raw)
        d1 = struct.unpack("<I", data[0:4])[0]
        d2 = struct.unpack("<H", data[4:6])[0]
        d3 = struct.unpack("<H", data[6:8])[0]
        d4 = data[8:16]
        return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0:2].hex()}-{d4[2:8].hex()}"


class ShellBagsParser:
    """Parser for ShellBags from registry hive."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with registry hive data."""
        self.hive = RegistryHive(data)
        self.root = self.hive.get_root_key()
        self.entries: list[ShellBagEntry] = []

    def parse(self) -> Iterator[ShellBagEntry]:
        """Parse all ShellBag entries."""
        if not self.root:
            return

        # Common paths for ShellBags
        bag_paths = [
            # NTUSER.DAT paths
            "Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
            # USRCLASS.DAT paths
            "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
        ]

        for bag_path in bag_paths:
            bag_key = self._find_key(bag_path)
            if bag_key:
                yield from self._parse_bag_mru(bag_key, "", 0)

    def _find_key(self, path: str):
        """Find a registry key by path."""
        if not self.root:
            return None

        parts = path.split("\\")
        current = self.root

        for part in parts:
            if not part:
                continue
            found = False
            for subkey in self.hive.get_subkeys(current):
                if subkey.name.lower() == part.lower():
                    current = subkey
                    found = True
                    break
            if not found:
                return None
        return current

    def _parse_bag_mru(
        self, key, parent_path: str, depth: int
    ) -> Iterator[ShellBagEntry]:
        """Recursively parse BagMRU entries."""
        if depth > 20:  # Prevent infinite recursion
            return

        items: list[ShellItem] = []
        slot_values = {}
        node_slot = None

        # Get values from this key
        for value in self.hive.get_values(key):
            if value.name.isdigit():
                # Numeric values are shell item data
                slot = int(value.name)
                slot_values[slot] = value.raw_data
            elif value.name.lower() == "nodeslot":
                # NodeSlot points to Bags entry
                data = value.raw_data
                if len(data) >= 4:
                    node_slot = struct.unpack("<I", data[0:4])[0]

        # Parse shell items
        for slot in sorted(slot_values.keys()):
            item_data = slot_values[slot]
            parser = ShellItemParser(item_data)
            item = parser.parse()
            if item:
                items.append(item)

        # Build path from items
        if items:
            parts = [parent_path] if parent_path else []
            for item in items:
                if item.name:
                    parts.append(item.name)
            current_path = "\\".join(parts)

            yield ShellBagEntry(
                slot=depth,
                path=current_path,
                items=items,
                last_write=key.timestamp if hasattr(key, "timestamp") else None,
                node_slot=node_slot,
            )

            # Process subkeys (child folders)
            for subkey in self.hive.get_subkeys(key):
                if subkey.name.isdigit():
                    # Get item for this subkey
                    slot = int(subkey.name)
                    if slot in slot_values:
                        item_data = slot_values[slot]
                        parser = ShellItemParser(item_data)
                        item = parser.parse()
                        if item and item.name:
                            child_path = (
                                f"{current_path}\\{item.name}"
                                if current_path
                                else item.name
                            )
                            yield from self._parse_bag_mru(
                                subkey, child_path, depth + 1
                            )


@ParserRegistry.register
class ShellBagsFileParser(BaseParser):
    """Parser for ShellBags from registry hives."""

    name: ClassVar[str] = "shellbags"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "shellbags",
        "usrclass.dat",
        "ntuser.dat",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize ShellBags parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse registry hive for ShellBags."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse ShellBags from registry hive bytes."""
        parser = ShellBagsParser(data)

        record_index = 0
        for entry in parser.parse():
            # Find best timestamp from items
            best_timestamp = None
            for item in entry.items:
                for ts in [item.modified, item.accessed, item.created]:
                    if ts and (best_timestamp is None or ts > best_timestamp):
                        best_timestamp = ts

            record_data: dict[str, Any] = {
                "path": entry.path,
                "slot": entry.slot,
            }

            if entry.node_slot is not None:
                record_data["node_slot"] = entry.node_slot

            # Add item details
            items_data = []
            for item in entry.items:
                item_info: dict[str, Any] = {
                    "name": item.name,
                    "type": hex(item.item_type),
                }
                if item.modified:
                    item_info["modified"] = item.modified.isoformat()
                if item.accessed:
                    item_info["accessed"] = item.accessed.isoformat()
                if item.created:
                    item_info["created"] = item.created.isoformat()
                if item.mft_entry is not None:
                    item_info["mft_entry"] = item.mft_entry
                    item_info["mft_sequence"] = item.mft_sequence
                items_data.append(item_info)

            if items_data:
                record_data["items"] = items_data

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("shellbags", record_index, entry.path)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=best_timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
