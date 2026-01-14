"""Windows LNK (shortcut) file parser.

Parses Windows shortcut files to extract target paths, timestamps,
and other forensically relevant metadata.
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

# LNK signature
LNK_SIGNATURE = b"\x4C\x00\x00\x00"
LNK_GUID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

# Link flags
LINK_FLAG_HAS_LINK_TARGET_ID_LIST = 0x00000001
LINK_FLAG_HAS_LINK_INFO = 0x00000002
LINK_FLAG_HAS_NAME = 0x00000004
LINK_FLAG_HAS_RELATIVE_PATH = 0x00000008
LINK_FLAG_HAS_WORKING_DIR = 0x00000010
LINK_FLAG_HAS_ARGUMENTS = 0x00000020
LINK_FLAG_HAS_ICON_LOCATION = 0x00000040
LINK_FLAG_IS_UNICODE = 0x00000080

# File attribute flags
FILE_ATTR_READONLY = 0x0001
FILE_ATTR_HIDDEN = 0x0002
FILE_ATTR_SYSTEM = 0x0004
FILE_ATTR_DIRECTORY = 0x0010
FILE_ATTR_ARCHIVE = 0x0020

# Drive types
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6


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


def _read_string(data: bytes, offset: int, is_unicode: bool) -> tuple[str, int]:
    """Read a string from LNK data."""
    if offset + 2 > len(data):
        return "", offset

    length = struct.unpack("<H", data[offset:offset + 2])[0]
    offset += 2

    if is_unicode:
        byte_length = length * 2
        if offset + byte_length > len(data):
            return "", offset
        try:
            result = data[offset:offset + byte_length].decode("utf-16-le")
        except UnicodeDecodeError:
            result = ""
        offset += byte_length
    else:
        if offset + length > len(data):
            return "", offset
        try:
            result = data[offset:offset + length].decode("cp1252", errors="replace")
        except Exception:
            result = ""
        offset += length

    return result, offset


@dataclass
class LnkFile:
    """Parsed LNK file data."""

    # Header timestamps
    created: datetime | None = None
    accessed: datetime | None = None
    modified: datetime | None = None

    # Target info
    file_size: int = 0
    file_attributes: int = 0
    is_directory: bool = False

    # Link info
    target_path: str = ""
    local_base_path: str = ""
    common_path_suffix: str = ""
    network_share_name: str = ""
    device_name: str = ""
    drive_type: int = 0
    drive_serial: int = 0
    volume_label: str = ""

    # String data
    name: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""

    # Machine info
    machine_id: str = ""
    droid_volume_id: str = ""
    droid_file_id: str = ""


class LnkParser:
    """Parser for Windows LNK files."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with LNK file data."""
        self.data = data
        self.result = LnkFile()
        self._parse()

    def _parse(self) -> None:
        """Parse the LNK file."""
        if len(self.data) < 76:
            return

        if self.data[0:4] != LNK_SIGNATURE:
            return

        if self.data[4:20] != LNK_GUID:
            return

        link_flags = struct.unpack("<I", self.data[20:24])[0]
        file_attrs = struct.unpack("<I", self.data[24:28])[0]

        self.result.file_attributes = file_attrs
        self.result.is_directory = bool(file_attrs & FILE_ATTR_DIRECTORY)

        self.result.created = _filetime_to_datetime(
            struct.unpack("<Q", self.data[28:36])[0]
        )
        self.result.accessed = _filetime_to_datetime(
            struct.unpack("<Q", self.data[36:44])[0]
        )
        self.result.modified = _filetime_to_datetime(
            struct.unpack("<Q", self.data[44:52])[0]
        )

        self.result.file_size = struct.unpack("<I", self.data[52:56])[0]

        # Icon index and show command at 56-64
        # Hot key at 64-66
        # Reserved at 66-76

        is_unicode = bool(link_flags & LINK_FLAG_IS_UNICODE)
        offset = 76

        # Parse Link Target ID List
        if link_flags & LINK_FLAG_HAS_LINK_TARGET_ID_LIST:
            if offset + 2 > len(self.data):
                return
            id_list_size = struct.unpack("<H", self.data[offset:offset + 2])[0]
            offset += 2 + id_list_size

        # Parse Link Info
        if link_flags & LINK_FLAG_HAS_LINK_INFO:
            if offset + 4 > len(self.data):
                return
            link_info_size = struct.unpack("<I", self.data[offset:offset + 4])[0]

            if offset + link_info_size <= len(self.data):
                self._parse_link_info(self.data[offset:offset + link_info_size])

            offset += link_info_size

        # Parse String Data
        if link_flags & LINK_FLAG_HAS_NAME:
            self.result.name, offset = _read_string(self.data, offset, is_unicode)

        if link_flags & LINK_FLAG_HAS_RELATIVE_PATH:
            self.result.relative_path, offset = _read_string(
                self.data, offset, is_unicode
            )

        if link_flags & LINK_FLAG_HAS_WORKING_DIR:
            self.result.working_dir, offset = _read_string(
                self.data, offset, is_unicode
            )

        if link_flags & LINK_FLAG_HAS_ARGUMENTS:
            self.result.arguments, offset = _read_string(
                self.data, offset, is_unicode
            )

        if link_flags & LINK_FLAG_HAS_ICON_LOCATION:
            self.result.icon_location, offset = _read_string(
                self.data, offset, is_unicode
            )

        # Parse Extra Data blocks
        self._parse_extra_data(offset)

    def _parse_link_info(self, data: bytes) -> None:
        """Parse the LinkInfo structure."""
        if len(data) < 28:
            return

        link_info_size = struct.unpack("<I", data[0:4])[0]
        link_info_header_size = struct.unpack("<I", data[4:8])[0]
        link_info_flags = struct.unpack("<I", data[8:12])[0]

        volume_id_offset = struct.unpack("<I", data[12:16])[0]
        local_base_path_offset = struct.unpack("<I", data[16:20])[0]
        common_network_relative_link_offset = struct.unpack("<I", data[20:24])[0]
        common_path_suffix_offset = struct.unpack("<I", data[24:28])[0]

        if link_info_flags & 0x01:  # VolumeIDAndLocalBasePath
            if volume_id_offset > 0 and volume_id_offset + 16 <= len(data):
                vol_data = data[volume_id_offset:]
                if len(vol_data) >= 16:
                    self.result.drive_type = struct.unpack("<I", vol_data[4:8])[0]
                    self.result.drive_serial = struct.unpack("<I", vol_data[8:12])[0]
                    vol_label_offset = struct.unpack("<I", vol_data[12:16])[0]

                    if vol_label_offset > 0 and vol_label_offset < len(vol_data):
                        label_data = vol_data[vol_label_offset:]
                        null_pos = label_data.find(b"\x00")
                        if null_pos > 0:
                            try:
                                self.result.volume_label = label_data[
                                    :null_pos
                                ].decode("cp1252", errors="replace")
                            except Exception:
                                pass

            if local_base_path_offset > 0 and local_base_path_offset < len(data):
                path_data = data[local_base_path_offset:]
                null_pos = path_data.find(b"\x00")
                if null_pos > 0:
                    try:
                        self.result.local_base_path = path_data[:null_pos].decode(
                            "cp1252", errors="replace"
                        )
                        self.result.target_path = self.result.local_base_path
                    except Exception:
                        pass

        if link_info_flags & 0x02:  # CommonNetworkRelativeLink
            if common_network_relative_link_offset > 0:
                net_offset = common_network_relative_link_offset
                if net_offset + 20 <= len(data):
                    net_data = data[net_offset:]
                    net_size = struct.unpack("<I", net_data[0:4])[0]
                    net_name_offset = struct.unpack("<I", net_data[8:12])[0]
                    device_name_offset = struct.unpack("<I", net_data[12:16])[0]

                    if net_name_offset > 0 and net_name_offset < len(net_data):
                        name_data = net_data[net_name_offset:]
                        null_pos = name_data.find(b"\x00")
                        if null_pos > 0:
                            try:
                                self.result.network_share_name = name_data[
                                    :null_pos
                                ].decode("cp1252", errors="replace")
                            except Exception:
                                pass

                    if device_name_offset > 0 and device_name_offset < len(net_data):
                        dev_data = net_data[device_name_offset:]
                        null_pos = dev_data.find(b"\x00")
                        if null_pos > 0:
                            try:
                                self.result.device_name = dev_data[:null_pos].decode(
                                    "cp1252", errors="replace"
                                )
                            except Exception:
                                pass

        if common_path_suffix_offset > 0 and common_path_suffix_offset < len(data):
            suffix_data = data[common_path_suffix_offset:]
            null_pos = suffix_data.find(b"\x00")
            if null_pos > 0:
                try:
                    self.result.common_path_suffix = suffix_data[:null_pos].decode(
                        "cp1252", errors="replace"
                    )
                except Exception:
                    pass

        if self.result.network_share_name and self.result.common_path_suffix:
            self.result.target_path = (
                self.result.network_share_name + self.result.common_path_suffix
            )

    def _parse_extra_data(self, offset: int) -> None:
        """Parse Extra Data blocks."""
        while offset + 8 <= len(self.data):
            block_size = struct.unpack("<I", self.data[offset:offset + 4])[0]

            if block_size < 4:
                break

            block_sig = struct.unpack("<I", self.data[offset + 4:offset + 8])[0]

            # Tracker Data Block (0xA0000003)
            if block_sig == 0xA0000003 and block_size >= 96:
                block_data = self.data[offset:offset + block_size]

                # Machine ID at offset 16, 16 bytes
                if len(block_data) >= 32:
                    machine_id_data = block_data[16:32]
                    null_pos = machine_id_data.find(b"\x00")
                    if null_pos > 0:
                        machine_id_data = machine_id_data[:null_pos]
                    try:
                        self.result.machine_id = machine_id_data.decode(
                            "ascii", errors="replace"
                        ).rstrip("\x00")
                    except Exception:
                        pass

                # Droid Volume ID at offset 32, 16 bytes (GUID)
                if len(block_data) >= 48:
                    droid_vol = block_data[32:48]
                    self.result.droid_volume_id = droid_vol.hex()

                # Droid File ID at offset 48, 16 bytes (GUID)
                if len(block_data) >= 64:
                    droid_file = block_data[48:64]
                    self.result.droid_file_id = droid_file.hex()

            offset += block_size


@ParserRegistry.register
class LnkFileParser(BaseParser):
    """Parser for Windows LNK files."""

    name: ClassVar[str] = "lnk"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["lnk", "shortcut"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize LNK parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse LNK file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse LNK from bytes."""
        parser = LnkParser(data)
        lnk = parser.result

        record_data: dict[str, Any] = {}

        if lnk.target_path:
            record_data["target_path"] = lnk.target_path
        if lnk.local_base_path:
            record_data["local_path"] = lnk.local_base_path
        if lnk.network_share_name:
            record_data["network_share"] = lnk.network_share_name
        if lnk.relative_path:
            record_data["relative_path"] = lnk.relative_path
        if lnk.working_dir:
            record_data["working_directory"] = lnk.working_dir
        if lnk.arguments:
            record_data["arguments"] = lnk.arguments
        if lnk.name:
            record_data["description"] = lnk.name

        if lnk.created:
            record_data["target_created"] = lnk.created.isoformat()
        if lnk.modified:
            record_data["target_modified"] = lnk.modified.isoformat()
        if lnk.accessed:
            record_data["target_accessed"] = lnk.accessed.isoformat()

        record_data["target_size"] = lnk.file_size
        record_data["is_directory"] = lnk.is_directory

        if lnk.volume_label:
            record_data["volume_label"] = lnk.volume_label
        if lnk.drive_serial:
            record_data["drive_serial"] = f"{lnk.drive_serial:08X}"

        drive_types = {
            0: "Unknown",
            1: "No Root Dir",
            2: "Removable",
            3: "Fixed",
            4: "Remote",
            5: "CD-ROM",
            6: "RAM Disk",
        }
        if lnk.drive_type:
            record_data["drive_type"] = drive_types.get(lnk.drive_type, "Unknown")

        # Machine info (from tracker data)
        if lnk.machine_id:
            record_data["machine_id"] = lnk.machine_id
        if lnk.droid_volume_id:
            record_data["droid_volume_id"] = lnk.droid_volume_id
        if lnk.droid_file_id:
            record_data["droid_file_id"] = lnk.droid_file_id

        evidence_ref = self.create_evidence_ref(
            record_offset=0,
            record_index=0,
        )

        target = lnk.target_path or lnk.local_base_path or "unknown"
        record_id = self.create_record_id("lnk", target)

        yield ParsedRecord(
            record_id=record_id,
            schema_version="v1",
            record_type="timeline",
            timestamp=lnk.modified or lnk.created,
            data=record_data,
            evidence_ref=evidence_ref,
        )
