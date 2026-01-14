"""Registry hive parser for Scrut DFIR CLI.

Custom implementation that parses Windows Registry hive files without external dependencies.
Based on libregf documentation and MS-RRP specifications.

Hive files supported:
- SYSTEM, SOFTWARE, SAM, SECURITY (system hives)
- NTUSER.DAT, UsrClass.dat (user hives)
"""

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# Registry file signatures
REGF_SIGNATURE = b"regf"
HBIN_SIGNATURE = b"hbin"

# Cell signatures
NK_SIGNATURE = b"nk"  # Named key (key node)
VK_SIGNATURE = b"vk"  # Value key
LF_SIGNATURE = b"lf"  # Fast lookup subkey list
LH_SIGNATURE = b"lh"  # Hash-based subkey list
LI_SIGNATURE = b"li"  # Index subkey list
RI_SIGNATURE = b"ri"  # Root index subkey list
SK_SIGNATURE = b"sk"  # Security key
DB_SIGNATURE = b"db"  # Big data

# NK flags
NK_FLAG_VOLATILE = 0x0001
NK_FLAG_HIVE_ENTRY = 0x0004
NK_FLAG_HIVE_EXIT = 0x0008
NK_FLAG_ASCII_NAME = 0x0020
NK_FLAG_SYMLINK = 0x0040
NK_FLAG_PREDEFINED = 0x0080

# VK flags
VK_FLAG_ASCII_NAME = 0x0001

# Registry data types
REG_NONE = 0x00000000
REG_SZ = 0x00000001
REG_EXPAND_SZ = 0x00000002
REG_BINARY = 0x00000003
REG_DWORD = 0x00000004
REG_DWORD_BIG_ENDIAN = 0x00000005
REG_LINK = 0x00000006
REG_MULTI_SZ = 0x00000007
REG_RESOURCE_LIST = 0x00000008
REG_FULL_RESOURCE_DESCRIPTOR = 0x00000009
REG_RESOURCE_REQUIREMENTS_LIST = 0x0000000A
REG_QWORD = 0x0000000B

REG_TYPE_NAMES = {
    REG_NONE: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_LINK: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    REG_QWORD: "REG_QWORD",
}


class RegistryCell:
    """Base class for registry cells."""

    def __init__(self, offset: int, size: int, data: bytes):
        self.offset = offset
        self.size = size
        self.data = data
        self.allocated = size < 0


class RegistryKey:
    """Represents a registry key (NK cell)."""

    def __init__(
        self,
        offset: int,
        name: str,
        class_name: str | None,
        last_written: datetime | None,
        flags: int,
        parent_offset: int,
        num_subkeys: int,
        num_values: int,
        subkeys_offset: int,
        values_offset: int,
        security_offset: int,
    ):
        self.offset = offset
        self.name = name
        self.class_name = class_name
        self.last_written = last_written
        self.flags = flags
        self.parent_offset = parent_offset
        self.num_subkeys = num_subkeys
        self.num_values = num_values
        self.subkeys_offset = subkeys_offset
        self.values_offset = values_offset
        self.security_offset = security_offset

    @property
    def is_root(self) -> bool:
        return bool(self.flags & NK_FLAG_HIVE_ENTRY)

    @property
    def is_volatile(self) -> bool:
        return bool(self.flags & NK_FLAG_VOLATILE)


class RegistryValue:
    """Represents a registry value (VK cell)."""

    def __init__(
        self,
        offset: int,
        name: str,
        data_type: int,
        data: bytes | None,
        data_offset: int,
        data_size: int,
    ):
        self.offset = offset
        self.name = name
        self.data_type = data_type
        self.raw_data = data
        self.data_offset = data_offset
        self.data_size = data_size

    @property
    def type_name(self) -> str:
        return REG_TYPE_NAMES.get(self.data_type, f"UNKNOWN({self.data_type})")

    def get_data(self) -> Any:
        """Get parsed data value based on type."""
        if self.raw_data is None:
            return None

        try:
            if self.data_type == REG_SZ or self.data_type == REG_EXPAND_SZ:
                # UTF-16LE string, null terminated
                return self.raw_data.decode("utf-16-le").rstrip("\x00")
            elif self.data_type == REG_DWORD:
                if len(self.raw_data) >= 4:
                    return struct.unpack("<I", self.raw_data[:4])[0]
                return None
            elif self.data_type == REG_DWORD_BIG_ENDIAN:
                if len(self.raw_data) >= 4:
                    return struct.unpack(">I", self.raw_data[:4])[0]
                return None
            elif self.data_type == REG_QWORD:
                if len(self.raw_data) >= 8:
                    return struct.unpack("<Q", self.raw_data[:8])[0]
                return None
            elif self.data_type == REG_MULTI_SZ:
                # Multiple null-terminated UTF-16LE strings
                strings = []
                text = self.raw_data.decode("utf-16-le")
                for s in text.split("\x00"):
                    if s:
                        strings.append(s)
                return strings
            elif self.data_type == REG_BINARY:
                return self.raw_data.hex()
            else:
                # Unknown type - return as hex
                return self.raw_data.hex()
        except Exception:
            return self.raw_data.hex() if self.raw_data else None


class RegistryHive:
    """Parser for Windows Registry hive files."""

    # Header offsets
    HEADER_SIGNATURE = 0
    HEADER_PRIMARY_SEQUENCE = 4
    HEADER_SECONDARY_SEQUENCE = 8
    HEADER_LAST_WRITTEN = 12
    HEADER_MAJOR_VERSION = 20
    HEADER_MINOR_VERSION = 24
    HEADER_TYPE = 28
    HEADER_FORMAT = 32
    HEADER_ROOT_KEY_OFFSET = 36
    HEADER_HIVE_BINS_SIZE = 40
    HEADER_CLUSTERING_FACTOR = 44
    HEADER_FILENAME = 48  # UTF-16LE, 64 chars max

    def __init__(self, data: bytes):
        """Initialize registry hive from raw data."""
        self.data = data
        self.major_version: int = 0
        self.minor_version: int = 0
        self.root_key_offset: int = 0
        self.hive_bins_size: int = 0
        self.filename: str = ""
        self.last_written: datetime | None = None

        self._keys: dict[int, RegistryKey] = {}
        self._values: dict[int, RegistryValue] = {}
        self._hive_data_offset = 4096  # Header is 4096 bytes

        self._parse_header()

    def _parse_header(self) -> None:
        """Parse the regf header."""
        if len(self.data) < 4096:
            raise ValueError("Registry hive file too small")

        if self.data[0:4] != REGF_SIGNATURE:
            raise ValueError(f"Invalid registry signature: {self.data[0:4]!r}")

        self.major_version = struct.unpack("<I", self.data[20:24])[0]
        self.minor_version = struct.unpack("<I", self.data[24:28])[0]
        self.root_key_offset = struct.unpack("<I", self.data[36:40])[0]
        self.hive_bins_size = struct.unpack("<I", self.data[40:44])[0]

        # Last written timestamp
        filetime = struct.unpack("<Q", self.data[12:20])[0]
        if filetime > 0:
            self.last_written = self._filetime_to_datetime(filetime)

        # Hive filename
        try:
            self.filename = self.data[48:176].decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            self.filename = ""

    def _absolute_offset(self, relative_offset: int) -> int:
        """Convert relative offset to absolute offset."""
        return self._hive_data_offset + relative_offset

    def _read_cell_size(self, offset: int) -> int:
        """Read cell size at given absolute offset."""
        if offset + 4 > len(self.data):
            return 0
        size = struct.unpack("<i", self.data[offset : offset + 4])[0]
        return size

    def _read_cell_data(self, offset: int) -> tuple[int, bytes]:
        """Read cell data at given absolute offset."""
        size = self._read_cell_size(offset)
        abs_size = abs(size)
        if offset + abs_size > len(self.data):
            return size, b""
        return size, self.data[offset + 4 : offset + abs_size]

    def _read_big_data(self, db_cell_data: bytes, data_size: int) -> bytes:
        """Read Big Data (db) cell and reconstruct the full value.

        Big Data cells are used for values larger than ~16KB.
        Structure:
            - Signature: "db" (2 bytes)
            - Segment count: 2 bytes
            - Segment list offset: 4 bytes (relative offset)

        The segment list contains offsets to data segments.
        Each segment is a cell containing up to ~16KB of data.
        """
        if len(db_cell_data) < 8:
            return b""

        # Parse db cell header
        segment_count = struct.unpack("<H", db_cell_data[2:4])[0]
        segment_list_offset = struct.unpack("<I", db_cell_data[4:8])[0]

        if segment_count == 0:
            return b""

        # Read segment list (array of relative offsets)
        segment_list_abs_offset = self._absolute_offset(segment_list_offset)
        _, segment_list_data = self._read_cell_data(segment_list_abs_offset)

        if len(segment_list_data) < segment_count * 4:
            return b""

        # Read each segment and concatenate
        result = bytearray()
        for i in range(segment_count):
            segment_offset = struct.unpack(
                "<I", segment_list_data[i * 4 : i * 4 + 4]
            )[0]
            segment_abs_offset = self._absolute_offset(segment_offset)
            _, segment_data = self._read_cell_data(segment_abs_offset)
            if segment_data:
                result.extend(segment_data)

        # Return only the requested size
        return bytes(result[:data_size])

    def get_root_key(self) -> RegistryKey | None:
        """Get the root key of the hive."""
        if self.root_key_offset == 0xFFFFFFFF:
            return None
        return self._read_key(self._absolute_offset(self.root_key_offset))

    def _read_key(self, offset: int) -> RegistryKey | None:
        """Read a key node (NK cell) at absolute offset."""
        if offset in self._keys:
            return self._keys[offset]

        size, data = self._read_cell_data(offset)
        if len(data) < 76:
            return None

        signature = data[0:2]
        if signature != NK_SIGNATURE:
            return None

        flags = struct.unpack("<H", data[2:4])[0]
        filetime = struct.unpack("<Q", data[4:12])[0]
        parent_offset = struct.unpack("<I", data[16:20])[0]
        num_subkeys = struct.unpack("<I", data[20:24])[0]
        num_volatile_subkeys = struct.unpack("<I", data[24:28])[0]
        subkeys_offset = struct.unpack("<I", data[28:32])[0]
        volatile_subkeys_offset = struct.unpack("<I", data[32:36])[0]
        num_values = struct.unpack("<I", data[36:40])[0]
        values_offset = struct.unpack("<I", data[40:44])[0]
        security_offset = struct.unpack("<I", data[44:48])[0]
        class_name_offset = struct.unpack("<I", data[48:52])[0]

        key_name_size = struct.unpack("<H", data[72:74])[0]
        class_name_size = struct.unpack("<H", data[74:76])[0]

        # Read key name
        name_bytes = data[76 : 76 + key_name_size]
        if flags & NK_FLAG_ASCII_NAME:
            name = name_bytes.decode("ascii", errors="replace")
        else:
            name = name_bytes.decode("utf-16-le", errors="replace")

        # Read class name if present
        class_name = None
        if class_name_offset != 0xFFFFFFFF and class_name_size > 0:
            class_abs_offset = self._absolute_offset(class_name_offset)
            _, class_data = self._read_cell_data(class_abs_offset)
            if class_data:
                class_name = class_data[:class_name_size].decode(
                    "utf-16-le", errors="replace"
                )

        last_written = self._filetime_to_datetime(filetime) if filetime > 0 else None

        key = RegistryKey(
            offset=offset,
            name=name,
            class_name=class_name,
            last_written=last_written,
            flags=flags,
            parent_offset=parent_offset,
            num_subkeys=num_subkeys,
            num_values=num_values,
            subkeys_offset=subkeys_offset,
            values_offset=values_offset,
            security_offset=security_offset,
        )
        self._keys[offset] = key
        return key

    def _read_value(self, offset: int) -> RegistryValue | None:
        """Read a value (VK cell) at absolute offset."""
        if offset in self._values:
            return self._values[offset]

        size, data = self._read_cell_data(offset)
        if len(data) < 20:
            return None

        signature = data[0:2]
        if signature != VK_SIGNATURE:
            return None

        name_size = struct.unpack("<H", data[2:4])[0]
        data_size = struct.unpack("<I", data[4:8])[0]
        data_offset = struct.unpack("<I", data[8:12])[0]
        data_type = struct.unpack("<I", data[12:16])[0]
        flags = struct.unpack("<H", data[16:18])[0]

        # Read value name
        if name_size == 0:
            name = "(Default)"
        else:
            name_bytes = data[20 : 20 + name_size]
            if flags & VK_FLAG_ASCII_NAME:
                name = name_bytes.decode("ascii", errors="replace")
            else:
                name = name_bytes.decode("utf-16-le", errors="replace")

        # Read value data
        value_data = None
        actual_data_size = data_size & 0x7FFFFFFF

        if data_size == 0:
            # No data
            value_data = None
        elif data_size & 0x80000000:
            # Data is inline (in the offset field)
            value_data = struct.pack("<I", data_offset)[:actual_data_size]
        else:
            # Data is external
            data_abs_offset = self._absolute_offset(data_offset)
            _, ext_data = self._read_cell_data(data_abs_offset)
            if ext_data:
                # Check for Big Data (db) cell - used for values > 16KB
                if len(ext_data) >= 8 and ext_data[0:2] == DB_SIGNATURE:
                    value_data = self._read_big_data(ext_data, actual_data_size)
                else:
                    value_data = ext_data[:actual_data_size]

        value = RegistryValue(
            offset=offset,
            name=name,
            data_type=data_type,
            data=value_data,
            data_offset=data_offset,
            data_size=actual_data_size,
        )
        self._values[offset] = value
        return value

    def get_subkeys(self, key: RegistryKey) -> Iterator[RegistryKey]:
        """Get subkeys of a key."""
        if key.num_subkeys == 0 or key.subkeys_offset == 0xFFFFFFFF:
            return

        subkeys_abs_offset = self._absolute_offset(key.subkeys_offset)
        yield from self._read_subkey_list(subkeys_abs_offset)

    def _read_subkey_list(self, offset: int) -> Iterator[RegistryKey]:
        """Read a subkey list at absolute offset."""
        size, data = self._read_cell_data(offset)
        if len(data) < 4:
            return

        signature = data[0:2]
        count = struct.unpack("<H", data[2:4])[0]

        if signature in (LF_SIGNATURE, LH_SIGNATURE):
            # Fast lookup or hash list: 8 bytes per entry
            for i in range(count):
                entry_offset = 4 + i * 8
                if entry_offset + 4 > len(data):
                    break
                key_offset = struct.unpack("<I", data[entry_offset : entry_offset + 4])[
                    0
                ]
                key = self._read_key(self._absolute_offset(key_offset))
                if key:
                    yield key

        elif signature == LI_SIGNATURE:
            # Index list: 4 bytes per entry
            for i in range(count):
                entry_offset = 4 + i * 4
                if entry_offset + 4 > len(data):
                    break
                key_offset = struct.unpack("<I", data[entry_offset : entry_offset + 4])[
                    0
                ]
                key = self._read_key(self._absolute_offset(key_offset))
                if key:
                    yield key

        elif signature == RI_SIGNATURE:
            # Root index: references to other subkey lists
            for i in range(count):
                entry_offset = 4 + i * 4
                if entry_offset + 4 > len(data):
                    break
                list_offset = struct.unpack("<I", data[entry_offset : entry_offset + 4])[
                    0
                ]
                yield from self._read_subkey_list(self._absolute_offset(list_offset))

    def get_values(self, key: RegistryKey) -> Iterator[RegistryValue]:
        """Get values of a key."""
        if key.num_values == 0 or key.values_offset == 0xFFFFFFFF:
            return

        values_abs_offset = self._absolute_offset(key.values_offset)
        _, data = self._read_cell_data(values_abs_offset)

        for i in range(key.num_values):
            entry_offset = i * 4
            if entry_offset + 4 > len(data):
                break
            value_offset = struct.unpack("<I", data[entry_offset : entry_offset + 4])[0]
            value = self._read_value(self._absolute_offset(value_offset))
            if value:
                yield value

    def walk(
        self, key: RegistryKey | None = None, path: str = ""
    ) -> Iterator[tuple[str, RegistryKey, list[RegistryValue]]]:
        """Walk the registry tree depth-first.

        Yields:
            Tuples of (path, key, values) for each key in the tree.
        """
        if key is None:
            key = self.get_root_key()
            if key is None:
                return
            path = key.name

        values = list(self.get_values(key))
        yield path, key, values

        for subkey in self.get_subkeys(key):
            subpath = f"{path}\\{subkey.name}" if path else subkey.name
            yield from self.walk(subkey, subpath)

    @staticmethod
    def _filetime_to_datetime(filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        unix_ts = (filetime - 116444736000000000) / 10000000
        try:
            return datetime.fromtimestamp(unix_ts, tz=UTC)
        except (OSError, ValueError):
            return datetime.min.replace(tzinfo=UTC)


@ParserRegistry.register
class RegistryParser(BaseParser):
    """Parser for Windows Registry hive files."""

    name: ClassVar[str] = "registry"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "registry",
        "SYSTEM",
        "SOFTWARE",
        "SAM",
        "SECURITY",
        "NTUSER.DAT",
        "UsrClass.dat",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Registry parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Registry hive file and yield records.

        Args:
            file_path: Path to Registry hive file

        Yields:
            ParsedRecord for each registry key with values
        """
        with open(file_path, "rb") as fh:
            data = fh.read()

        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse Registry hive from raw bytes.

        Args:
            data: Raw Registry hive file content

        Yields:
            ParsedRecord with registry key and value information

        Raises:
            ValueError: If the registry hive cannot be parsed
        """
        hive = RegistryHive(data)

        record_index = 0
        for path, key, values in hive.walk():
            # Build record data
            record_data: dict[str, Any] = {
                "key_path": path,
                "key_name": key.name,
            }

            if key.last_written:
                record_data["last_written"] = key.last_written.isoformat()

            if key.class_name:
                record_data["class_name"] = key.class_name

            # Add values
            if values:
                values_list = []
                for value in values:
                    value_entry = {
                        "name": value.name,
                        "type": value.type_name,
                    }

                    parsed_data = value.get_data()
                    if parsed_data is not None:
                        # Truncate very long values
                        if isinstance(parsed_data, str) and len(parsed_data) > 1000:
                            value_entry["data"] = parsed_data[:1000] + "..."
                            value_entry["truncated"] = True
                        elif isinstance(parsed_data, list) and len(parsed_data) > 100:
                            value_entry["data"] = parsed_data[:100]
                            value_entry["truncated"] = True
                        else:
                            value_entry["data"] = parsed_data

                    values_list.append(value_entry)

                record_data["values"] = values_list
                record_data["value_count"] = len(values_list)

            # Create record ID
            record_id = self.create_record_id(
                "registry",
                path,
                key.offset,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=self.normalize_timestamp(key.last_written),
                timestamp_original=(
                    key.last_written.isoformat() if key.last_written else None
                ),
                data=record_data,
                evidence_ref=self.create_evidence_ref(
                    record_offset=key.offset,
                    record_index=record_index,
                ),
            )
            record_index += 1


def parse_registry(
    file_path: Path,
    target_id: UUID,
    artifact_path: str,
    source_hash: str,
    timezone_str: str = "UTC",
) -> Iterator[ParsedRecord]:
    """Convenience function to parse a Registry hive file.

    Args:
        file_path: Path to Registry hive file
        target_id: Target UUID
        artifact_path: Artifact path for evidence_ref
        source_hash: SHA-256 of artifact
        timezone_str: Output timezone

    Yields:
        ParsedRecord for each registry key
    """
    parser = RegistryParser(
        target_id=target_id,
        artifact_path=artifact_path,
        source_hash=source_hash,
        timezone_str=timezone_str,
    )
    yield from parser.parse(file_path)
