"""FAT filesystem reader.

Provides direct file access to FAT12/FAT16/FAT32 partitions within forensic images
without requiring OS-level mounting.
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import BinaryIO

from scrut.images.filesystem.base import FileInfo, FileStream, FilesystemReader

# FAT attribute flags
FAT_ATTR_READ_ONLY = 0x01
FAT_ATTR_HIDDEN = 0x02
FAT_ATTR_SYSTEM = 0x04
FAT_ATTR_VOLUME_ID = 0x08
FAT_ATTR_DIRECTORY = 0x10
FAT_ATTR_ARCHIVE = 0x20
FAT_ATTR_LONG_NAME = 0x0F

# Special cluster values
FAT12_EOC = 0x0FF8
FAT16_EOC = 0xFFF8
FAT32_EOC = 0x0FFFFFF8


@dataclass
class FATBootSector:
    """FAT boot sector (BPB) information."""

    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    root_entry_count: int  # 0 for FAT32
    total_sectors: int
    sectors_per_fat: int
    root_cluster: int  # FAT32 only
    fat_type: str  # "FAT12", "FAT16", "FAT32"


@dataclass
class FATDirectoryEntry:
    """FAT directory entry."""

    name: str
    extension: str
    attributes: int
    created_time: datetime | None
    modified_time: datetime | None
    accessed_date: datetime | None
    first_cluster: int
    size: int
    is_directory: bool
    is_long_name: bool


class FATReader(FilesystemReader):
    """Reader for FAT12/FAT16/FAT32 filesystems.

    Provides file access by parsing FAT and directory entries.
    """

    def __init__(self, image_reader, partition_offset: int, partition_size: int) -> None:
        """Initialize FAT reader.

        Args:
            image_reader: Parent image reader for sector access
            partition_offset: Byte offset where partition starts
            partition_size: Size of partition in bytes
        """
        super().__init__(image_reader, partition_offset, partition_size)

        self._boot_sector: FATBootSector | None = None
        self._fat_start: int = 0
        self._data_start: int = 0
        self._root_dir_start: int = 0  # FAT12/16 only

        self._parse_boot_sector()

    def _parse_boot_sector(self) -> None:
        """Parse FAT boot sector (BPB)."""
        boot_data = self._read_bytes(0, 512)

        # Basic BPB fields
        bytes_per_sector = struct.unpack("<H", boot_data[11:13])[0]
        sectors_per_cluster = boot_data[13]
        reserved_sectors = struct.unpack("<H", boot_data[14:16])[0]
        fat_count = boot_data[16]
        root_entry_count = struct.unpack("<H", boot_data[17:19])[0]
        total_sectors_16 = struct.unpack("<H", boot_data[19:21])[0]
        sectors_per_fat_16 = struct.unpack("<H", boot_data[22:24])[0]
        total_sectors_32 = struct.unpack("<I", boot_data[32:36])[0]

        total_sectors = total_sectors_32 if total_sectors_16 == 0 else total_sectors_16

        # FAT32 specific fields
        if sectors_per_fat_16 == 0:
            # FAT32
            sectors_per_fat = struct.unpack("<I", boot_data[36:40])[0]
            root_cluster = struct.unpack("<I", boot_data[44:48])[0]
            fat_type = "FAT32"
        else:
            sectors_per_fat = sectors_per_fat_16
            root_cluster = 0
            # Determine FAT12 vs FAT16
            root_dir_sectors = ((root_entry_count * 32) + (bytes_per_sector - 1)) // bytes_per_sector
            data_sectors = total_sectors - (reserved_sectors + fat_count * sectors_per_fat + root_dir_sectors)
            cluster_count = data_sectors // sectors_per_cluster

            if cluster_count < 4085:
                fat_type = "FAT12"
            else:
                fat_type = "FAT16"

        self._boot_sector = FATBootSector(
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            reserved_sectors=reserved_sectors,
            fat_count=fat_count,
            root_entry_count=root_entry_count,
            total_sectors=total_sectors,
            sectors_per_fat=sectors_per_fat,
            root_cluster=root_cluster,
            fat_type=fat_type,
        )

        # Calculate offsets
        self._fat_start = reserved_sectors * bytes_per_sector

        if fat_type == "FAT32":
            self._data_start = self._fat_start + fat_count * sectors_per_fat * bytes_per_sector
        else:
            # FAT12/16: root directory comes before data area
            self._root_dir_start = self._fat_start + fat_count * sectors_per_fat * bytes_per_sector
            root_dir_size = root_entry_count * 32
            self._data_start = self._root_dir_start + root_dir_size

    @property
    def cluster_size(self) -> int:
        """Size of a cluster in bytes."""
        return self._boot_sector.bytes_per_sector * self._boot_sector.sectors_per_cluster

    def _cluster_to_offset(self, cluster: int) -> int:
        """Convert cluster number to byte offset within partition.

        Note: Clusters are numbered starting at 2.
        """
        return self._data_start + (cluster - 2) * self.cluster_size

    @lru_cache(maxsize=1024)
    def _get_fat_entry(self, cluster: int) -> int:
        """Get the next cluster in chain from FAT."""
        fat_type = self._boot_sector.fat_type

        if fat_type == "FAT32":
            offset = self._fat_start + cluster * 4
            data = self._read_bytes(offset, 4)
            return struct.unpack("<I", data)[0] & 0x0FFFFFFF
        elif fat_type == "FAT16":
            offset = self._fat_start + cluster * 2
            data = self._read_bytes(offset, 2)
            return struct.unpack("<H", data)[0]
        else:  # FAT12
            offset = self._fat_start + (cluster * 3) // 2
            data = self._read_bytes(offset, 2)
            value = struct.unpack("<H", data)[0]
            if cluster & 1:
                return value >> 4
            else:
                return value & 0x0FFF

    def _is_end_of_chain(self, cluster: int) -> bool:
        """Check if cluster marks end of chain."""
        fat_type = self._boot_sector.fat_type

        if fat_type == "FAT32":
            return cluster >= FAT32_EOC
        elif fat_type == "FAT16":
            return cluster >= FAT16_EOC
        else:  # FAT12
            return cluster >= FAT12_EOC

    def _get_cluster_chain(self, start_cluster: int) -> list[int]:
        """Get all clusters in a file's cluster chain."""
        if start_cluster < 2:
            return []

        chain = [start_cluster]
        current = start_cluster

        # Limit chain length to prevent infinite loops
        max_clusters = self._boot_sector.total_sectors // self._boot_sector.sectors_per_cluster

        while len(chain) < max_clusters:
            next_cluster = self._get_fat_entry(current)
            if self._is_end_of_chain(next_cluster) or next_cluster < 2:
                break
            chain.append(next_cluster)
            current = next_cluster

        return chain

    def _read_cluster(self, cluster: int) -> bytes:
        """Read a single cluster."""
        if cluster < 2:
            return b"\x00" * self.cluster_size

        offset = self._cluster_to_offset(cluster)
        return self._read_bytes(offset, self.cluster_size)

    def _read_file_data(self, start_cluster: int, size: int) -> bytes:
        """Read file data following cluster chain."""
        if size == 0:
            return b""

        chain = self._get_cluster_chain(start_cluster)
        if not chain:
            return b""

        result = bytearray()
        remaining = size

        for cluster in chain:
            cluster_data = self._read_cluster(cluster)
            to_add = min(remaining, len(cluster_data))
            result.extend(cluster_data[:to_add])
            remaining -= to_add
            if remaining <= 0:
                break

        return bytes(result)

    def _decode_fat_datetime(self, date_word: int, time_word: int) -> datetime | None:
        """Decode FAT date/time format."""
        if date_word == 0:
            return None

        try:
            year = ((date_word >> 9) & 0x7F) + 1980
            month = (date_word >> 5) & 0x0F
            day = date_word & 0x1F

            if time_word == 0:
                return datetime(year, month, day, tzinfo=UTC)

            hour = (time_word >> 11) & 0x1F
            minute = (time_word >> 5) & 0x3F
            second = (time_word & 0x1F) * 2

            return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
        except (ValueError, OSError):
            return None

    def _parse_directory_entry(self, data: bytes) -> FATDirectoryEntry | None:
        """Parse a 32-byte directory entry."""
        if len(data) < 32:
            return None

        first_byte = data[0]

        # Check for empty or deleted entry
        if first_byte == 0x00:  # End of directory
            return None
        if first_byte == 0xE5:  # Deleted entry
            return None

        attributes = data[11]

        # Check for long filename entry (skip for now)
        if attributes == FAT_ATTR_LONG_NAME:
            return FATDirectoryEntry(
                name="",
                extension="",
                attributes=attributes,
                created_time=None,
                modified_time=None,
                accessed_date=None,
                first_cluster=0,
                size=0,
                is_directory=False,
                is_long_name=True,
            )

        # Volume label - skip
        if attributes & FAT_ATTR_VOLUME_ID:
            return None

        # Short filename
        name = data[0:8].decode("cp437", errors="ignore").rstrip()
        extension = data[8:11].decode("cp437", errors="ignore").rstrip()

        # Handle special first character
        if first_byte == 0x05:
            name = "\xe5" + name[1:]

        # Timestamps
        created_time_raw = struct.unpack("<H", data[14:16])[0]
        created_date_raw = struct.unpack("<H", data[16:18])[0]
        accessed_date_raw = struct.unpack("<H", data[18:20])[0]
        modified_time_raw = struct.unpack("<H", data[22:24])[0]
        modified_date_raw = struct.unpack("<H", data[24:26])[0]

        # Cluster (high word for FAT32)
        cluster_high = struct.unpack("<H", data[20:22])[0]
        cluster_low = struct.unpack("<H", data[26:28])[0]

        if self._boot_sector.fat_type == "FAT32":
            first_cluster = (cluster_high << 16) | cluster_low
        else:
            first_cluster = cluster_low

        size = struct.unpack("<I", data[28:32])[0]

        return FATDirectoryEntry(
            name=name,
            extension=extension,
            attributes=attributes,
            created_time=self._decode_fat_datetime(created_date_raw, created_time_raw),
            modified_time=self._decode_fat_datetime(modified_date_raw, modified_time_raw),
            accessed_date=self._decode_fat_datetime(accessed_date_raw, 0),
            first_cluster=first_cluster,
            size=size,
            is_directory=bool(attributes & FAT_ATTR_DIRECTORY),
            is_long_name=False,
        )

    def _read_directory(self, cluster: int) -> list[FATDirectoryEntry]:
        """Read directory entries from a directory."""
        entries = []

        if cluster == 0:
            # Root directory for FAT12/16
            if self._boot_sector.fat_type in ("FAT12", "FAT16"):
                root_size = self._boot_sector.root_entry_count * 32
                data = self._read_bytes(self._root_dir_start, root_size)

                offset = 0
                while offset < len(data):
                    entry = self._parse_directory_entry(data[offset : offset + 32])
                    if entry is None:
                        if data[offset] == 0x00:  # End of directory
                            break
                    elif not entry.is_long_name:
                        entries.append(entry)
                    offset += 32

                return entries
            else:
                # FAT32 root directory
                cluster = self._boot_sector.root_cluster

        # Read directory from cluster chain
        chain = self._get_cluster_chain(cluster)
        long_name_parts: list[str] = []

        for clust in chain:
            data = self._read_cluster(clust)
            offset = 0

            while offset < len(data):
                entry_data = data[offset : offset + 32]
                if len(entry_data) < 32:
                    break

                if entry_data[0] == 0x00:  # End of directory
                    return entries

                entry = self._parse_directory_entry(entry_data)

                if entry is None:
                    offset += 32
                    continue

                if entry.is_long_name:
                    # Collect long name parts
                    lfn_data = entry_data
                    seq = lfn_data[0] & 0x3F
                    chars = (
                        lfn_data[1:11].decode("utf-16-le", errors="ignore") +
                        lfn_data[14:26].decode("utf-16-le", errors="ignore") +
                        lfn_data[28:32].decode("utf-16-le", errors="ignore")
                    )
                    chars = chars.rstrip("\x00\xff")

                    if lfn_data[0] & 0x40:  # First LFN entry
                        long_name_parts = [chars]
                    else:
                        long_name_parts.insert(0, chars)
                else:
                    # Apply long name if we collected one
                    if long_name_parts:
                        entry.name = "".join(long_name_parts)
                        entry.extension = ""
                        long_name_parts = []

                    entries.append(entry)

                offset += 32

        return entries

    def _get_full_name(self, entry: FATDirectoryEntry) -> str:
        """Get full filename from directory entry."""
        if entry.extension:
            return f"{entry.name}.{entry.extension}"
        return entry.name

    def _find_entry(self, path: str) -> FATDirectoryEntry | None:
        """Find directory entry for a path."""
        path = path.replace("\\", "/").strip("/")

        if not path:
            # Root directory
            return FATDirectoryEntry(
                name="",
                extension="",
                attributes=FAT_ATTR_DIRECTORY,
                created_time=None,
                modified_time=None,
                accessed_date=None,
                first_cluster=self._boot_sector.root_cluster if self._boot_sector.fat_type == "FAT32" else 0,
                size=0,
                is_directory=True,
                is_long_name=False,
            )

        components = path.split("/")
        current_cluster = self._boot_sector.root_cluster if self._boot_sector.fat_type == "FAT32" else 0

        for i, component in enumerate(components):
            entries = self._read_directory(current_cluster)

            found = None
            for entry in entries:
                full_name = self._get_full_name(entry)
                if full_name.lower() == component.lower():
                    found = entry
                    break

            if found is None:
                return None

            if i < len(components) - 1:
                # Not the last component - must be a directory
                if not found.is_directory:
                    return None
                current_cluster = found.first_cluster
            else:
                return found

        return None

    def exists(self, path: str) -> bool:
        """Check if a file or directory exists."""
        return self._find_entry(path) is not None

    def is_file(self, path: str) -> bool:
        """Check if path is a file."""
        entry = self._find_entry(path)
        return entry is not None and not entry.is_directory

    def is_directory(self, path: str) -> bool:
        """Check if path is a directory."""
        entry = self._find_entry(path)
        return entry is not None and entry.is_directory

    def get_file_info(self, path: str) -> FileInfo:
        """Get information about a file or directory."""
        entry = self._find_entry(path)
        if not entry:
            raise FileNotFoundError(f"Path not found: {path}")

        name = self._get_full_name(entry)
        if not name:
            name = "/"

        return FileInfo(
            name=name,
            path=path,
            size=entry.size,
            is_directory=entry.is_directory,
            is_file=not entry.is_directory,
            created_time=entry.created_time,
            modified_time=entry.modified_time,
            accessed_time=entry.accessed_date,
        )

    def open(self, path: str) -> BinaryIO:
        """Open a file for reading."""
        entry = self._find_entry(path)
        if not entry:
            raise FileNotFoundError(f"File not found: {path}")

        if entry.is_directory:
            raise IsADirectoryError(f"Is a directory: {path}")

        data = self._read_file_data(entry.first_cluster, entry.size)
        return FileStream(self, path, data)

    def read_file(self, path: str) -> bytes:
        """Read entire file contents."""
        entry = self._find_entry(path)
        if not entry:
            raise FileNotFoundError(f"File not found: {path}")

        if entry.is_directory:
            raise IsADirectoryError(f"Is a directory: {path}")

        return self._read_file_data(entry.first_cluster, entry.size)

    def list_dir(self, path: str) -> Iterator[str]:
        """List directory contents."""
        entry = self._find_entry(path)
        if not entry:
            raise FileNotFoundError(f"Directory not found: {path}")

        if not entry.is_directory:
            raise NotADirectoryError(f"Not a directory: {path}")

        entries = self._read_directory(entry.first_cluster)

        for dir_entry in entries:
            name = self._get_full_name(dir_entry)
            # Skip . and .. entries
            if name not in (".", ".."):
                yield name

    def walk(self, path: str = "") -> Iterator[tuple[str, list[str], list[str]]]:
        """Walk directory tree."""
        entry = self._find_entry(path)
        if not entry or not entry.is_directory:
            return

        entries = self._read_directory(entry.first_cluster)

        dirs = []
        files = []

        for dir_entry in entries:
            name = self._get_full_name(dir_entry)
            if name in (".", ".."):
                continue

            if dir_entry.is_directory:
                dirs.append(name)
            else:
                files.append(name)

        yield path, sorted(dirs), sorted(files)

        # Recurse into subdirectories
        for dir_name in dirs:
            child_path = f"{path}/{dir_name}" if path else dir_name
            yield from self.walk(child_path)
