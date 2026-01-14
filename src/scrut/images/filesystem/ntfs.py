"""NTFS filesystem reader.

Provides direct file access to NTFS partitions within forensic images
without requiring OS-level mounting.
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import BinaryIO

from scrut.images.filesystem.base import FileInfo, FileStream, FilesystemReader

NTFS_SIGNATURE = b"NTFS    "

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0

FILE_ATTR_READONLY = 0x0001
FILE_ATTR_HIDDEN = 0x0002
FILE_ATTR_SYSTEM = 0x0004
FILE_ATTR_DIRECTORY = 0x0010
FILE_ATTR_ARCHIVE = 0x0020
FILE_ATTR_DEVICE = 0x0040
FILE_ATTR_NORMAL = 0x0080
FILE_ATTR_TEMPORARY = 0x0100
FILE_ATTR_SPARSE_FILE = 0x0200
FILE_ATTR_REPARSE_POINT = 0x0400
FILE_ATTR_COMPRESSED = 0x0800
FILE_ATTR_OFFLINE = 0x1000
FILE_ATTR_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTR_ENCRYPTED = 0x4000

MFT_ENTRY_MFT = 0
MFT_ENTRY_MFTMIRR = 1
MFT_ENTRY_LOGFILE = 2
MFT_ENTRY_VOLUME = 3
MFT_ENTRY_ATTRDEF = 4
MFT_ENTRY_ROOT = 5
MFT_ENTRY_BITMAP = 6
MFT_ENTRY_BOOT = 7
MFT_ENTRY_BADCLUS = 8


@dataclass
class NTFSBootSector:
    """NTFS boot sector information."""

    bytes_per_sector: int
    sectors_per_cluster: int
    mft_cluster: int
    mft_mirror_cluster: int
    clusters_per_mft_record: int
    clusters_per_index_record: int
    total_sectors: int
    volume_serial: int


@dataclass
class DataRun:
    """NTFS data run (describes extent of file data)."""

    cluster_offset: int  # Relative to previous run (signed)
    cluster_count: int
    start_cluster: int  # Absolute cluster number


@dataclass
class MFTAttribute:
    """NTFS MFT attribute."""

    type_id: int
    name: str
    is_resident: bool
    data: bytes  # For resident attributes
    data_runs: list[DataRun]  # For non-resident attributes
    allocated_size: int
    real_size: int


@dataclass
class MFTEntry:
    """NTFS MFT entry (file record)."""

    entry_number: int
    flags: int
    sequence_number: int
    attributes: list[MFTAttribute]
    is_directory: bool
    is_in_use: bool


class NTFSReader(FilesystemReader):
    """Reader for NTFS filesystems.

    Provides file access by parsing MFT and navigating directory structure.
    """

    def __init__(self, image_reader, partition_offset: int, partition_size: int) -> None:
        """Initialize NTFS reader.

        Args:
            image_reader: Parent image reader for sector access
            partition_offset: Byte offset where partition starts
            partition_size: Size of partition in bytes
        """
        super().__init__(image_reader, partition_offset, partition_size)

        self._boot_sector: NTFSBootSector | None = None
        self._mft_data: bytes | None = None
        self._bytes_per_mft_record: int = 1024  # Default

        self._parse_boot_sector()

    def _parse_boot_sector(self) -> None:
        """Parse NTFS boot sector."""
        boot_data = self._read_bytes(0, 512)

        if boot_data[3:11] != NTFS_SIGNATURE:
            raise ValueError("Invalid NTFS signature")

        bytes_per_sector = struct.unpack("<H", boot_data[11:13])[0]
        sectors_per_cluster = boot_data[13]
        mft_cluster = struct.unpack("<Q", boot_data[48:56])[0]
        mft_mirror_cluster = struct.unpack("<Q", boot_data[56:64])[0]

        clusters_per_mft = struct.unpack("<b", boot_data[64:65])[0]
        if clusters_per_mft < 0:
            self._bytes_per_mft_record = 2 ** abs(clusters_per_mft)
        else:
            self._bytes_per_mft_record = clusters_per_mft * sectors_per_cluster * bytes_per_sector

        clusters_per_index = struct.unpack("<b", boot_data[68:69])[0]
        total_sectors = struct.unpack("<Q", boot_data[40:48])[0]
        volume_serial = struct.unpack("<Q", boot_data[72:80])[0]

        self._boot_sector = NTFSBootSector(
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            mft_cluster=mft_cluster,
            mft_mirror_cluster=mft_mirror_cluster,
            clusters_per_mft_record=clusters_per_mft,
            clusters_per_index_record=clusters_per_index,
            total_sectors=total_sectors,
            volume_serial=volume_serial,
        )

    @property
    def cluster_size(self) -> int:
        """Size of a cluster in bytes."""
        return self._boot_sector.bytes_per_sector * self._boot_sector.sectors_per_cluster

    def _cluster_to_offset(self, cluster: int) -> int:
        """Convert cluster number to byte offset within partition."""
        return cluster * self.cluster_size

    def _read_clusters(self, start_cluster: int, count: int) -> bytes:
        """Read clusters from partition."""
        offset = self._cluster_to_offset(start_cluster)
        size = count * self.cluster_size
        return self._read_bytes(offset, size)

    @lru_cache(maxsize=1024)
    def _read_mft_entry(self, entry_number: int) -> MFTEntry | None:
        """Read and parse an MFT entry.

        Args:
            entry_number: MFT entry number

        Returns:
            Parsed MFTEntry or None if invalid
        """
        if entry_number == 0:
            mft_offset = self._cluster_to_offset(self._boot_sector.mft_cluster)
        else:
            mft_offset = self._cluster_to_offset(self._boot_sector.mft_cluster)
            mft_offset += entry_number * self._bytes_per_mft_record

        entry_data = self._read_bytes(mft_offset, self._bytes_per_mft_record)

        return self._parse_mft_entry(entry_data, entry_number)

    def _parse_mft_entry(self, data: bytes, entry_number: int) -> MFTEntry | None:
        """Parse an MFT entry from raw data."""
        if len(data) < 48:
            return None

        if data[:4] != b"FILE":
            return None

        data = self._apply_fixup(data)

        # update_seq_offset = struct.unpack("<H", data[4:6])[0]
        # update_seq_count = struct.unpack("<H", data[6:8])[0]
        # lsn = struct.unpack("<Q", data[8:16])[0]
        sequence_number = struct.unpack("<H", data[16:18])[0]
        # link_count = struct.unpack("<H", data[18:20])[0]
        first_attr_offset = struct.unpack("<H", data[20:22])[0]
        flags = struct.unpack("<H", data[22:24])[0]
        # used_size = struct.unpack("<I", data[24:28])[0]
        # allocated_size = struct.unpack("<I", data[28:32])[0]

        is_in_use = bool(flags & 0x01)
        is_directory = bool(flags & 0x02)

        attributes = []
        offset = first_attr_offset

        while offset < len(data) - 8:
            attr_type = struct.unpack("<I", data[offset : offset + 4])[0]

            if attr_type == 0xFFFFFFFF:  # End marker
                break

            attr_size = struct.unpack("<I", data[offset + 4 : offset + 8])[0]
            if attr_size == 0 or attr_size > len(data) - offset:
                break

            attr_data = data[offset : offset + attr_size]
            attr = self._parse_attribute(attr_data)
            if attr:
                attributes.append(attr)

            offset += attr_size

        return MFTEntry(
            entry_number=entry_number,
            flags=flags,
            sequence_number=sequence_number,
            attributes=attributes,
            is_directory=is_directory,
            is_in_use=is_in_use,
        )

    def _apply_fixup(self, data: bytes) -> bytes:
        """Apply NTFS fixup array to record."""
        if len(data) < 48:
            return data

        data = bytearray(data)

        update_seq_offset = struct.unpack("<H", data[4:6])[0]
        update_seq_count = struct.unpack("<H", data[6:8])[0]

        if update_seq_offset + update_seq_count * 2 > len(data):
            return bytes(data)

        update_seq = data[update_seq_offset : update_seq_offset + 2]

        for i in range(1, update_seq_count):
            fixup_value = data[update_seq_offset + i * 2 : update_seq_offset + i * 2 + 2]
            sector_end = i * 512 - 2

            if sector_end + 2 <= len(data):
                if data[sector_end : sector_end + 2] == update_seq:
                    data[sector_end : sector_end + 2] = fixup_value

        return bytes(data)

    def _parse_attribute(self, data: bytes) -> MFTAttribute | None:
        """Parse an MFT attribute."""
        if len(data) < 24:
            return None

        attr_type = struct.unpack("<I", data[0:4])[0]
        # attr_size = struct.unpack("<I", data[4:8])[0]
        non_resident = data[8]
        name_length = data[9]
        name_offset = struct.unpack("<H", data[10:12])[0]
        # flags = struct.unpack("<H", data[12:14])[0]
        name = ""
        if name_length > 0 and name_offset + name_length * 2 <= len(data):
            name_bytes = data[name_offset : name_offset + name_length * 2]
            name = name_bytes.decode("utf-16-le", errors="ignore")

        if non_resident:
            if len(data) < 64:
                return None

            # start_vcn = struct.unpack("<Q", data[16:24])[0]
            # end_vcn = struct.unpack("<Q", data[24:32])[0]
            run_offset = struct.unpack("<H", data[32:34])[0]
            # compression_unit = struct.unpack("<H", data[34:36])[0]
            allocated_size = struct.unpack("<Q", data[40:48])[0]
            real_size = struct.unpack("<Q", data[48:56])[0]

            data_runs = self._parse_data_runs(data[run_offset:])

            return MFTAttribute(
                type_id=attr_type,
                name=name,
                is_resident=False,
                data=b"",
                data_runs=data_runs,
                allocated_size=allocated_size,
                real_size=real_size,
            )
        else:
            if len(data) < 24:
                return None

            content_size = struct.unpack("<I", data[16:20])[0]
            content_offset = struct.unpack("<H", data[20:22])[0]

            content = b""
            if content_offset + content_size <= len(data):
                content = data[content_offset : content_offset + content_size]

            return MFTAttribute(
                type_id=attr_type,
                name=name,
                is_resident=True,
                data=content,
                data_runs=[],
                allocated_size=content_size,
                real_size=content_size,
            )

    def _parse_data_runs(self, data: bytes) -> list[DataRun]:
        """Parse NTFS data runs."""
        runs = []
        offset = 0
        current_cluster = 0

        while offset < len(data):
            header = data[offset]
            if header == 0:
                break

            length_size = header & 0x0F
            offset_size = (header >> 4) & 0x0F

            if offset + 1 + length_size + offset_size > len(data):
                break

            length_bytes = data[offset + 1 : offset + 1 + length_size]
            run_length = int.from_bytes(length_bytes, "little")

            if offset_size > 0:
                offset_bytes = data[offset + 1 + length_size : offset + 1 + length_size + offset_size]
                run_offset = int.from_bytes(offset_bytes, "little", signed=True)
                if offset_bytes[-1] & 0x80:
                    run_offset -= 1 << (offset_size * 8)
                    run_offset = int.from_bytes(offset_bytes, "little", signed=False)
                    if offset_bytes[-1] & 0x80:
                        run_offset = run_offset - (1 << (offset_size * 8))
            else:
                run_offset = 0  # Sparse run

            current_cluster += run_offset

            runs.append(DataRun(
                cluster_offset=run_offset,
                cluster_count=run_length,
                start_cluster=current_cluster,
            ))

            offset += 1 + length_size + offset_size

        return runs

    def _read_attribute_data(self, attr: MFTAttribute) -> bytes:
        """Read data from an attribute."""
        if attr.is_resident:
            return attr.data

        result = bytearray()

        for run in attr.data_runs:
            if run.cluster_offset == 0 and run.start_cluster == 0:
                result.extend(b"\x00" * run.cluster_count * self.cluster_size)
            else:
                cluster_data = self._read_clusters(run.start_cluster, run.cluster_count)
                result.extend(cluster_data)

        return bytes(result[: attr.real_size])

    def _get_file_entry(self, path: str) -> MFTEntry | None:
        """Get MFT entry for a file path."""
        path = path.replace("\\", "/").strip("/")

        if not path:
            return self._read_mft_entry(MFT_ENTRY_ROOT)

        current_entry = self._read_mft_entry(MFT_ENTRY_ROOT)

        for component in path.split("/"):
            if not component:
                continue

            if not current_entry or not current_entry.is_directory:
                return None

            found = False
            for child_name, child_entry_num in self._list_directory_entries(current_entry):
                if child_name.lower() == component.lower():
                    current_entry = self._read_mft_entry(child_entry_num)
                    found = True
                    break

            if not found:
                return None

        return current_entry

    def _list_directory_entries(self, dir_entry: MFTEntry) -> Iterator[tuple[str, int]]:
        """List entries in a directory.

        Yields:
            Tuples of (filename, mft_entry_number)
        """
        for attr in dir_entry.attributes:
            if attr.type_id == ATTR_INDEX_ROOT and attr.name == "$I30":
                yield from self._parse_index_entries(attr.data)

        for attr in dir_entry.attributes:
            if attr.type_id == ATTR_INDEX_ALLOCATION and attr.name == "$I30":
                index_data = self._read_attribute_data(attr)
                offset = 0
                while offset < len(index_data):
                    if index_data[offset : offset + 4] == b"INDX":
                        record_data = self._apply_fixup(index_data[offset : offset + 4096])
                        yield from self._parse_index_record(record_data)
                    offset += 4096

    def _parse_index_entries(self, data: bytes) -> Iterator[tuple[str, int]]:
        """Parse index entries from INDEX_ROOT attribute."""
        if len(data) < 32:
            return

        entries_offset = struct.unpack("<I", data[16:20])[0] + 16
        # entries_size = struct.unpack("<I", data[20:24])[0]
        # allocated_size = struct.unpack("<I", data[24:28])[0]
        # flags = data[28]

        yield from self._parse_index_entry_list(data[entries_offset:])

    def _parse_index_record(self, data: bytes) -> Iterator[tuple[str, int]]:
        """Parse index entries from INDEX_ALLOCATION record."""
        if len(data) < 24 or data[:4] != b"INDX":
            return

        entries_offset = struct.unpack("<I", data[24:28])[0] + 24
        yield from self._parse_index_entry_list(data[entries_offset:])

    def _parse_index_entry_list(self, data: bytes) -> Iterator[tuple[str, int]]:
        """Parse a list of index entries."""
        offset = 0

        while offset < len(data) - 16:
            mft_ref = struct.unpack("<Q", data[offset : offset + 8])[0]
            entry_length = struct.unpack("<H", data[offset + 8 : offset + 10])[0]
            flags = struct.unpack("<I", data[offset + 12 : offset + 16])[0]

            if entry_length == 0:
                break

            if flags & 0x02:
                break

            entry_num = mft_ref & 0x0000FFFFFFFFFFFF

            if entry_length > 16:
                fn_data = data[offset + 16 : offset + entry_length]
                filename = self._parse_filename_attr(fn_data)
                if filename and entry_num > 0:
                    yield filename, entry_num

            offset += entry_length

    def _parse_filename_attr(self, data: bytes) -> str | None:
        """Parse FILE_NAME attribute."""
        if len(data) < 66:
            return None

        # parent_ref = struct.unpack("<Q", data[0:8])[0]
        # creation_time = struct.unpack("<Q", data[8:16])[0]
        # modification_time = struct.unpack("<Q", data[16:24])[0]
        # mft_modification_time = struct.unpack("<Q", data[24:32])[0]
        # access_time = struct.unpack("<Q", data[32:40])[0]
        # allocated_size = struct.unpack("<Q", data[40:48])[0]
        # real_size = struct.unpack("<Q", data[48:56])[0]
        # flags = struct.unpack("<I", data[56:60])[0]
        # reparse_value = struct.unpack("<I", data[60:64])[0]
        name_length = data[64]
        # namespace = data[65]

        if len(data) < 66 + name_length * 2:
            return None

        name_bytes = data[66 : 66 + name_length * 2]
        return name_bytes.decode("utf-16-le", errors="ignore")

    def _filetime_to_datetime(self, filetime: int) -> datetime | None:
        """Convert Windows FILETIME to datetime."""
        if filetime == 0:
            return None

        unix_time = (filetime - 116444736000000000) / 10000000

        try:
            return datetime.fromtimestamp(unix_time, tz=UTC)
        except (OSError, ValueError):
            return None

    def exists(self, path: str) -> bool:
        """Check if a file or directory exists."""
        entry = self._get_file_entry(path)
        return entry is not None and entry.is_in_use

    def is_file(self, path: str) -> bool:
        """Check if path is a file."""
        entry = self._get_file_entry(path)
        return entry is not None and entry.is_in_use and not entry.is_directory

    def is_directory(self, path: str) -> bool:
        """Check if path is a directory."""
        entry = self._get_file_entry(path)
        return entry is not None and entry.is_in_use and entry.is_directory

    def get_file_info(self, path: str) -> FileInfo:
        """Get information about a file or directory."""
        entry = self._get_file_entry(path)
        if not entry:
            raise FileNotFoundError(f"Path not found: {path}")

        name = path.split("/")[-1] if "/" in path else path
        if not name:
            name = "/"

        size = 0
        for attr in entry.attributes:
            if attr.type_id == ATTR_DATA and attr.name == "":
                size = attr.real_size
                break

        created = None
        modified = None
        accessed = None

        for attr in entry.attributes:
            if attr.type_id == ATTR_STANDARD_INFORMATION:
                if len(attr.data) >= 32:
                    created = self._filetime_to_datetime(
                        struct.unpack("<Q", attr.data[0:8])[0]
                    )
                    modified = self._filetime_to_datetime(
                        struct.unpack("<Q", attr.data[8:16])[0]
                    )
                    accessed = self._filetime_to_datetime(
                        struct.unpack("<Q", attr.data[24:32])[0]
                    )
                break

        return FileInfo(
            name=name,
            path=path,
            size=size,
            is_directory=entry.is_directory,
            is_file=not entry.is_directory,
            created_time=created,
            modified_time=modified,
            accessed_time=accessed,
        )

    def open(self, path: str) -> BinaryIO:
        """Open a file for reading."""
        entry = self._get_file_entry(path)
        if not entry:
            raise FileNotFoundError(f"File not found: {path}")

        if entry.is_directory:
            raise IsADirectoryError(f"Is a directory: {path}")

        data = self.read_file(path)
        return FileStream(self, path, data)

    def read_file(self, path: str) -> bytes:
        """Read entire file contents."""
        entry = self._get_file_entry(path)
        if not entry:
            raise FileNotFoundError(f"File not found: {path}")

        if entry.is_directory:
            raise IsADirectoryError(f"Is a directory: {path}")

        for attr in entry.attributes:
            if attr.type_id == ATTR_DATA and attr.name == "":
                return self._read_attribute_data(attr)

        return b""

    def list_dir(self, path: str) -> Iterator[str]:
        """List directory contents."""
        entry = self._get_file_entry(path)
        if not entry:
            raise FileNotFoundError(f"Directory not found: {path}")

        if not entry.is_directory:
            raise NotADirectoryError(f"Not a directory: {path}")

        seen = set()
        for name, _ in self._list_directory_entries(entry):
            if name not in (".", "..") and name not in seen:
                seen.add(name)
                yield name

    def walk(self, path: str = "") -> Iterator[tuple[str, list[str], list[str]]]:
        """Walk directory tree."""
        entry = self._get_file_entry(path)
        if not entry or not entry.is_directory:
            return

        dirs = []
        files = []

        for name, entry_num in self._list_directory_entries(entry):
            if name in (".", ".."):
                continue

            child_entry = self._read_mft_entry(entry_num)
            if child_entry and child_entry.is_in_use:
                if child_entry.is_directory:
                    dirs.append(name)
                else:
                    files.append(name)

        yield path, sorted(dirs), sorted(files)

        for dir_name in dirs:
            child_path = f"{path}/{dir_name}" if path else dir_name
            yield from self.walk(child_path)
