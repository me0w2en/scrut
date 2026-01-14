"""EWF (Expert Witness Format / E01) image reader.

Provides direct access to E01 forensic images without mounting.
Supports split files (.E01, .E02, ...) and zlib-compressed chunks.
"""

import struct
import zlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

from scrut.images.base import ImageReader
from scrut.images.filesystem.base import FilesystemReader

# EWF signature: "EVF\x09\x0d\x0a\xff\x00"
EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


@dataclass
class EWFSection:
    """EWF section descriptor."""

    type_name: str
    offset: int
    size: int
    next_offset: int


@dataclass
class EWFChunkInfo:
    """Information about a data chunk."""

    file_index: int  # Which segment file
    offset: int  # Absolute offset within file
    size: int  # Compressed size
    is_compressed: bool


class EWFReader(ImageReader):
    """Reader for EWF (E01) forensic images.

    Supports:
    - Split files (.E01, .E02, ...)
    - zlib compressed chunks
    - Random access via chunk table
    """

    DEFAULT_CHUNK_SIZE = 32768  # 32KB (64 sectors)
    DEFAULT_SECTORS_PER_CHUNK = 64

    def __init__(self, path: Path) -> None:
        """Initialize EWF reader.

        Args:
            path: Path to the first segment file (.E01)
        """
        super().__init__(path)

        self._segment_files: list[Path] = []
        self._segment_handles: list[BinaryIO] = []
        self._chunk_table: list[EWFChunkInfo] = []
        self._media_size: int = 0
        self._chunk_size: int = self.DEFAULT_CHUNK_SIZE
        self._sectors_per_chunk: int = self.DEFAULT_SECTORS_PER_CHUNK

        self._open()

    def _open(self) -> None:
        """Open and parse the EWF image."""
        # Find all segment files
        self._find_segments()

        # Open first segment and verify signature
        self._segment_handles = []
        for seg_path in self._segment_files:
            fh = open(seg_path, "rb")
            self._segment_handles.append(fh)

        # Verify EWF signature
        self._segment_handles[0].seek(0)
        sig = self._segment_handles[0].read(8)
        if sig != EWF_SIGNATURE:
            raise ValueError(f"Invalid EWF signature: {sig!r}")

        # Parse sections from all segments
        self._parse_all_segments()

    def _find_segments(self) -> None:
        """Find all segment files for split images."""
        self._segment_files = [self.path]

        # Check for additional segments (.E02, .E03, ..., .EAA, etc.)
        base = self.path.stem[:-1] if self.path.suffix.lower().startswith(".e") else self.path.stem
        parent = self.path.parent

        # Try numbered extensions (.E01 -> .E02, .E03, ...)
        segment_num = 2
        while True:
            if segment_num <= 99:
                ext = f".E{segment_num:02d}"
            else:
                # After .E99, use .EAA, .EAB, ...
                letter1 = chr(ord("A") + (segment_num - 100) // 26)
                letter2 = chr(ord("A") + (segment_num - 100) % 26)
                ext = f".E{letter1}{letter2}"

            next_seg = parent / f"{base}{self.path.suffix[:-2]}{ext[-2:]}"

            # Try case-insensitive match
            found = None
            for f in parent.iterdir():
                if f.name.lower() == next_seg.name.lower():
                    found = f
                    break

            if found:
                self._segment_files.append(found)
                segment_num += 1
            else:
                break

    def _parse_all_segments(self) -> None:
        """Parse sections from all segment files."""
        for seg_idx, fh in enumerate(self._segment_handles):
            self._parse_segment(fh, seg_idx)

    def _parse_segment(self, fh: BinaryIO, seg_idx: int) -> None:
        """Parse a single segment file."""
        fh.seek(0, 2)
        file_size = fh.tell()

        # First, collect all sections
        sections: list[EWFSection] = []
        offset = 13  # After file header

        while offset < file_size:
            fh.seek(offset)
            section = self._read_section_header(fh, offset)

            if section is None:
                break

            sections.append(section)

            section_type = section.type_name.rstrip("\x00")
            if section_type in ("done", "next"):
                break

            offset = section.next_offset
            if offset == 0 or offset >= file_size:
                break

        # Parse volume/disk section first
        for section in sections:
            section_type = section.type_name.rstrip("\x00")
            if section_type in ("volume", "disk"):
                self._parse_volume_section(fh, section)
                break

        # Parse table sections with their corresponding sectors sections
        # Track the most recent sectors section to handle relative offsets
        current_sectors_start = None

        for section in sections:
            section_type = section.type_name.rstrip("\x00")

            if section_type == "sectors":
                # Data section - remember its start offset (after header)
                current_sectors_start = section.offset + 76

            elif section_type == "table":
                # Table section - parse chunk offsets
                if current_sectors_start is not None:
                    self._parse_table_section(fh, section, seg_idx, current_sectors_start)

    def _read_section_header(self, fh: BinaryIO, offset: int) -> EWFSection | None:
        """Read an EWF section header.

        Section header structure (76 bytes):
        - type: 16 bytes (null-terminated string)
        - next: 8 bytes (offset to next section)
        - size: 8 bytes (section size)
        - padding: 40 bytes
        - checksum: 4 bytes
        """
        fh.seek(offset)
        data = fh.read(76)

        if len(data) < 76:
            return None

        type_bytes = data[:16]
        next_offset = struct.unpack("<Q", data[16:24])[0]
        size = struct.unpack("<Q", data[24:32])[0]

        type_name = type_bytes.split(b"\x00")[0].decode("ascii", errors="ignore")

        return EWFSection(
            type_name=type_name,
            offset=offset,
            size=size,
            next_offset=next_offset,
        )

    def _parse_volume_section(self, fh: BinaryIO, section: EWFSection) -> None:
        """Parse volume/disk section for media info."""
        fh.seek(section.offset + 76)  # Skip section header

        # EWF disk section structure:
        # - media_type: 1 byte
        # - unknown: 3 bytes
        # - chunk_count: 4 bytes
        # - sectors_per_chunk: 4 bytes
        # - bytes_per_sector: 4 bytes
        # - sector_count: 8 bytes

        data = fh.read(24)
        if len(data) >= 24:
            (
                reserved,
                chunk_count,
                sectors_per_chunk,
                bytes_per_sector,
                sector_count,
            ) = struct.unpack("<IIIIQ", data[:24])

            if sectors_per_chunk > 0:
                self._sectors_per_chunk = sectors_per_chunk
            if bytes_per_sector > 0:
                self.SECTOR_SIZE = bytes_per_sector

            self._chunk_size = self._sectors_per_chunk * self.SECTOR_SIZE
            self._media_size = sector_count * self.SECTOR_SIZE

    def _parse_table_section(
        self, fh: BinaryIO, section: EWFSection, seg_idx: int, sectors_start: int
    ) -> None:
        """Parse chunk table section.

        Table entries can be either absolute or relative offsets.
        If first entry equals sectors_start, offsets are absolute.
        Otherwise, offsets are relative to sectors_start.

        Args:
            fh: File handle
            section: Table section info
            seg_idx: Segment file index
            sectors_start: Start offset of corresponding sectors section data
        """
        fh.seek(section.offset + 76)  # Skip section header

        # Table header:
        # - entry_count: 4 bytes
        # - padding: 16 bytes
        # - checksum: 4 bytes
        header = fh.read(24)
        if len(header) < 4:
            return

        entry_count = struct.unpack("<I", header[:4])[0]

        # Read chunk table entries (4 bytes each)
        # MSB indicates if chunk is compressed
        table_data = fh.read(entry_count * 4)

        if len(table_data) < 4:
            return

        # Determine if offsets are absolute or relative
        # by checking if first entry equals sectors_start
        first_entry = struct.unpack("<I", table_data[:4])[0]
        first_offset = first_entry & 0x7FFFFFFF
        use_relative_offsets = (first_offset != sectors_start)

        # Base offset for relative addressing
        base_offset = sectors_start if use_relative_offsets else 0

        for i in range(entry_count):
            if i * 4 + 4 > len(table_data):
                break

            entry = struct.unpack("<I", table_data[i * 4 : i * 4 + 4])[0]

            # MSB (bit 31) indicates compression
            is_compressed = bool(entry & 0x80000000)
            chunk_offset = entry & 0x7FFFFFFF

            # Apply base offset for relative addressing
            absolute_offset = base_offset + chunk_offset

            # Calculate chunk size from next entry
            if i + 1 < entry_count and (i + 1) * 4 + 4 <= len(table_data):
                next_entry = struct.unpack("<I", table_data[(i + 1) * 4 : (i + 1) * 4 + 4])[0]
                next_offset = next_entry & 0x7FFFFFFF
                chunk_size = next_offset - chunk_offset
            else:
                # Last chunk in this table - use default or calculate from section end
                chunk_size = self._chunk_size

            # Ensure reasonable chunk size
            if chunk_size <= 0 or chunk_size > self._chunk_size * 2:
                chunk_size = self._chunk_size

            self._chunk_table.append(
                EWFChunkInfo(
                    file_index=seg_idx,
                    offset=absolute_offset,
                    size=chunk_size,
                    is_compressed=is_compressed,
                )
            )

    @property
    def size(self) -> int:
        """Total size of the disk image in bytes."""
        if self._media_size > 0:
            return self._media_size
        # Fallback: estimate from chunk count
        return len(self._chunk_table) * self._chunk_size

    def read_sectors(self, offset: int, count: int) -> bytes:
        """Read sectors from the image.

        Args:
            offset: Starting sector number
            count: Number of sectors to read

        Returns:
            Raw sector data
        """
        result = bytearray()
        byte_offset = offset * self.SECTOR_SIZE
        bytes_to_read = count * self.SECTOR_SIZE

        while bytes_to_read > 0:
            # Find which chunk contains this offset
            chunk_index = byte_offset // self._chunk_size
            offset_in_chunk = byte_offset % self._chunk_size

            if chunk_index >= len(self._chunk_table):
                # Beyond end of image, pad with zeros
                result.extend(b"\x00" * bytes_to_read)
                break

            # Get decompressed chunk data
            chunk_data = self._get_chunk(chunk_index)

            # Calculate how much to read from this chunk
            available = len(chunk_data) - offset_in_chunk

            # Handle case where chunk is smaller than expected (e.g., decompression failed)
            if available <= 0:
                # Skip to next chunk boundary
                byte_offset = (chunk_index + 1) * self._chunk_size
                continue

            to_read = min(bytes_to_read, available)

            result.extend(chunk_data[offset_in_chunk : offset_in_chunk + to_read])

            byte_offset += to_read
            bytes_to_read -= to_read

        return bytes(result)

    @lru_cache(maxsize=256)
    def _get_chunk(self, chunk_index: int) -> bytes:
        """Get decompressed chunk data.

        Args:
            chunk_index: Index into chunk table

        Returns:
            Decompressed chunk data
        """
        if chunk_index >= len(self._chunk_table):
            return b"\x00" * self._chunk_size

        chunk_info = self._chunk_table[chunk_index]
        fh = self._segment_handles[chunk_info.file_index]

        fh.seek(chunk_info.offset)
        raw_data = fh.read(chunk_info.size)

        if chunk_info.is_compressed:
            # Check for zlib header (0x78xx)
            if len(raw_data) >= 2 and raw_data[0] == 0x78:
                try:
                    decompressed = zlib.decompress(raw_data)
                    return decompressed
                except zlib.error:
                    # Decompression failed despite zlib header - corrupt data
                    pass
            # No zlib header or decompression failed
            # Flag was likely set incorrectly - treat as uncompressed

        # Uncompressed chunk: return exactly chunk_size bytes
        # (stored size may include trailing checksum)
        if len(raw_data) >= self._chunk_size:
            return raw_data[:self._chunk_size]
        return raw_data

    def get_partitions(self) -> list[dict]:
        """Get partition table information."""
        # Read MBR (first sector)
        mbr = self.read_sectors(0, 1)

        partitions = []

        # Check for MBR signature (0x55AA at offset 510)
        if len(mbr) >= 512 and mbr[510:512] == b"\x55\xaa":
            # Parse partition table (4 entries at offset 446)
            for i in range(4):
                entry_offset = 446 + i * 16
                entry = mbr[entry_offset : entry_offset + 16]

                if len(entry) < 16:
                    continue

                status = entry[0]
                partition_type = entry[4]
                start_lba = struct.unpack("<I", entry[8:12])[0]
                size_sectors = struct.unpack("<I", entry[12:16])[0]

                if partition_type == 0 or size_sectors == 0:
                    continue

                # Determine filesystem type
                fs_type = "unknown"
                if partition_type == 0x07:
                    fs_type = "ntfs"
                elif partition_type in (0x0B, 0x0C, 0x1B, 0x1C):
                    fs_type = "fat32"
                elif partition_type in (0x01, 0x04, 0x06, 0x0E):
                    fs_type = "fat16"
                elif partition_type == 0x83:
                    fs_type = "ext"
                elif partition_type == 0xEE:
                    fs_type = "gpt"

                partitions.append({
                    "index": i,
                    "type": fs_type,
                    "type_id": partition_type,
                    "start_sector": start_lba,
                    "size_sectors": size_sectors,
                    "bootable": status == 0x80,
                })

        # If no MBR partitions, check if this is a direct filesystem
        if not partitions:
            # Check for NTFS signature at sector 0
            if len(mbr) >= 11 and mbr[3:11] == b"NTFS    ":
                # This is a direct NTFS filesystem (no partition table)
                total_sectors = self._media_size // self.SECTOR_SIZE
                partitions.append({
                    "index": 0,
                    "type": "ntfs",
                    "type_id": 0x07,
                    "start_sector": 0,
                    "size_sectors": total_sectors,
                    "bootable": False,
                })

        return partitions

    def get_filesystem(self, partition_index: int = 0) -> FilesystemReader:
        """Get filesystem reader for a partition."""
        partitions = self.get_partitions()

        if not partitions:
            raise ValueError("No partitions found in image")

        if partition_index >= len(partitions):
            raise ValueError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]
        offset = partition["start_sector"] * self.SECTOR_SIZE
        size = partition["size_sectors"] * self.SECTOR_SIZE
        fs_type = partition["type"]

        if fs_type == "ntfs":
            from scrut.images.filesystem.ntfs import NTFSReader
            return NTFSReader(self, offset, size)
        elif fs_type in ("fat32", "fat16"):
            from scrut.images.filesystem.fat import FATReader
            return FATReader(self, offset, size)
        else:
            raise ValueError(f"Unsupported filesystem type: {fs_type}")

    def close(self) -> None:
        """Close all segment file handles."""
        for fh in self._segment_handles:
            fh.close()
        self._segment_handles = []
        self._get_chunk.cache_clear()
