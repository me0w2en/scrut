"""Raw (dd) image reader.

Provides direct access to raw/dd forensic images without mounting.
"""

import struct
from pathlib import Path

from scrut.images.base import ImageReader
from scrut.images.filesystem.base import FilesystemReader


class RawReader(ImageReader):
    """Reader for raw/dd disk images.

    Raw images are uncompressed byte-for-byte copies of disks.
    Supports split raw images (.001, .002, ... or .aa, .ab, ...).
    """

    def __init__(self, path: Path) -> None:
        """Initialize raw image reader.

        Args:
            path: Path to the raw image file (or first segment)
        """
        super().__init__(path)

        self._segment_files: list[Path] = []
        self._segment_sizes: list[int] = []
        self._file_handle = None

        self._find_segments()
        self._open()

    def _find_segments(self) -> None:
        """Find all segment files for split images."""
        self._segment_files = [self.path]

        suffix = self.path.suffix.lower()
        parent = self.path.parent
        stem = self.path.stem

        if suffix == ".001" or (len(suffix) == 4 and suffix[1:].isdigit()):
            num = 2
            while True:
                next_seg = parent / f"{stem}.{num:03d}"
                if next_seg.exists():
                    self._segment_files.append(next_seg)
                    num += 1
                else:
                    break

        elif len(suffix) == 3 and suffix[1:].isalpha():
            chars = list(suffix[1:])
            while True:
                chars[1] = chr(ord(chars[1]) + 1)
                if chars[1] > "z":
                    chars[1] = "a"
                    chars[0] = chr(ord(chars[0]) + 1)
                    if chars[0] > "z":
                        break

                next_seg = parent / f"{stem}.{''.join(chars)}"
                if next_seg.exists():
                    self._segment_files.append(next_seg)
                else:
                    break

        self._segment_sizes = [f.stat().st_size for f in self._segment_files]

    def _open(self) -> None:
        """Open the image file."""
        if len(self._segment_files) == 1:
            self._file_handle = open(self._segment_files[0], "rb")

    @property
    def size(self) -> int:
        """Total size of the disk image in bytes."""
        if self._size is None:
            self._size = sum(self._segment_sizes)
        return self._size

    def read_sectors(self, offset: int, count: int) -> bytes:
        """Read sectors from the image.

        Args:
            offset: Starting sector number
            count: Number of sectors to read

        Returns:
            Raw sector data
        """
        byte_offset = offset * self.SECTOR_SIZE
        bytes_to_read = count * self.SECTOR_SIZE

        return self._read_at_offset(byte_offset, bytes_to_read)

    def _read_at_offset(self, offset: int, size: int) -> bytes:
        """Read bytes from absolute offset across segments.

        Args:
            offset: Byte offset
            size: Number of bytes to read

        Returns:
            Raw bytes
        """
        if len(self._segment_files) == 1:
            self._file_handle.seek(offset)
            return self._file_handle.read(size)

        result = bytearray()
        remaining = size
        current_offset = offset

        while remaining > 0:
            segment_idx, offset_in_segment = self._find_segment(current_offset)

            if segment_idx >= len(self._segment_files):
                result.extend(b"\x00" * remaining)
                break

            segment_size = self._segment_sizes[segment_idx]
            available = segment_size - offset_in_segment
            to_read = min(remaining, available)

            with open(self._segment_files[segment_idx], "rb") as fh:
                fh.seek(offset_in_segment)
                data = fh.read(to_read)
                result.extend(data)

            current_offset += to_read
            remaining -= to_read

        return bytes(result)

    def _find_segment(self, offset: int) -> tuple[int, int]:
        """Find segment index and offset within segment.

        Args:
            offset: Absolute byte offset

        Returns:
            Tuple of (segment_index, offset_within_segment)
        """
        cumulative = 0
        for i, seg_size in enumerate(self._segment_sizes):
            if offset < cumulative + seg_size:
                return i, offset - cumulative
            cumulative += seg_size

        return len(self._segment_files), 0

    def get_partitions(self) -> list[dict]:
        """Get partition table information."""
        mbr = self.read_sectors(0, 1)

        partitions = []

        if len(mbr) >= 512 and mbr[510:512] == b"\x55\xaa":
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

                fs_type = "unknown"
                if partition_type == 0x07:
                    fs_type = "ntfs"
                elif partition_type in (0x0B, 0x0C, 0x1B, 0x1C):
                    fs_type = "fat32"
                elif partition_type in (0x01, 0x04, 0x06, 0x0E):
                    fs_type = "fat16"

                partitions.append({
                    "index": i,
                    "type": fs_type,
                    "type_id": partition_type,
                    "start_sector": start_lba,
                    "size_sectors": size_sectors,
                    "bootable": status == 0x80,
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
        """Close file handle."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
