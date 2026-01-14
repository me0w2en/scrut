"""Base interface for forensic image readers.

Provides abstraction for reading data from various forensic image formats
(E01/EWF, raw/dd, VMDK) without OS-level mounting.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from scrut.images.filesystem.base import FilesystemReader


class ImageReader(ABC):
    """Abstract base class for forensic image readers.

    Image readers provide sector-level access to disk images and
    can enumerate/access filesystems within the image.
    """

    SECTOR_SIZE = 512  # Standard sector size

    def __init__(self, path: Path) -> None:
        """Initialize image reader.

        Args:
            path: Path to the image file (or first segment for split images)
        """
        self.path = Path(path)
        self._size: int | None = None

    @property
    @abstractmethod
    def size(self) -> int:
        """Total size of the disk image in bytes."""
        ...

    @abstractmethod
    def read_sectors(self, offset: int, count: int) -> bytes:
        """Read sectors from the image.

        Args:
            offset: Starting sector number (0-based)
            count: Number of sectors to read

        Returns:
            Raw bytes from the specified sectors
        """
        ...

    def read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from arbitrary offset.

        Args:
            offset: Byte offset (0-based)
            size: Number of bytes to read

        Returns:
            Raw bytes from the specified location
        """
        start_sector = offset // self.SECTOR_SIZE
        end_sector = (offset + size + self.SECTOR_SIZE - 1) // self.SECTOR_SIZE
        sector_count = end_sector - start_sector

        data = self.read_sectors(start_sector, sector_count)

        start_offset = offset % self.SECTOR_SIZE
        return data[start_offset:start_offset + size]

    @abstractmethod
    def get_partitions(self) -> list[dict]:
        """Get partition table information.

        Returns:
            List of partition info dicts with keys:
            - index: Partition number
            - type: Partition type (e.g., 'ntfs', 'fat32')
            - start_sector: Starting sector
            - size_sectors: Size in sectors
            - bootable: Whether partition is bootable
        """
        ...

    @abstractmethod
    def get_filesystem(self, partition_index: int = 0) -> FilesystemReader:
        """Get filesystem reader for a partition.

        Args:
            partition_index: Partition index (0-based), default is first partition

        Returns:
            FilesystemReader for the specified partition
        """
        ...

    def open_file(self, path: str, partition_index: int = 0) -> BinaryIO:
        """Open a file inside the image.

        Convenience method that gets filesystem and opens file.

        Args:
            path: Path to file within the filesystem (e.g., "Windows/System32/config/SAM")
            partition_index: Which partition to use

        Returns:
            File-like object for reading
        """
        fs = self.get_filesystem(partition_index)
        return fs.open(path)

    def exists(self, path: str, partition_index: int = 0) -> bool:
        """Check if a file exists inside the image.

        Args:
            path: Path to file within the filesystem
            partition_index: Which partition to check

        Returns:
            True if file exists
        """
        fs = self.get_filesystem(partition_index)
        return fs.exists(path)

    def list_dir(self, path: str, partition_index: int = 0) -> Iterator[str]:
        """List directory contents.

        Args:
            path: Directory path within the filesystem
            partition_index: Which partition to use

        Yields:
            File/directory names in the directory
        """
        fs = self.get_filesystem(partition_index)
        yield from fs.list_dir(path)

    @abstractmethod
    def close(self) -> None:
        """Close the image and release resources."""
        ...

    def __enter__(self) -> "ImageReader":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()


def open_image(path: Path | str) -> ImageReader:
    """Open a forensic image file.

    Auto-detects image format based on file extension and magic bytes.

    Args:
        path: Path to the image file

    Returns:
        Appropriate ImageReader subclass instance

    Raises:
        ValueError: If image format is not supported
        FileNotFoundError: If image file doesn't exist
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Image file not found: {path}")

    suffix = path.suffix.lower()

    if suffix in {".e01", ".ex01", ".s01"}:
        from scrut.images.ewf import EWFReader
        return EWFReader(path)

    elif suffix in {".raw", ".dd", ".img", ".bin"}:
        from scrut.images.raw import RawReader
        return RawReader(path)

    elif suffix in {".vmdk"}:
        from scrut.images.vmdk import VMDKReader
        return VMDKReader(path)

    else:
        with open(path, "rb") as f:
            magic = f.read(8)

        if magic.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
            from scrut.images.ewf import EWFReader
            return EWFReader(path)

        if magic.startswith(b"KDMV") or magic.startswith(b"# Disk"):
            from scrut.images.vmdk import VMDKReader
            return VMDKReader(path)

        from scrut.images.raw import RawReader
        return RawReader(path)
