"""Base interface for filesystem readers.

Provides abstraction for reading files from various filesystem types
(NTFS, FAT32, ext4) within forensic images.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from typing import BinaryIO


@dataclass
class FileInfo:
    """Information about a file in the filesystem."""

    name: str
    path: str
    size: int
    is_directory: bool
    is_file: bool
    created_time: datetime | None = None
    modified_time: datetime | None = None
    accessed_time: datetime | None = None
    attributes: dict | None = None


class FilesystemReader(ABC):
    """Abstract base class for filesystem readers.

    Provides file-level access to filesystem within a disk image partition.
    """

    def __init__(self, image_reader, partition_offset: int, partition_size: int) -> None:
        """Initialize filesystem reader.

        Args:
            image_reader: Parent ImageReader for sector access
            partition_offset: Byte offset where partition starts
            partition_size: Size of partition in bytes
        """
        self.image_reader = image_reader
        self.partition_offset = partition_offset
        self.partition_size = partition_size

    def _read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from partition (partition-relative offset).

        Args:
            offset: Offset within partition
            size: Number of bytes to read

        Returns:
            Raw bytes
        """
        absolute_offset = self.partition_offset + offset
        return self.image_reader.read_bytes(absolute_offset, size)

    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if a file or directory exists.

        Args:
            path: Path within filesystem (e.g., "Windows/System32/config/SAM")

        Returns:
            True if path exists
        """
        ...

    @abstractmethod
    def is_file(self, path: str) -> bool:
        """Check if path is a file.

        Args:
            path: Path within filesystem

        Returns:
            True if path is a file
        """
        ...

    @abstractmethod
    def is_directory(self, path: str) -> bool:
        """Check if path is a directory.

        Args:
            path: Path within filesystem

        Returns:
            True if path is a directory
        """
        ...

    @abstractmethod
    def get_file_info(self, path: str) -> FileInfo:
        """Get information about a file or directory.

        Args:
            path: Path within filesystem

        Returns:
            FileInfo with metadata

        Raises:
            FileNotFoundError: If path doesn't exist
        """
        ...

    @abstractmethod
    def open(self, path: str) -> BinaryIO:
        """Open a file for reading.

        Args:
            path: Path within filesystem

        Returns:
            File-like object for reading

        Raises:
            FileNotFoundError: If file doesn't exist
            IsADirectoryError: If path is a directory
        """
        ...

    @abstractmethod
    def read_file(self, path: str) -> bytes:
        """Read entire file contents.

        Args:
            path: Path within filesystem

        Returns:
            File contents as bytes

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        ...

    @abstractmethod
    def list_dir(self, path: str) -> Iterator[str]:
        """List directory contents.

        Args:
            path: Directory path

        Yields:
            Names of files and directories

        Raises:
            FileNotFoundError: If directory doesn't exist
            NotADirectoryError: If path is not a directory
        """
        ...

    @abstractmethod
    def walk(self, path: str = "") -> Iterator[tuple[str, list[str], list[str]]]:
        """Walk directory tree.

        Like os.walk(), yields (dirpath, dirnames, filenames) tuples.

        Args:
            path: Starting directory (empty for root)

        Yields:
            Tuples of (dirpath, dirnames, filenames)
        """
        ...

    def find_files(self, pattern: str, path: str = "") -> Iterator[str]:
        """Find files matching a pattern.

        Args:
            pattern: Glob pattern (e.g., "*.evtx", "*.pf")
            path: Starting directory

        Yields:
            Paths to matching files
        """
        import fnmatch

        for dirpath, dirnames, filenames in self.walk(path):
            for filename in filenames:
                if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                    if dirpath:
                        yield f"{dirpath}/{filename}"
                    else:
                        yield filename


class FileStream(BytesIO):
    """File-like stream backed by filesystem data.

    Provides standard file operations (read, seek, tell) for
    files within a forensic image.
    """

    def __init__(self, fs_reader: FilesystemReader, path: str, data: bytes) -> None:
        """Initialize file stream.

        Args:
            fs_reader: Parent filesystem reader
            path: Path to file
            data: File contents
        """
        super().__init__(data)
        self.fs_reader = fs_reader
        self.file_path = path
        self._size = len(data)

    @property
    def size(self) -> int:
        """File size in bytes."""
        return self._size

    def __repr__(self) -> str:
        return f"<FileStream '{self.file_path}' size={self._size}>"
