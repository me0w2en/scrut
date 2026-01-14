"""EvidenceRef generation and verification for Scrut DFIR CLI."""

import hashlib
from pathlib import Path
from uuid import UUID

from scrut.models.record import EvidenceRef


class EvidenceRefGenerator:
    """Generates EvidenceRef instances with consistent provenance."""

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        parser_name: str,
        parser_version: str,
    ) -> None:
        """Initialize generator with context.

        Args:
            target_id: Target UUID
            artifact_path: Path to artifact within target
            source_hash: SHA-256 hash of artifact
            parser_name: Name of the parser
            parser_version: Version of the parser
        """
        self.target_id = target_id
        self.artifact_path = artifact_path
        self.source_hash = source_hash.lower()
        self.parser_name = parser_name
        self.parser_version = parser_version

    def create(
        self,
        record_offset: int | None = None,
        record_index: int | None = None,
    ) -> EvidenceRef:
        """Create an EvidenceRef for a record.

        Args:
            record_offset: Byte offset within artifact
            record_index: Record index within artifact

        Returns:
            EvidenceRef with full provenance
        """
        return EvidenceRef(
            target_id=self.target_id,
            artifact_path=self.artifact_path,
            record_offset=record_offset,
            record_index=record_index,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            source_hash=self.source_hash,
        )

    @classmethod
    def from_file(
        cls,
        file_path: Path,
        target_id: UUID,
        artifact_path: str,
        parser_name: str,
        parser_version: str,
    ) -> "EvidenceRefGenerator":
        """Create generator from file, computing hash automatically.

        Args:
            file_path: Path to artifact file
            target_id: Target UUID
            artifact_path: Path within target
            parser_name: Parser name
            parser_version: Parser version

        Returns:
            EvidenceRefGenerator instance
        """
        source_hash = compute_file_hash(file_path)
        return cls(
            target_id=target_id,
            artifact_path=artifact_path,
            source_hash=source_hash,
            parser_name=parser_name,
            parser_version=parser_version,
        )


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Lowercase hex SHA-256 hash
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_source_hash(file_path: Path, expected_hash: str) -> bool:
    """Verify that a file matches an expected hash.

    Args:
        file_path: Path to file
        expected_hash: Expected SHA-256 hash (lowercase hex)

    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = compute_file_hash(file_path)
    return actual_hash.lower() == expected_hash.lower()


class HashMismatchError(Exception):
    """Raised when a file hash doesn't match expected value."""

    def __init__(self, file_path: Path, expected: str, actual: str) -> None:
        self.file_path = file_path
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Hash mismatch for {file_path}: expected {expected}, got {actual}"
        )
