"""Base parser interface for Scrut DFIR CLI."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import EvidenceRef, ParsedRecord


class BaseParser(ABC):
    """Base class for all forensic artifact parsers.

    Parsers must implement the `parse` method to convert artifact data
    into normalized ParsedRecord instances with evidence provenance.
    """

    # Parser metadata (must be set by subclasses)
    name: ClassVar[str]
    version: ClassVar[str]
    supported_artifacts: ClassVar[list[str]]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize parser with context.

        Args:
            target_id: Target UUID for evidence_ref
            artifact_path: Path to artifact within target
            source_hash: SHA-256 hash of artifact
            timezone_str: Output timezone for timestamp normalization
        """
        self.target_id = target_id
        self.artifact_path = artifact_path
        self.source_hash = source_hash
        self.timezone_str = timezone_str

    @abstractmethod
    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse artifact file and yield records.

        Args:
            file_path: Path to artifact file

        Yields:
            ParsedRecord instances with evidence provenance

        Note:
            Implementations should yield records in deterministic order
            (typically by timestamp or record offset).
        """
        ...

    def create_evidence_ref(
        self,
        record_offset: int | None = None,
        record_index: int | None = None,
    ) -> EvidenceRef:
        """Create EvidenceRef for a parsed record.

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
            parser_name=self.name,
            parser_version=self.version,
            source_hash=self.source_hash,
        )

    def normalize_timestamp(self, ts: datetime | None) -> datetime | None:
        """Normalize timestamp to case timezone.

        Args:
            ts: Input timestamp

        Returns:
            Timestamp in UTC (or None if input is None)
        """
        if ts is None:
            return None

        # Ensure timezone-aware
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        # Convert to UTC for storage
        return ts.astimezone(UTC)

    def create_record_id(self, *components: Any) -> str:
        """Create deterministic record ID from components.

        Args:
            *components: ID components (will be joined with ':')

        Returns:
            Unique, deterministic record ID
        """
        return ":".join(str(c) for c in components)


class ParserRegistry:
    """Registry of available parsers."""

    _parsers: ClassVar[dict[str, type[BaseParser]]] = {}

    @classmethod
    def register(cls, parser_class: type[BaseParser]) -> type[BaseParser]:
        """Register a parser class.

        Args:
            parser_class: Parser class to register

        Returns:
            The registered class (for use as decorator)
        """
        for artifact_type in parser_class.supported_artifacts:
            cls._parsers[artifact_type] = parser_class
        return parser_class

    @classmethod
    def get(cls, artifact_type: str) -> type[BaseParser] | None:
        """Get parser for artifact type.

        Args:
            artifact_type: Artifact type (e.g., 'evtx', 'prefetch')

        Returns:
            Parser class or None if not found
        """
        return cls._parsers.get(artifact_type)

    @classmethod
    def supported_types(cls) -> list[str]:
        """Get list of supported artifact types.

        Returns:
            List of artifact type names
        """
        return list(cls._parsers.keys())
