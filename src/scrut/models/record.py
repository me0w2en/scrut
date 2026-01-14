"""Record and EvidenceRef models for Scrut DFIR CLI."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class EvidenceRef(BaseModel):
    """Provenance pointer linking a record to its source.

    Every parsed record includes an EvidenceRef to enable
    direct navigation to the source evidence.
    """

    target_id: UUID = Field(
        ...,
        description="Source target UUID",
    )

    artifact_path: str = Field(
        ...,
        description="Path to source artifact within target",
    )

    record_offset: int | None = Field(
        default=None,
        ge=0,
        description="Byte offset within artifact",
    )

    record_index: int | None = Field(
        default=None,
        ge=0,
        description="Record index within artifact",
    )

    parser_name: str = Field(
        ...,
        description="Parser that produced this record",
    )

    parser_version: str = Field(
        ...,
        description="Parser version",
    )

    source_hash: str = Field(
        ...,
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 of source artifact",
    )

    model_config = {"extra": "forbid"}

    @field_validator("source_hash")
    @classmethod
    def validate_lowercase_hash(cls, v: str) -> str:
        """Ensure hash is lowercase."""
        return v.lower()


class ParsedRecord(BaseModel):
    """Parsed record from an artifact.

    Represents a single normalized record with full provenance.
    """

    record_id: str = Field(
        ...,
        description="Unique identifier (artifact-scoped, stable across reruns)",
    )

    schema_version: str = Field(
        default="v1",
        pattern=r"^v[0-9]+$",
        description="Schema version",
    )

    record_type: Literal["timeline", "entity", "ioc", "raw"] = Field(
        ...,
        description="Type discriminator",
    )

    timestamp: datetime | None = Field(
        default=None,
        description="Event timestamp (ISO-8601, normalized to case timezone)",
    )

    timestamp_original: str | None = Field(
        default=None,
        description="Original timestamp string before normalization",
    )

    data: dict[str, Any] = Field(
        ...,
        description="Record payload (type-specific)",
    )

    evidence_ref: EvidenceRef = Field(
        ...,
        description="Provenance pointer to source",
    )

    model_config = {"extra": "forbid"}


class Artifact(BaseModel):
    """Discovered forensic artifact within a target."""

    artifact_id: UUID = Field(
        ...,
        description="Unique identifier",
    )

    target_id: UUID = Field(
        ...,
        description="Parent target reference",
    )

    type: str = Field(
        ...,
        description="Artifact type (evtx, prefetch, registry, mft, etc.)",
    )

    path: str = Field(
        ...,
        description="Relative path within target",
    )

    hash_sha256: str = Field(
        ...,
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 hash of artifact file",
    )

    size_bytes: int = Field(
        ...,
        ge=0,
        description="File size in bytes",
    )

    discovered_at: datetime = Field(
        ...,
        description="ISO-8601 discovery timestamp",
    )

    record_count: int | None = Field(
        default=None,
        ge=0,
        description="Estimated record count (after parsing)",
    )

    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Artifact-specific metadata",
    )

    model_config = {"extra": "forbid"}
