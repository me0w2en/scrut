"""Case and Target models for investigation management."""

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    """Case lifecycle status."""

    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class TargetType(str, Enum):
    """Target type classification."""

    IMAGE = "image"
    FOLDER = "folder"
    COLLECTION = "collection"
    OUTPUT = "output"


class TargetStatus(str, Enum):
    """Target indexing status."""

    PENDING = "pending"
    INDEXED = "indexed"
    ERROR = "error"


class Case(BaseModel):
    """Investigation container that groups related targets."""

    case_id: UUID = Field(default_factory=uuid4, description="Unique identifier (UUID v4)")
    name: str = Field(..., min_length=1, max_length=255, pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    description: str | None = Field(default=None, description="Case notes and context")
    analyst: str | None = Field(default=None, description="Primary analyst identifier")
    timezone: str = Field(default="UTC", description="Case timezone (IANA format)")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="ISO-8601 creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="ISO-8601 last update timestamp",
    )
    status: CaseStatus = Field(default=CaseStatus.DRAFT, description="Case lifecycle status")
    tags: list[str] = Field(default_factory=list, description="Classification tags")
    metadata: dict[str, Any] | None = Field(default=None, description="Custom key-value pairs")

    model_config = {"use_enum_values": False}

    def to_json_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict matching schema."""
        data = self.model_dump(mode="json", exclude_none=True)
        data["status"] = self.status.value
        return data


class Target(BaseModel):
    """Evidence source registered within a case."""

    target_id: UUID = Field(default_factory=uuid4, description="Unique identifier (UUID v4)")
    case_id: UUID = Field(..., description="Parent case reference")
    name: str = Field(..., min_length=1, description="Target display name")
    type: TargetType = Field(..., description="Target type")
    path: str = Field(..., description="Absolute path to target")
    format: str | None = Field(default=None, description="Specific format (E01, raw, VMDK, etc.)")
    hash_sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$", description="SHA-256 hash of target")
    size_bytes: int = Field(..., ge=0, description="Total size in bytes")
    added_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="ISO-8601 registration timestamp",
    )
    indexed_at: datetime | None = Field(
        default=None, description="ISO-8601 indexing completion timestamp"
    )
    status: TargetStatus = Field(
        default=TargetStatus.PENDING, description="Target indexing status"
    )
    metadata: dict[str, Any] | None = Field(default=None, description="Target-specific metadata")

    model_config = {"use_enum_values": False}

    def to_json_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict matching schema."""
        data = self.model_dump(mode="json", exclude_none=True)
        data["status"] = self.status.value
        data["type"] = self.type.value
        return data
