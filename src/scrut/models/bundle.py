"""Bundle and manifest models for reproducible evidence packaging.

Bundles package results with full provenance metadata for audit and
reproducibility verification.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class CommandRecord(BaseModel):
    """Record of a command execution for reproducibility."""

    command: str = Field(..., description="Full command string executed")
    args: dict[str, Any] = Field(
        default_factory=dict, description="Parsed command arguments"
    )
    exit_code: int = Field(..., description="Command exit code")
    started_at: datetime = Field(..., description="Command start timestamp")
    completed_at: datetime = Field(..., description="Command completion timestamp")
    duration_ms: int = Field(..., description="Execution duration in milliseconds")
    output_file: str | None = Field(None, description="Output file path if applicable")
    output_hash: str | None = Field(
        None, description="SHA-256 hash of output file"
    )


class EnvironmentInfo(BaseModel):
    """Environment information for reproducibility."""

    python_version: str = Field(..., description="Python version")
    scrut_version: str = Field(..., description="Scrut version")
    platform: str = Field(..., description="Operating system platform")
    hostname: str = Field(..., description="Machine hostname")
    username: str = Field(..., description="Current username")
    cwd: str = Field(..., description="Working directory")
    env_vars: dict[str, str] = Field(
        default_factory=dict,
        description="Relevant environment variables (filtered)",
    )


class TargetReference(BaseModel):
    """Reference to a target included in the bundle."""

    target_id: UUID = Field(..., description="Target UUID")
    name: str = Field(..., description="Target name")
    type: str = Field(..., description="Target type (image, folder, output)")
    path: str = Field(..., description="Original path")
    hash: str = Field(..., description="SHA-256 hash of target")
    size_bytes: int = Field(..., description="Target size in bytes")


class ResultReference(BaseModel):
    """Reference to a result file in the bundle."""

    filename: str = Field(..., description="Result filename in bundle")
    artifact_type: str = Field(..., description="Artifact type (evtx, prefetch, etc.)")
    source_artifact: str = Field(..., description="Source artifact path")
    record_count: int = Field(..., description="Number of records in result")
    hash: str = Field(..., description="SHA-256 hash of result file")
    size_bytes: int = Field(..., description="Result file size in bytes")


class BundleManifest(BaseModel):
    """Manifest containing all provenance metadata for a bundle."""

    manifest_version: str = Field(
        default="1.0.0", description="Manifest schema version"
    )
    bundle_id: UUID = Field(..., description="Unique bundle identifier")
    case_id: UUID = Field(..., description="Associated case identifier")
    case_name: str = Field(..., description="Case name")
    created_at: datetime = Field(..., description="Bundle creation timestamp")
    created_by: str = Field(..., description="Analyst who created the bundle")

    # Environment
    environment: EnvironmentInfo = Field(
        ..., description="Environment information"
    )

    # Targets
    targets: list[TargetReference] = Field(
        default_factory=list, description="Targets included in bundle"
    )

    # Commands executed
    commands: list[CommandRecord] = Field(
        default_factory=list, description="Commands executed to produce results"
    )

    # Results
    results: list[ResultReference] = Field(
        default_factory=list, description="Result files in bundle"
    )

    # Hashes for verification
    bundle_hash: str | None = Field(
        None, description="SHA-256 hash of entire bundle directory"
    )

    # Optional signing
    signature: str | None = Field(
        None, description="Digital signature of manifest"
    )
    signed_by: str | None = Field(
        None, description="Identity of signer"
    )
    signed_at: datetime | None = Field(
        None, description="Timestamp of signature"
    )


class Bundle(BaseModel):
    """Evidence bundle containing results and provenance metadata."""

    manifest: BundleManifest = Field(..., description="Bundle manifest")
    bundle_path: str = Field(..., description="Path to bundle directory")

    @property
    def bundle_id(self) -> UUID:
        """Get the bundle ID."""
        return self.manifest.bundle_id

    @property
    def case_id(self) -> UUID:
        """Get the associated case ID."""
        return self.manifest.case_id
