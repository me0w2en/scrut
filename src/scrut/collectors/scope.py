"""Collection scope definitions for controlled artifact acquisition.

Defines what artifacts to collect, time ranges, and filtering criteria.
Supports predefined scopes for common investigation types.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel


class ArtifactCategory(str, Enum):
    """Categories of forensic artifacts."""

    EXECUTION = "execution"  # Prefetch, ShimCache, Amcache
    PERSISTENCE = "persistence"  # Services, Scheduled Tasks, Registry Run keys
    NETWORK = "network"  # Firewall logs, DNS cache, connections
    AUTHENTICATION = "authentication"  # Security event logs, SAM
    FILE_SYSTEM = "file_system"  # MFT, USN Journal, file metadata
    USER_ACTIVITY = "user_activity"  # Browser history, Recent files, Shellbags
    LOGS = "logs"  # Event logs, application logs
    MEMORY = "memory"  # Process dumps, memory artifacts
    REGISTRY = "registry"  # Full registry hives


class PredefinedScope(str, Enum):
    """Predefined collection scopes for common scenarios."""

    MINIMAL = "minimal"  # Quick triage, essential artifacts only
    STANDARD = "standard"  # Balanced collection for most investigations
    COMPREHENSIVE = "comprehensive"  # Full collection for detailed analysis
    MALWARE = "malware"  # Focused on execution and persistence
    LATERAL_MOVEMENT = "lateral_movement"  # Authentication and network
    DATA_EXFILTRATION = "data_exfiltration"  # File system and network


class CollectionScope(BaseModel):
    """Defines what artifacts to collect and filtering criteria."""

    name: str
    description: str = ""
    categories: list[ArtifactCategory] = []
    artifact_types: list[str] = []
    exclude_artifact_types: list[str] = []
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    max_file_size_mb: int = 100
    include_deleted: bool = False
    include_slack_space: bool = False
    path_filters: list[str] = []
    exclude_paths: list[str] = []
    user_filters: list[str] = []
    priority: Literal["speed", "completeness"] = "completeness"

    def includes_category(self, category: ArtifactCategory) -> bool:
        """Check if scope includes a category."""
        if not self.categories:
            return True  # Empty means all
        return category in self.categories

    def includes_artifact(self, artifact_type: str) -> bool:
        """Check if scope includes an artifact type."""
        if artifact_type in self.exclude_artifact_types:
            return False
        if not self.artifact_types:
            return True  # Empty means all
        return artifact_type in self.artifact_types

    def is_in_time_range(self, timestamp: datetime | None) -> bool:
        """Check if timestamp is within scope's time range."""
        if timestamp is None:
            return True
        if self.time_range_start and timestamp < self.time_range_start:
            return False
        if self.time_range_end and timestamp > self.time_range_end:
            return False
        return True


class ScopeBuilder:
    """Fluent builder for CollectionScope."""

    def __init__(self, name: str = "custom") -> None:
        """Initialize builder with scope name."""
        self._name = name
        self._description = ""
        self._categories: list[ArtifactCategory] = []
        self._artifact_types: list[str] = []
        self._exclude_artifact_types: list[str] = []
        self._time_range_start: datetime | None = None
        self._time_range_end: datetime | None = None
        self._max_file_size_mb = 100
        self._include_deleted = False
        self._include_slack_space = False
        self._path_filters: list[str] = []
        self._exclude_paths: list[str] = []
        self._user_filters: list[str] = []
        self._priority: Literal["speed", "completeness"] = "completeness"

    def description(self, desc: str) -> "ScopeBuilder":
        """Set scope description."""
        self._description = desc
        return self

    def categories(self, *cats: ArtifactCategory) -> "ScopeBuilder":
        """Set artifact categories to collect."""
        self._categories = list(cats)
        return self

    def artifact_types(self, *types: str) -> "ScopeBuilder":
        """Set specific artifact types to collect."""
        self._artifact_types = list(types)
        return self

    def exclude_artifacts(self, *types: str) -> "ScopeBuilder":
        """Exclude specific artifact types."""
        self._exclude_artifact_types = list(types)
        return self

    def time_range(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> "ScopeBuilder":
        """Set time range filter."""
        self._time_range_start = start
        self._time_range_end = end
        return self

    def last_days(self, days: int) -> "ScopeBuilder":
        """Set time range to last N days."""
        self._time_range_start = datetime.now() - timedelta(days=days)
        self._time_range_end = datetime.now()
        return self

    def max_file_size(self, size_mb: int) -> "ScopeBuilder":
        """Set maximum file size to collect."""
        self._max_file_size_mb = size_mb
        return self

    def include_deleted(self, include: bool = True) -> "ScopeBuilder":
        """Include deleted files."""
        self._include_deleted = include
        return self

    def include_slack_space(self, include: bool = True) -> "ScopeBuilder":
        """Include file slack space."""
        self._include_slack_space = include
        return self

    def path_filters(self, *paths: str) -> "ScopeBuilder":
        """Filter by paths (glob patterns supported)."""
        self._path_filters = list(paths)
        return self

    def exclude_paths(self, *paths: str) -> "ScopeBuilder":
        """Exclude paths (glob patterns supported)."""
        self._exclude_paths = list(paths)
        return self

    def users(self, *users: str) -> "ScopeBuilder":
        """Filter by user accounts."""
        self._user_filters = list(users)
        return self

    def priority_speed(self) -> "ScopeBuilder":
        """Prioritize collection speed."""
        self._priority = "speed"
        return self

    def priority_completeness(self) -> "ScopeBuilder":
        """Prioritize collection completeness."""
        self._priority = "completeness"
        return self

    def build(self) -> CollectionScope:
        """Build the CollectionScope."""
        return CollectionScope(
            name=self._name,
            description=self._description,
            categories=self._categories,
            artifact_types=self._artifact_types,
            exclude_artifact_types=self._exclude_artifact_types,
            time_range_start=self._time_range_start,
            time_range_end=self._time_range_end,
            max_file_size_mb=self._max_file_size_mb,
            include_deleted=self._include_deleted,
            include_slack_space=self._include_slack_space,
            path_filters=self._path_filters,
            exclude_paths=self._exclude_paths,
            user_filters=self._user_filters,
            priority=self._priority,
        )

    @classmethod
    def from_predefined(cls, scope: PredefinedScope) -> "ScopeBuilder":
        """Create builder from predefined scope."""
        builder = cls(scope.value)

        if scope == PredefinedScope.MINIMAL:
            builder.description("Quick triage - essential artifacts only")
            builder.categories(
                ArtifactCategory.EXECUTION,
                ArtifactCategory.AUTHENTICATION,
            )
            builder.artifact_types(
                "evtx_security",
                "prefetch",
                "amcache",
            )
            builder.last_days(7)
            builder.priority_speed()

        elif scope == PredefinedScope.STANDARD:
            builder.description("Standard collection for most investigations")
            builder.categories(
                ArtifactCategory.EXECUTION,
                ArtifactCategory.PERSISTENCE,
                ArtifactCategory.AUTHENTICATION,
                ArtifactCategory.LOGS,
            )
            builder.last_days(30)

        elif scope == PredefinedScope.COMPREHENSIVE:
            builder.description("Full collection for detailed analysis")
            builder.include_deleted(True)
            builder.max_file_size(500)

        elif scope == PredefinedScope.MALWARE:
            builder.description("Malware investigation - execution and persistence")
            builder.categories(
                ArtifactCategory.EXECUTION,
                ArtifactCategory.PERSISTENCE,
                ArtifactCategory.FILE_SYSTEM,
            )
            builder.artifact_types(
                "prefetch",
                "shimcache",
                "amcache",
                "services",
                "scheduledtasks",
                "evtx_security",
                "evtx_system",
                "evtx_powershell",
            )

        elif scope == PredefinedScope.LATERAL_MOVEMENT:
            builder.description("Lateral movement detection")
            builder.categories(
                ArtifactCategory.AUTHENTICATION,
                ArtifactCategory.NETWORK,
            )
            builder.artifact_types(
                "evtx_security",
                "evtx_rdp",
                "firewall",
                "dns_cache",
            )
            builder.last_days(14)

        elif scope == PredefinedScope.DATA_EXFILTRATION:
            builder.description("Data exfiltration investigation")
            builder.categories(
                ArtifactCategory.FILE_SYSTEM,
                ArtifactCategory.NETWORK,
                ArtifactCategory.USER_ACTIVITY,
            )
            builder.artifact_types(
                "usnjrnl",
                "mft",
                "browser_history",
                "recent_files",
                "shellbags",
            )

        return builder


def minimal_scope() -> CollectionScope:
    """Get minimal collection scope for quick triage."""
    return ScopeBuilder.from_predefined(PredefinedScope.MINIMAL).build()


def standard_scope() -> CollectionScope:
    """Get standard collection scope."""
    return ScopeBuilder.from_predefined(PredefinedScope.STANDARD).build()


def comprehensive_scope() -> CollectionScope:
    """Get comprehensive collection scope."""
    return ScopeBuilder.from_predefined(PredefinedScope.COMPREHENSIVE).build()


def malware_scope() -> CollectionScope:
    """Get malware investigation scope."""
    return ScopeBuilder.from_predefined(PredefinedScope.MALWARE).build()
