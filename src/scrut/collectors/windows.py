"""Windows artifact collector for forensic evidence acquisition.

Collects common Windows forensic artifacts:
- Event Logs (EVTX)
- Registry Hives
- Prefetch files
- Browser data
- And more
"""

import hashlib
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Literal

from pydantic import BaseModel

from scrut.collectors.scope import ArtifactCategory, CollectionScope


class WindowsArtifactType(str, Enum):
    """Types of Windows artifacts."""

    EVTX_SECURITY = "evtx_security"
    EVTX_SYSTEM = "evtx_system"
    EVTX_APPLICATION = "evtx_application"
    EVTX_POWERSHELL = "evtx_powershell"
    EVTX_RDP = "evtx_rdp"
    EVTX_SYSMON = "evtx_sysmon"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    SHIMCACHE = "shimcache"
    REGISTRY_SAM = "registry_sam"
    REGISTRY_SYSTEM = "registry_system"
    REGISTRY_SOFTWARE = "registry_software"
    REGISTRY_SECURITY = "registry_security"
    REGISTRY_NTUSER = "registry_ntuser"
    REGISTRY_USRCLASS = "registry_usrclass"
    MFT = "mft"
    USNJRNL = "usnjrnl"
    BROWSER_CHROME = "browser_chrome"
    BROWSER_EDGE = "browser_edge"
    BROWSER_FIREFOX = "browser_firefox"
    SCHEDULED_TASKS = "scheduled_tasks"
    SERVICES = "services"
    LNK_FILES = "lnk_files"
    JUMP_LISTS = "jump_lists"


@dataclass
class WindowsArtifact:
    """A Windows artifact definition."""

    artifact_type: WindowsArtifactType
    name: str
    category: ArtifactCategory
    paths: list[str]  # Paths relative to system root or user profile
    description: str = ""
    requires_admin: bool = False
    priority: int = 1  # 1 = highest priority
    file_pattern: str | None = None


class CollectedFile(BaseModel):
    """A collected file with metadata."""

    source_path: str
    dest_path: str
    artifact_type: str
    size_bytes: int
    md5: str
    sha256: str
    collected_at: datetime
    error: str | None = None


class CollectionResult(BaseModel):
    """Result of a collection operation."""

    success: bool
    total_files: int
    total_bytes: int
    collected_files: list[CollectedFile]
    errors: list[str]
    skipped: list[str]
    duration_seconds: float


WINDOWS_ARTIFACTS: list[WindowsArtifact] = [
    WindowsArtifact(
        artifact_type=WindowsArtifactType.EVTX_SECURITY,
        name="Security Event Log",
        category=ArtifactCategory.AUTHENTICATION,
        paths=["Windows/System32/winevt/Logs/Security.evtx"],
        description="Security events including logons, privilege use",
        requires_admin=True,
        priority=1,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.EVTX_SYSTEM,
        name="System Event Log",
        category=ArtifactCategory.LOGS,
        paths=["Windows/System32/winevt/Logs/System.evtx"],
        description="System events including service changes",
        requires_admin=True,
        priority=1,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.EVTX_APPLICATION,
        name="Application Event Log",
        category=ArtifactCategory.LOGS,
        paths=["Windows/System32/winevt/Logs/Application.evtx"],
        description="Application events",
        requires_admin=True,
        priority=2,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.EVTX_POWERSHELL,
        name="PowerShell Event Log",
        category=ArtifactCategory.EXECUTION,
        paths=[
            "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
            "Windows/System32/winevt/Logs/Windows PowerShell.evtx",
        ],
        description="PowerShell execution events",
        requires_admin=True,
        priority=1,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.EVTX_SYSMON,
        name="Sysmon Event Log",
        category=ArtifactCategory.EXECUTION,
        paths=["Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"],
        description="Sysmon process and network events",
        requires_admin=True,
        priority=1,
    ),

    WindowsArtifact(
        artifact_type=WindowsArtifactType.PREFETCH,
        name="Prefetch Files",
        category=ArtifactCategory.EXECUTION,
        paths=["Windows/Prefetch"],
        description="Application execution history",
        requires_admin=True,
        priority=1,
        file_pattern="*.pf",
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.AMCACHE,
        name="Amcache",
        category=ArtifactCategory.EXECUTION,
        paths=["Windows/appcompat/Programs/Amcache.hve"],
        description="Application compatibility cache",
        requires_admin=True,
        priority=1,
    ),

    WindowsArtifact(
        artifact_type=WindowsArtifactType.REGISTRY_SAM,
        name="SAM Registry",
        category=ArtifactCategory.AUTHENTICATION,
        paths=["Windows/System32/config/SAM"],
        description="Security Account Manager",
        requires_admin=True,
        priority=1,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.REGISTRY_SYSTEM,
        name="SYSTEM Registry",
        category=ArtifactCategory.REGISTRY,
        paths=["Windows/System32/config/SYSTEM"],
        description="System configuration",
        requires_admin=True,
        priority=1,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.REGISTRY_SOFTWARE,
        name="SOFTWARE Registry",
        category=ArtifactCategory.REGISTRY,
        paths=["Windows/System32/config/SOFTWARE"],
        description="Software configuration",
        requires_admin=True,
        priority=1,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.REGISTRY_NTUSER,
        name="NTUSER.DAT",
        category=ArtifactCategory.USER_ACTIVITY,
        paths=["Users/*/NTUSER.DAT"],
        description="User registry hive",
        requires_admin=True,
        priority=2,
    ),

    WindowsArtifact(
        artifact_type=WindowsArtifactType.MFT,
        name="MFT",
        category=ArtifactCategory.FILE_SYSTEM,
        paths=["$MFT"],
        description="Master File Table",
        requires_admin=True,
        priority=2,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.USNJRNL,
        name="USN Journal",
        category=ArtifactCategory.FILE_SYSTEM,
        paths=["$Extend/$UsnJrnl:$J"],
        description="Change journal",
        requires_admin=True,
        priority=2,
    ),

    WindowsArtifact(
        artifact_type=WindowsArtifactType.BROWSER_CHROME,
        name="Chrome History",
        category=ArtifactCategory.USER_ACTIVITY,
        paths=[
            "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
            "Users/*/AppData/Local/Google/Chrome/User Data/Default/Cookies",
        ],
        description="Chrome browser data",
        requires_admin=False,
        priority=2,
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.BROWSER_EDGE,
        name="Edge History",
        category=ArtifactCategory.USER_ACTIVITY,
        paths=[
            "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
        ],
        description="Edge browser data",
        requires_admin=False,
        priority=2,
    ),

    WindowsArtifact(
        artifact_type=WindowsArtifactType.SCHEDULED_TASKS,
        name="Scheduled Tasks",
        category=ArtifactCategory.PERSISTENCE,
        paths=["Windows/System32/Tasks"],
        description="Scheduled task definitions",
        requires_admin=True,
        priority=1,
    ),

    WindowsArtifact(
        artifact_type=WindowsArtifactType.LNK_FILES,
        name="LNK Files",
        category=ArtifactCategory.USER_ACTIVITY,
        paths=[
            "Users/*/AppData/Roaming/Microsoft/Windows/Recent",
            "Users/*/Desktop/*.lnk",
        ],
        description="Shortcut files showing recent activity",
        requires_admin=False,
        priority=2,
        file_pattern="*.lnk",
    ),
    WindowsArtifact(
        artifact_type=WindowsArtifactType.JUMP_LISTS,
        name="Jump Lists",
        category=ArtifactCategory.USER_ACTIVITY,
        paths=[
            "Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
            "Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations",
        ],
        description="Application jump lists",
        requires_admin=False,
        priority=2,
    ),
]


class WindowsCollector:
    """Collects Windows forensic artifacts."""

    def __init__(
        self,
        system_root: Path,
        output_dir: Path,
        scope: CollectionScope | None = None,
    ) -> None:
        """Initialize the collector.

        Args:
            system_root: Path to Windows system root (e.g., mounted image)
            output_dir: Directory to store collected artifacts
            scope: Collection scope (defaults to all)
        """
        self._system_root = system_root
        self._output_dir = output_dir
        self._scope = scope
        self._collected: list[CollectedFile] = []
        self._errors: list[str] = []
        self._skipped: list[str] = []

    def get_artifacts(self) -> list[WindowsArtifact]:
        """Get list of artifacts matching the scope."""
        artifacts = []
        for artifact in WINDOWS_ARTIFACTS:
            if self._should_collect(artifact):
                artifacts.append(artifact)
        return sorted(artifacts, key=lambda a: a.priority)

    def collect(
        self,
        progress_callback: Any | None = None,
    ) -> CollectionResult:
        """Collect all artifacts matching the scope.

        Args:
            progress_callback: Optional callback(artifact_name, current, total)

        Returns:
            CollectionResult with collection status
        """
        import time

        start_time = time.time()
        artifacts = self.get_artifacts()
        total = len(artifacts)

        for i, artifact in enumerate(artifacts):
            if progress_callback:
                progress_callback(artifact.name, i + 1, total)

            self._collect_artifact(artifact)

        duration = time.time() - start_time

        return CollectionResult(
            success=len(self._errors) == 0,
            total_files=len(self._collected),
            total_bytes=sum(f.size_bytes for f in self._collected),
            collected_files=self._collected,
            errors=self._errors,
            skipped=self._skipped,
            duration_seconds=duration,
        )

    def collect_artifact(self, artifact_type: WindowsArtifactType) -> list[CollectedFile]:
        """Collect a specific artifact type.

        Args:
            artifact_type: Type of artifact to collect

        Returns:
            List of collected files
        """
        artifact = next(
            (a for a in WINDOWS_ARTIFACTS if a.artifact_type == artifact_type),
            None,
        )
        if not artifact:
            return []

        before_count = len(self._collected)
        self._collect_artifact(artifact)
        return self._collected[before_count:]

    def _should_collect(self, artifact: WindowsArtifact) -> bool:
        """Check if artifact should be collected based on scope."""
        if not self._scope:
            return True

        if not self._scope.includes_category(artifact.category):
            return False

        if not self._scope.includes_artifact(artifact.artifact_type.value):
            return False

        return True

    def _collect_artifact(self, artifact: WindowsArtifact) -> None:
        """Collect a single artifact."""
        for path_pattern in artifact.paths:
            if "*" in path_pattern:
                self._collect_glob(artifact, path_pattern)
            else:
                self._collect_file(artifact, path_pattern)

    def _collect_glob(self, artifact: WindowsArtifact, pattern: str) -> None:
        """Collect files matching a glob pattern."""
        try:
            for path in self._system_root.glob(pattern):
                if path.is_file():
                    if artifact.file_pattern:
                        import fnmatch
                        if not fnmatch.fnmatch(path.name, artifact.file_pattern):
                            continue
                    self._copy_file(artifact, path)
                elif path.is_dir() and artifact.file_pattern:
                    for file_path in path.glob(artifact.file_pattern):
                        if file_path.is_file():
                            self._copy_file(artifact, file_path)
        except Exception as e:
            self._errors.append(f"Error collecting {artifact.name}: {e}")

    def _collect_file(self, artifact: WindowsArtifact, rel_path: str) -> None:
        """Collect a single file."""
        source_path = self._system_root / rel_path

        if not source_path.exists():
            self._skipped.append(f"{artifact.name}: {rel_path} not found")
            return

        if source_path.is_dir():
            if artifact.file_pattern:
                for file_path in source_path.glob(artifact.file_pattern):
                    if file_path.is_file():
                        self._copy_file(artifact, file_path)
            else:
                for file_path in source_path.rglob("*"):
                    if file_path.is_file():
                        self._copy_file(artifact, file_path)
        else:
            self._copy_file(artifact, source_path)

    def _copy_file(self, artifact: WindowsArtifact, source_path: Path) -> None:
        """Copy a file to output directory with hashing."""
        try:
            size = source_path.stat().st_size
            if self._scope and size > self._scope.max_file_size_mb * 1024 * 1024:
                self._skipped.append(
                    f"{artifact.name}: {source_path.name} exceeds size limit"
                )
                return

            rel_path = source_path.relative_to(self._system_root)
            dest_dir = self._output_dir / artifact.artifact_type.value
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / source_path.name

            counter = 1
            original_dest = dest_path
            while dest_path.exists():
                dest_path = original_dest.with_stem(f"{original_dest.stem}_{counter}")
                counter += 1

            shutil.copy2(source_path, dest_path)

            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()

            with open(dest_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)

            collected = CollectedFile(
                source_path=str(source_path),
                dest_path=str(dest_path),
                artifact_type=artifact.artifact_type.value,
                size_bytes=size,
                md5=md5_hash.hexdigest(),
                sha256=sha256_hash.hexdigest(),
                collected_at=datetime.now(),
            )
            self._collected.append(collected)

        except PermissionError:
            self._errors.append(
                f"{artifact.name}: Permission denied for {source_path}"
            )
        except Exception as e:
            self._errors.append(f"{artifact.name}: {source_path} - {e}")

    def iter_artifacts(self) -> Iterator[WindowsArtifact]:
        """Iterate over artifacts to collect."""
        for artifact in self.get_artifacts():
            yield artifact
