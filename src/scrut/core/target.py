"""Target management operations."""

import hashlib
import json
from pathlib import Path
from uuid import UUID

from scrut.core.errors import ScrutError
from scrut.models.case import Target, TargetStatus, TargetType


class TargetError(ScrutError):
    """Target-related error."""

    pass


class TargetNotFoundError(TargetError):
    """Target not found."""

    pass


class TargetPathError(TargetError):
    """Target path is invalid or inaccessible."""

    pass


class TargetManager:
    """Manages target registration and operations."""

    TARGETS_FILE = "targets.json"

    def __init__(self, case_path: Path) -> None:
        """Initialize target manager.

        Args:
            case_path: Path to case directory
        """
        self.case_path = Path(case_path)

    @property
    def targets_file(self) -> Path:
        """Path to targets.json file."""
        return self.case_path / self.TARGETS_FILE

    @property
    def case_file(self) -> Path:
        """Path to case.json file."""
        return self.case_path / "case.json"

    def _load_case_id(self) -> UUID:
        """Load case ID from case.json.

        Returns:
            Case UUID

        Raises:
            TargetError: If case.json doesn't exist
        """
        if not self.case_file.exists():
            raise TargetError(
                code="CASE_NOT_FOUND",
                message=f"No case found at {self.case_path}",
                remediation="Initialize a case first with 'scrut case init'",
            )

        with open(self.case_file) as f:
            data = json.load(f)

        return UUID(data["case_id"])

    def _load_targets(self) -> list[Target]:
        """Load all targets from disk.

        Returns:
            List of Target instances
        """
        if not self.targets_file.exists():
            return []

        with open(self.targets_file) as f:
            data = json.load(f)

        targets = []
        for item in data:
            item["type"] = TargetType(item["type"])
            item["status"] = TargetStatus(item["status"])
            targets.append(Target(**item))

        return targets

    def _save_targets(self, targets: list[Target]) -> None:
        """Save targets to disk.

        Args:
            targets: List of Target instances
        """
        data = [t.to_json_dict() for t in targets]
        with open(self.targets_file, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def add(
        self,
        path: Path,
        name: str,
        target_type: TargetType | None = None,
        format: str | None = None,
        metadata: dict | None = None,
    ) -> Target:
        """Add a new target to the case.

        Args:
            path: Path to the evidence source
            name: Target display name
            target_type: Optional type (auto-detected if not specified)
            format: Optional format specification
            metadata: Optional target metadata

        Returns:
            Created Target instance

        Raises:
            TargetPathError: If path doesn't exist or is inaccessible
        """
        path = Path(path).resolve()

        if not path.exists():
            raise TargetPathError(
                code="TARGET_PATH_NOT_FOUND",
                message=f"Target path does not exist: {path}",
                remediation="Verify the path exists and is accessible",
            )

        case_id = self._load_case_id()

        if target_type is None:
            target_type = self._detect_type(path)

        hash_sha256, size_bytes = self._compute_hash_and_size(path)

        target = Target(
            case_id=case_id,
            name=name,
            type=target_type,
            path=str(path),
            format=format,
            hash_sha256=hash_sha256,
            size_bytes=size_bytes,
            metadata=metadata,
        )

        targets = self._load_targets()
        targets.append(target)
        self._save_targets(targets)

        return target

    def list(self) -> list[Target]:
        """List all targets in the case.

        Returns:
            List of Target instances
        """
        return self._load_targets()

    def info(self, target_id: str) -> Target:
        """Get target information.

        Args:
            target_id: Target UUID string

        Returns:
            Target instance

        Raises:
            TargetNotFoundError: If target not found
        """
        target_uuid = UUID(target_id)
        targets = self._load_targets()

        for target in targets:
            if target.target_id == target_uuid:
                return target

        raise TargetNotFoundError(
            code="TARGET_NOT_FOUND",
            message=f"Target not found: {target_id}",
            remediation="List targets with 'scrut target list'",
        )

    def _detect_type(self, path: Path) -> TargetType:
        """Auto-detect target type from path.

        Args:
            path: Path to evidence source

        Returns:
            Detected TargetType
        """
        if path.is_dir():
            if (path / ".velociraptor").exists():
                return TargetType.COLLECTION
            return TargetType.FOLDER

        suffix = path.suffix.lower()
        if suffix in {".e01", ".ex01", ".raw", ".dd", ".vmdk", ".vhd", ".vhdx"}:
            return TargetType.IMAGE

        return TargetType.FOLDER

    def _compute_hash_and_size(self, path: Path) -> tuple[str, int]:
        """Compute SHA-256 hash and total size of target.

        Args:
            path: Path to target

        Returns:
            Tuple of (hash_sha256, size_bytes)
        """
        hasher = hashlib.sha256()
        total_size = 0

        if path.is_file():
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
                    total_size += len(chunk)
        else:
            for file_path in sorted(path.rglob("*")):
                if file_path.is_file():
                    with open(file_path, "rb") as f:
                        while chunk := f.read(8192):
                            hasher.update(chunk)
                            total_size += len(chunk)

        return hasher.hexdigest(), total_size
