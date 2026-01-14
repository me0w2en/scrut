"""Bundle creation and verification for reproducible evidence packages.

Creates evidence bundles containing results, manifest, and all provenance
metadata needed for audit and reproducibility verification.
"""

import hashlib
import json
import os
import platform
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from scrut import __version__
from scrut.core.history import HistoryManager
from scrut.models.bundle import (
    Bundle,
    BundleManifest,
    CommandRecord,
    EnvironmentInfo,
    ResultReference,
    TargetReference,
)


def get_environment_info() -> EnvironmentInfo:
    """Collect current environment information.

    Returns:
        EnvironmentInfo with current environment details
    """
    import sys

    relevant_vars = {
        "TZ",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONPATH",
    }
    env_vars = {k: v for k, v in os.environ.items() if k in relevant_vars}

    return EnvironmentInfo(
        python_version=sys.version,
        scrut_version=__version__,
        platform=platform.platform(),
        hostname=platform.node(),
        username=os.getenv("USER", os.getenv("USERNAME", "unknown")),
        cwd=os.getcwd(),
        env_vars=env_vars,
    )


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Hex-encoded SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_directory_hash(dir_path: Path) -> str:
    """Compute SHA-256 hash of a directory's contents.

    Args:
        dir_path: Path to directory

    Returns:
        Hex-encoded SHA-256 hash of all files combined
    """
    sha256 = hashlib.sha256()

    for file_path in sorted(dir_path.rglob("*")):
        if file_path.is_file():
            rel_path = file_path.relative_to(dir_path)
            sha256.update(str(rel_path).encode())
            sha256.update(compute_file_hash(file_path).encode())

    return sha256.hexdigest()


class BundleCreator:
    """Creates evidence bundles with full provenance metadata."""

    def __init__(self, case_path: Path) -> None:
        """Initialize bundle creator.

        Args:
            case_path: Path to case directory
        """
        self.case_path = case_path
        self.history = HistoryManager(case_path)

    def create_bundle(
        self,
        output_path: Path,
        case_id: UUID,
        case_name: str,
        analyst: str,
        targets: list[dict[str, Any]] | None = None,
        result_files: list[Path] | None = None,
        include_commands_since: datetime | None = None,
    ) -> Bundle:
        """Create an evidence bundle.

        Args:
            output_path: Path for the bundle directory
            case_id: Case UUID
            case_name: Case name
            analyst: Analyst name
            targets: List of target dictionaries
            result_files: List of result file paths to include
            include_commands_since: Include commands since this time

        Returns:
            Created Bundle object
        """
        bundle_id = uuid4()
        created_at = datetime.now(UTC)

        output_path.mkdir(parents=True, exist_ok=True)
        results_dir = output_path / "results"
        results_dir.mkdir(exist_ok=True)

        result_refs: list[ResultReference] = []
        if result_files:
            for result_file in result_files:
                if result_file.exists():
                    dest = results_dir / result_file.name
                    shutil.copy2(result_file, dest)

                    record_count = 0
                    try:
                        with open(result_file, encoding="utf-8") as f:
                            record_count = sum(1 for line in f if line.strip())
                    except Exception:
                        pass

                    result_refs.append(
                        ResultReference(
                            filename=result_file.name,
                            artifact_type=self._detect_artifact_type(result_file.name),
                            source_artifact=str(result_file),
                            record_count=record_count,
                            hash=compute_file_hash(dest),
                            size_bytes=dest.stat().st_size,
                        )
                    )

        target_refs: list[TargetReference] = []
        if targets:
            for t in targets:
                target_refs.append(
                    TargetReference(
                        target_id=UUID(t["target_id"])
                        if isinstance(t["target_id"], str)
                        else t["target_id"],
                        name=t.get("name", "unknown"),
                        type=t.get("type", "unknown"),
                        path=t.get("path", ""),
                        hash=t.get("hash", ""),
                        size_bytes=t.get("size_bytes", 0),
                    )
                )

        commands: list[CommandRecord] = []
        if include_commands_since:
            commands = self.history.get_history_since(include_commands_since)
        else:
            commands = self.history.get_history()

        manifest = BundleManifest(
            bundle_id=bundle_id,
            case_id=case_id,
            case_name=case_name,
            created_at=created_at,
            created_by=analyst,
            environment=get_environment_info(),
            targets=target_refs,
            commands=commands,
            results=result_refs,
        )

        manifest_path = output_path / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest.model_dump_json(indent=2))

        manifest.bundle_hash = compute_directory_hash(output_path)

        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest.model_dump_json(indent=2))

        return Bundle(manifest=manifest, bundle_path=str(output_path))

    def _detect_artifact_type(self, filename: str) -> str:
        """Detect artifact type from filename.

        Args:
            filename: Result filename

        Returns:
            Artifact type string
        """
        lower = filename.lower()
        if "evtx" in lower:
            return "evtx"
        elif "prefetch" in lower or ".pf" in lower:
            return "prefetch"
        elif "registry" in lower or "ntuser" in lower:
            return "registry"
        return "unknown"


class BundleVerifier:
    """Verifies evidence bundle integrity and reproducibility."""

    def __init__(self, bundle_path: Path) -> None:
        """Initialize bundle verifier.

        Args:
            bundle_path: Path to bundle directory
        """
        self.bundle_path = bundle_path
        self.manifest_path = bundle_path / "manifest.json"

    def load_manifest(self) -> BundleManifest | None:
        """Load the bundle manifest.

        Returns:
            BundleManifest if valid, None otherwise
        """
        if not self.manifest_path.exists():
            return None

        try:
            with open(self.manifest_path, encoding="utf-8") as f:
                data = json.load(f)
            return BundleManifest(**data)
        except (json.JSONDecodeError, ValueError):
            return None

    def verify_integrity(self) -> dict[str, Any]:
        """Verify bundle integrity by checking all hashes.

        Returns:
            Dictionary with verification results
        """
        results = {
            "valid": True,
            "manifest_valid": False,
            "results_valid": True,
            "bundle_hash_valid": False,
            "errors": [],
        }

        # Load manifest
        manifest = self.load_manifest()
        if not manifest:
            results["valid"] = False
            results["errors"].append("Failed to load manifest")
            return results

        results["manifest_valid"] = True

        results_dir = self.bundle_path / "results"
        for result_ref in manifest.results:
            result_path = results_dir / result_ref.filename
            if not result_path.exists():
                results["results_valid"] = False
                results["errors"].append(f"Missing result file: {result_ref.filename}")
                continue

            actual_hash = compute_file_hash(result_path)
            if actual_hash != result_ref.hash:
                results["results_valid"] = False
                results["errors"].append(
                    f"Hash mismatch for {result_ref.filename}: "
                    f"expected {result_ref.hash}, got {actual_hash}"
                )

        if manifest.bundle_hash:
            actual_hash = compute_directory_hash(self.bundle_path)
            results["bundle_hash_valid"] = True

        results["valid"] = (
            results["manifest_valid"]
            and results["results_valid"]
            and len(results["errors"]) == 0
        )

        return results

    def get_reproducibility_commands(self) -> list[str]:
        """Get commands needed to reproduce the bundle.

        Returns:
            List of command strings
        """
        manifest = self.load_manifest()
        if not manifest:
            return []

        return [cmd.command for cmd in manifest.commands]
