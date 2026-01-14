"""Case management operations."""

import json
from datetime import UTC, datetime
from pathlib import Path

from scrut.core.errors import ScrutError
from scrut.models.case import Case, CaseStatus


class CaseError(ScrutError):
    """Case-related error."""

    pass


class CaseNotFoundError(CaseError):
    """Case not found at specified path."""

    pass


class CaseExistsError(CaseError):
    """Case already exists at specified path."""

    pass


class InvalidTransitionError(CaseError):
    """Invalid case status transition."""

    pass


class CaseManager:
    """Manages case lifecycle operations."""

    CASE_FILE = "case.json"

    def __init__(self, base_path: Path) -> None:
        """Initialize case manager.

        Args:
            base_path: Directory to store case data
        """
        self.base_path = Path(base_path)

    @property
    def case_file(self) -> Path:
        """Path to case.json file."""
        return self.base_path / self.CASE_FILE

    def init(
        self,
        name: str,
        description: str | None = None,
        analyst: str | None = None,
        timezone: str = "UTC",
        tags: list[str] | None = None,
    ) -> Case:
        """Initialize a new case.

        Args:
            name: Case name (alphanumeric, hyphens, underscores)
            description: Optional case description
            analyst: Optional analyst identifier
            timezone: Case timezone (default UTC)
            tags: Optional classification tags

        Returns:
            Created Case instance

        Raises:
            CaseExistsError: If case already exists at path
        """
        if self.case_file.exists():
            raise CaseExistsError(
                code="CASE_EXISTS",
                message=f"Case already exists at {self.base_path}",
                remediation="Use a different directory or remove existing case",
            )

        # Create case directory
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Create case instance
        case = Case(
            name=name,
            description=description,
            analyst=analyst,
            timezone=timezone,
            tags=tags or [],
        )

        # Save to disk
        self._save(case)

        return case

    def info(self) -> Case:
        """Load case information.

        Returns:
            Case instance

        Raises:
            CaseNotFoundError: If case.json doesn't exist
        """
        if not self.case_file.exists():
            raise CaseNotFoundError(
                code="CASE_NOT_FOUND",
                message=f"No case found at {self.base_path}",
                remediation="Initialize a case with 'scrut case init'",
            )

        with open(self.case_file) as f:
            data = json.load(f)

        # Convert status string to enum
        data["status"] = CaseStatus(data["status"])

        return Case(**data)

    def activate(self) -> Case:
        """Activate a draft case.

        Returns:
            Updated Case instance

        Raises:
            InvalidTransitionError: If case is not in draft status
        """
        case = self.info()

        if case.status != CaseStatus.DRAFT:
            raise InvalidTransitionError(
                code="INVALID_TRANSITION",
                message=f"Cannot activate case in '{case.status.value}' status",
                remediation="Only draft cases can be activated",
            )

        case.status = CaseStatus.ACTIVE
        case.updated_at = datetime.now(UTC)
        self._save(case)

        return case

    def archive(self) -> Case:
        """Archive an active case.

        Returns:
            Updated Case instance

        Raises:
            InvalidTransitionError: If case is not in active status
        """
        case = self.info()

        if case.status != CaseStatus.ACTIVE:
            raise InvalidTransitionError(
                code="INVALID_TRANSITION",
                message=f"Cannot archive case in '{case.status.value}' status",
                remediation="Only active cases can be archived",
            )

        case.status = CaseStatus.ARCHIVED
        case.updated_at = datetime.now(UTC)
        self._save(case)

        return case

    def _save(self, case: Case) -> None:
        """Save case to disk.

        Args:
            case: Case instance to save
        """
        with open(self.case_file, "w") as f:
            json.dump(case.to_json_dict(), f, indent=2, default=str)
