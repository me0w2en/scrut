"""Playbook models for automated investigation workflows.

Playbooks define reusable, deterministic sequences of forensic analysis
steps that can be executed against targets.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class OnErrorAction(str, Enum):
    """Action to take when a step fails."""

    CONTINUE = "continue"
    STOP = "stop"
    SKIP = "skip"


class PlaybookStep(BaseModel):
    """A single step in a playbook execution."""

    step_id: str = Field(..., description="Unique step identifier within playbook")
    name: str = Field(..., description="Human-readable step name")
    command: str = Field(
        ..., description="Scrut command to execute (e.g., 'parse evtx')"
    )
    params: dict[str, Any] = Field(
        default_factory=dict, description="Command parameters"
    )
    on_error: OnErrorAction = Field(
        default=OnErrorAction.STOP, description="Action when step fails"
    )
    timeout_seconds: int | None = Field(
        default=None, description="Step timeout in seconds"
    )
    depends_on: list[str] = Field(
        default_factory=list, description="Step IDs this step depends on"
    )
    description: str | None = Field(
        default=None, description="Detailed step description"
    )
    condition: str | None = Field(
        default=None, description="Condition expression for conditional execution"
    )


class Playbook(BaseModel):
    """A playbook defining an automated investigation workflow."""

    playbook_id: str = Field(..., description="Unique playbook identifier")
    name: str = Field(..., description="Human-readable playbook name")
    description: str = Field(..., description="Playbook purpose and scope")
    version: str = Field(..., description="Playbook version (semver)")
    author: str | None = Field(default=None, description="Playbook author")
    tags: list[str] = Field(default_factory=list, description="Classification tags")
    steps: list[PlaybookStep] = Field(..., description="Ordered list of steps")
    variables: dict[str, Any] = Field(
        default_factory=dict, description="Default variable values"
    )
    estimated_duration_seconds: int | None = Field(
        default=None, description="Estimated total execution time"
    )

    def get_step(self, step_id: str) -> PlaybookStep | None:
        """Get a step by its ID."""
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None

    def get_execution_order(self) -> list[str]:
        """Get step IDs in execution order (respecting dependencies)."""
        executed: set[str] = set()
        order: list[str] = []

        while len(order) < len(self.steps):
            for step in self.steps:
                if step.step_id in executed:
                    continue
                deps_satisfied = all(dep in executed for dep in step.depends_on)
                if deps_satisfied:
                    order.append(step.step_id)
                    executed.add(step.step_id)
                    break
            else:
                remaining = [s.step_id for s in self.steps if s.step_id not in executed]
                raise ValueError(f"Circular dependency detected in steps: {remaining}")

        return order


class PlaybookRunStatus(str, Enum):
    """Status of a playbook run."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepResult(BaseModel):
    """Result of executing a single step."""

    step_id: str = Field(..., description="Step that was executed")
    status: Literal["success", "failed", "skipped"] = Field(
        ..., description="Step execution status"
    )
    started_at: datetime = Field(..., description="Step start time")
    completed_at: datetime = Field(..., description="Step completion time")
    duration_ms: int = Field(..., description="Execution duration in milliseconds")
    records_processed: int = Field(default=0, description="Records processed")
    output_file: str | None = Field(default=None, description="Output file path")
    error_message: str | None = Field(default=None, description="Error message if failed")
    exit_code: int = Field(default=0, description="Command exit code")


class PlaybookRun(BaseModel):
    """Record of a playbook execution."""

    run_id: UUID = Field(default_factory=uuid4, description="Unique run identifier")
    playbook_id: str = Field(..., description="Playbook being executed")
    playbook_version: str = Field(..., description="Version of playbook")
    target_id: UUID = Field(..., description="Target being analyzed")
    case_id: UUID | None = Field(default=None, description="Associated case")
    status: PlaybookRunStatus = Field(
        default=PlaybookRunStatus.PENDING, description="Current run status"
    )
    current_step: str | None = Field(
        default=None, description="Currently executing step ID"
    )
    completed_steps: list[str] = Field(
        default_factory=list, description="Completed step IDs"
    )
    step_results: list[StepResult] = Field(
        default_factory=list, description="Results for each completed step"
    )
    started_at: datetime | None = Field(default=None, description="Run start time")
    paused_at: datetime | None = Field(default=None, description="Time run was paused")
    completed_at: datetime | None = Field(
        default=None, description="Run completion time"
    )
    error_message: str | None = Field(
        default=None, description="Error message if run failed"
    )
    variables: dict[str, Any] = Field(
        default_factory=dict, description="Variable values for this run"
    )
    output_dir: str | None = Field(
        default=None, description="Directory containing run outputs"
    )

    @property
    def is_complete(self) -> bool:
        """Check if the run is complete (success or failure)."""
        return self.status in (
            PlaybookRunStatus.COMPLETED,
            PlaybookRunStatus.FAILED,
            PlaybookRunStatus.CANCELLED,
        )

    @property
    def duration_ms(self) -> int | None:
        """Calculate total run duration in milliseconds."""
        if not self.started_at:
            return None
        end_time = self.completed_at or self.paused_at or datetime.now()
        return int((end_time - self.started_at).total_seconds() * 1000)

    def get_step_result(self, step_id: str) -> StepResult | None:
        """Get result for a specific step."""
        for result in self.step_results:
            if result.step_id == step_id:
                return result
        return None


class PlaybookExplainResult(BaseModel):
    """Result of explaining a playbook (dry-run)."""

    playbook_id: str = Field(..., description="Playbook ID")
    playbook_name: str = Field(..., description="Playbook name")
    playbook_version: str = Field(..., description="Playbook version")
    target_id: UUID = Field(..., description="Target for execution")
    steps: list[dict[str, Any]] = Field(
        ..., description="Steps that would be executed"
    )
    total_steps: int = Field(..., description="Total number of steps")
    estimated_duration_seconds: int | None = Field(
        default=None, description="Estimated total duration"
    )
    estimated_records: int | None = Field(
        default=None, description="Estimated records to process"
    )
    variables: dict[str, Any] = Field(
        default_factory=dict, description="Variables that will be used"
    )
    warnings: list[str] = Field(
        default_factory=list, description="Potential issues detected"
    )
