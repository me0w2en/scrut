"""Playbook executor for step-by-step investigation workflows.

Executes playbook steps in order, handling dependencies, errors,
and progress reporting.
"""

import shlex
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import click

from scrut.core.errors import ScrutError
from scrut.models.playbook import (
    OnErrorAction,
    Playbook,
    PlaybookExplainResult,
    PlaybookRun,
    PlaybookRunStatus,
    PlaybookStep,
    StepResult,
)


class PlaybookExecutionError(ScrutError):
    """Raised when playbook execution fails."""

    def __init__(self, playbook_id: str, step_id: str, message: str) -> None:
        super().__init__(
            code="PLAYBOOK_EXECUTION_ERROR",
            message=f"Playbook '{playbook_id}' failed at step '{step_id}': {message}",
            remediation="Check the step configuration and try again",
            retryable=True,
            context={"playbook_id": playbook_id, "step_id": step_id},
        )


class PlaybookExecutor:
    """Executes playbook steps against a target."""

    def __init__(
        self,
        playbook: Playbook,
        target_id: UUID,
        case_path: Path,
        output_dir: Path | None = None,
        variables: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the executor.

        Args:
            playbook: Playbook to execute
            target_id: Target UUID to analyze
            case_path: Path to case directory
            output_dir: Directory for step outputs
            variables: Variable overrides
        """
        self.playbook = playbook
        self.target_id = target_id
        self.case_path = case_path
        self.output_dir = output_dir or case_path / "playbook_outputs"
        self.variables = {**playbook.variables, **(variables or {})}
        self._run: PlaybookRun | None = None

    def execute(
        self,
        resume_run: PlaybookRun | None = None,
        step_filter: str | None = None,
        dry_run: bool = False,
    ) -> Iterator[tuple[PlaybookStep, StepResult]]:
        """Execute the playbook steps.

        Args:
            resume_run: Previous run to resume from
            step_filter: Only execute this specific step
            dry_run: If True, only simulate execution

        Yields:
            Tuples of (step, result) for each executed step
        """
        if resume_run:
            self._run = resume_run
            self._run.status = PlaybookRunStatus.RUNNING
            self._run.paused_at = None
        else:
            self._run = PlaybookRun(
                playbook_id=self.playbook.playbook_id,
                playbook_version=self.playbook.version,
                target_id=self.target_id,
                status=PlaybookRunStatus.RUNNING,
                started_at=datetime.now(UTC),
                variables=self.variables,
                output_dir=str(self.output_dir),
            )

        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            execution_order = self.playbook.get_execution_order()
        except ValueError as e:
            self._run.status = PlaybookRunStatus.FAILED
            self._run.error_message = str(e)
            return

        for step_id in execution_order:
            if step_id in self._run.completed_steps:
                continue

            if step_filter and step_id != step_filter:
                continue

            step = self.playbook.get_step(step_id)
            if step is None:
                continue

            self._run.current_step = step_id
            self._emit_progress(step, "starting")

            if dry_run:
                result = self._dry_run_step(step)
            else:
                result = self._execute_step(step)

            self._run.step_results.append(result)

            if result.status == "success":
                self._run.completed_steps.append(step_id)
                self._emit_progress(step, "completed", result)
                yield step, result
            elif result.status == "skipped":
                self._run.completed_steps.append(step_id)
                self._emit_progress(step, "skipped", result)
                yield step, result
            else:
                self._emit_progress(step, "failed", result)
                yield step, result

                if step.on_error == OnErrorAction.STOP:
                    self._run.status = PlaybookRunStatus.FAILED
                    self._run.error_message = result.error_message
                    self._run.completed_at = datetime.now(UTC)
                    return
                elif step.on_error == OnErrorAction.SKIP:
                    self._run.completed_steps.append(step_id)
                    continue

        self._run.status = PlaybookRunStatus.COMPLETED
        self._run.completed_at = datetime.now(UTC)
        self._run.current_step = None

    def explain(self) -> PlaybookExplainResult:
        """Generate an execution plan without running anything.

        Returns:
            PlaybookExplainResult with execution plan details
        """
        steps = []
        warnings = []

        try:
            execution_order = self.playbook.get_execution_order()
        except ValueError as e:
            warnings.append(f"Dependency error: {e}")
            execution_order = [s.step_id for s in self.playbook.steps]

        for step_id in execution_order:
            step = self.playbook.get_step(step_id)
            if step is None:
                continue

            command = self._build_command(step)
            steps.append({
                "step_id": step.step_id,
                "name": step.name,
                "command": command,
                "description": step.description,
                "on_error": step.on_error.value,
                "timeout_seconds": step.timeout_seconds,
                "depends_on": step.depends_on,
            })

        return PlaybookExplainResult(
            playbook_id=self.playbook.playbook_id,
            playbook_name=self.playbook.name,
            playbook_version=self.playbook.version,
            target_id=self.target_id,
            steps=steps,
            total_steps=len(steps),
            estimated_duration_seconds=self.playbook.estimated_duration_seconds,
            estimated_records=None,
            variables=self.variables,
            warnings=warnings,
        )

    def pause(self) -> PlaybookRun:
        """Pause the current execution.

        Returns:
            Current run state for later resume
        """
        if self._run:
            self._run.status = PlaybookRunStatus.PAUSED
            self._run.paused_at = datetime.now(UTC)
        return self._run

    def get_run(self) -> PlaybookRun | None:
        """Get the current run state."""
        return self._run

    def _execute_step(self, step: PlaybookStep) -> StepResult:
        """Execute a single step.

        Args:
            step: Step to execute

        Returns:
            StepResult with execution details
        """
        started_at = datetime.now(UTC)
        command = self._build_command(step)

        output_file = self.output_dir / f"{step.step_id}.jsonl"

        try:
            args = shlex.split(command)

            if args[0] == "scrut":
                args = args[1:]

            full_command = [
                sys.executable,
                "-m",
                "scrut.cli.main",
                *args,
            ]

            with open(output_file, "w") as out_f:
                process = subprocess.run(
                    full_command,
                    cwd=str(self.case_path),
                    capture_output=False,
                    stdout=out_f,
                    stderr=subprocess.PIPE,
                    timeout=step.timeout_seconds,
                    text=True,
                )

            completed_at = datetime.now(UTC)
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            records_processed = 0
            if output_file.exists():
                with open(output_file) as f:
                    records_processed = sum(1 for line in f if line.strip())

            if process.returncode == 0:
                return StepResult(
                    step_id=step.step_id,
                    status="success",
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    records_processed=records_processed,
                    output_file=str(output_file),
                    exit_code=process.returncode,
                )
            else:
                return StepResult(
                    step_id=step.step_id,
                    status="failed",
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    records_processed=records_processed,
                    output_file=str(output_file),
                    error_message=process.stderr or f"Exit code: {process.returncode}",
                    exit_code=process.returncode,
                )

        except subprocess.TimeoutExpired:
            completed_at = datetime.now(UTC)
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)
            return StepResult(
                step_id=step.step_id,
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                error_message=f"Step timed out after {step.timeout_seconds} seconds",
                exit_code=-1,
            )
        except Exception as e:
            completed_at = datetime.now(UTC)
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)
            return StepResult(
                step_id=step.step_id,
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                error_message=str(e),
                exit_code=-1,
            )

    def _dry_run_step(self, step: PlaybookStep) -> StepResult:
        """Simulate step execution without running anything.

        Args:
            step: Step to simulate

        Returns:
            StepResult with simulated data
        """
        now = datetime.now(UTC)
        return StepResult(
            step_id=step.step_id,
            status="success",
            started_at=now,
            completed_at=now,
            duration_ms=0,
            records_processed=0,
            output_file=None,
            exit_code=0,
        )

    def _build_command(self, step: PlaybookStep) -> str:
        """Build the full command string for a step.

        Args:
            step: Step to build command for

        Returns:
            Full command string
        """
        command = step.command

        if not command.startswith("scrut"):
            command = f"scrut {command}"

        command += f" --target {self.target_id}"

        for key, value in step.params.items():
            if isinstance(value, bool):
                if value:
                    command += f" --{key.replace('_', '-')}"
            elif isinstance(value, list):
                for v in value:
                    command += f" --{key.replace('_', '-')} {shlex.quote(str(v))}"
            else:
                value_str = str(value)
                for var_name, var_value in self.variables.items():
                    value_str = value_str.replace(f"${{{var_name}}}", str(var_value))
                command += f" --{key.replace('_', '-')} {shlex.quote(value_str)}"

        return command

    def _emit_progress(
        self,
        step: PlaybookStep,
        status: str,
        result: StepResult | None = None,
    ) -> None:
        """Emit progress information to stderr.

        Args:
            step: Current step
            status: Status string
            result: Step result if available
        """
        step_num = self.playbook.steps.index(step) + 1
        total_steps = len(self.playbook.steps)

        if status == "starting":
            msg = f"[{step_num}/{total_steps}] {step.name}..."
        elif status == "completed":
            duration = f" ({result.duration_ms}ms)" if result else ""
            records = f" - {result.records_processed} records" if result and result.records_processed > 0 else ""
            msg = f"[{step_num}/{total_steps}] {step.name} - OK{duration}{records}"
        elif status == "failed":
            error = f": {result.error_message}" if result and result.error_message else ""
            msg = f"[{step_num}/{total_steps}] {step.name} - FAILED{error}"
        elif status == "skipped":
            msg = f"[{step_num}/{total_steps}] {step.name} - SKIPPED"
        else:
            msg = f"[{step_num}/{total_steps}] {step.name} - {status}"

        click.echo(msg, err=True)

    def _estimate_eta(self, completed_steps: int, total_steps: int) -> str | None:
        """Estimate time remaining based on completed steps.

        Args:
            completed_steps: Number of steps completed
            total_steps: Total number of steps

        Returns:
            ETA string or None
        """
        if not self._run or not self._run.started_at or completed_steps == 0:
            return None

        elapsed = (datetime.now(UTC) - self._run.started_at).total_seconds()
        avg_per_step = elapsed / completed_steps
        remaining_steps = total_steps - completed_steps
        eta_seconds = int(avg_per_step * remaining_steps)

        if eta_seconds < 60:
            return f"{eta_seconds}s"
        elif eta_seconds < 3600:
            return f"{eta_seconds // 60}m {eta_seconds % 60}s"
        else:
            hours = eta_seconds // 3600
            minutes = (eta_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
