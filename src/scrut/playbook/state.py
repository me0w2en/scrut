"""Playbook state management for pause/resume functionality.

Persists playbook run state to enable resuming interrupted executions.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from scrut.models.playbook import PlaybookRun, PlaybookRunStatus, StepResult


class PlaybookStateManager:
    """Manages playbook run state persistence."""

    STATE_DIR_NAME = ".scrut"
    RUNS_DIR_NAME = "playbook_runs"

    def __init__(self, case_path: Path) -> None:
        """Initialize the state manager.

        Args:
            case_path: Path to case directory
        """
        self.case_path = case_path
        self.state_dir = case_path / self.STATE_DIR_NAME / self.RUNS_DIR_NAME

    def save_state(self, run: PlaybookRun) -> Path:
        """Save run state to disk.

        Args:
            run: PlaybookRun to save

        Returns:
            Path to saved state file
        """
        self.state_dir.mkdir(parents=True, exist_ok=True)
        state_file = self.state_dir / f"{run.run_id}.json"

        state_data = self._run_to_dict(run)
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state_data, f, indent=2, default=str)

        return state_file

    def load_state(self, run_id: UUID | str) -> PlaybookRun | None:
        """Load run state from disk.

        Args:
            run_id: Run UUID to load

        Returns:
            PlaybookRun if found, None otherwise
        """
        if isinstance(run_id, str):
            run_id_str = run_id
        else:
            run_id_str = str(run_id)

        state_file = self.state_dir / f"{run_id_str}.json"
        if not state_file.exists():
            return None

        with open(state_file, encoding="utf-8") as f:
            state_data = json.load(f)

        return self._dict_to_run(state_data)

    def delete_state(self, run_id: UUID | str) -> bool:
        """Delete run state from disk.

        Args:
            run_id: Run UUID to delete

        Returns:
            True if deleted, False if not found
        """
        if isinstance(run_id, str):
            run_id_str = run_id
        else:
            run_id_str = str(run_id)

        state_file = self.state_dir / f"{run_id_str}.json"
        if state_file.exists():
            state_file.unlink()
            return True
        return False

    def list_runs(
        self,
        status: PlaybookRunStatus | str | None = None,
        playbook_id: str | None = None,
    ) -> list[PlaybookRun]:
        """List all saved runs.

        Args:
            status: Filter by status
            playbook_id: Filter by playbook ID

        Returns:
            List of PlaybookRun objects
        """
        runs = []

        if not self.state_dir.exists():
            return runs

        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, encoding="utf-8") as f:
                    state_data = json.load(f)
                run = self._dict_to_run(state_data)

                if status is not None:
                    if isinstance(status, str):
                        status = PlaybookRunStatus(status)
                    if run.status != status:
                        continue

                if playbook_id is not None:
                    if run.playbook_id != playbook_id:
                        continue

                runs.append(run)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue

        runs.sort(key=lambda r: r.started_at or datetime.min, reverse=True)
        return runs

    def get_paused_runs(self) -> list[PlaybookRun]:
        """Get all paused runs that can be resumed.

        Returns:
            List of paused PlaybookRun objects
        """
        return self.list_runs(status=PlaybookRunStatus.PAUSED)

    def get_active_run(self, playbook_id: str) -> PlaybookRun | None:
        """Get an active (running or paused) run for a playbook.

        Args:
            playbook_id: Playbook ID to check

        Returns:
            Active run if found, None otherwise
        """
        runs = self.list_runs(playbook_id=playbook_id)
        for run in runs:
            if run.status in (PlaybookRunStatus.RUNNING, PlaybookRunStatus.PAUSED):
                return run
        return None

    def _run_to_dict(self, run: PlaybookRun) -> dict[str, Any]:
        """Convert PlaybookRun to dictionary for serialization.

        Args:
            run: PlaybookRun to convert

        Returns:
            Dictionary representation
        """
        data = {
            "run_id": str(run.run_id),
            "playbook_id": run.playbook_id,
            "playbook_version": run.playbook_version,
            "target_id": str(run.target_id),
            "case_id": str(run.case_id) if run.case_id else None,
            "status": run.status.value,
            "current_step": run.current_step,
            "completed_steps": run.completed_steps,
            "step_results": [
                {
                    "step_id": r.step_id,
                    "status": r.status,
                    "started_at": r.started_at.isoformat(),
                    "completed_at": r.completed_at.isoformat(),
                    "duration_ms": r.duration_ms,
                    "records_processed": r.records_processed,
                    "output_file": r.output_file,
                    "error_message": r.error_message,
                    "exit_code": r.exit_code,
                }
                for r in run.step_results
            ],
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "paused_at": run.paused_at.isoformat() if run.paused_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "error_message": run.error_message,
            "variables": run.variables,
            "output_dir": run.output_dir,
        }
        return data

    def _dict_to_run(self, data: dict[str, Any]) -> PlaybookRun:
        """Convert dictionary to PlaybookRun.

        Args:
            data: Dictionary representation

        Returns:
            PlaybookRun object
        """
        step_results = []
        for r in data.get("step_results", []):
            step_results.append(
                StepResult(
                    step_id=r["step_id"],
                    status=r["status"],
                    started_at=datetime.fromisoformat(r["started_at"]),
                    completed_at=datetime.fromisoformat(r["completed_at"]),
                    duration_ms=r["duration_ms"],
                    records_processed=r.get("records_processed", 0),
                    output_file=r.get("output_file"),
                    error_message=r.get("error_message"),
                    exit_code=r.get("exit_code", 0),
                )
            )

        return PlaybookRun(
            run_id=UUID(data["run_id"]),
            playbook_id=data["playbook_id"],
            playbook_version=data["playbook_version"],
            target_id=UUID(data["target_id"]),
            case_id=UUID(data["case_id"]) if data.get("case_id") else None,
            status=PlaybookRunStatus(data["status"]),
            current_step=data.get("current_step"),
            completed_steps=data.get("completed_steps", []),
            step_results=step_results,
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            paused_at=datetime.fromisoformat(data["paused_at"]) if data.get("paused_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            error_message=data.get("error_message"),
            variables=data.get("variables", {}),
            output_dir=data.get("output_dir"),
        )
