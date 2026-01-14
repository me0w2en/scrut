"""Command history tracking for reproducibility.

Records all commands executed during a case for bundle creation
and reproducibility verification.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scrut.models.bundle import CommandRecord


class HistoryManager:
    """Manages command execution history for a case."""

    HISTORY_FILE = "history.jsonl"

    def __init__(self, case_path: Path) -> None:
        """Initialize history manager.

        Args:
            case_path: Path to case directory
        """
        self.case_path = case_path
        self.history_file = case_path / self.HISTORY_FILE
        self._current_command: dict[str, Any] | None = None

    def start_command(
        self,
        command: str,
        args: dict[str, Any] | None = None,
    ) -> None:
        """Record the start of a command execution.

        Args:
            command: Command string
            args: Parsed arguments
        """
        self._current_command = {
            "command": command,
            "args": args or {},
            "started_at": datetime.now(UTC).isoformat(),
        }

    def end_command(
        self,
        exit_code: int,
        output_file: str | None = None,
        output_hash: str | None = None,
    ) -> CommandRecord | None:
        """Record the end of a command execution.

        Args:
            exit_code: Command exit code
            output_file: Path to output file if applicable
            output_hash: SHA-256 hash of output file

        Returns:
            CommandRecord for the completed command
        """
        if not self._current_command:
            return None

        completed_at = datetime.now(UTC)
        started_at = datetime.fromisoformat(self._current_command["started_at"])
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        record = CommandRecord(
            command=self._current_command["command"],
            args=self._current_command["args"],
            exit_code=exit_code,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            output_file=output_file,
            output_hash=output_hash,
        )

        self._append_record(record)

        self._current_command = None
        return record

    def _append_record(self, record: CommandRecord) -> None:
        """Append a record to the history file.

        Args:
            record: Command record to append
        """
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

    def get_history(self) -> list[CommandRecord]:
        """Get all command records from history.

        Returns:
            List of command records
        """
        if not self.history_file.exists():
            return []

        records = []
        with open(self.history_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        records.append(CommandRecord(**data))
                    except (json.JSONDecodeError, ValueError):
                        continue

        return records

    def get_history_since(self, since: datetime) -> list[CommandRecord]:
        """Get command records since a specific time.

        Args:
            since: Start timestamp

        Returns:
            List of command records after the timestamp
        """
        return [r for r in self.get_history() if r.started_at >= since]

    def clear_history(self) -> None:
        """Clear all command history."""
        if self.history_file.exists():
            self.history_file.unlink()
