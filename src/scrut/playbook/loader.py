"""Playbook loader for YAML/JSON playbook definitions.

Loads playbook definitions from files and validates them against
the Playbook model schema.
"""

import re
from pathlib import Path
from typing import Any

import yaml

from scrut.core.errors import ScrutError
from scrut.models.playbook import Playbook, PlaybookStep


class PlaybookNotFoundError(ScrutError):
    """Raised when a playbook cannot be found."""

    def __init__(self, playbook_name: str, search_paths: list[Path]) -> None:
        super().__init__(
            code="PLAYBOOK_NOT_FOUND",
            message=f"Playbook '{playbook_name}' not found",
            remediation=f"Check that the playbook exists in one of: {[str(p) for p in search_paths]}",
            retryable=False,
            context={"playbook_name": playbook_name, "search_paths": [str(p) for p in search_paths]},
        )


class PlaybookValidationError(ScrutError):
    """Raised when a playbook fails validation."""

    def __init__(self, playbook_path: Path, errors: list[str]) -> None:
        super().__init__(
            code="PLAYBOOK_VALIDATION_ERROR",
            message=f"Playbook '{playbook_path}' failed validation",
            remediation="Fix the validation errors and try again",
            retryable=False,
            context={"playbook_path": str(playbook_path), "errors": errors},
        )


class PlaybookLoader:
    """Loads playbook definitions from YAML/JSON files."""

    BUILTIN_PATH = Path(__file__).parent.parent.parent.parent / "playbooks"

    def __init__(self, playbook_paths: list[Path] | None = None) -> None:
        """Initialize the playbook loader.

        Args:
            playbook_paths: Additional paths to search for playbooks
        """
        self.paths: list[Path] = []
        if self.BUILTIN_PATH.exists():
            self.paths.append(self.BUILTIN_PATH)
        if playbook_paths:
            self.paths.extend(playbook_paths)

    def load(self, name: str, variables: dict[str, Any] | None = None) -> Playbook:
        """Load a playbook by name.

        Args:
            name: Playbook name (without extension) or path
            variables: Variable overrides for substitution

        Returns:
            Loaded Playbook object

        Raises:
            PlaybookNotFoundError: If playbook cannot be found
            PlaybookValidationError: If playbook fails validation
        """
        playbook_path = self._find_playbook(name)
        if playbook_path is None:
            raise PlaybookNotFoundError(name, self.paths)

        return self._load_file(playbook_path, variables)

    def list_playbooks(self) -> list[dict[str, Any]]:
        """List all available playbooks.

        Returns:
            List of playbook metadata dictionaries
        """
        playbooks = []

        for search_path in self.paths:
            if not search_path.exists():
                continue

            for yaml_file in search_path.glob("*.yaml"):
                try:
                    playbook = self._load_file(yaml_file)
                    playbooks.append({
                        "playbook_id": playbook.playbook_id,
                        "name": playbook.name,
                        "description": playbook.description,
                        "version": playbook.version,
                        "author": playbook.author,
                        "tags": playbook.tags,
                        "steps_count": len(playbook.steps),
                        "path": str(yaml_file),
                    })
                except Exception:
                    continue

            for yml_file in search_path.glob("*.yml"):
                try:
                    playbook = self._load_file(yml_file)
                    playbooks.append({
                        "playbook_id": playbook.playbook_id,
                        "name": playbook.name,
                        "description": playbook.description,
                        "version": playbook.version,
                        "author": playbook.author,
                        "tags": playbook.tags,
                        "steps_count": len(playbook.steps),
                        "path": str(yml_file),
                    })
                except Exception:
                    continue

        return playbooks

    def _find_playbook(self, name: str) -> Path | None:
        """Find a playbook file by name.

        Args:
            name: Playbook name or path

        Returns:
            Path to playbook file or None if not found
        """
        if Path(name).exists():
            return Path(name)

        name_path = Path(name)
        if name_path.suffix in (".yaml", ".yml"):
            base_name = name_path.stem
        else:
            base_name = name

        for search_path in self.paths:
            for ext in (".yaml", ".yml"):
                candidate = search_path / f"{base_name}{ext}"
                if candidate.exists():
                    return candidate

        return None

    def _load_file(
        self, path: Path, variables: dict[str, Any] | None = None
    ) -> Playbook:
        """Load and parse a playbook file.

        Args:
            path: Path to playbook file
            variables: Variable overrides

        Returns:
            Parsed Playbook object
        """
        with open(path, encoding="utf-8") as f:
            content = f.read()

        if variables:
            content = self._substitute_variables(content, variables)

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise PlaybookValidationError(path, [f"YAML parse error: {e}"])

        errors = self._validate_playbook_data(data, path)
        if errors:
            raise PlaybookValidationError(path, errors)

        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(**step_data))

        return Playbook(
            playbook_id=data.get("playbook_id", path.stem),
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            author=data.get("author"),
            tags=data.get("tags", []),
            steps=steps,
            variables=data.get("variables", {}),
            estimated_duration_seconds=data.get("estimated_duration_seconds"),
        )

    def _substitute_variables(
        self, content: str, variables: dict[str, Any]
    ) -> str:
        """Substitute variables in playbook content.

        Supports ${VAR} and ${VAR:-default} syntax.

        Args:
            content: Raw playbook content
            variables: Variable values

        Returns:
            Content with variables substituted
        """
        def replace_var(match: re.Match[str]) -> str:
            var_expr = match.group(1)
            if ":-" in var_expr:
                var_name, default = var_expr.split(":-", 1)
                return str(variables.get(var_name, default))
            return str(variables.get(var_expr, match.group(0)))

        pattern = r"\$\{([^}]+)\}"
        return re.sub(pattern, replace_var, content)

    def _validate_playbook_data(
        self, data: dict[str, Any], path: Path
    ) -> list[str]:
        """Validate playbook data structure.

        Args:
            data: Parsed YAML data
            path: Path to playbook file

        Returns:
            List of validation errors
        """
        errors = []

        if not isinstance(data, dict):
            errors.append("Playbook must be a YAML object")
            return errors

        if "name" not in data:
            errors.append("Missing required field: name")

        steps = data.get("steps", [])
        if not isinstance(steps, list):
            errors.append("'steps' must be a list")
        elif len(steps) == 0:
            errors.append("Playbook must have at least one step")
        else:
            step_ids = set()
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    errors.append(f"Step {i} must be an object")
                    continue

                if "step_id" not in step:
                    errors.append(f"Step {i} missing required field: step_id")
                else:
                    if step["step_id"] in step_ids:
                        errors.append(f"Duplicate step_id: {step['step_id']}")
                    step_ids.add(step["step_id"])

                if "name" not in step:
                    errors.append(f"Step {i} missing required field: name")

                if "command" not in step:
                    errors.append(f"Step {i} missing required field: command")

                if "depends_on" in step:
                    for dep in step["depends_on"]:
                        if dep not in step_ids and dep not in [
                            s.get("step_id") for s in steps
                        ]:
                            pass

                if "on_error" in step:
                    valid_actions = {"continue", "stop", "skip"}
                    if step["on_error"] not in valid_actions:
                        errors.append(
                            f"Step {step.get('step_id', i)}: invalid on_error value '{step['on_error']}'. "
                            f"Must be one of: {valid_actions}"
                        )

        return errors
