"""Plugin interface definitions.

Defines the abstract base class for parser plugins and related types.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Literal


@dataclass
class PluginContext:
    """Context provided to plugin during execution."""

    file_path: Path
    artifact_type: str
    options: dict[str, Any] = field(default_factory=dict)
    temp_dir: Path | None = None
    timeout_seconds: int = 300
    max_records: int | None = None


@dataclass
class PluginRecord:
    """A record produced by a plugin."""

    timestamp: datetime | None
    data: dict[str, Any]
    record_type: str = "generic"
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    tags: list[str] = field(default_factory=list)


@dataclass
class PluginResult:
    """Result from plugin execution."""

    success: bool
    records: list[PluginRecord]
    record_count: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    execution_time_ms: int = 0


class ParserPlugin(ABC):
    """Abstract base class for parser plugins.

    Implement this class to create a custom parser plugin.
    Plugins must be stateless and produce consistent output.

    Example:
        class MyCustomParser(ParserPlugin):
            @property
            def name(self) -> str:
                return "my_custom_parser"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def supported_artifacts(self) -> list[str]:
                return ["custom_log"]

            def can_parse(self, file_path: Path) -> bool:
                return file_path.suffix == ".customlog"

            def parse(self, context: PluginContext) -> Iterator[PluginRecord]:
                with open(context.file_path) as f:
                    for line in f:
                        yield PluginRecord(
                            timestamp=None,
                            data={"line": line.strip()},
                        )
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version (semver format)."""
        ...

    @property
    @abstractmethod
    def supported_artifacts(self) -> list[str]:
        """List of artifact types this plugin can parse."""
        ...

    @property
    def description(self) -> str:
        """Human-readable plugin description."""
        return ""

    @property
    def author(self) -> str:
        """Plugin author."""
        return ""

    @property
    def requires_dependencies(self) -> list[str]:
        """List of required Python packages."""
        return []

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if plugin can parse the given file.

        Args:
            file_path: Path to the file to check

        Returns:
            True if plugin can parse this file
        """
        ...

    @abstractmethod
    def parse(self, context: PluginContext) -> Iterator[PluginRecord]:
        """Parse a file and yield records.

        Args:
            context: PluginContext with file path and options

        Yields:
            PluginRecord objects
        """
        ...

    def validate(self) -> list[str]:
        """Validate plugin configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not self.name:
            errors.append("Plugin name is required")
        if not self.version:
            errors.append("Plugin version is required")
        if not self.supported_artifacts:
            errors.append("At least one supported artifact is required")

        return errors

    def get_schema(self) -> dict[str, Any]:
        """Get JSON schema for plugin output.

        Returns:
            JSON Schema dict describing output format
        """
        return {
            "type": "object",
            "properties": {
                "timestamp": {"type": ["string", "null"]},
                "data": {"type": "object"},
                "record_type": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
                "tags": {"type": "array", "items": {"type": "string"}},
            },
        }

    def initialize(self) -> None:
        """Initialize plugin resources.

        Called once when plugin is loaded. Override to perform setup.
        """
        pass

    def cleanup(self) -> None:
        """Clean up plugin resources.

        Called when plugin is unloaded. Override to perform cleanup.
        """
        pass


class PluginError(Exception):
    """Exception raised by plugin operations."""

    def __init__(self, plugin_name: str, message: str):
        self.plugin_name = plugin_name
        self.message = message
        super().__init__(f"[{plugin_name}] {message}")


class PluginLoadError(PluginError):
    """Error loading a plugin."""

    pass


class PluginExecutionError(PluginError):
    """Error executing a plugin."""

    pass
