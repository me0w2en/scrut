"""Plugin manifest definitions.

Defines the manifest format for plugin metadata and configuration.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class PluginInfo(BaseModel):
    """Basic plugin information."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""
    repository: str = ""


class PluginDependency(BaseModel):
    """A plugin dependency."""

    package: str
    version: str = "*"
    optional: bool = False


class PluginCapability(BaseModel):
    """A capability provided by the plugin."""

    artifact_type: str
    file_extensions: list[str] = []
    mime_types: list[str] = []
    magic_bytes: bytes | None = None


class PluginManifest(BaseModel):
    """Plugin manifest describing metadata and capabilities.

    This manifest is typically stored as plugin.json in the plugin directory.

    Example:
        {
            "name": "custom-log-parser",
            "version": "1.0.0",
            "description": "Parser for custom log format",
            "author": "Your Name",
            "entry_point": "parser.py",
            "plugin_class": "CustomLogParser",
            "capabilities": [
                {
                    "artifact_type": "custom_log",
                    "file_extensions": [".log", ".customlog"]
                }
            ],
            "dependencies": [
                {"package": "python", "version": ">=3.11"}
            ],
            "permissions": ["file_read"]
        }
    """

    name: str = Field(..., min_length=1, max_length=64)
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+")
    description: str = ""
    author: str = ""
    license: str = "MIT"
    homepage: str = ""

    entry_point: str = Field(..., description="Python file containing plugin class")
    plugin_class: str = Field(..., description="Name of the ParserPlugin subclass")

    capabilities: list[PluginCapability] = []
    supported_platforms: list[Literal["windows", "linux", "darwin"]] = [
        "windows",
        "linux",
        "darwin",
    ]

    dependencies: list[PluginDependency] = []
    python_version: str = ">=3.11"

    permissions: list[
        Literal["file_read", "file_write", "network", "subprocess", "env_vars"]
    ] = ["file_read"]
    sandbox: bool = True
    max_memory_mb: int = 512
    max_execution_seconds: int = 300

    tags: list[str] = []
    category: str = "parser"
    min_scrut_version: str = "0.1.0"

    def get_info(self) -> PluginInfo:
        """Get basic plugin info."""
        return PluginInfo(
            name=self.name,
            version=self.version,
            description=self.description,
            author=self.author,
            license=self.license,
            homepage=self.homepage,
        )

    def supports_artifact(self, artifact_type: str) -> bool:
        """Check if plugin supports an artifact type."""
        return any(c.artifact_type == artifact_type for c in self.capabilities)

    def supports_extension(self, extension: str) -> bool:
        """Check if plugin supports a file extension."""
        ext_lower = extension.lower()
        return any(
            ext_lower in [e.lower() for e in c.file_extensions]
            for c in self.capabilities
        )

    def get_artifact_types(self) -> list[str]:
        """Get list of supported artifact types."""
        return [c.artifact_type for c in self.capabilities]


class InstalledPlugin(BaseModel):
    """Metadata for an installed plugin."""

    manifest: PluginManifest
    install_path: str
    installed_at: datetime
    enabled: bool = True
    last_used: datetime | None = None
    error_count: int = 0
    last_error: str | None = None


class PluginRegistry(BaseModel):
    """Registry of installed plugins."""

    plugins: dict[str, InstalledPlugin] = {}
    updated_at: datetime = Field(default_factory=datetime.now)

    def register(self, plugin: InstalledPlugin) -> None:
        """Register a plugin."""
        self.plugins[plugin.manifest.name] = plugin
        self.updated_at = datetime.now()

    def unregister(self, name: str) -> bool:
        """Unregister a plugin."""
        if name in self.plugins:
            del self.plugins[name]
            self.updated_at = datetime.now()
            return True
        return False

    def get(self, name: str) -> InstalledPlugin | None:
        """Get a plugin by name."""
        return self.plugins.get(name)

    def get_enabled(self) -> list[InstalledPlugin]:
        """Get all enabled plugins."""
        return [p for p in self.plugins.values() if p.enabled]

    def find_for_artifact(self, artifact_type: str) -> list[InstalledPlugin]:
        """Find plugins that support an artifact type."""
        return [
            p
            for p in self.plugins.values()
            if p.enabled and p.manifest.supports_artifact(artifact_type)
        ]

    def find_for_extension(self, extension: str) -> list[InstalledPlugin]:
        """Find plugins that support a file extension."""
        return [
            p
            for p in self.plugins.values()
            if p.enabled and p.manifest.supports_extension(extension)
        ]
