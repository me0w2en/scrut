"""Plugin discovery and loading.

Discovers and loads plugins from configured directories.
"""

import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from scrut.plugins.interface import (
    ParserPlugin,
    PluginError,
    PluginLoadError,
)
from scrut.plugins.manifest import (
    InstalledPlugin,
    PluginManifest,
    PluginRegistry,
)


DEFAULT_PLUGIN_DIRS = [
    Path.home() / ".scrut" / "plugins",
    Path("/etc/scrut/plugins"),
]


class PluginLoader:
    """Loads and manages plugins."""

    def __init__(
        self,
        plugin_dirs: list[Path] | None = None,
        registry_path: Path | None = None,
    ) -> None:
        """Initialize the plugin loader.

        Args:
            plugin_dirs: Directories to search for plugins
            registry_path: Path to plugin registry file
        """
        self._plugin_dirs = plugin_dirs or DEFAULT_PLUGIN_DIRS
        self._registry_path = registry_path or (
            Path.home() / ".scrut" / "plugin_registry.json"
        )
        self._loaded_plugins: dict[str, ParserPlugin] = {}
        self._registry: PluginRegistry | None = None

    @property
    def registry(self) -> PluginRegistry:
        """Get the plugin registry, loading if necessary."""
        if self._registry is None:
            self._registry = self._load_registry()
        return self._registry

    def _load_registry(self) -> PluginRegistry:
        """Load registry from disk."""
        if self._registry_path.exists():
            try:
                data = json.loads(self._registry_path.read_text())
                return PluginRegistry(**data)
            except Exception:
                pass
        return PluginRegistry()

    def _save_registry(self) -> None:
        """Save registry to disk."""
        if self._registry:
            self._registry_path.parent.mkdir(parents=True, exist_ok=True)
            self._registry_path.write_text(
                self._registry.model_dump_json(indent=2)
            )

    def discover(self) -> list[PluginManifest]:
        """Discover available plugins in plugin directories.

        Returns:
            List of plugin manifests found
        """
        manifests = []

        for plugin_dir in self._plugin_dirs:
            if not plugin_dir.exists():
                continue

            for item in plugin_dir.iterdir():
                if item.is_dir():
                    manifest = self._load_manifest(item)
                    if manifest:
                        manifests.append(manifest)

        return manifests

    def _load_manifest(self, plugin_path: Path) -> PluginManifest | None:
        """Load plugin manifest from directory."""
        manifest_file = plugin_path / "plugin.json"
        if not manifest_file.exists():
            return None

        try:
            data = json.loads(manifest_file.read_text())
            return PluginManifest(**data)
        except Exception:
            return None

    def install(self, plugin_path: Path) -> InstalledPlugin:
        """Install a plugin from a directory.

        Args:
            plugin_path: Path to plugin directory

        Returns:
            InstalledPlugin metadata

        Raises:
            PluginLoadError: If plugin cannot be installed
        """
        manifest = self._load_manifest(plugin_path)
        if not manifest:
            raise PluginLoadError(
                str(plugin_path), "No valid plugin.json manifest found"
            )

        plugin = self._load_plugin_class(plugin_path, manifest)
        errors = plugin.validate()
        if errors:
            raise PluginLoadError(manifest.name, f"Validation errors: {errors}")

        installed = InstalledPlugin(
            manifest=manifest,
            install_path=str(plugin_path),
            installed_at=datetime.now(),
            enabled=True,
        )

        self.registry.register(installed)
        self._save_registry()

        return installed

    def uninstall(self, plugin_name: str) -> bool:
        """Uninstall a plugin.

        Args:
            plugin_name: Name of plugin to uninstall

        Returns:
            True if plugin was uninstalled
        """
        if plugin_name in self._loaded_plugins:
            plugin = self._loaded_plugins[plugin_name]
            plugin.cleanup()
            del self._loaded_plugins[plugin_name]

        result = self.registry.unregister(plugin_name)
        if result:
            self._save_registry()

        return result

    def load(self, plugin_name: str) -> ParserPlugin:
        """Load a plugin by name.

        Args:
            plugin_name: Name of the plugin to load

        Returns:
            Loaded ParserPlugin instance

        Raises:
            PluginLoadError: If plugin cannot be loaded
        """
        if plugin_name in self._loaded_plugins:
            return self._loaded_plugins[plugin_name]

        installed = self.registry.get(plugin_name)
        if not installed:
            raise PluginLoadError(plugin_name, "Plugin not installed")

        if not installed.enabled:
            raise PluginLoadError(plugin_name, "Plugin is disabled")

        plugin_path = Path(installed.install_path)
        plugin = self._load_plugin_class(plugin_path, installed.manifest)

        plugin.initialize()

        self._loaded_plugins[plugin_name] = plugin

        installed.last_used = datetime.now()
        self._save_registry()

        return plugin

    def _load_plugin_class(
        self, plugin_path: Path, manifest: PluginManifest
    ) -> ParserPlugin:
        """Load the plugin class from a plugin directory."""
        entry_point = plugin_path / manifest.entry_point

        if not entry_point.exists():
            raise PluginLoadError(
                manifest.name, f"Entry point not found: {manifest.entry_point}"
            )

        try:
            spec = importlib.util.spec_from_file_location(
                f"scrut_plugin_{manifest.name}", entry_point
            )
            if spec is None or spec.loader is None:
                raise PluginLoadError(manifest.name, "Failed to create module spec")

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            plugin_class = getattr(module, manifest.plugin_class, None)
            if plugin_class is None:
                raise PluginLoadError(
                    manifest.name,
                    f"Plugin class not found: {manifest.plugin_class}",
                )

            if not issubclass(plugin_class, ParserPlugin):
                raise PluginLoadError(
                    manifest.name,
                    f"{manifest.plugin_class} is not a ParserPlugin subclass",
                )

            return plugin_class()

        except PluginLoadError:
            raise
        except Exception as e:
            raise PluginLoadError(manifest.name, f"Failed to load: {e}")

    def load_all(self) -> dict[str, ParserPlugin]:
        """Load all enabled plugins.

        Returns:
            Dict mapping plugin names to instances
        """
        loaded = {}
        for installed in self.registry.get_enabled():
            try:
                plugin = self.load(installed.manifest.name)
                loaded[installed.manifest.name] = plugin
            except PluginError:
                pass
        return loaded

    def unload(self, plugin_name: str) -> None:
        """Unload a plugin.

        Args:
            plugin_name: Name of plugin to unload
        """
        if plugin_name in self._loaded_plugins:
            plugin = self._loaded_plugins[plugin_name]
            plugin.cleanup()
            del self._loaded_plugins[plugin_name]

    def unload_all(self) -> None:
        """Unload all loaded plugins."""
        for plugin_name in list(self._loaded_plugins.keys()):
            self.unload(plugin_name)

    def get_loaded(self) -> dict[str, ParserPlugin]:
        """Get all currently loaded plugins."""
        return dict(self._loaded_plugins)

    def enable(self, plugin_name: str) -> bool:
        """Enable a plugin.

        Args:
            plugin_name: Name of plugin to enable

        Returns:
            True if plugin was enabled
        """
        installed = self.registry.get(plugin_name)
        if installed:
            installed.enabled = True
            self._save_registry()
            return True
        return False

    def disable(self, plugin_name: str) -> bool:
        """Disable a plugin.

        Args:
            plugin_name: Name of plugin to disable

        Returns:
            True if plugin was disabled
        """
        self.unload(plugin_name)

        installed = self.registry.get(plugin_name)
        if installed:
            installed.enabled = False
            self._save_registry()
            return True
        return False


def discover_plugins(
    plugin_dirs: list[Path] | None = None,
) -> list[PluginManifest]:
    """Discover available plugins.

    Args:
        plugin_dirs: Optional list of directories to search

    Returns:
        List of plugin manifests found
    """
    loader = PluginLoader(plugin_dirs=plugin_dirs)
    return loader.discover()
