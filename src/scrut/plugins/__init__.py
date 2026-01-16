"""Plugin system for extending Scrut with custom parsers.

Provides a plugin architecture for:
- Custom artifact parsers
- Third-party integrations
- Organization-specific forensic tools

Plugins are isolated and run in separate processes for security.
"""

from scrut.plugins.interface import ParserPlugin, PluginContext, PluginResult
from scrut.plugins.manifest import PluginManifest, PluginInfo
from scrut.plugins.loader import PluginLoader, discover_plugins
from scrut.plugins.runner import PluginRunner

__all__ = [
    "ParserPlugin",
    "PluginContext",
    "PluginResult",
    "PluginManifest",
    "PluginInfo",
    "PluginLoader",
    "PluginRunner",
    "discover_plugins",
]
