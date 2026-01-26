"""Evidence collectors for automated artifact acquisition.

Provides collectors for gathering forensic artifacts from:
- Windows systems (Event Logs, Registry, Prefetch, etc.)
- Network devices
- Cloud environments

Collectors support scoped collection to limit what artifacts are gathered.
"""

from scrut.collectors.scope import CollectionScope, ScopeBuilder
from scrut.collectors.windows import WindowsArtifact, WindowsCollector

__all__ = [
    "CollectionScope",
    "ScopeBuilder",
    "WindowsCollector",
    "WindowsArtifact",
]
