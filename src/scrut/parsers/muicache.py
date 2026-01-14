r"""MUICache parser.

Parses MUICache registry entries to track program execution.
MUICache stores display names of executed applications.

Location:
- NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
- UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"


@dataclass
class MUICacheEntry:
    """A MUICache entry representing an executed application."""

    executable_path: str
    display_name: str
    entry_type: str  # FriendlyAppName, ApplicationCompany, etc.


class MUICacheParser:
    """Parser for MUICache registry entries."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[MUICacheEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse MUICache entries from registry data."""
        if len(self.data) < 100:
            return

        # Look for MuiCache key pattern
        muicache_idx = self.data.find(b"MuiCache")
        if muicache_idx == -1:
            # Try alternate spellings
            muicache_idx = self.data.find(b"MUICache")

        if muicache_idx == -1:
            return

        # Search for executable path patterns with associated display names
        # MUICache entries have format: path.FriendlyAppName = DisplayName
        # Or: path.ApplicationCompany = CompanyName

        # Find all .exe, .dll, .msc, etc. paths
        path_pattern = re.compile(
            rb"([A-Za-z]:\\[^\\/:*?\"<>|\x00]{1,200}(?:\\[^\\/:*?\"<>|\x00]{1,200})*\.[A-Za-z]{2,4})",
            re.IGNORECASE,
        )

        found_paths = set()
        for match in path_pattern.finditer(self.data):
            try:
                path = match.group(1).decode("ascii", errors="replace")
                if path not in found_paths:
                    found_paths.add(path)
                    entry = self._extract_entry(path, match.start())
                    if entry:
                        self.entries.append(entry)
            except Exception:
                pass

        # Also look for Unicode paths
        self._parse_unicode_paths()

    def _parse_unicode_paths(self) -> None:
        """Parse Unicode path entries."""
        i = 0
        while i < len(self.data) - 4:
            # Look for drive letter pattern in Unicode (C:\)
            if (
                self.data[i] in range(65, 91)  # A-Z
                and self.data[i + 1] == 0
                and self.data[i + 2] == ord(":")
                and self.data[i + 3] == 0
                and self.data[i + 4] == ord("\\")
                and self.data[i + 5] == 0
            ):
                # Extract Unicode string
                path = self._extract_unicode_string(i)
                if path and len(path) > 5:
                    # Check if it looks like a valid path
                    if "\\" in path and "." in path:
                        entry = self._extract_entry_for_path(path)
                        if entry and entry.executable_path not in [
                            e.executable_path for e in self.entries
                        ]:
                            self.entries.append(entry)
            i += 2

    def _extract_unicode_string(self, start: int) -> str:
        """Extract a Unicode string starting at offset."""
        chars = []
        i = start
        while i < len(self.data) - 1 and len(chars) < 300:
            if self.data[i + 1] == 0 and 0x20 <= self.data[i] < 0x7F:
                chars.append(chr(self.data[i]))
                i += 2
            elif self.data[i] == 0 and self.data[i + 1] == 0:
                break
            else:
                break
        return "".join(chars)

    def _extract_entry(self, path: str, offset: int) -> MUICacheEntry | None:
        """Extract MUICache entry for a path."""
        # Look for display name near the path
        start = max(0, offset - 200)
        end = min(len(self.data), offset + len(path) + 500)
        chunk = self.data[start:end]

        # Try to find FriendlyAppName value
        display_name = ""
        entry_type = "FriendlyAppName"

        # Look for Unicode string after the path
        path_idx = chunk.find(path.encode("ascii", errors="replace"))
        if path_idx != -1:
            search_start = path_idx + len(path)
            # Look for display name pattern
            for i in range(search_start, min(search_start + 200, len(chunk) - 1)):
                if chunk[i + 1] == 0 and 0x20 <= chunk[i] < 0x7F:
                    # Found start of Unicode string
                    display_name = self._extract_unicode_from_chunk(chunk, i)
                    if display_name and len(display_name) >= 2:
                        break

        if not display_name:
            # Use filename as display name
            display_name = Path(path).stem

        return MUICacheEntry(
            executable_path=path,
            display_name=display_name,
            entry_type=entry_type,
        )

    def _extract_entry_for_path(self, path: str) -> MUICacheEntry | None:
        """Create a basic entry for a path."""
        display_name = Path(path).stem
        return MUICacheEntry(
            executable_path=path,
            display_name=display_name,
            entry_type="FriendlyAppName",
        )

    def _extract_unicode_from_chunk(self, chunk: bytes, start: int) -> str:
        """Extract Unicode string from chunk."""
        chars = []
        i = start
        while i < len(chunk) - 1 and len(chars) < 200:
            if chunk[i + 1] == 0 and 0x20 <= chunk[i] < 0x7F:
                chars.append(chr(chunk[i]))
                i += 2
            else:
                break
        return "".join(chars)


@ParserRegistry.register
class MUICacheFileParser(BaseParser):
    """Parser for MUICache registry entries."""

    name: ClassVar[str] = "muicache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "muicache",
        "mui_cache",
        "program_execution",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize MUICache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse MUICache from registry hive."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse MUICache from bytes."""
        parser = MUICacheParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "executable_path": entry.executable_path,
                "display_name": entry.display_name,
                "entry_type": entry.entry_type,
                "source_file": filename,
            }

            # Extract filename and extension
            try:
                path_obj = Path(entry.executable_path)
                record_data["filename"] = path_obj.name
                record_data["extension"] = path_obj.suffix.lower()

                # Extract directory
                record_data["directory"] = str(path_obj.parent)
            except Exception:
                pass

            # Analyze for suspicious patterns
            risk_indicators = self._analyze_entry(entry)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "muicache", entry.executable_path
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=None,  # MUICache doesn't store timestamps
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_entry(self, entry: MUICacheEntry) -> list[str]:
        """Analyze MUICache entry for suspicious patterns."""
        indicators = []

        path_lower = entry.executable_path.lower()

        # Suspicious paths
        suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
            "\\public\\",
            "\\downloads\\",
            "\\desktop\\",
        ]
        if any(p in path_lower for p in suspicious_paths):
            indicators.append("suspicious_path")

        # Script interpreters
        script_hosts = ["powershell", "cmd.exe", "wscript", "cscript", "mshta"]
        if any(h in path_lower for h in script_hosts):
            indicators.append("script_host")

        # Remote execution tools
        remote_tools = ["psexec", "winrm", "wmic", "mstsc"]
        if any(t in path_lower for t in remote_tools):
            indicators.append("remote_execution_tool")

        # Hacking tools
        hack_tools = ["mimikatz", "procdump", "lazagne", "rubeus"]
        if any(t in path_lower for t in hack_tools):
            indicators.append("potential_hack_tool")

        # Unusual extension
        ext = Path(entry.executable_path).suffix.lower()
        if ext and ext not in [".exe", ".msc", ".cpl", ".dll"]:
            indicators.append("unusual_extension")

        return indicators
