"""RecentApps parser.

Parses RecentApps registry entries to track recently used applications
in Windows 10+.

Locations:
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\
- Each app has a GUID subkey with LastAccessedTime and AppId
"""

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"


def _filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME to datetime."""
    if filetime == 0 or filetime < 0:
        return None
    try:
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return None
        timestamp = (filetime - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (OSError, ValueError, OverflowError):
        return None


@dataclass
class RecentAppEntry:
    """A recent app entry."""

    app_guid: str
    app_id: str
    app_path: str
    last_accessed: datetime | None
    launch_count: int


class RecentAppsParser:
    """Parser for RecentApps registry entries."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[RecentAppEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse RecentApps from registry data."""
        if len(self.data) < 100:
            return

        # Find RecentApps key
        recent_idx = self.data.find(b"RecentApps")
        if recent_idx == -1:
            return

        # Find app GUIDs under RecentApps
        guid_pattern = re.compile(
            rb"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}",
        )

        found_guids = set()
        for match in guid_pattern.finditer(self.data[recent_idx:]):
            guid = match.group(0).decode("ascii")
            if guid not in found_guids:
                found_guids.add(guid)
                entry = self._extract_app_entry(guid, recent_idx + match.start())
                if entry:
                    self.entries.append(entry)

    def _extract_app_entry(self, guid: str, offset: int) -> RecentAppEntry | None:
        """Extract app entry data for a GUID."""
        # Search for related values near the GUID
        start = max(0, offset - 100)
        end = min(len(self.data), offset + 2000)
        chunk = self.data[start:end]

        # Look for AppId value
        app_id = ""
        app_path = ""

        # Find AppId (usually contains executable path or app user model ID)
        app_id_patterns = [
            # UWP app format
            rb"([A-Za-z0-9_\.\-]+![A-Za-z0-9_\.\-]+)",
            rb"([A-Za-z]:\\[^\x00]{5,260}\.exe)",
        ]

        for pattern in app_id_patterns:
            match = re.search(pattern, chunk)
            if match:
                try:
                    app_id = match.group(1).decode("ascii", errors="replace")
                    if "\\" in app_id:
                        app_path = app_id
                    break
                except Exception:
                    pass

        # Also try Unicode extraction
        if not app_id:
            app_id = self._extract_unicode_app_id(chunk)

        # Find LastAccessedTime
        last_accessed = None
        la_idx = chunk.find(b"LastAccessedTime")
        if la_idx != -1:
            # Look for FILETIME after the value name
            for i in range(la_idx + 16, min(la_idx + 100, len(chunk) - 8)):
                try:
                    filetime = struct.unpack("<Q", chunk[i : i + 8])[0]
                    dt = _filetime_to_datetime(filetime)
                    if dt and dt.year >= 2015 and dt.year <= 2100:
                        last_accessed = dt
                        break
                except struct.error:
                    pass

        # Find LaunchCount
        launch_count = 0
        lc_idx = chunk.find(b"LaunchCount")
        if lc_idx != -1:
            for i in range(lc_idx + 11, min(lc_idx + 50, len(chunk) - 4)):
                try:
                    count = struct.unpack("<I", chunk[i : i + 4])[0]
                    if count < 100000:  # Reasonable count
                        launch_count = count
                        break
                except struct.error:
                    pass

        if app_id or last_accessed:
            return RecentAppEntry(
                app_guid=guid,
                app_id=app_id,
                app_path=app_path,
                last_accessed=last_accessed,
                launch_count=launch_count,
            )

        return None

    def _extract_unicode_app_id(self, chunk: bytes) -> str:
        """Extract Unicode app ID from chunk."""
        # Look for common app ID patterns
        i = 0
        while i < len(chunk) - 4:
            # Look for drive letter in Unicode
            if (
                chunk[i] in range(65, 91)  # A-Z
                and chunk[i + 1] == 0
                and chunk[i + 2] == ord(":")
                and chunk[i + 3] == 0
            ):
                path = self._extract_unicode_string(chunk, i)
                if path and ".exe" in path.lower():
                    return path
            i += 2
        return ""

    def _extract_unicode_string(self, chunk: bytes, start: int) -> str:
        """Extract Unicode string from chunk."""
        chars = []
        i = start
        while i < len(chunk) - 1 and len(chars) < 300:
            if chunk[i + 1] == 0 and 0x20 <= chunk[i] < 0x7F:
                chars.append(chr(chunk[i]))
                i += 2
            else:
                break
        return "".join(chars)


@ParserRegistry.register
class RecentAppsFileParser(BaseParser):
    """Parser for RecentApps registry entries."""

    name: ClassVar[str] = "recentapps"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "recentapps",
        "recent_apps",
        "recent_applications",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize RecentApps parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse RecentApps from registry hive."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse RecentApps from bytes."""
        parser = RecentAppsParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "app_guid": entry.app_guid,
                "source_file": filename,
            }

            if entry.app_id:
                record_data["app_id"] = entry.app_id
            if entry.app_path:
                record_data["app_path"] = entry.app_path
                try:
                    record_data["filename"] = Path(entry.app_path).name
                except Exception:
                    pass
            if entry.last_accessed:
                record_data["last_accessed"] = entry.last_accessed.isoformat()
            if entry.launch_count:
                record_data["launch_count"] = entry.launch_count

            risk_indicators = self._analyze_entry(entry)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "recent_app",
                entry.app_guid,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.last_accessed,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_entry(self, entry: RecentAppEntry) -> list[str]:
        """Analyze app entry for suspicious patterns."""
        indicators = []

        path_lower = (entry.app_path or entry.app_id or "").lower()

        suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
            "\\downloads\\",
            "\\public\\",
        ]
        if any(p in path_lower for p in suspicious_paths):
            indicators.append("suspicious_path")

        script_hosts = ["powershell", "cmd.exe", "wscript", "cscript", "mshta"]
        if any(h in path_lower for h in script_hosts):
            indicators.append("script_host")

        remote_tools = ["psexec", "mstsc", "wmic", "winrm"]
        if any(t in path_lower for t in remote_tools):
            indicators.append("remote_tool")

        hack_tools = ["mimikatz", "procdump", "lazagne", "rubeus", "bloodhound"]
        if any(t in path_lower for t in hack_tools):
            indicators.append("potential_hack_tool")

        return indicators
