"""BAM/DAM (Background Activity Moderator/Desktop Activity Moderator) parser.

Parses BAM/DAM registry entries to track program execution with timestamps.
Available in Windows 10 1709+ (Fall Creators Update).

Locations:
- SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>\\
- SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\<SID>\\
- SYSTEM\\ControlSet001\\Services\\bam\\UserSettings\\<SID>\\ (older format)
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
class BAMEntry:
    """A BAM/DAM execution entry."""

    executable_path: str
    execution_time: datetime | None
    user_sid: str
    source: str  # "bam" or "dam"
    sequence_number: int = 0


class BAMParser:
    """Parser for BAM/DAM registry entries."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[BAMEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse BAM/DAM entries from registry data."""
        if len(self.data) < 100:
            return

        # Parse BAM entries
        self._parse_bam_dam("bam")
        self._parse_bam_dam("dam")

    def _parse_bam_dam(self, source: str) -> None:
        """Parse either BAM or DAM entries."""
        # Look for source pattern in registry
        source_pattern = re.compile(
            rb"\\Services\\" + source.encode() + rb"\\",
            re.IGNORECASE,
        )

        if not source_pattern.search(self.data):
            return

        # Find SID patterns (user directories)
        sid_pattern = re.compile(
            rb"(S-1-5-21-[\d\-]+)",
        )

        sids = set()
        for match in sid_pattern.finditer(self.data):
            try:
                sid = match.group(1).decode("ascii")
                sids.add(sid)
            except Exception:
                pass

        # For each SID, find executable paths with timestamps
        for sid in sids:
            self._parse_user_entries(sid, source)

    def _parse_user_entries(self, sid: str, source: str) -> None:
        """Parse execution entries for a specific user."""
        # Find executable paths
        # BAM stores paths as value names with FILETIME data

        # Look for device paths (\\Device\\HarddiskVolume)
        device_pattern = re.compile(
            rb"(\\Device\\HarddiskVolume\d+\\[^\x00]{5,500})",
        )

        # Also look for regular paths
        path_pattern = re.compile(
            rb"([A-Za-z]:\\[^\x00]{5,500})",
        )

        found_paths = set()

        for pattern in [device_pattern, path_pattern]:
            for match in pattern.finditer(self.data):
                try:
                    path = match.group(1).decode("ascii", errors="replace")
                    if path not in found_paths:
                        found_paths.add(path)

                        # Try to find timestamp near the path
                        timestamp = self._find_timestamp_near(match.start())

                        self.entries.append(
                            BAMEntry(
                                executable_path=path,
                                execution_time=timestamp,
                                user_sid=sid,
                                source=source,
                            )
                        )
                except Exception:
                    pass

        # Also try Unicode paths
        self._parse_unicode_paths(sid, source)

    def _parse_unicode_paths(self, sid: str, source: str) -> None:
        """Parse Unicode executable paths."""
        i = 0
        while i < len(self.data) - 6:
            # Look for \\Device pattern in Unicode
            if (
                self.data[i] == ord("\\")
                and self.data[i + 1] == 0
                and self.data[i + 2] == ord("D")
                and self.data[i + 3] == 0
            ):
                path = self._extract_unicode_path(i)
                if path and "\\Device\\HarddiskVolume" in path:
                    if path not in [e.executable_path for e in self.entries]:
                        timestamp = self._find_timestamp_near(i)
                        self.entries.append(
                            BAMEntry(
                                executable_path=path,
                                execution_time=timestamp,
                                user_sid=sid,
                                source=source,
                            )
                        )
            i += 2

    def _extract_unicode_path(self, start: int) -> str:
        """Extract Unicode path string."""
        chars = []
        i = start
        while i < len(self.data) - 1 and len(chars) < 500:
            if self.data[i + 1] == 0 and 0x20 <= self.data[i] < 0x7F:
                chars.append(chr(self.data[i]))
                i += 2
            elif self.data[i] == 0 and self.data[i + 1] == 0:
                break
            else:
                break
        return "".join(chars)

    def _find_timestamp_near(self, offset: int) -> datetime | None:
        """Find FILETIME timestamp near an offset."""
        # BAM stores timestamp after the path
        # Look in the region after the path

        search_start = offset
        search_end = min(offset + 1000, len(self.data) - 8)

        for i in range(search_start, search_end):
            try:
                filetime = struct.unpack("<Q", self.data[i : i + 8])[0]
                dt = _filetime_to_datetime(filetime)
                if dt and dt.year >= 2017 and dt.year <= 2100:
                    return dt
            except struct.error:
                pass

        return None


@ParserRegistry.register
class BAMFileParser(BaseParser):
    """Parser for BAM/DAM registry entries."""

    name: ClassVar[str] = "bam"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "bam",
        "dam",
        "background_activity",
        "desktop_activity",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize BAM parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse SYSTEM registry hive for BAM/DAM entries."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse BAM/DAM from bytes."""
        parser = BAMParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "executable_path": entry.executable_path,
                "user_sid": entry.user_sid,
                "source": entry.source,
                "source_file": filename,
            }

            # Normalize device path to drive letter if possible
            if entry.executable_path.startswith("\\Device\\HarddiskVolume"):
                record_data["device_path"] = entry.executable_path
                # Extract filename
                parts = entry.executable_path.split("\\")
                if parts:
                    record_data["filename"] = parts[-1]

            if entry.execution_time:
                record_data["execution_time"] = entry.execution_time.isoformat()

            # Analyze for suspicious patterns
            risk_indicators = self._analyze_entry(entry)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "bam_entry",
                entry.executable_path,
                entry.user_sid,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.execution_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_entry(self, entry: BAMEntry) -> list[str]:
        """Analyze BAM entry for suspicious patterns."""
        indicators = []

        path_lower = entry.executable_path.lower()

        # Suspicious locations
        suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
            "\\public\\",
            "\\downloads\\",
            "\\users\\public\\",
        ]
        if any(p in path_lower for p in suspicious_paths):
            indicators.append("suspicious_path")

        # Script hosts
        script_hosts = ["powershell", "cmd.exe", "wscript", "cscript", "mshta"]
        if any(h in path_lower for h in script_hosts):
            indicators.append("script_host_execution")

        # Remote tools
        remote_tools = ["psexec", "paexec", "winrm", "wmic"]
        if any(t in path_lower for t in remote_tools):
            indicators.append("remote_execution_tool")

        # Known hack tools
        hack_tools = ["mimikatz", "procdump", "rubeus", "lazagne", "bloodhound"]
        if any(t in path_lower for t in hack_tools):
            indicators.append("potential_hack_tool")

        return indicators
