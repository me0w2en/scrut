r"""Syscache parser.

Parses Syscache.hve registry hive to track file execution and
object access on Windows systems (primarily Windows 7).

Location:
- %SystemRoot%\System32\config\syscache.hve
- %SystemRoot%\AppCompat\Programs\Amcache.hve (replacement in Win8+)

The Syscache.hve contains ObjectTable entries that record
files/objects accessed on the system.
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
class SyscacheEntry:
    """A syscache entry representing a file/object access."""

    object_id: str
    file_path: str
    file_name: str
    sha1_hash: str
    last_modified: datetime | None
    file_size: int
    usn: int  # USN Journal sequence number


class SyscacheParser:
    """Parser for Syscache.hve registry hive."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[SyscacheEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse Syscache.hve data."""
        if len(self.data) < 4096:
            return

        # Check for registry hive signature
        if self.data[:4] != b"regf":
            return

        # Parse object table entries
        self._parse_object_table()

    def _parse_object_table(self) -> None:
        """Parse ObjectTable entries from syscache."""
        # Look for ObjectTable key
        obj_idx = self.data.find(b"ObjectTable")
        if obj_idx == -1:
            # Try alternate locations
            obj_idx = self.data.find(b"Object")

        if obj_idx == -1:
            return

        # Find file path entries
        # Syscache stores paths and associated metadata

        # Look for device paths
        device_pattern = re.compile(
            rb"(\\Device\\HarddiskVolume\d+\\[^\x00]{5,300})",
        )

        for match in device_pattern.finditer(self.data):
            try:
                path = match.group(1).decode("ascii", errors="replace")
                entry = self._extract_entry(path, match.start())
                if entry:
                    self.entries.append(entry)
            except Exception:
                pass

        # Also look for regular paths in Unicode
        self._parse_unicode_entries()

    def _parse_unicode_entries(self) -> None:
        """Parse Unicode path entries."""
        i = 0
        while i < len(self.data) - 6:
            # Look for \\Device pattern in Unicode
            if (
                self.data[i] == ord("\\")
                and self.data[i + 1] == 0
                and self.data[i + 2] == ord("D")
                and self.data[i + 3] == 0
                and self.data[i + 4] == ord("e")
                and self.data[i + 5] == 0
            ):
                path = self._extract_unicode_string(i)
                if path and "HarddiskVolume" in path:
                    if path not in [e.file_path for e in self.entries]:
                        entry = self._extract_entry(path, i)
                        if entry:
                            self.entries.append(entry)
            i += 2

    def _extract_entry(self, path: str, offset: int) -> SyscacheEntry | None:
        """Extract syscache entry for a file path."""
        # Search for associated metadata
        start = max(0, offset - 500)
        end = min(len(self.data), offset + 1000)
        chunk = self.data[start:end]

        # Extract file name from path
        file_name = ""
        if "\\" in path:
            file_name = path.split("\\")[-1]

        # Look for SHA1 hash (20 bytes, often stored nearby)
        sha1_hash = ""
        # SHA1 hashes in syscache are sometimes stored as hex strings
        sha1_pattern = re.compile(rb"[0-9A-Fa-f]{40}")
        sha1_match = sha1_pattern.search(chunk)
        if sha1_match:
            sha1_hash = sha1_match.group().decode("ascii")

        # Look for timestamp
        last_modified = None
        for i in range(0, len(chunk) - 8, 4):
            try:
                filetime = struct.unpack("<Q", chunk[i : i + 8])[0]
                dt = _filetime_to_datetime(filetime)
                if dt and dt.year >= 2000 and dt.year <= 2100:
                    last_modified = dt
                    break
            except struct.error:
                pass

        # Look for file size
        file_size = 0
        for i in range(0, len(chunk) - 8, 4):
            try:
                size = struct.unpack("<Q", chunk[i : i + 8])[0]
                # Reasonable file size (< 10GB)
                if 1000 < size < 10_000_000_000:
                    file_size = size
                    break
            except struct.error:
                pass

        # Look for USN
        usn = 0

        # Only include if we have meaningful data
        if file_name or sha1_hash or last_modified:
            # Generate object ID
            object_id = f"obj_{offset:08x}"

            return SyscacheEntry(
                object_id=object_id,
                file_path=path,
                file_name=file_name,
                sha1_hash=sha1_hash,
                last_modified=last_modified,
                file_size=file_size,
                usn=usn,
            )

        return None

    def _extract_unicode_string(self, start: int) -> str:
        """Extract Unicode string from offset."""
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


@ParserRegistry.register
class SyscacheFileParser(BaseParser):
    """Parser for Syscache.hve registry hive."""

    name: ClassVar[str] = "syscache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "syscache",
        "syscache.hve",
        "object_table",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Syscache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Syscache.hve file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse Syscache from bytes."""
        parser = SyscacheParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "object_id": entry.object_id,
                "file_path": entry.file_path,
                "source_file": filename,
            }

            if entry.file_name:
                record_data["file_name"] = entry.file_name
                # Extract extension
                if "." in entry.file_name:
                    record_data["extension"] = entry.file_name.split(".")[-1].lower()

            if entry.sha1_hash:
                record_data["sha1_hash"] = entry.sha1_hash

            if entry.last_modified:
                record_data["last_modified"] = entry.last_modified.isoformat()

            if entry.file_size:
                record_data["file_size"] = entry.file_size

            if entry.usn:
                record_data["usn"] = entry.usn

            # Analyze for suspicious patterns
            risk_indicators = self._analyze_entry(entry)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "syscache_entry",
                entry.object_id,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.last_modified,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_entry(self, entry: SyscacheEntry) -> list[str]:
        """Analyze syscache entry for suspicious patterns."""
        indicators = []

        path_lower = entry.file_path.lower()

        # Suspicious locations
        suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
        ]
        if any(p in path_lower for p in suspicious_paths):
            indicators.append("suspicious_path")

        # Script files
        script_extensions = [".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"]
        if entry.file_name:
            if any(entry.file_name.lower().endswith(ext) for ext in script_extensions):
                indicators.append("script_file")

        # Executables in suspicious locations
        if entry.file_name and entry.file_name.lower().endswith(".exe"):
            if any(p in path_lower for p in suspicious_paths):
                indicators.append("suspicious_executable")

        # Known malware tools
        hack_tools = ["mimikatz", "procdump", "psexec", "lazagne"]
        if any(t in path_lower for t in hack_tools):
            indicators.append("potential_hack_tool")

        return indicators
