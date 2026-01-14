"""Windows Search History parser.

Parses Windows Search history from registry to track
user searches in Explorer, Start Menu, and Cortana.

Locations:
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU
- %LOCALAPPDATA%\\Packages\\Microsoft.Windows.Cortana_*\\LocalState\\DeviceSearchCache\
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"


@dataclass
class SearchEntry:
    """A search history entry."""

    query: str
    source: str  # WordWheelQuery, TypedPaths, RunMRU, Cortana
    index: int
    timestamp: datetime | None = None


class SearchHistoryParser:
    """Parser for Windows Search history."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[SearchEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse search history from registry data."""
        if len(self.data) < 100:
            return

        self._parse_wordwheelquery()
        self._parse_typedpaths()
        self._parse_runmru()

    def _parse_wordwheelquery(self) -> None:
        """Parse WordWheelQuery (Explorer search box history)."""
        # Look for WordWheelQuery pattern
        wwq_idx = self.data.find(b"WordWheelQuery")
        if wwq_idx == -1:
            return

        # WordWheelQuery stores searches as numbered values (0, 1, 2, ...)
        # and a MRUListEx value with the order

        # Find MRUListEx to get order
        mru_idx = self.data.find(b"MRUListEx", wwq_idx)

        # Look for Unicode strings in the region
        search_start = wwq_idx
        search_end = min(search_start + 10000, len(self.data))
        chunk = self.data[search_start:search_end]

        strings = self._extract_unicode_strings(chunk)

        for i, s in enumerate(strings):
            # Filter out registry key names and short strings
            if len(s) >= 2 and not s.startswith("MRU") and not s.startswith("Word"):
                self.entries.append(
                    SearchEntry(
                        query=s,
                        source="WordWheelQuery",
                        index=i,
                    )
                )

    def _parse_typedpaths(self) -> None:
        """Parse TypedPaths (Explorer address bar history)."""
        tp_idx = self.data.find(b"TypedPaths")
        if tp_idx == -1:
            return

        # TypedPaths stores paths as url1, url2, etc.
        search_start = tp_idx
        search_end = min(search_start + 5000, len(self.data))
        chunk = self.data[search_start:search_end]

        # Look for path patterns
        path_pattern = re.compile(
            rb"url\d+",
            re.IGNORECASE,
        )

        # Extract Unicode paths
        strings = self._extract_unicode_strings(chunk)

        for s in strings:
                if (
                len(s) >= 3
                and (s.startswith("C:") or s.startswith("\\\\") or "://" in s)
            ):
                self.entries.append(
                    SearchEntry(
                        query=s,
                        source="TypedPaths",
                        index=len(self.entries),
                    )
                )

    def _parse_runmru(self) -> None:
        """Parse RunMRU (Run dialog history)."""
        run_idx = self.data.find(b"RunMRU")
        if run_idx == -1:
            return

        search_start = run_idx
        search_end = min(search_start + 5000, len(self.data))
        chunk = self.data[search_start:search_end]

        # RunMRU stores commands as lettered values (a, b, c, ...)
        strings = self._extract_unicode_strings(chunk)

        for s in strings:
            # RunMRU entries end with \1
            if s.endswith("\\1"):
                s = s[:-2]  # Remove \1 suffix

            if (
                len(s) >= 2
                and not s.startswith("MRU")
                and not s.startswith("Run")
                and s not in ["a", "b", "c", "d", "e", "f"]
            ):
                self.entries.append(
                    SearchEntry(
                        query=s,
                        source="RunMRU",
                        index=len(self.entries),
                    )
                )

    def _extract_unicode_strings(self, chunk: bytes, min_length: int = 2) -> list[str]:
        """Extract Unicode strings from a chunk."""
        strings = []
        i = 0
        current = []

        while i < len(chunk) - 1:
            # Check for Unicode character (ASCII followed by null)
            if chunk[i + 1] == 0 and 0x20 <= chunk[i] < 0x7F:
                current.append(chr(chunk[i]))
                i += 2
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []
                i += 1

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings


@ParserRegistry.register
class SearchHistoryFileParser(BaseParser):
    """Parser for Windows Search history."""

    name: ClassVar[str] = "searchhistory"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "searchhistory",
        "search_history",
        "wordwheelquery",
        "typedpaths",
        "runmru",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Search History parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse search history from registry hive."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse search history from bytes."""
        parser = SearchHistoryParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "query": entry.query,
                "source": entry.source,
                "index": entry.index,
                "source_file": filename,
            }

            risk_indicators = self._analyze_search(entry)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "search_entry",
                entry.source,
                entry.index,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_search(self, entry: SearchEntry) -> list[str]:
        """Analyze search entry for suspicious patterns."""
        indicators = []

        query_lower = entry.query.lower()

        sensitive_patterns = [
            "password",
            "credential",
            "secret",
            "private",
            "ssh",
            "vpn",
            "bitcoin",
            "wallet",
        ]
        if any(p in query_lower for p in sensitive_patterns):
            indicators.append("sensitive_search")

        hack_tools = [
            "mimikatz",
            "metasploit",
            "nmap",
            "wireshark",
            "hashcat",
            "john",
            "burp",
            "sqlmap",
        ]
        if any(t in query_lower for t in hack_tools):
            indicators.append("hack_tool_search")

        if entry.source == "RunMRU":
            if "powershell" in query_lower:
                indicators.append("powershell_execution")

            if "cmd" in query_lower:
                indicators.append("cmd_execution")

            if any(t in query_lower for t in ["net ", "netsh", "ipconfig"]):
                indicators.append("network_command")

            if any(t in query_lower for t in ["mstsc", "psexec", "\\\\", "wmic"]):
                indicators.append("remote_access")

        if entry.query.startswith("\\\\"):
            indicators.append("network_path")

        return indicators
