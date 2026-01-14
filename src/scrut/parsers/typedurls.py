r"""TypedURLs parser.

Parses TypedURLs registry entries to track URLs typed in
Internet Explorer and legacy Edge browser address bar.

Locations:
- NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs
- NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLsTime (IE10+)
- NTUSER.DAT\Software\Microsoft\Edge\TypedURLs
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
class TypedURLEntry:
    """A typed URL entry."""

    url: str
    index: int
    timestamp: datetime | None
    browser: str  # IE, Edge


class TypedURLsParser:
    """Parser for TypedURLs registry entries."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[TypedURLEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse TypedURLs from registry data."""
        if len(self.data) < 100:
            return

        self._parse_typed_urls("Internet Explorer", "IE")

        self._parse_typed_urls("Edge", "Edge")

    def _parse_typed_urls(self, browser_key: str, browser_name: str) -> None:
        """Parse TypedURLs for a specific browser."""
        browser_bytes = browser_key.encode("ascii")
        browser_idx = self.data.find(browser_bytes)

        if browser_idx == -1:
            return

        typed_idx = self.data.find(b"TypedURLs", browser_idx)
        if typed_idx == -1:
            return

        search_start = typed_idx
        search_end = min(search_start + 10000, len(self.data))
        chunk = self.data[search_start:search_end]

        time_idx = self.data.find(b"TypedURLsTime", browser_idx)
        time_chunk = None
        if time_idx != -1:
            time_chunk = self.data[time_idx : min(time_idx + 10000, len(self.data))]

        url_pattern = re.compile(rb"url(\d+)")

        url_indices = set()
        for match in url_pattern.finditer(chunk):
            try:
                idx = int(match.group(1))
                url_indices.add(idx)
            except ValueError:
                pass

        urls = self._extract_url_strings(chunk)

        for i, url in enumerate(urls):
            timestamp = None

            if time_chunk:
                timestamp = self._find_timestamp_for_index(time_chunk, i + 1)

            self.entries.append(
                TypedURLEntry(
                    url=url,
                    index=i + 1,
                    timestamp=timestamp,
                    browser=browser_name,
                )
            )

    def _extract_url_strings(self, chunk: bytes) -> list[str]:
        """Extract URL strings from chunk."""
        urls = []

        i = 0
        while i < len(chunk) - 10:
            if chunk[i] == ord("h") and chunk[i + 1] == 0:
                url = self._extract_unicode_url(chunk, i)
                if url and url not in urls:
                    urls.append(url)
            i += 2

        return urls

    def _extract_unicode_url(self, chunk: bytes, start: int) -> str:
        """Extract a Unicode URL starting at offset."""
        chars = []
        i = start

        while i < len(chunk) - 1 and len(chars) < 500:
            if chunk[i + 1] == 0:
                if 0x21 <= chunk[i] < 0x7F:  # Printable non-space
                    chars.append(chr(chunk[i]))
                    i += 2
                elif chunk[i] == 0:  # Null terminator
                    break
                else:
                    break
            else:
                break

        result = "".join(chars)

        if result.startswith(("http://", "https://", "ftp://", "file://")):
            return result

        return ""

    def _find_timestamp_for_index(
        self, time_chunk: bytes, index: int
    ) -> datetime | None:
        """Find timestamp for a specific URL index."""
        pattern = f"url{index}".encode("ascii")
        idx = time_chunk.find(pattern)

        if idx == -1:
            return None

        search_start = idx + len(pattern)
        for i in range(search_start, min(search_start + 100, len(time_chunk) - 8)):
            try:
                filetime = struct.unpack("<Q", time_chunk[i : i + 8])[0]
                dt = _filetime_to_datetime(filetime)
                if dt and dt.year >= 2000 and dt.year <= 2100:
                    return dt
            except struct.error:
                pass

        return None


@ParserRegistry.register
class TypedURLsFileParser(BaseParser):
    """Parser for TypedURLs registry entries."""

    name: ClassVar[str] = "typedurls"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "typedurls",
        "typed_urls",
        "ie_history",
        "edge_typed",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize TypedURLs parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse TypedURLs from registry hive."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse TypedURLs from bytes."""
        parser = TypedURLsParser(data)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "url": entry.url,
                "index": entry.index,
                "browser": entry.browser,
                "source_file": filename,
            }

            domain_match = re.search(r"://([^/:]+)", entry.url)
            if domain_match:
                record_data["domain"] = domain_match.group(1)

            if entry.timestamp:
                record_data["typed_time"] = entry.timestamp.isoformat()

            risk_indicators = self._analyze_url(entry)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "typed_url",
                entry.browser,
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

    def _analyze_url(self, entry: TypedURLEntry) -> list[str]:
        """Analyze URL for suspicious patterns."""
        indicators = []

        url_lower = entry.url.lower()

        if re.search(r"://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
            indicators.append("ip_address_url")

        port_match = re.search(r":(\d+)/", url_lower)
        if port_match:
            port = int(port_match.group(1))
            if port not in [80, 443, 8080, 8443]:
                indicators.append("non_standard_port")

        file_sharing = [
            "pastebin",
            "paste.ee",
            "hastebin",
            "transfer.sh",
            "file.io",
            "mega.nz",
            "mediafire",
            "anonfiles",
            "dropbox",
        ]
        if any(fs in url_lower for fs in file_sharing):
            indicators.append("file_sharing_service")

        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
        if any(tld in url_lower for tld in suspicious_tlds):
            indicators.append("suspicious_tld")

        if re.search(r"[?&].*=[A-Za-z0-9+/]{20,}=*", url_lower):
            indicators.append("possible_encoded_data")

        if url_lower.startswith("file://"):
            indicators.append("local_file_access")

        return indicators
