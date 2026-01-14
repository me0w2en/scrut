"""BITS (Background Intelligent Transfer Service) parser.

Parses BITS job queue files to track file downloads, which can
indicate malware delivery mechanisms.

Locations:
- %ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader\\qmgr.db (Win10+)
- %ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader\\qmgr0.dat (legacy)
- %ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader\\qmgr1.dat (legacy)
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# BITS queue file signatures
QMGR_SIGNATURE = b"\x00\x00\x00\x00"  # Varies by version
ESE_SIGNATURE = b"\xef\xcd\xab\x89"  # ESE database signature


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
class BITSJob:
    """A BITS job entry."""

    job_id: str
    job_name: str
    job_type: str  # download, upload
    state: str
    owner: str = ""
    created_time: datetime | None = None
    modified_time: datetime | None = None
    completed_time: datetime | None = None
    source_url: str = ""
    target_path: str = ""
    bytes_total: int = 0
    bytes_transferred: int = 0
    priority: str = ""
    error_code: int = 0
    error_description: str = ""
    files: list[dict[str, Any]] = None

    def __post_init__(self):
        if self.files is None:
            self.files = []


class BITSQueueParser:
    """Parser for BITS queue files (qmgr.db, qmgr0.dat, qmgr1.dat)."""

    # Job states
    JOB_STATES = {
        0: "Queued",
        1: "Connecting",
        2: "Transferring",
        3: "Suspended",
        4: "Error",
        5: "TransientError",
        6: "Transferred",
        7: "Acknowledged",
        8: "Cancelled",
    }

    # Job types
    JOB_TYPES = {
        0: "Download",
        1: "Upload",
        2: "UploadReply",
    }

    # Job priority
    JOB_PRIORITY = {
        0: "Foreground",
        1: "High",
        2: "Normal",
        3: "Low",
    }

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename.lower()
        self.jobs: list[BITSJob] = []
        self._parse()

    def _parse(self) -> None:
        """Parse BITS queue file."""
        if len(self.data) < 16:
            return

        # Check for ESE database (qmgr.db in Win10+)
        if len(self.data) >= 4 and self.data[4:8] == ESE_SIGNATURE:
            self._parse_ese()
        else:
            self._parse_legacy()

    def _parse_ese(self) -> None:
        """Parse ESE database format (Windows 10+)."""
        # ESE parsing is complex - extract strings and patterns
        self._extract_from_strings()

    def _parse_legacy(self) -> None:
        """Parse legacy qmgr0.dat/qmgr1.dat format."""
        # Legacy format has a header followed by job records
        # Structure varies by Windows version

        offset = 0

        # Try to find job records by looking for patterns
        # BITS jobs typically contain URLs and file paths

        # Look for GUID patterns (job IDs)
        guid_pattern = re.compile(
            rb"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
        )

        guids = list(guid_pattern.finditer(self.data))

        for match in guids:
            job_id = match.group().decode("ascii")

            # Try to extract job info from surrounding data
            start = max(0, match.start() - 1024)
            end = min(len(self.data), match.end() + 4096)
            chunk = self.data[start:end]

            job = self._extract_job_from_chunk(job_id, chunk)
            if job:
                self.jobs.append(job)

        # If no GUIDs found, try string extraction
        if not self.jobs:
            self._extract_from_strings()

    def _extract_job_from_chunk(
        self, job_id: str, chunk: bytes
    ) -> BITSJob | None:
        """Extract job info from a data chunk."""
        # Extract URLs
        url_pattern = re.compile(rb"https?://[^\x00\s]{5,500}")
        urls = [m.group().decode("ascii", errors="replace") for m in url_pattern.finditer(chunk)]

        # Extract file paths
        path_pattern = re.compile(rb"[A-Za-z]:\\[^\x00]{5,260}")
        paths = [m.group().decode("ascii", errors="replace") for m in path_pattern.finditer(chunk)]

        # Extract domain/user
        user_pattern = re.compile(rb"[A-Za-z0-9_-]+\\[A-Za-z0-9_-]+")
        users = [m.group().decode("ascii", errors="replace") for m in user_pattern.finditer(chunk)]

        if urls or paths:
            return BITSJob(
                job_id=job_id,
                job_name=f"Job-{job_id[:8]}",
                job_type="download" if urls else "unknown",
                state="unknown",
                owner=users[0] if users else "",
                source_url=urls[0] if urls else "",
                target_path=paths[0] if paths else "",
                files=[{"url": url, "path": paths[i] if i < len(paths) else ""}
                       for i, url in enumerate(urls)],
            )

        return None

    def _extract_from_strings(self) -> None:
        """Extract BITS jobs from embedded strings."""
        # Extract all meaningful strings
        strings = self._extract_strings()

        urls = []
        paths = []
        guids = []
        users = []

        for s in strings:
            if s.startswith("http://") or s.startswith("https://"):
                urls.append(s)
            elif len(s) > 3 and s[1] == ":" and s[2] == "\\":
                paths.append(s)
            elif re.match(
                r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
                s,
            ):
                guids.append(s)
            elif "\\" in s and len(s.split("\\")) == 2:
                users.append(s)

        # Create job entries from extracted data
        if urls:
            for i, url in enumerate(urls):
                job_id = guids[i] if i < len(guids) else f"{{unknown-{i}}}"
                target = paths[i] if i < len(paths) else ""

                self.jobs.append(
                    BITSJob(
                        job_id=job_id,
                        job_name=f"ExtractedJob-{i}",
                        job_type="download",
                        state="unknown",
                        owner=users[0] if users else "",
                        source_url=url,
                        target_path=target,
                    )
                )

    def _extract_strings(self, min_length: int = 6) -> list[str]:
        """Extract ASCII and Unicode strings."""
        strings = []

        # ASCII strings
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        for match in ascii_pattern.finditer(self.data):
            try:
                s = match.group().decode("ascii")
                strings.append(s)
            except UnicodeDecodeError:
                pass

        # Unicode strings (simple extraction)
        i = 0
        current = []
        while i < len(self.data) - 1:
            if self.data[i + 1] == 0 and 0x20 <= self.data[i] <= 0x7E:
                current.append(chr(self.data[i]))
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
class BITSFileParser(BaseParser):
    """Parser for BITS queue files."""

    name: ClassVar[str] = "bits"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "bits",
        "bits_jobs",
        "qmgr",
        "qmgr.db",
        "qmgr0.dat",
        "qmgr1.dat",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize BITS parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse BITS queue file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse BITS queue from bytes."""
        parser = BITSQueueParser(data, filename)

        record_index = 0
        for job in parser.jobs:
            record_data: dict[str, Any] = {
                "job_id": job.job_id,
                "job_name": job.job_name,
                "job_type": job.job_type,
                "state": job.state,
                "source_file": filename,
            }

            if job.owner:
                record_data["owner"] = job.owner
            if job.source_url:
                record_data["source_url"] = job.source_url
            if job.target_path:
                record_data["target_path"] = job.target_path
            if job.bytes_total > 0:
                record_data["bytes_total"] = job.bytes_total
            if job.bytes_transferred > 0:
                record_data["bytes_transferred"] = job.bytes_transferred
            if job.priority:
                record_data["priority"] = job.priority
            if job.error_code:
                record_data["error_code"] = job.error_code
            if job.error_description:
                record_data["error_description"] = job.error_description
            if job.files:
                record_data["files"] = job.files

            # Analyze for suspicious patterns
            risk_indicators = self._analyze_job(job)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "bits_job", job.job_id, job.source_url[:50] if job.source_url else ""
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=job.created_time or job.modified_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_job(self, job: BITSJob) -> list[str]:
        """Analyze BITS job for suspicious patterns."""
        indicators = []

        url_lower = job.source_url.lower() if job.source_url else ""
        path_lower = job.target_path.lower() if job.target_path else ""

        # Suspicious file extensions
        suspicious_extensions = [
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".js",
            ".hta",
            ".scr",
            ".msi",
        ]
        if any(url_lower.endswith(ext) for ext in suspicious_extensions):
            indicators.append("executable_download")

        # Suspicious target locations
        suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
            "\\public\\",
            "\\programdata\\",
        ]
        if any(p in path_lower for p in suspicious_paths):
            indicators.append("suspicious_target_path")

        # IP address URL (not domain)
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
            indicators.append("ip_based_url")

        # Non-standard ports
        if re.search(r":\d{4,5}/", url_lower):
            port_match = re.search(r":(\d{4,5})/", url_lower)
            if port_match:
                port = int(port_match.group(1))
                if port not in [80, 443, 8080, 8443]:
                    indicators.append("non_standard_port")

        # Encoded or obfuscated URLs
        if "%" in url_lower and url_lower.count("%") > 3:
            indicators.append("encoded_url")

        # Pastebin/file sharing services
        file_sharing = [
            "pastebin.com",
            "paste.ee",
            "hastebin.com",
            "transfer.sh",
            "file.io",
            "anonfiles.com",
            "mega.nz",
            "mediafire.com",
        ]
        if any(fs in url_lower for fs in file_sharing):
            indicators.append("file_sharing_service")

        return indicators
