"""Windows Defender parser for security event tracking.

Parses Windows Defender logs, quarantine files, and detection history
for malware analysis and incident response.

Locations:
- %ProgramData%\\Microsoft\\Windows Defender\\Support\\MPLog-*.log
- %ProgramData%\\Microsoft\\Windows Defender\\Quarantine\
- %ProgramData%\\Microsoft\\Windows Defender\\Scans\\History\
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# MPLog timestamp patterns
MPLOG_TIMESTAMP_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)"
)
MPLOG_DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})")

# Detection patterns in MPLog
THREAT_PATTERN = re.compile(r"threat[:\s]+([^\r\n,]+)", re.IGNORECASE)
FILE_PATTERN = re.compile(r"file[:\s]+([^\r\n,]+)", re.IGNORECASE)
ACTION_PATTERN = re.compile(r"action[:\s]+([^\r\n,]+)", re.IGNORECASE)
PROCESS_PATTERN = re.compile(r"process[:\s]+([^\r\n,]+)", re.IGNORECASE)

# Quarantine file signature
QUARANTINE_SIGNATURE = b"\x0B\xAD\x00"  # Partial signature


@dataclass
class DefenderLogEntry:
    """A single Windows Defender log entry."""

    timestamp: datetime | None
    entry_type: str
    message: str
    threat_name: str = ""
    file_path: str = ""
    action: str = ""
    process: str = ""
    raw_line: str = ""
    severity: str = ""


@dataclass
class DefenderDetection:
    """A Windows Defender detection record."""

    detection_id: str
    threat_name: str
    threat_type: str = ""
    severity: str = ""
    file_path: str = ""
    action_taken: str = ""
    timestamp: datetime | None = None
    process: str = ""
    user: str = ""
    additional_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class QuarantineEntry:
    """A quarantined file entry."""

    quarantine_id: str
    original_path: str = ""
    threat_name: str = ""
    quarantine_time: datetime | None = None
    file_size: int = 0
    detection_source: str = ""


class MPLogParser:
    """Parser for Windows Defender MPLog files."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.entries: list[DefenderLogEntry] = []
        self.detections: list[DefenderDetection] = []
        self._parse()

    def _parse(self) -> None:
        """Parse MPLog file."""
        try:
            # Try UTF-16 LE first (common for Windows logs)
            try:
                text = self.data.decode("utf-16-le")
            except UnicodeDecodeError:
                try:
                    text = self.data.decode("utf-8")
                except UnicodeDecodeError:
                    text = self.data.decode("latin-1", errors="replace")

            current_entry = []
            current_timestamp = None

            for line in text.splitlines():
                line = line.strip()
                if not line:
                    if current_entry:
                        self._process_entry(current_timestamp, current_entry)
                        current_entry = []
                        current_timestamp = None
                    continue

                # Check for timestamp at start of line
                ts_match = MPLOG_TIMESTAMP_PATTERN.search(line)
                if ts_match:
                    if current_entry:
                        self._process_entry(current_timestamp, current_entry)
                        current_entry = []

                    try:
                        current_timestamp = datetime.fromisoformat(
                            ts_match.group(1).replace("Z", "+00:00")
                        )
                    except ValueError:
                        current_timestamp = None

                current_entry.append(line)

            # Process final entry
            if current_entry:
                self._process_entry(current_timestamp, current_entry)

        except Exception:
            pass

    def _process_entry(
        self, timestamp: datetime | None, lines: list[str]
    ) -> None:
        """Process a log entry."""
        if not lines:
            return

        full_text = "\n".join(lines)
        entry_type = self._classify_entry(full_text)

        # Extract key information
        threat_match = THREAT_PATTERN.search(full_text)
        file_match = FILE_PATTERN.search(full_text)
        action_match = ACTION_PATTERN.search(full_text)
        process_match = PROCESS_PATTERN.search(full_text)

        entry = DefenderLogEntry(
            timestamp=timestamp,
            entry_type=entry_type,
            message=lines[0][:200] if lines else "",
            threat_name=threat_match.group(1).strip() if threat_match else "",
            file_path=file_match.group(1).strip() if file_match else "",
            action=action_match.group(1).strip() if action_match else "",
            process=process_match.group(1).strip() if process_match else "",
            raw_line=full_text[:500],
        )

        self.entries.append(entry)

        # Create detection record if this is a threat-related entry
        if entry.threat_name or entry_type in ["detection", "threat", "quarantine"]:
            detection = DefenderDetection(
                detection_id=f"{timestamp.isoformat() if timestamp else 'unknown'}-{len(self.detections)}",
                threat_name=entry.threat_name,
                threat_type=entry_type,
                file_path=entry.file_path,
                action_taken=entry.action,
                timestamp=timestamp,
                process=entry.process,
            )
            self.detections.append(detection)

    def _classify_entry(self, text: str) -> str:
        """Classify log entry type."""
        text_lower = text.lower()

        if any(
            k in text_lower
            for k in ["threat", "malware", "virus", "trojan", "ransom"]
        ):
            return "detection"
        elif "quarantine" in text_lower:
            return "quarantine"
        elif "scan" in text_lower:
            return "scan"
        elif "update" in text_lower:
            return "update"
        elif "exclusion" in text_lower:
            return "exclusion"
        elif any(k in text_lower for k in ["error", "failed", "failure"]):
            return "error"
        elif any(k in text_lower for k in ["start", "stop", "init"]):
            return "service"
        elif "real-time" in text_lower or "realtime" in text_lower:
            return "realtime_protection"
        else:
            return "info"


class DetectionHistoryParser:
    """Parser for Defender detection history files."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename
        self.detections: list[DefenderDetection] = []
        self._parse()

    def _parse(self) -> None:
        """Parse detection history file."""
        # Detection history files can be binary or text
        # Try to extract relevant information
        try:
            # Check if it's a text file
            try:
                text = self.data.decode("utf-8")
                self._parse_text(text)
            except UnicodeDecodeError:
                self._parse_binary()
        except Exception:
            pass

    def _parse_text(self, text: str) -> None:
        """Parse text-based detection history."""
        # Simple key-value extraction
        detection_data: dict[str, str] = {}

        for line in text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                detection_data[key.strip()] = value.strip()

        if detection_data:
            self.detections.append(
                DefenderDetection(
                    detection_id=detection_data.get("ID", self.filename),
                    threat_name=detection_data.get(
                        "ThreatName", detection_data.get("Threat", "")
                    ),
                    file_path=detection_data.get(
                        "Path", detection_data.get("File", "")
                    ),
                    action_taken=detection_data.get("Action", ""),
                    additional_info=detection_data,
                )
            )

    def _parse_binary(self) -> None:
        """Parse binary detection history format."""
        # Binary format varies by Windows version
        # Extract strings that look like paths or threat names
        strings = self._extract_strings()

        threat_name = ""
        file_path = ""

        for s in strings:
            if "\\" in s and len(s) > 5:
                if not file_path:
                    file_path = s
            elif any(
                k in s.lower()
                for k in ["trojan", "virus", "malware", "ransom", "hack"]
            ):
                threat_name = s

        if threat_name or file_path:
            self.detections.append(
                DefenderDetection(
                    detection_id=self.filename,
                    threat_name=threat_name,
                    file_path=file_path,
                )
            )

    def _extract_strings(self, min_length: int = 4) -> list[str]:
        """Extract ASCII and Unicode strings from binary data."""
        strings = []

        # ASCII strings
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        for match in ascii_pattern.finditer(self.data):
            try:
                strings.append(match.group().decode("ascii"))
            except UnicodeDecodeError:
                pass

        # Unicode strings (UTF-16LE)
        i = 0
        while i < len(self.data) - 2:
            if self.data[i + 1] == 0 and 0x20 <= self.data[i] <= 0x7E:
                # Potential Unicode string
                end = i
                while end < len(self.data) - 1:
                    if self.data[end + 1] == 0 and 0x20 <= self.data[end] <= 0x7E:
                        end += 2
                    else:
                        break
                if end - i >= min_length * 2:
                    try:
                        s = self.data[i:end].decode("utf-16-le")
                        strings.append(s)
                    except UnicodeDecodeError:
                        pass
                i = end
            else:
                i += 1

        return strings


class QuarantineParser:
    """Parser for Windows Defender quarantine files."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename
        self.entries: list[QuarantineEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse quarantine file/metadata."""
        if len(self.data) < 16:
            return

        # Quarantine files have various formats
        # Try to extract metadata
        try:
            strings = self._extract_strings()

            original_path = ""
            threat_name = ""

            for s in strings:
                if "\\" in s and ":" in s:
                    original_path = s
                elif any(
                    k in s.lower()
                    for k in ["trojan", "virus", "malware", "ransom", "hack"]
                ):
                    threat_name = s

            if original_path or threat_name:
                self.entries.append(
                    QuarantineEntry(
                        quarantine_id=self.filename,
                        original_path=original_path,
                        threat_name=threat_name,
                        file_size=len(self.data),
                    )
                )
        except Exception:
            pass

    def _extract_strings(self, min_length: int = 4) -> list[str]:
        """Extract strings from quarantine data."""
        strings = []

        # Simple ASCII extraction
        current = []
        for byte in self.data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings


@ParserRegistry.register
class DefenderFileParser(BaseParser):
    """Parser for Windows Defender artifacts."""

    name: ClassVar[str] = "defender"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "defender",
        "windows_defender",
        "mplog",
        "quarantine",
        "detection_history",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Defender parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Defender artifact file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse Defender artifact from bytes."""
        fname_lower = filename.lower()

        if "mplog" in fname_lower or fname_lower.endswith(".log"):
            yield from self._parse_mplog(data, filename)
        elif "quarantine" in fname_lower:
            yield from self._parse_quarantine(data, filename)
        else:
            yield from self._parse_detection_history(data, filename)

    def _parse_mplog(
        self, data: bytes, filename: str
    ) -> Iterator[ParsedRecord]:
        """Parse MPLog file."""
        parser = MPLogParser(data)

        record_index = 0

        # Emit detection records
        for detection in parser.detections:
            record_data: dict[str, Any] = {
                "detection_id": detection.detection_id,
                "threat_name": detection.threat_name,
                "threat_type": detection.threat_type,
                "severity": detection.severity,
                "action_taken": detection.action_taken,
                "source_file": filename,
            }

            if detection.file_path:
                record_data["file_path"] = detection.file_path
            if detection.process:
                record_data["process"] = detection.process
            if detection.user:
                record_data["user"] = detection.user

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "defender_detection",
                detection.detection_id,
                detection.threat_name,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="ioc",
                timestamp=detection.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        # Emit log entries
        for entry in parser.entries:
            if entry.entry_type in ["detection", "quarantine", "error"]:
                # Already covered in detections or important
                pass

            record_data = {
                "entry_type": entry.entry_type,
                "message": entry.message,
                "source_file": filename,
            }

            if entry.threat_name:
                record_data["threat_name"] = entry.threat_name
            if entry.file_path:
                record_data["file_path"] = entry.file_path
            if entry.action:
                record_data["action"] = entry.action

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "defender_log", record_index, entry.message[:30]
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

    def _parse_quarantine(
        self, data: bytes, filename: str
    ) -> Iterator[ParsedRecord]:
        """Parse quarantine file."""
        parser = QuarantineParser(data, filename)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "quarantine_id": entry.quarantine_id,
                "original_path": entry.original_path,
                "threat_name": entry.threat_name,
                "file_size": entry.file_size,
                "source_file": filename,
            }

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "defender_quarantine",
                entry.quarantine_id,
                entry.threat_name,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="ioc",
                timestamp=entry.quarantine_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _parse_detection_history(
        self, data: bytes, filename: str
    ) -> Iterator[ParsedRecord]:
        """Parse detection history file."""
        parser = DetectionHistoryParser(data, filename)

        record_index = 0
        for detection in parser.detections:
            record_data: dict[str, Any] = {
                "detection_id": detection.detection_id,
                "threat_name": detection.threat_name,
                "file_path": detection.file_path,
                "action_taken": detection.action_taken,
                "source_file": filename,
            }

            if detection.additional_info:
                record_data["additional_info"] = detection.additional_info

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "defender_history",
                detection.detection_id,
                detection.threat_name,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="ioc",
                timestamp=detection.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
