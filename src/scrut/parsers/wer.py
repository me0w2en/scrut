"""Windows Error Reporting (WER) parser.

Parses Windows Error Reporting files to identify application crashes
and system errors, which can indicate exploitation or malware activity.

Locations:
- %ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive\
- %ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue\
- %LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportArchive\
- %LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportQueue\
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

# WER event types
EVENT_TYPES = {
    "APPCRASH": "Application Crash",
    "APPCRASH_CRIT": "Critical Application Crash",
    "MoAppCrash": "Modern App Crash",
    "MoAppHang": "Modern App Hang",
    "WindowsUpdateFailure3": "Windows Update Failure",
    "CLR20r3": "CLR Runtime Error",
    "BEX": "Buffer Overflow",
    "BEX64": "Buffer Overflow (64-bit)",
    "KERNELBASE": "Kernel Base Error",
}


def _parse_wer_timestamp(ts_str: str) -> datetime | None:
    """Parse WER timestamp format."""
    # Format: 133123456789012345 (FILETIME as string)
    try:
        filetime = int(ts_str)
        EPOCH_DIFF = 116444736000000000
        if filetime < EPOCH_DIFF:
            return None
        timestamp = (filetime - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (ValueError, OSError, OverflowError):
        pass

    # Try ISO format
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        pass

    return None


@dataclass
class WERReport:
    """A Windows Error Report."""

    event_type: str
    event_type_name: str
    application_name: str
    application_path: str
    application_version: str
    module_name: str
    module_path: str
    module_version: str
    exception_code: str
    fault_offset: str
    timestamp: datetime | None
    report_id: str
    os_version: str = ""
    locale: str = ""
    response_type: str = ""


class WERParser:
    """Parser for Windows Error Reporting files."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename
        self.reports: list[WERReport] = []
        self._parse()

    def _parse(self) -> None:
        """Parse WER data."""
        if len(self.data) < 50:
            return

        # Determine file type
        filename_lower = self.filename.lower()

        if filename_lower.endswith(".wer") or filename_lower == "report.wer":
            self._parse_wer_file()
        else:
            # Try to detect format
            if b"[Report]" in self.data or b"EventType=" in self.data:
                self._parse_wer_file()
            elif b"<?xml" in self.data:
                self._parse_xml_report()
            else:
                self._parse_generic()

    def _parse_wer_file(self) -> None:
        """Parse .wer text file format."""
        try:
            # Try different encodings
            for encoding in ["utf-16-le", "utf-8", "ascii"]:
                try:
                    text = self.data.decode(encoding)
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            else:
                text = self.data.decode("utf-8", errors="replace")

            # Parse key=value pairs
            values = {}
            for line in text.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()

            # Extract report data
            event_type = values.get("EventType", "Unknown")
            event_type_name = EVENT_TYPES.get(event_type, event_type)

            # Parse P parameters (application info)
            app_name = values.get("P1", values.get("AppName", ""))
            app_version = values.get("P2", values.get("AppVer", ""))
            module_name = values.get("P3", values.get("ModName", ""))
            module_version = values.get("P4", values.get("ModVer", ""))
            exception_code = values.get("P6", values.get("ExceptionCode", ""))
            fault_offset = values.get("P7", values.get("Offset", ""))

            # Get paths
            app_path = values.get("AppPath", values.get("TargetAppPath", ""))
            module_path = values.get("OriginalFilename", "")

            # Timestamp
            ts_str = values.get("EventTime", values.get("ReportTime", ""))
            timestamp = _parse_wer_timestamp(ts_str) if ts_str else None

            # Report ID
            report_id = values.get("ReportIdentifier", values.get("ReportId", ""))

            if app_name or module_name:
                self.reports.append(
                    WERReport(
                        event_type=event_type,
                        event_type_name=event_type_name,
                        application_name=app_name,
                        application_path=app_path,
                        application_version=app_version,
                        module_name=module_name,
                        module_path=module_path,
                        module_version=module_version,
                        exception_code=exception_code,
                        fault_offset=fault_offset,
                        timestamp=timestamp,
                        report_id=report_id,
                        os_version=values.get("OSVer", ""),
                        locale=values.get("Lcid", ""),
                        response_type=values.get("Response", ""),
                    )
                )
        except Exception:
            pass

    def _parse_xml_report(self) -> None:
        """Parse XML format WER report."""
        try:
            text = self.data.decode("utf-8", errors="replace")

            # Extract values using regex
            def extract_tag(tag: str) -> str:
                match = re.search(f"<{tag}>([^<]*)</{tag}>", text, re.IGNORECASE)
                return match.group(1) if match else ""

            event_type = extract_tag("EventType")
            event_type_name = EVENT_TYPES.get(event_type, event_type)

            # Extract parameters
            params = re.findall(r"<Parameter\d+>([^<]*)</Parameter\d+>", text)

            if params or event_type:
                self.reports.append(
                    WERReport(
                        event_type=event_type or "Unknown",
                        event_type_name=event_type_name or "Unknown",
                        application_name=params[0] if len(params) > 0 else "",
                        application_path=extract_tag("AppPath"),
                        application_version=params[1] if len(params) > 1 else "",
                        module_name=params[2] if len(params) > 2 else "",
                        module_path="",
                        module_version=params[3] if len(params) > 3 else "",
                        exception_code=params[5] if len(params) > 5 else "",
                        fault_offset=params[6] if len(params) > 6 else "",
                        timestamp=None,
                        report_id=extract_tag("ReportIdentifier"),
                    )
                )
        except Exception:
            pass

    def _parse_generic(self) -> None:
        """Try to extract data from unknown format."""
        # Look for common patterns
        text = self.data.decode("utf-8", errors="replace")

        # Find executable paths
        exe_pattern = re.compile(
            r"([A-Za-z]:\\[^\\/:*?\"<>|\r\n]{1,200}(?:\\[^\\/:*?\"<>|\r\n]{1,200})*\.exe)",
            re.IGNORECASE,
        )

        exes = exe_pattern.findall(text)
        for exe in exes[:5]:  # Limit to first 5
            self.reports.append(
                WERReport(
                    event_type="Unknown",
                    event_type_name="Unknown Error",
                    application_name=Path(exe).name,
                    application_path=exe,
                    application_version="",
                    module_name="",
                    module_path="",
                    module_version="",
                    exception_code="",
                    fault_offset="",
                    timestamp=None,
                    report_id="",
                )
            )


@ParserRegistry.register
class WERFileParser(BaseParser):
    """Parser for Windows Error Reporting files."""

    name: ClassVar[str] = "wer"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "wer",
        "windows_error_reporting",
        "error_reporting",
        "crash_report",
    ]

    # Exception codes that might indicate exploitation
    SUSPICIOUS_EXCEPTION_CODES = {
        "c0000005": "Access Violation",
        "c00000fd": "Stack Overflow",
        "c000001d": "Illegal Instruction",
        "c0000096": "Privileged Instruction",
        "c0000409": "Stack Buffer Overrun",
        "80000003": "Breakpoint (Debug)",
    }

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize WER parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse WER file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse WER from bytes."""
        parser = WERParser(data, filename)

        record_index = 0
        for report in parser.reports:
            record_data: dict[str, Any] = {
                "event_type": report.event_type,
                "event_type_name": report.event_type_name,
                "source_file": filename,
            }

            if report.application_name:
                record_data["application_name"] = report.application_name
            if report.application_path:
                record_data["application_path"] = report.application_path
            if report.application_version:
                record_data["application_version"] = report.application_version
            if report.module_name:
                record_data["module_name"] = report.module_name
            if report.module_path:
                record_data["module_path"] = report.module_path
            if report.module_version:
                record_data["module_version"] = report.module_version
            if report.exception_code:
                record_data["exception_code"] = report.exception_code
                # Add human-readable description
                code_lower = report.exception_code.lower().replace("0x", "")
                if code_lower in self.SUSPICIOUS_EXCEPTION_CODES:
                    record_data["exception_description"] = self.SUSPICIOUS_EXCEPTION_CODES[code_lower]
            if report.fault_offset:
                record_data["fault_offset"] = report.fault_offset
            if report.report_id:
                record_data["report_id"] = report.report_id
            if report.os_version:
                record_data["os_version"] = report.os_version

            # Analyze for suspicious patterns
            risk_indicators = self._analyze_report(report)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "wer_report",
                report.application_name,
                report.exception_code,
                record_index,
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=report.timestamp,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_report(self, report: WERReport) -> list[str]:
        """Analyze WER report for suspicious patterns."""
        indicators = []

        # Check exception code for exploitation indicators
        if report.exception_code:
            code_lower = report.exception_code.lower().replace("0x", "")
            if code_lower in self.SUSPICIOUS_EXCEPTION_CODES:
                indicators.append("suspicious_exception")

        # BEX/BEX64 indicates buffer overflow
        if report.event_type in ["BEX", "BEX64"]:
            indicators.append("buffer_overflow")

        # Check application path
        if report.application_path:
            path_lower = report.application_path.lower()

            # System processes crashing
            system_processes = [
                "lsass.exe",
                "csrss.exe",
                "services.exe",
                "svchost.exe",
                "winlogon.exe",
            ]
            if any(p in path_lower for p in system_processes):
                indicators.append("system_process_crash")

            # Security software
            security_software = ["defender", "antivirus", "antimalware", "security"]
            if any(s in path_lower for s in security_software):
                indicators.append("security_software_crash")

            # Browser crashes (potential exploitation)
            browsers = ["chrome", "firefox", "edge", "iexplore", "opera"]
            if any(b in path_lower for b in browsers):
                indicators.append("browser_crash")

            # Office crashes (potential exploitation)
            office_apps = ["winword", "excel", "powerpnt", "outlook"]
            if any(o in path_lower for o in office_apps):
                indicators.append("office_crash")

        # Check module for common exploitation targets
        if report.module_name:
            module_lower = report.module_name.lower()
            vuln_modules = ["flash", "java", "silverlight", "acrobat", "reader"]
            if any(m in module_lower for m in vuln_modules):
                indicators.append("vulnerable_component")

        return indicators
