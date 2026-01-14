r"""WMI Persistence parser.

Parses the WMI repository to detect persistence mechanisms
such as event subscriptions used by malware.

Locations:
- %SystemRoot%\System32\wbem\Repository\OBJECTS.DATA
- %SystemRoot%\System32\wbem\Repository\FS\OBJECTS.DATA (Win10+)

Key WMI classes for persistence:
- __EventFilter: Event query definitions
- __EventConsumer: Event handlers (CommandLineEventConsumer, ActiveScriptEventConsumer)
- __FilterToConsumerBinding: Links filters to consumers
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

# WMI consumer types
CONSUMER_TYPES = {
    "CommandLineEventConsumer": "command_line",
    "ActiveScriptEventConsumer": "script",
    "LogFileEventConsumer": "log_file",
    "NTEventLogEventConsumer": "event_log",
    "SMTPEventConsumer": "smtp",
}


@dataclass
class WMIEventFilter:
    """WMI Event Filter definition."""

    name: str
    query: str
    query_language: str = "WQL"
    namespace: str = ""
    created_time: datetime | None = None


@dataclass
class WMIEventConsumer:
    """WMI Event Consumer definition."""

    name: str
    consumer_type: str
    executable_path: str = ""
    command_line: str = ""
    script_text: str = ""
    script_filename: str = ""
    working_directory: str = ""
    user: str = ""
    created_time: datetime | None = None


@dataclass
class WMIBinding:
    """WMI Filter to Consumer Binding."""

    filter_name: str
    consumer_name: str
    consumer_type: str = ""
    created_time: datetime | None = None


@dataclass
class WMIPersistence:
    """A complete WMI persistence mechanism."""

    filter: WMIEventFilter | None
    consumer: WMIEventConsumer | None
    binding: WMIBinding | None
    risk_level: str = "unknown"
    risk_indicators: list[str] = field(default_factory=list)


class WMIRepositoryParser:
    """Parser for WMI repository OBJECTS.DATA file."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.filters: list[WMIEventFilter] = []
        self.consumers: list[WMIEventConsumer] = []
        self.bindings: list[WMIBinding] = []
        self._parse()

    def _parse(self) -> None:
        """Parse WMI repository."""
        if len(self.data) < 100:
            return

        # Extract strings that look like WMI objects
        self._extract_filters()
        self._extract_consumers()
        self._extract_bindings()

    def _extract_filters(self) -> None:
        """Extract __EventFilter instances."""
        # Look for EventFilter patterns
        # Format: __EventFilter followed by Name and Query

        # Pattern for WQL queries
        wql_pattern = re.compile(
            rb"SELECT\s+\*\s+FROM\s+[^\x00]{5,200}",
            re.IGNORECASE,
        )

        for match in wql_pattern.finditer(self.data):
            query = match.group().decode("ascii", errors="replace")

            # Look for filter name near the query
            start = max(0, match.start() - 500)
            chunk = self.data[start : match.start()]

            name = self._extract_string_near(chunk, b"Name")
            if not name:
                name = f"Filter_{match.start()}"

            self.filters.append(
                WMIEventFilter(
                    name=name,
                    query=query,
                    query_language="WQL",
                )
            )

    def _extract_consumers(self) -> None:
        """Extract __EventConsumer instances."""
        # Look for CommandLineEventConsumer
        cmdline_pattern = re.compile(
            rb"CommandLineEventConsumer",
            re.IGNORECASE,
        )

        for match in cmdline_pattern.finditer(self.data):
            # Look for executable path and command line near this
            end = min(len(self.data), match.end() + 2000)
            chunk = self.data[match.start() : end]

            exe_path = ""
            cmd_line = ""
            name = ""

            # Extract ExecutablePath
            exe_match = re.search(
                rb"ExecutablePath[^\x00]*?([A-Za-z]:\\[^\x00]{5,260})",
                chunk,
            )
            if exe_match:
                exe_path = exe_match.group(1).decode("ascii", errors="replace")

            # Extract CommandLineTemplate
            cmd_match = re.search(
                rb"CommandLineTemplate[^\x00]*?([^\x00]{5,500})",
                chunk,
            )
            if cmd_match:
                cmd_line = cmd_match.group(1).decode("ascii", errors="replace")

            # Extract Name
            name = self._extract_string_near(chunk, b"Name")
            if not name:
                name = f"Consumer_{match.start()}"

            if exe_path or cmd_line:
                self.consumers.append(
                    WMIEventConsumer(
                        name=name,
                        consumer_type="CommandLineEventConsumer",
                        executable_path=exe_path,
                        command_line=cmd_line,
                    )
                )

        # Look for ActiveScriptEventConsumer
        script_pattern = re.compile(
            rb"ActiveScriptEventConsumer",
            re.IGNORECASE,
        )

        for match in script_pattern.finditer(self.data):
            end = min(len(self.data), match.end() + 4000)
            chunk = self.data[match.start() : end]

            script_text = ""
            script_filename = ""
            name = ""

            # Extract ScriptText
            script_match = re.search(
                rb"ScriptText[^\x00]*?([^\x00]{10,4000})",
                chunk,
            )
            if script_match:
                script_text = script_match.group(1).decode("ascii", errors="replace")

            # Extract ScriptFileName
            file_match = re.search(
                rb"ScriptFileName[^\x00]*?([A-Za-z]:\\[^\x00]{5,260})",
                chunk,
            )
            if file_match:
                script_filename = file_match.group(1).decode("ascii", errors="replace")

            name = self._extract_string_near(chunk, b"Name")
            if not name:
                name = f"Consumer_{match.start()}"

            if script_text or script_filename:
                self.consumers.append(
                    WMIEventConsumer(
                        name=name,
                        consumer_type="ActiveScriptEventConsumer",
                        script_text=script_text[:500],  # Truncate long scripts
                        script_filename=script_filename,
                    )
                )

    def _extract_bindings(self) -> None:
        """Extract __FilterToConsumerBinding instances."""
        # Look for binding patterns
        binding_pattern = re.compile(
            rb"__FilterToConsumerBinding",
            re.IGNORECASE,
        )

        for match in binding_pattern.finditer(self.data):
            end = min(len(self.data), match.end() + 1000)
            chunk = self.data[match.start() : end]

            # Extract Filter reference
            filter_match = re.search(rb'Filter[^\x00]*?"([^"]+)"', chunk)
            filter_name = (
                filter_match.group(1).decode("ascii", errors="replace")
                if filter_match
                else ""
            )

            # Extract Consumer reference
            consumer_match = re.search(rb'Consumer[^\x00]*?"([^"]+)"', chunk)
            consumer_name = (
                consumer_match.group(1).decode("ascii", errors="replace")
                if consumer_match
                else ""
            )

            if filter_name or consumer_name:
                self.bindings.append(
                    WMIBinding(
                        filter_name=filter_name,
                        consumer_name=consumer_name,
                    )
                )

    def _extract_string_near(
        self, chunk: bytes, keyword: bytes, max_distance: int = 100
    ) -> str:
        """Extract a string value near a keyword."""
        idx = chunk.find(keyword)
        if idx == -1:
            return ""

        # Look for string after keyword
        start = idx + len(keyword)
        end = min(start + max_distance, len(chunk))
        sub_chunk = chunk[start:end]

        # Extract first reasonable string
        strings = re.findall(rb"[\x20-\x7e]{3,100}", sub_chunk)
        if strings:
            return strings[0].decode("ascii", errors="replace")

        return ""

    def get_persistence_mechanisms(self) -> list[WMIPersistence]:
        """Match filters, consumers, and bindings into complete persistence mechanisms."""
        mechanisms = []

        # Create lookup dicts
        filter_dict = {f.name: f for f in self.filters}
        consumer_dict = {c.name: c for c in self.consumers}

        # Match through bindings
        for binding in self.bindings:
            filter_obj = None
            consumer_obj = None

            # Try to find matching filter
            for name, f in filter_dict.items():
                if name in binding.filter_name or binding.filter_name in name:
                    filter_obj = f
                    break

            # Try to find matching consumer
            for name, c in consumer_dict.items():
                if name in binding.consumer_name or binding.consumer_name in name:
                    consumer_obj = c
                    break

            if filter_obj or consumer_obj:
                mechanism = WMIPersistence(
                    filter=filter_obj,
                    consumer=consumer_obj,
                    binding=binding,
                )
                mechanism.risk_indicators = self._analyze_risk(mechanism)
                mechanism.risk_level = (
                    "high"
                    if len(mechanism.risk_indicators) >= 2
                    else "medium"
                    if mechanism.risk_indicators
                    else "low"
                )
                mechanisms.append(mechanism)

        # Also add unmatched consumers as potential persistence
        matched_consumers = {m.consumer.name for m in mechanisms if m.consumer}
        for consumer in self.consumers:
            if consumer.name not in matched_consumers:
                mechanism = WMIPersistence(
                    filter=None,
                    consumer=consumer,
                    binding=None,
                )
                mechanism.risk_indicators = self._analyze_risk(mechanism)
                mechanism.risk_level = "medium"
                mechanisms.append(mechanism)

        return mechanisms

    def _analyze_risk(self, mechanism: WMIPersistence) -> list[str]:
        """Analyze risk indicators for a persistence mechanism."""
        indicators = []

        if mechanism.consumer:
            consumer = mechanism.consumer

            # Check consumer type
            if consumer.consumer_type == "ActiveScriptEventConsumer":
                indicators.append("script_consumer")

            # Check for suspicious paths
            path = (consumer.executable_path + consumer.command_line).lower()
            if any(
                p in path
                for p in ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\"]
            ):
                indicators.append("suspicious_path")

            # Check for powershell
            if "powershell" in path or "pwsh" in path:
                indicators.append("powershell_execution")

            # Check for encoded commands
            if "-enc" in path or "-encodedcommand" in path:
                indicators.append("encoded_command")

            # Check for common malware tools
            if any(
                t in path
                for t in ["cmd.exe", "wscript", "cscript", "mshta", "regsvr32"]
            ):
                indicators.append("lolbin_execution")

            # Check script content
            if consumer.script_text:
                script_lower = consumer.script_text.lower()
                if any(
                    p in script_lower
                    for p in [
                        "downloadstring",
                        "invoke-expression",
                        "iex",
                        "webclient",
                        "downloadfile",
                    ]
                ):
                    indicators.append("download_execution")

        if mechanism.filter:
            query_lower = mechanism.filter.query.lower()

            # Check for process-based triggers
            if "__instancecreationevent" in query_lower:
                if "win32_process" in query_lower:
                    indicators.append("process_trigger")

            # Check for startup triggers
            if any(
                t in query_lower
                for t in ["win32_logonsession", "startup", "logon"]
            ):
                indicators.append("startup_trigger")

        return indicators


@ParserRegistry.register
class WMIFileParser(BaseParser):
    """Parser for WMI repository files."""

    name: ClassVar[str] = "wmi"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "wmi",
        "wmi_persistence",
        "objects.data",
        "wmi_repository",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize WMI parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse WMI repository file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse WMI repository from bytes."""
        parser = WMIRepositoryParser(data)
        mechanisms = parser.get_persistence_mechanisms()

        record_index = 0

        for mechanism in mechanisms:
            record_data: dict[str, Any] = {
                "persistence_type": "wmi_event_subscription",
                "risk_level": mechanism.risk_level,
                "source_file": filename,
            }

            if mechanism.risk_indicators:
                record_data["risk_indicators"] = mechanism.risk_indicators

            if mechanism.filter:
                record_data["filter"] = {
                    "name": mechanism.filter.name,
                    "query": mechanism.filter.query,
                    "query_language": mechanism.filter.query_language,
                }

            if mechanism.consumer:
                consumer_data: dict[str, Any] = {
                    "name": mechanism.consumer.name,
                    "type": mechanism.consumer.consumer_type,
                }
                if mechanism.consumer.executable_path:
                    consumer_data["executable_path"] = mechanism.consumer.executable_path
                if mechanism.consumer.command_line:
                    consumer_data["command_line"] = mechanism.consumer.command_line
                if mechanism.consumer.script_text:
                    consumer_data["script_text"] = mechanism.consumer.script_text[:200]
                if mechanism.consumer.script_filename:
                    consumer_data["script_filename"] = mechanism.consumer.script_filename

                record_data["consumer"] = consumer_data

            if mechanism.binding:
                record_data["binding"] = {
                    "filter": mechanism.binding.filter_name,
                    "consumer": mechanism.binding.consumer_name,
                }

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            # Create record ID from consumer name or filter name
            id_component = ""
            if mechanism.consumer:
                id_component = mechanism.consumer.name
            elif mechanism.filter:
                id_component = mechanism.filter.name

            record_id = self.create_record_id(
                "wmi_persistence", record_index, id_component
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="ioc",
                timestamp=None,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        # Also emit raw filter and consumer counts
        if parser.filters or parser.consumers:
            summary_data = {
                "summary": True,
                "filter_count": len(parser.filters),
                "consumer_count": len(parser.consumers),
                "binding_count": len(parser.bindings),
                "persistence_count": len(mechanisms),
                "source_file": filename,
            }

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("wmi_summary", filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=summary_data,
                evidence_ref=evidence_ref,
            )
