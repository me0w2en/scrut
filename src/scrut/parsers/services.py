r"""Windows Services parser.

Parses Windows services configuration from the SYSTEM registry hive
to identify installed services, startup types, and potential persistence.

Location:
- SYSTEM\CurrentControlSet\Services\*
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# Service types
SERVICE_TYPES = {
    0x001: "KERNEL_DRIVER",
    0x002: "FILE_SYSTEM_DRIVER",
    0x004: "ADAPTER",
    0x008: "RECOGNIZER_DRIVER",
    0x010: "WIN32_OWN_PROCESS",
    0x020: "WIN32_SHARE_PROCESS",
    0x050: "USER_OWN_PROCESS",
    0x060: "USER_SHARE_PROCESS",
    0x100: "INTERACTIVE_PROCESS",
}

# Service start types
START_TYPES = {
    0: "Boot",
    1: "System",
    2: "Automatic",
    3: "Manual",
    4: "Disabled",
}

# Service error control
ERROR_CONTROL = {
    0: "Ignore",
    1: "Normal",
    2: "Severe",
    3: "Critical",
}


@dataclass
class ServiceEntry:
    """A Windows service entry."""

    name: str
    display_name: str
    description: str
    service_type: int
    service_type_name: str
    start_type: int
    start_type_name: str
    error_control: int
    image_path: str
    object_name: str  # Account the service runs as
    depends_on: list[str]
    service_dll: str = ""
    failure_actions: str = ""


def _to_unicode_pattern(ascii_str: bytes) -> bytes:
    """Convert ASCII bytes to UTF-16-LE pattern."""
    return b"".join(bytes([b, 0]) for b in ascii_str)


class ServicesParser:
    """Parser for Windows services from registry data."""

    def __init__(self, data: bytes, hive_type: str = "SYSTEM") -> None:
        """Initialize parser."""
        self.data = data
        self.hive_type = hive_type
        self.services: list[ServiceEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse services from registry hive data."""
        if len(self.data) < 4096:
            return

        # Registry hives store strings in UTF-16-LE (Unicode)
        # Look for service key patterns in Unicode format
        # Services have keys like: Services\<name>

        # Unicode pattern for "Services\"
        services_unicode = _to_unicode_pattern(b"Services\\")

        found_services = set()

        # Find all occurrences of "Services\" in Unicode
        idx = 0
        while True:
            idx = self.data.find(services_unicode, idx)
            if idx == -1:
                break

            # Extract service name after "Services\"
            name_start = idx + len(services_unicode)
            service_name = self._extract_unicode_name(name_start)

            if service_name and len(service_name) >= 2:
                # Filter out value names and invalid names
                if service_name not in found_services:
                    if not self._is_value_name(service_name):
                        found_services.add(service_name)

            idx += 2  # Move past current match

        # For each service, try to extract details
        for service_name in found_services:
            service = self._extract_service(service_name)
            if service:
                self.services.append(service)

    def _extract_unicode_name(self, start: int) -> str:
        """Extract a Unicode string starting at the given offset."""
        chars = []
        i = start
        while i < len(self.data) - 1 and len(chars) < 256:
            low = self.data[i]
            high = self.data[i + 1]

            # Check for valid ASCII character in Unicode
            if high == 0 and (0x20 <= low <= 0x7E or low == ord("_") or low == ord("-")):
                chars.append(chr(low))
                i += 2
            # Stop at null terminator or backslash (end of key name)
            elif low == 0 and high == 0 or low == ord("\\") and high == 0:
                break
            else:
                break

        return "".join(chars)

    def _is_value_name(self, name: str) -> bool:
        """Check if name is a registry value name, not a service name."""
        value_names = {
            "Type", "Start", "ErrorControl", "ImagePath", "DisplayName",
            "Description", "ObjectName", "DependOnService", "ServiceDll",
            "FailureActions", "RequiredPrivileges", "ServiceSidType",
            "DelayedAutostart", "Group", "Tag", "Parameters", "Security",
            "Enum", "Performance", "Linkage", "NetworkProvider",
        }
        return name in value_names

    def _extract_service(self, name: str) -> ServiceEntry | None:
        """Extract service details from registry data."""
        # Find the service key location in Unicode
        name_unicode = _to_unicode_pattern(name.encode("ascii", errors="replace"))
        services_pattern = _to_unicode_pattern(b"Services\\") + name_unicode

        idx = self.data.find(services_pattern)
        if idx == -1:
            # Try just finding the service name
            idx = self.data.find(name_unicode)
            if idx == -1:
                return None

        # Search for values in surrounding area
        start = max(0, idx - 200)
        end = min(len(self.data), idx + 8192)
        chunk = self.data[start:end]

        # Extract values (search for Unicode value names)
        display_name = self._find_unicode_string_value(chunk, b"DisplayName")
        description = self._find_unicode_string_value(chunk, b"Description")
        image_path = self._find_unicode_string_value(chunk, b"ImagePath")
        object_name = self._find_unicode_string_value(chunk, b"ObjectName")
        service_dll = self._find_unicode_string_value(chunk, b"ServiceDll")

        # Extract numeric values
        service_type = self._find_dword_value(chunk, b"Type")
        start_type = self._find_dword_value(chunk, b"Start")
        error_control = self._find_dword_value(chunk, b"ErrorControl")

        # Extract dependencies (multi-string)
        depends_on = self._find_multi_string_value(chunk, b"DependOnService")

        # Only include if we have meaningful data
        if not image_path and service_type is None:
            return None

        return ServiceEntry(
            name=name,
            display_name=display_name or name,
            description=description or "",
            service_type=service_type or 0,
            service_type_name=SERVICE_TYPES.get(service_type or 0, f"Unknown({service_type})"),
            start_type=start_type if start_type is not None else 3,
            start_type_name=START_TYPES.get(start_type if start_type is not None else 3, "Unknown"),
            error_control=error_control or 0,
            image_path=image_path or "",
            object_name=object_name or "LocalSystem",
            depends_on=depends_on,
            service_dll=service_dll or "",
        )

    def _find_unicode_string_value(self, chunk: bytes, name: bytes) -> str:
        """Find a Unicode string value in registry data."""
        # Search for the value name in Unicode
        name_unicode = _to_unicode_pattern(name)
        idx = chunk.find(name_unicode)
        if idx == -1:
            # Also try ASCII (some registry internals use ASCII)
            idx = chunk.find(name)
            if idx == -1:
                return ""

        # Look for string data after the name
        search_start = idx + len(name_unicode) if name_unicode in chunk[idx:idx+50] else idx + len(name)
        search_end = min(search_start + 1000, len(chunk))
        sub_chunk = chunk[search_start:search_end]

        # Extract Unicode strings
        strings = []
        i = 0
        current = []
        while i < len(sub_chunk) - 1:
            low = sub_chunk[i]
            high = sub_chunk[i + 1]

            if high == 0 and 0x20 <= low <= 0x7E or high == 0 and low in (ord("\\"), ord(":"), ord(".")):
                current.append(chr(low))
                i += 2
            else:
                if len(current) >= 3:
                    strings.append("".join(current))
                current = []
                i += 1

        if len(current) >= 3:
            strings.append("".join(current))

        # Return the first meaningful string found (prefer paths)
        for s in strings:
            if len(s) >= 3:
                # Prefer strings that look like paths or have meaningful content
                if "\\" in s or s.endswith(".exe") or s.endswith(".sys") or s.endswith(".dll"):
                    return s
        for s in strings:
            if len(s) >= 3:
                return s

        return ""

    def _find_dword_value(self, chunk: bytes, name: bytes) -> int | None:
        """Find a DWORD value in registry data."""
        # Search for value name in Unicode
        name_unicode = _to_unicode_pattern(name)
        idx = chunk.find(name_unicode)
        if idx == -1:
            idx = chunk.find(name)
            if idx == -1:
                return None

        # Look for 4-byte value near the name
        search_start = idx + len(name_unicode) if name_unicode in chunk[idx:idx+50] else idx + len(name)
        search_end = min(search_start + 100, len(chunk))

        # Try to find a reasonable DWORD value
        for i in range(search_start, min(search_end, len(chunk) - 4)):
            try:
                val = struct.unpack("<I", chunk[i : i + 4])[0]
                # Reasonable service type/start values are small
                if val <= 0x200:
                    return val
            except struct.error:
                pass

        return None

    def _find_multi_string_value(self, chunk: bytes, name: bytes) -> list[str]:
        """Find a multi-string value in registry data."""
        name_unicode = _to_unicode_pattern(name)
        idx = chunk.find(name_unicode)
        if idx == -1:
            idx = chunk.find(name)
            if idx == -1:
                return []

        # Look for string data after the name
        search_start = idx + len(name_unicode) if name_unicode in chunk[idx:idx+50] else idx + len(name)
        search_end = min(search_start + 500, len(chunk))
        sub_chunk = chunk[search_start:search_end]

        # Extract Unicode strings separated by nulls
        strings = []
        current = []
        i = 0
        while i < len(sub_chunk) - 1:
            low = sub_chunk[i]
            high = sub_chunk[i + 1]

            if high == 0:
                if 0x20 <= low <= 0x7E:
                    current.append(chr(low))
                elif low == 0 and current:
                    strings.append("".join(current))
                    current = []
                i += 2
            else:
                if current:
                    strings.append("".join(current))
                    current = []
                i += 1

        if current:
            strings.append("".join(current))

        return [s for s in strings if len(s) >= 2]


@ParserRegistry.register
class ServicesFileParser(BaseParser):
    """Parser for Windows services from SYSTEM registry hive."""

    name: ClassVar[str] = "services"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "services",
        "windows_services",
        "system_services",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize services parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse SYSTEM registry hive for services."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse services from registry hive bytes."""
        parser = ServicesParser(data)

        record_index = 0
        for service in parser.services:
            record_data: dict[str, Any] = {
                "service_name": service.name,
                "display_name": service.display_name,
                "service_type": service.service_type,
                "service_type_name": service.service_type_name,
                "start_type": service.start_type,
                "start_type_name": service.start_type_name,
                "error_control": service.error_control,
                "source_file": filename,
            }

            if service.description:
                record_data["description"] = service.description
            if service.image_path:
                record_data["image_path"] = service.image_path
            if service.object_name:
                record_data["run_as"] = service.object_name
            if service.depends_on:
                record_data["depends_on"] = service.depends_on
            if service.service_dll:
                record_data["service_dll"] = service.service_dll

            # Analyze for suspicious patterns
            risk_indicators = self._analyze_service(service)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "service", service.name
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _analyze_service(self, service: ServiceEntry) -> list[str]:
        """Analyze service for suspicious patterns."""
        indicators = []

        path_lower = service.image_path.lower() if service.image_path else ""

        # Suspicious paths
        suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\",
            "\\programdata\\",
            "\\users\\public\\",
        ]
        if any(p in path_lower for p in suspicious_paths):
            indicators.append("suspicious_path")

        # PowerShell in service
        if "powershell" in path_lower or "pwsh" in path_lower:
            indicators.append("powershell_service")

        # CMD in service
        if "cmd.exe" in path_lower or "cmd /c" in path_lower:
            indicators.append("cmd_service")

        # Script hosts
        if any(h in path_lower for h in ["wscript", "cscript", "mshta"]):
            indicators.append("script_host_service")

        # Encoded commands
        if "-enc" in path_lower or "-encodedcommand" in path_lower:
            indicators.append("encoded_command")

        # No extension or unusual extension
        if service.image_path:
            ext = Path(service.image_path).suffix.lower()
            if ext and ext not in [".exe", ".sys", ".dll"]:
                indicators.append("unusual_extension")

        # Automatic start from suspicious location
        if service.start_type in [0, 1, 2] and indicators:  # Boot, System, Auto
            indicators.append("auto_start_suspicious")

        return indicators
