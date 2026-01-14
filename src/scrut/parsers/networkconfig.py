"""Windows Network Configuration parser.

Parses network configuration from registry to identify
network interfaces, profiles, and connection history.

Locations:
- SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\
- SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\
- SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\
"""

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# Network category types
NETWORK_CATEGORIES = {
    0: "Public",
    1: "Private",
    2: "Domain",
}

# Interface types
INTERFACE_TYPES = {
    6: "Ethernet",
    71: "WiFi",
    23: "PPP",
    24: "Loopback",
    131: "Tunnel",
}


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


def _to_unicode_pattern(ascii_str: bytes) -> bytes:
    """Convert ASCII bytes to UTF-16-LE pattern."""
    return b"".join(bytes([b, 0]) for b in ascii_str)


@dataclass
class NetworkInterface:
    """A network interface configuration."""

    interface_guid: str
    ip_address: str
    subnet_mask: str
    default_gateway: str
    dhcp_enabled: bool
    dhcp_server: str = ""
    dns_servers: list[str] = field(default_factory=list)
    domain: str = ""
    lease_obtained: datetime | None = None
    lease_expires: datetime | None = None


@dataclass
class NetworkProfile:
    """A network profile (connection history)."""

    profile_guid: str
    profile_name: str
    description: str
    category: int
    category_name: str
    date_created: datetime | None
    date_last_connected: datetime | None
    managed: bool = False
    gateway_mac: str = ""
    dns_suffix: str = ""


class NetworkConfigParser:
    """Parser for Windows network configuration."""

    def __init__(self, data: bytes, hive_type: str = "SYSTEM") -> None:
        """Initialize parser."""
        self.data = data
        self.hive_type = hive_type
        self.interfaces: list[NetworkInterface] = []
        self.profiles: list[NetworkProfile] = []
        self._parse()

    def _parse(self) -> None:
        """Parse network configuration from registry data."""
        if len(self.data) < 100:
            return

        if self.hive_type.upper() == "SYSTEM":
            self._parse_interfaces()
        elif self.hive_type.upper() == "SOFTWARE":
            self._parse_profiles()
        else:
            self._parse_interfaces()
            self._parse_profiles()

    def _parse_interfaces(self) -> None:
        """Parse network interfaces from SYSTEM hive."""
        # Registry stores strings in UTF-16-LE (Unicode)
        # Look for "Interfaces\" pattern in Unicode
        interfaces_unicode = _to_unicode_pattern(b"Interfaces\\")

        found_guids = set()

        # Find all occurrences of "Interfaces\" in Unicode
        idx = 0
        while True:
            idx = self.data.find(interfaces_unicode, idx)
            if idx == -1:
                break

            # Extract GUID after "Interfaces\"
            guid_start = idx + len(interfaces_unicode)
            guid = self._extract_unicode_guid(guid_start)

            if guid and guid not in found_guids:
                found_guids.add(guid)

            idx += 2

        for guid in found_guids:
            interface = self._extract_interface(guid)
            if interface:
                self.interfaces.append(interface)

    def _extract_unicode_guid(self, start: int) -> str:
        """Extract a GUID in Unicode format."""
        # GUIDs look like: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
        chars = []
        i = start
        while i < len(self.data) - 1 and len(chars) < 40:
            low = self.data[i]
            high = self.data[i + 1]

            if high == 0:
                char = chr(low)
                if char in "0123456789ABCDEFabcdef{}-":
                    chars.append(char)
                    i += 2
                else:
                    break
            else:
                break

        guid = "".join(chars)
        # Validate GUID format
        if len(guid) == 38 and guid.startswith("{") and guid.endswith("}"):
            return guid
        return ""

    def _extract_interface(self, guid: str) -> NetworkInterface | None:
        """Extract interface configuration."""
        # Find the interface key location in Unicode
        guid_unicode = _to_unicode_pattern(guid.encode("ascii"))
        interfaces_pattern = _to_unicode_pattern(b"Interfaces\\") + guid_unicode

        idx = self.data.find(interfaces_pattern)
        if idx == -1:
            idx = self.data.find(guid_unicode)
            if idx == -1:
                return None

        start = max(0, idx - 200)
        end = min(len(self.data), idx + 4096)
        chunk = self.data[start:end]

        ip_address = self._find_ip_value(chunk, b"IPAddress")
        subnet_mask = self._find_ip_value(chunk, b"SubnetMask")
        default_gateway = self._find_ip_value(chunk, b"DefaultGateway")
        dhcp_server = self._find_ip_value(chunk, b"DhcpServer")
        dns_servers = self._find_multi_ip_value(chunk, b"NameServer")
        domain = self._find_string_value(chunk, b"Domain")

        dhcp_enabled = self._find_dword_value(chunk, b"EnableDHCP")
        lease_obtained = self._find_filetime_value(chunk, b"LeaseObtainedTime")
        lease_expires = self._find_filetime_value(chunk, b"LeaseTerminatesTime")

        if not ip_address and dhcp_enabled is None:
            return None

        return NetworkInterface(
            interface_guid=guid,
            ip_address=ip_address or "",
            subnet_mask=subnet_mask or "",
            default_gateway=default_gateway or "",
            dhcp_enabled=bool(dhcp_enabled) if dhcp_enabled is not None else True,
            dhcp_server=dhcp_server or "",
            dns_servers=dns_servers,
            domain=domain or "",
            lease_obtained=lease_obtained,
            lease_expires=lease_expires,
        )

    def _parse_profiles(self) -> None:
        """Parse network profiles from SOFTWARE hive."""
        # Look for "NetworkList\Profiles\" in Unicode
        profiles_unicode = _to_unicode_pattern(b"Profiles\\")

        found_guids = set()

        idx = 0
        while True:
            idx = self.data.find(profiles_unicode, idx)
            if idx == -1:
                break

            # Extract GUID after "Profiles\"
            guid_start = idx + len(profiles_unicode)
            guid = self._extract_unicode_guid(guid_start)

            if guid and guid not in found_guids:
                found_guids.add(guid)

            idx += 2

        for guid in found_guids:
            profile = self._extract_profile(guid)
            if profile:
                self.profiles.append(profile)

    def _extract_profile(self, guid: str) -> NetworkProfile | None:
        """Extract network profile."""
        # Find profile in Unicode
        guid_unicode = _to_unicode_pattern(guid.encode("ascii"))
        profiles_pattern = _to_unicode_pattern(b"Profiles\\") + guid_unicode

        idx = self.data.find(profiles_pattern)
        if idx == -1:
            idx = self.data.find(guid_unicode)
            if idx == -1:
                return None

        start = max(0, idx - 200)
        end = min(len(self.data), idx + 2048)
        chunk = self.data[start:end]

        profile_name = self._find_string_value(chunk, b"ProfileName")
        description = self._find_string_value(chunk, b"Description")
        category = self._find_dword_value(chunk, b"Category")
        managed = self._find_dword_value(chunk, b"Managed")

        date_created = self._find_filetime_value(chunk, b"DateCreated")
        date_last_connected = self._find_filetime_value(chunk, b"DateLastConnected")

        if not profile_name:
            return None

        return NetworkProfile(
            profile_guid=guid,
            profile_name=profile_name,
            description=description or "",
            category=category if category is not None else 0,
            category_name=NETWORK_CATEGORIES.get(category or 0, "Unknown"),
            date_created=date_created,
            date_last_connected=date_last_connected,
            managed=bool(managed) if managed is not None else False,
        )

    def _find_string_value(self, chunk: bytes, name: bytes) -> str:
        """Find string value in registry data."""
        # Search for value name in Unicode
        name_unicode = _to_unicode_pattern(name)
        idx = chunk.find(name_unicode)
        if idx == -1:
            # Also try ASCII
            idx = chunk.find(name)
            if idx == -1:
                return ""

        search_start = idx + (len(name_unicode) if name_unicode in chunk[idx:idx+50] else len(name))
        search_end = min(search_start + 500, len(chunk))
        sub_chunk = chunk[search_start:search_end]

        strings = []
        i = 0
        current = []
        while i < len(sub_chunk) - 1:
            low = sub_chunk[i]
            high = sub_chunk[i + 1]

            if high == 0 and (0x20 <= low <= 0x7E or low in (ord("."), ord(":"), ord("\\"))):
                current.append(chr(low))
                i += 2
            else:
                if len(current) >= 2:
                    strings.append("".join(current))
                current = []
                i += 1

        if len(current) >= 2:
            strings.append("".join(current))

        for s in strings:
            if len(s) >= 2:
                return s
        return ""

    def _find_ip_value(self, chunk: bytes, name: bytes) -> str:
        """Find IP address value."""
        s = self._find_string_value(chunk, name)
        if s and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
            return s
        return ""

    def _find_multi_ip_value(self, chunk: bytes, name: bytes) -> list[str]:
        """Find multiple IP addresses (comma or space separated)."""
        s = self._find_string_value(chunk, name)
        if not s:
            return []

        parts = re.split(r"[,\s]+", s)
        ips = []
        for part in parts:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", part.strip()):
                ips.append(part.strip())
        return ips

    def _find_dword_value(self, chunk: bytes, name: bytes) -> int | None:
        """Find DWORD value."""
        # Search in Unicode
        name_unicode = _to_unicode_pattern(name)
        idx = chunk.find(name_unicode)
        if idx == -1:
            idx = chunk.find(name)
            if idx == -1:
                return None

        search_start = idx + (len(name_unicode) if name_unicode in chunk[idx:idx+50] else len(name))
        for i in range(search_start, min(search_start + 100, len(chunk) - 4)):
            try:
                val = struct.unpack("<I", chunk[i : i + 4])[0]
                if val <= 10:
                    return val
            except struct.error:
                pass
        return None

    def _find_filetime_value(self, chunk: bytes, name: bytes) -> datetime | None:
        """Find FILETIME value."""
        # Search in Unicode
        name_unicode = _to_unicode_pattern(name)
        idx = chunk.find(name_unicode)
        if idx == -1:
            idx = chunk.find(name)
            if idx == -1:
                return None

        search_start = idx + (len(name_unicode) if name_unicode in chunk[idx:idx+50] else len(name))
        for i in range(search_start, min(search_start + 100, len(chunk) - 8)):
            try:
                val = struct.unpack("<Q", chunk[i : i + 8])[0]
                dt = _filetime_to_datetime(val)
                if dt and dt.year >= 2000 and dt.year <= 2100:
                    return dt
            except struct.error:
                pass
        return None


@ParserRegistry.register
class NetworkConfigFileParser(BaseParser):
    """Parser for Windows network configuration."""

    name: ClassVar[str] = "networkconfig"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "networkconfig",
        "network_config",
        "network_interfaces",
        "network_profiles",
        "networklist",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize network config parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse network configuration from registry hive."""
        with open(file_path, "rb") as f:
            data = f.read()

        filename = file_path.name.upper()
        if "SYSTEM" in filename:
            hive_type = "SYSTEM"
        elif "SOFTWARE" in filename:
            hive_type = "SOFTWARE"
        else:
            hive_type = "UNKNOWN"

        yield from self.parse_bytes(data, file_path.name, hive_type)

    def parse_bytes(
        self, data: bytes, filename: str = "", hive_type: str = "UNKNOWN"
    ) -> Iterator[ParsedRecord]:
        """Parse network configuration from bytes."""
        parser = NetworkConfigParser(data, hive_type)

        record_index = 0

        for interface in parser.interfaces:
            record_data: dict[str, Any] = {
                "record_type": "network_interface",
                "interface_guid": interface.interface_guid,
                "dhcp_enabled": interface.dhcp_enabled,
                "source_file": filename,
            }

            if interface.ip_address:
                record_data["ip_address"] = interface.ip_address
            if interface.subnet_mask:
                record_data["subnet_mask"] = interface.subnet_mask
            if interface.default_gateway:
                record_data["default_gateway"] = interface.default_gateway
            if interface.dhcp_server:
                record_data["dhcp_server"] = interface.dhcp_server
            if interface.dns_servers:
                record_data["dns_servers"] = interface.dns_servers
            if interface.domain:
                record_data["domain"] = interface.domain
            if interface.lease_obtained:
                record_data["lease_obtained"] = interface.lease_obtained.isoformat()
            if interface.lease_expires:
                record_data["lease_expires"] = interface.lease_expires.isoformat()

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "network_interface", interface.interface_guid
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=interface.lease_obtained,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        for profile in parser.profiles:
            record_data = {
                "record_type": "network_profile",
                "profile_guid": profile.profile_guid,
                "profile_name": profile.profile_name,
                "category": profile.category,
                "category_name": profile.category_name,
                "managed": profile.managed,
                "source_file": filename,
            }

            if profile.description:
                record_data["description"] = profile.description
            if profile.date_created:
                record_data["date_created"] = profile.date_created.isoformat()
            if profile.date_last_connected:
                record_data["date_last_connected"] = profile.date_last_connected.isoformat()

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "network_profile", profile.profile_guid
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=profile.date_last_connected or profile.date_created,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
