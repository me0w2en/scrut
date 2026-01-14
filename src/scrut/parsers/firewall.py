"""Windows Firewall Rules parser.

Parses Windows Firewall rules from registry to identify
network access rules and potential security issues.

Locations:
- SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\
- SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\
"""

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# Firewall rule actions
RULE_ACTIONS = {
    0: "Block",
    1: "Allow",
    2: "AllowBypass",  # Allow even if firewall is on
}

# Firewall rule directions
RULE_DIRECTIONS = {
    1: "Inbound",
    2: "Outbound",
}

# Firewall profiles
PROFILES = {
    1: "Domain",
    2: "Private",
    4: "Public",
    2147483647: "All",
}

# Protocols
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    58: "ICMPv6",
    256: "Any",
}


@dataclass
class FirewallRule:
    """A Windows Firewall rule."""

    name: str
    description: str
    action: str
    direction: str
    enabled: bool
    profiles: list[str]
    protocol: str
    local_ports: str
    remote_ports: str
    local_addresses: str
    remote_addresses: str
    application_path: str
    service_name: str
    edge_traversal: bool = False


class FirewallParser:
    """Parser for Windows Firewall rules."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.rules: list[FirewallRule] = []
        self.settings: dict[str, Any] = {}
        self._parse()

    def _parse(self) -> None:
        """Parse firewall data from registry."""
        if len(self.data) < 100:
            return

        # Parse firewall rules
        self._parse_rules()

        # Parse global settings
        self._parse_settings()

    def _parse_rules(self) -> None:
        """Parse firewall rule entries."""
        # Look for FirewallRules value patterns
        # Rules are stored as pipe-delimited strings
        # Format: v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|...

        # Find rule patterns
        rule_pattern = re.compile(
            rb"v2\.\d+\|[A-Za-z]+=",
            re.IGNORECASE,
        )

        for match in rule_pattern.finditer(self.data):
            # Extract the full rule string
            start = match.start()
            end = start + 2000  # Rules can be long
            chunk = self.data[start:end]

            # Find end of rule (null terminator or invalid char)
            rule_end = 0
            for i, b in enumerate(chunk):
                if b == 0 or b > 127:
                    rule_end = i
                    break
            else:
                rule_end = len(chunk)

            if rule_end < 10:
                continue

            rule_str = chunk[:rule_end].decode("ascii", errors="replace")
            rule = self._parse_rule_string(rule_str)
            if rule:
                self.rules.append(rule)

    def _parse_rule_string(self, rule_str: str) -> FirewallRule | None:
        """Parse a firewall rule string."""
        if not rule_str.startswith("v2."):
            return None

        # Split by pipe
        parts = rule_str.split("|")
        if len(parts) < 3:
            return None

        # Parse key=value pairs
        values = {}
        for part in parts[1:]:  # Skip version
            if "=" in part:
                key, value = part.split("=", 1)
                values[key] = value

        # Extract rule properties
        name = values.get("Name", "Unknown")
        description = values.get("Desc", "")
        action = values.get("Action", "Allow")
        direction = values.get("Dir", "In")
        enabled = values.get("Active", "TRUE").upper() == "TRUE"
        protocol = values.get("Protocol", "")
        local_ports = values.get("LPort", "*")
        remote_ports = values.get("RPort", "*")
        local_addresses = values.get("LA4", values.get("LA6", "*"))
        remote_addresses = values.get("RA4", values.get("RA6", "*"))
        app_path = values.get("App", "")
        service_name = values.get("Svc", "")
        edge_traversal = values.get("Edge", "FALSE").upper() == "TRUE"

        # Parse profiles
        profile_str = values.get("Profile", "")
        profiles = []
        if profile_str:
            if "Domain" in profile_str:
                profiles.append("Domain")
            if "Private" in profile_str:
                profiles.append("Private")
            if "Public" in profile_str:
                profiles.append("Public")
        if not profiles:
            profiles = ["All"]

        # Map protocol number to name
        if protocol.isdigit():
            protocol = PROTOCOLS.get(int(protocol), f"Protocol-{protocol}")

        return FirewallRule(
            name=name,
            description=description,
            action=action,
            direction=direction,
            enabled=enabled,
            profiles=profiles,
            protocol=protocol,
            local_ports=local_ports,
            remote_ports=remote_ports,
            local_addresses=local_addresses,
            remote_addresses=remote_addresses,
            application_path=app_path,
            service_name=service_name,
            edge_traversal=edge_traversal,
        )

    def _parse_settings(self) -> None:
        """Parse global firewall settings."""
        # Look for EnableFirewall, DefaultInboundAction, etc.
        settings_keys = [
            (b"EnableFirewall", "enabled"),
            (b"DefaultInboundAction", "default_inbound"),
            (b"DefaultOutboundAction", "default_outbound"),
            (b"DisableNotifications", "notifications_disabled"),
        ]

        for key_bytes, setting_name in settings_keys:
            idx = self.data.find(key_bytes)
            if idx != -1:
                # Look for DWORD value nearby
                for i in range(idx + len(key_bytes), min(idx + len(key_bytes) + 50, len(self.data) - 4)):
                    try:
                        val = struct.unpack("<I", self.data[i : i + 4])[0]
                        if val <= 10:  # Reasonable value
                            self.settings[setting_name] = val
                            break
                    except struct.error:
                        pass


@ParserRegistry.register
class FirewallFileParser(BaseParser):
    """Parser for Windows Firewall rules."""

    name: ClassVar[str] = "firewall"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "firewall",
        "firewall_rules",
        "windows_firewall",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize firewall parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse firewall rules from registry hive."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse firewall rules from registry bytes."""
        parser = FirewallParser(data)

        record_index = 0

        # Emit individual rules
        for rule in parser.rules:
            record_data: dict[str, Any] = {
                "rule_name": rule.name,
                "action": rule.action,
                "direction": rule.direction,
                "enabled": rule.enabled,
                "profiles": rule.profiles,
                "protocol": rule.protocol,
                "source_file": filename,
            }

            if rule.description:
                record_data["description"] = rule.description
            if rule.local_ports and rule.local_ports != "*":
                record_data["local_ports"] = rule.local_ports
            if rule.remote_ports and rule.remote_ports != "*":
                record_data["remote_ports"] = rule.remote_ports
            if rule.local_addresses and rule.local_addresses != "*":
                record_data["local_addresses"] = rule.local_addresses
            if rule.remote_addresses and rule.remote_addresses != "*":
                record_data["remote_addresses"] = rule.remote_addresses
            if rule.application_path:
                record_data["application_path"] = rule.application_path
            if rule.service_name:
                record_data["service_name"] = rule.service_name
            if rule.edge_traversal:
                record_data["edge_traversal"] = True

            # Analyze for security issues
            risk_indicators = self._analyze_rule(rule)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "firewall_rule", rule.name, rule.direction
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

        # Emit summary with settings
        if parser.rules or parser.settings:
            summary_data: dict[str, Any] = {
                "summary": True,
                "rule_count": len(parser.rules),
                "enabled_rules": sum(1 for r in parser.rules if r.enabled),
                "inbound_rules": sum(1 for r in parser.rules if r.direction == "In"),
                "outbound_rules": sum(1 for r in parser.rules if r.direction == "Out"),
                "allow_rules": sum(1 for r in parser.rules if r.action == "Allow"),
                "block_rules": sum(1 for r in parser.rules if r.action == "Block"),
                "source_file": filename,
            }

            if parser.settings:
                summary_data["settings"] = parser.settings

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("firewall_summary", filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=summary_data,
                evidence_ref=evidence_ref,
            )

    def _analyze_rule(self, rule: FirewallRule) -> list[str]:
        """Analyze firewall rule for security issues."""
        indicators = []

        # Allow any inbound
        if rule.action == "Allow" and rule.direction == "In":
            if rule.remote_addresses == "*" and rule.remote_ports == "*":
                indicators.append("allow_all_inbound")

        # Dangerous ports open
        dangerous_ports = ["445", "3389", "22", "23", "5985", "5986"]
        if rule.action == "Allow" and rule.direction == "In":
            if any(p in (rule.local_ports or "") for p in dangerous_ports):
                indicators.append("dangerous_port_open")

        # Public profile with Allow
        if rule.action == "Allow" and "Public" in rule.profiles:
            if rule.enabled:
                indicators.append("public_profile_allow")

        # Edge traversal enabled (bypasses NAT)
        if rule.edge_traversal:
            indicators.append("edge_traversal")

        # Suspicious application path
        if rule.application_path:
            path_lower = rule.application_path.lower()
            suspicious_paths = [
                "\\temp\\",
                "\\tmp\\",
                "\\appdata\\",
                "\\downloads\\",
            ]
            if any(p in path_lower for p in suspicious_paths):
                indicators.append("suspicious_app_path")

            # Non-exe application
            if not path_lower.endswith(".exe"):
                indicators.append("non_exe_application")

        return indicators
