r"""PowerShell History parser for command execution tracking.

Parses PowerShell ConsoleHost_history.txt files to extract
command history for forensic analysis.

Locations:
- %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
"""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# Known PowerShell history locations (relative to user profile)
POWERSHELL_HISTORY_PATHS = [
    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
    # Legacy location
    "AppData/Roaming/PSReadLine/ConsoleHost_history.txt",
]


@dataclass
class PowerShellCommand:
    """A single PowerShell command from history."""

    command: str
    line_number: int
    username: str = ""


class PowerShellHistoryParser:
    """Parser for PowerShell ConsoleHost_history.txt files."""

    def __init__(self, data: bytes, username: str = "") -> None:
        """Initialize parser with history file data."""
        self.data = data
        self.username = username
        self.commands: list[PowerShellCommand] = []
        self._parse()

    def _parse(self) -> None:
        """Parse PowerShell history file."""
        try:
            # Try UTF-8 first, then fall back to other encodings
            try:
                text = self.data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = self.data.decode("utf-16-le")
                except UnicodeDecodeError:
                    text = self.data.decode("latin-1")

            lines = text.splitlines()

            for line_num, line in enumerate(lines, start=1):
                line = line.strip()
                if line:
                    self.commands.append(
                        PowerShellCommand(
                            command=line,
                            line_number=line_num,
                            username=self.username,
                        )
                    )
        except Exception:
            pass


@ParserRegistry.register
class PowerShellHistoryFileParser(BaseParser):
    """Parser for PowerShell history files."""

    name: ClassVar[str] = "powershell"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "powershell",
        "powershell_history",
        "consolehost_history",
        "psreadline",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize PowerShell history parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse PowerShell history file."""
        with open(file_path, "rb") as f:
            data = f.read()

        # Try to extract username from path
        username = self._extract_username(str(file_path))
        yield from self.parse_bytes(data, username)

    def parse_bytes(
        self, data: bytes, username: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse PowerShell history from bytes."""
        parser = PowerShellHistoryParser(data, username)

        for cmd in parser.commands:
            record_data: dict[str, Any] = {
                "command": cmd.command,
                "line_number": cmd.line_number,
            }

            if cmd.username:
                record_data["username"] = cmd.username

            # Analyze command for suspicious patterns
            risk_indicators = self._analyze_command(cmd.command)
            if risk_indicators:
                record_data["risk_indicators"] = risk_indicators

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=cmd.line_number - 1,
            )

            record_id = self.create_record_id(
                "powershell", cmd.line_number, cmd.command[:50]
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=None,  # History file doesn't have timestamps
                data=record_data,
                evidence_ref=evidence_ref,
            )

    def _extract_username(self, path: str) -> str:
        """Extract username from file path."""
        # Path pattern: Users/<username>/AppData/...
        path_lower = path.lower().replace("\\", "/")
        if "/users/" in path_lower:
            parts = path.replace("\\", "/").split("/")
            try:
                users_idx = next(
                    i for i, p in enumerate(parts) if p.lower() == "users"
                )
                if users_idx + 1 < len(parts):
                    return parts[users_idx + 1]
            except StopIteration:
                pass
        return ""

    def _analyze_command(self, command: str) -> list[str]:
        """Analyze command for suspicious patterns."""
        indicators = []
        cmd_lower = command.lower()

        # Encoded commands
        if "-encodedcommand" in cmd_lower or "-enc " in cmd_lower:
            indicators.append("encoded_command")

        # Download patterns
        if any(
            p in cmd_lower
            for p in [
                "invoke-webrequest",
                "iwr ",
                "wget ",
                "curl ",
                "downloadstring",
                "downloadfile",
                "net.webclient",
                "start-bitstransfer",
            ]
        ):
            indicators.append("download_activity")

        # Execution bypass
        if "-executionpolicy" in cmd_lower and any(
            p in cmd_lower for p in ["bypass", "unrestricted"]
        ):
            indicators.append("execution_policy_bypass")

        # Credential access
        if any(
            p in cmd_lower
            for p in [
                "get-credential",
                "convertto-securestring",
                "mimikatz",
                "invoke-mimikatz",
                "sekurlsa",
                "lsadump",
            ]
        ):
            indicators.append("credential_access")

        # Reconnaissance
        if any(
            p in cmd_lower
            for p in [
                "get-aduser",
                "get-adcomputer",
                "get-adgroup",
                "get-netuser",
                "get-netcomputer",
                "get-netgroup",
                "get-domainuser",
            ]
        ):
            indicators.append("ad_reconnaissance")

        # Persistence
        if any(
            p in cmd_lower
            for p in [
                "new-scheduledtask",
                "register-scheduledjob",
                "new-service",
                "set-itemproperty.*run",
                "wmi ",
                "invoke-wmimethod",
            ]
        ):
            indicators.append("persistence_mechanism")

        # Lateral movement
        if any(
            p in cmd_lower
            for p in [
                "invoke-command",
                "enter-pssession",
                "new-pssession",
                "invoke-wmimethod",
                "invoke-psexec",
                "invoke-smbexec",
            ]
        ):
            indicators.append("lateral_movement")

        # Defense evasion
        if any(
            p in cmd_lower
            for p in [
                "set-mppreference",
                "add-mppreference",
                "-disablerealtimemonitoring",
                "amsi",
                "invoke-obfuscation",
            ]
        ):
            indicators.append("defense_evasion")

        return indicators
