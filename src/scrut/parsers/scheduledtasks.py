"""Scheduled Tasks parser for persistence mechanisms.

Parses Windows Scheduled Task files (XML format and legacy .job format)
to extract task configurations for persistence analysis.
"""

import struct
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# .job file signature
JOB_SIGNATURE = 0x0001

# Task trigger types
TRIGGER_TYPE_ONCE = 0
TRIGGER_TYPE_DAILY = 1
TRIGGER_TYPE_WEEKLY = 2
TRIGGER_TYPE_MONTHLY_DATE = 3
TRIGGER_TYPE_MONTHLY_DOW = 4
TRIGGER_TYPE_IDLE = 5
TRIGGER_TYPE_REGISTRATION = 6
TRIGGER_TYPE_BOOT = 7
TRIGGER_TYPE_LOGON = 8
TRIGGER_TYPE_SESSION_STATE_CHANGE = 11

TRIGGER_NAMES = {
    TRIGGER_TYPE_ONCE: "Once",
    TRIGGER_TYPE_DAILY: "Daily",
    TRIGGER_TYPE_WEEKLY: "Weekly",
    TRIGGER_TYPE_MONTHLY_DATE: "Monthly",
    TRIGGER_TYPE_MONTHLY_DOW: "Monthly DoW",
    TRIGGER_TYPE_IDLE: "On Idle",
    TRIGGER_TYPE_REGISTRATION: "At Registration",
    TRIGGER_TYPE_BOOT: "At Boot",
    TRIGGER_TYPE_LOGON: "At Logon",
    TRIGGER_TYPE_SESSION_STATE_CHANGE: "Session Change",
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


def _systemtime_to_datetime(
    year: int, month: int, day: int,
    hour: int, minute: int, second: int
) -> datetime | None:
    """Convert SYSTEMTIME components to datetime."""
    try:
        if year < 1970 or year > 2100:
            return None
        if month < 1 or month > 12:
            return None
        if day < 1 or day > 31:
            return None
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except (ValueError, OverflowError):
        return None


@dataclass
class TaskTrigger:
    """A scheduled task trigger."""

    trigger_type: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    enabled: bool = True
    repetition_interval: str = ""
    repetition_duration: str = ""
    days_of_week: list[str] = field(default_factory=list)
    days_of_month: list[int] = field(default_factory=list)
    user_id: str = ""


@dataclass
class TaskAction:
    """A scheduled task action."""

    action_type: str  # Exec, ComHandler, SendEmail, ShowMessage
    command: str = ""
    arguments: str = ""
    working_directory: str = ""
    class_id: str = ""
    data: str = ""


@dataclass
class ScheduledTask:
    """A complete scheduled task definition."""

    name: str
    path: str
    enabled: bool = True
    hidden: bool = False
    author: str = ""
    description: str = ""
    date_created: datetime | None = None
    last_run: datetime | None = None
    next_run: datetime | None = None
    user_id: str = ""
    run_level: str = ""
    triggers: list[TaskTrigger] = field(default_factory=list)
    actions: list[TaskAction] = field(default_factory=list)
    security_descriptor: str = ""
    source: str = ""


class XMLTaskParser:
    """Parser for XML format scheduled tasks (Vista+)."""

    # XML namespaces
    NS = {
        "": "http://schemas.microsoft.com/windows/2004/02/mit/task",
        "task": "http://schemas.microsoft.com/windows/2004/02/mit/task",
    }

    def __init__(self, data: bytes, name: str = "") -> None:
        """Initialize parser with XML data."""
        self.data = data
        self.name = name
        self.task: ScheduledTask | None = None
        self._parse()

    def _parse(self) -> None:
        """Parse XML task definition."""
        try:
            # Try to decode as UTF-8, UTF-16, or other
            xml_text = None
            for encoding in ["utf-8", "utf-16-le", "utf-16-be", "latin-1"]:
                try:
                    xml_text = self.data.decode(encoding)
                    if xml_text.startswith("\ufeff"):
                        xml_text = xml_text[1:]  # Remove BOM
                    break
                except UnicodeDecodeError:
                    continue

            if not xml_text:
                return

            # Parse XML
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return
        except Exception:
            return

        # Extract namespace from root if different
        ns = self.NS.copy()
        if root.tag.startswith("{"):
            default_ns = root.tag[1:root.tag.index("}")]
            ns[""] = default_ns
            ns["task"] = default_ns

        self.task = ScheduledTask(
            name=self.name,
            path="",
            source="XML",
        )

        # Registration Info
        reg_info = root.find("RegistrationInfo", ns) or root.find("task:RegistrationInfo", ns)
        if reg_info is not None:
            self._parse_registration_info(reg_info, ns)

        # Triggers
        triggers_elem = root.find("Triggers", ns) or root.find("task:Triggers", ns)
        if triggers_elem is not None:
            self._parse_triggers(triggers_elem, ns)

        # Actions
        actions_elem = root.find("Actions", ns) or root.find("task:Actions", ns)
        if actions_elem is not None:
            self._parse_actions(actions_elem, ns)

        # Principals
        principals_elem = root.find("Principals", ns) or root.find("task:Principals", ns)
        if principals_elem is not None:
            self._parse_principals(principals_elem, ns)

        # Settings
        settings_elem = root.find("Settings", ns) or root.find("task:Settings", ns)
        if settings_elem is not None:
            self._parse_settings(settings_elem, ns)

    def _parse_registration_info(self, elem, ns) -> None:
        """Parse RegistrationInfo element."""
        author = elem.find("Author", ns) or elem.find("task:Author", ns)
        if author is not None and author.text:
            self.task.author = author.text

        desc = elem.find("Description", ns) or elem.find("task:Description", ns)
        if desc is not None and desc.text:
            self.task.description = desc.text

        date = elem.find("Date", ns) or elem.find("task:Date", ns)
        if date is not None and date.text:
            try:
                # ISO format: 2024-01-15T10:30:00
                self.task.date_created = datetime.fromisoformat(
                    date.text.replace("Z", "+00:00")
                )
            except ValueError:
                pass

        uri = elem.find("URI", ns) or elem.find("task:URI", ns)
        if uri is not None and uri.text:
            self.task.path = uri.text

        sd = elem.find("SecurityDescriptor", ns) or elem.find("task:SecurityDescriptor", ns)
        if sd is not None and sd.text:
            self.task.security_descriptor = sd.text

    def _parse_triggers(self, elem, ns) -> None:
        """Parse Triggers element."""
        trigger_types = [
            ("TimeTrigger", "Time"),
            ("CalendarTrigger", "Calendar"),
            ("BootTrigger", "Boot"),
            ("LogonTrigger", "Logon"),
            ("IdleTrigger", "Idle"),
            ("RegistrationTrigger", "Registration"),
            ("SessionStateChangeTrigger", "Session"),
            ("EventTrigger", "Event"),
        ]

        for tag, ttype in trigger_types:
            for trig_elem in elem.findall(tag, ns) + elem.findall(f"task:{tag}", ns):
                trigger = TaskTrigger(trigger_type=ttype)

                # Enabled
                enabled = trig_elem.find("Enabled", ns) or trig_elem.find("task:Enabled", ns)
                if enabled is not None:
                    trigger.enabled = enabled.text.lower() == "true"

                # Start boundary
                start = trig_elem.find("StartBoundary", ns) or trig_elem.find("task:StartBoundary", ns)
                if start is not None and start.text:
                    try:
                        trigger.start_time = datetime.fromisoformat(
                            start.text.replace("Z", "+00:00")
                        )
                    except ValueError:
                        pass

                # End boundary
                end = trig_elem.find("EndBoundary", ns) or trig_elem.find("task:EndBoundary", ns)
                if end is not None and end.text:
                    try:
                        trigger.end_time = datetime.fromisoformat(
                            end.text.replace("Z", "+00:00")
                        )
                    except ValueError:
                        pass

                # User ID (for logon trigger)
                user = trig_elem.find("UserId", ns) or trig_elem.find("task:UserId", ns)
                if user is not None and user.text:
                    trigger.user_id = user.text

                # Repetition
                rep = trig_elem.find("Repetition", ns) or trig_elem.find("task:Repetition", ns)
                if rep is not None:
                    interval = rep.find("Interval", ns) or rep.find("task:Interval", ns)
                    if interval is not None and interval.text:
                        trigger.repetition_interval = interval.text
                    duration = rep.find("Duration", ns) or rep.find("task:Duration", ns)
                    if duration is not None and duration.text:
                        trigger.repetition_duration = duration.text

                self.task.triggers.append(trigger)

    def _parse_actions(self, elem, ns) -> None:
        """Parse Actions element."""
        # Exec actions
        for exec_elem in elem.findall("Exec", ns) + elem.findall("task:Exec", ns):
            action = TaskAction(action_type="Exec")

            command = exec_elem.find("Command", ns) or exec_elem.find("task:Command", ns)
            if command is not None and command.text:
                action.command = command.text

            args = exec_elem.find("Arguments", ns) or exec_elem.find("task:Arguments", ns)
            if args is not None and args.text:
                action.arguments = args.text

            workdir = exec_elem.find("WorkingDirectory", ns) or exec_elem.find("task:WorkingDirectory", ns)
            if workdir is not None and workdir.text:
                action.working_directory = workdir.text

            self.task.actions.append(action)

        # ComHandler actions
        for com_elem in elem.findall("ComHandler", ns) + elem.findall("task:ComHandler", ns):
            action = TaskAction(action_type="ComHandler")

            clsid = com_elem.find("ClassId", ns) or com_elem.find("task:ClassId", ns)
            if clsid is not None and clsid.text:
                action.class_id = clsid.text

            data = com_elem.find("Data", ns) or com_elem.find("task:Data", ns)
            if data is not None and data.text:
                action.data = data.text

            self.task.actions.append(action)

    def _parse_principals(self, elem, ns) -> None:
        """Parse Principals element."""
        for principal in elem.findall("Principal", ns) + elem.findall("task:Principal", ns):
            user_id = principal.find("UserId", ns) or principal.find("task:UserId", ns)
            if user_id is not None and user_id.text:
                self.task.user_id = user_id.text

            run_level = principal.find("RunLevel", ns) or principal.find("task:RunLevel", ns)
            if run_level is not None and run_level.text:
                self.task.run_level = run_level.text

    def _parse_settings(self, elem, ns) -> None:
        """Parse Settings element."""
        enabled = elem.find("Enabled", ns) or elem.find("task:Enabled", ns)
        if enabled is not None:
            self.task.enabled = enabled.text.lower() == "true"

        hidden = elem.find("Hidden", ns) or elem.find("task:Hidden", ns)
        if hidden is not None:
            self.task.hidden = hidden.text.lower() == "true"


class JobFileParser:
    """Parser for .job files (Windows XP format)."""

    def __init__(self, data: bytes, name: str = "") -> None:
        """Initialize parser with .job file data."""
        self.data = data
        self.name = name
        self.task: ScheduledTask | None = None
        self._parse()

    def _parse(self) -> None:
        """Parse .job file structure."""
        if len(self.data) < 68:
            return

        # Fixed-length section
        # Product version at offset 0
        product_version = struct.unpack("<H", self.data[0:2])[0]
        if product_version != JOB_SIGNATURE:
            return

        # File version at offset 2
        file_version = struct.unpack("<H", self.data[2:4])[0]

        # UUID at offset 4 (16 bytes)

        # App name offset at offset 20
        app_name_offset = struct.unpack("<H", self.data[20:22])[0]

        # Trigger offset
        trigger_offset = struct.unpack("<H", self.data[22:24])[0]

        # Error retry count
        error_retry_count = struct.unpack("<H", self.data[24:26])[0]

        # Error retry interval
        error_retry_interval = struct.unpack("<H", self.data[26:28])[0]

        # Idle deadline and wait
        idle_deadline = struct.unpack("<H", self.data[28:30])[0]
        idle_wait = struct.unpack("<H", self.data[30:32])[0]

        # Priority at offset 32
        priority = struct.unpack("<I", self.data[32:36])[0]

        # Maximum run time at offset 36
        max_run_time = struct.unpack("<I", self.data[36:40])[0]

        # Exit code at offset 40
        exit_code = struct.unpack("<I", self.data[40:44])[0]

        # Status at offset 44
        status = struct.unpack("<I", self.data[44:48])[0]

        # Flags at offset 48
        flags = struct.unpack("<I", self.data[48:52])[0]

        # Last run time (SYSTEMTIME) at offset 52
        last_run = self._parse_systemtime(52)

        self.task = ScheduledTask(
            name=self.name,
            path="",
            source="JOB",
            last_run=last_run,
        )

        # Parse variable-length section
        offset = 68

        # Running instance count
        if offset + 2 <= len(self.data):
            running_count = struct.unpack("<H", self.data[offset:offset + 2])[0]
            offset += 2

        # Application name (Unicode)
        app_name, offset = self._read_unicode_string(offset)
        if app_name:
            self.task.actions.append(
                TaskAction(action_type="Exec", command=app_name)
            )

        # Parameters
        params, offset = self._read_unicode_string(offset)
        if params and self.task.actions:
            self.task.actions[0].arguments = params

        # Working directory
        workdir, offset = self._read_unicode_string(offset)
        if workdir and self.task.actions:
            self.task.actions[0].working_directory = workdir

        # Author
        author, offset = self._read_unicode_string(offset)
        if author:
            self.task.author = author

        # Comment
        comment, offset = self._read_unicode_string(offset)
        if comment:
            self.task.description = comment

        # User data (skip)
        if offset + 2 <= len(self.data):
            user_data_len = struct.unpack("<H", self.data[offset:offset + 2])[0]
            offset += 2 + user_data_len

        # Reserved data (skip)
        if offset + 2 <= len(self.data):
            reserved_len = struct.unpack("<H", self.data[offset:offset + 2])[0]
            offset += 2 + reserved_len

        # Triggers
        if offset + 2 <= len(self.data):
            trigger_count = struct.unpack("<H", self.data[offset:offset + 2])[0]
            offset += 2

            for _ in range(trigger_count):
                if offset + 48 > len(self.data):
                    break

                trigger = self._parse_trigger(offset)
                if trigger:
                    self.task.triggers.append(trigger)

                offset += 48

    def _parse_systemtime(self, offset: int) -> datetime | None:
        """Parse SYSTEMTIME structure."""
        if offset + 16 > len(self.data):
            return None

        year = struct.unpack("<H", self.data[offset:offset + 2])[0]
        month = struct.unpack("<H", self.data[offset + 2:offset + 4])[0]
        # day_of_week = struct.unpack("<H", self.data[offset + 4:offset + 6])[0]
        day = struct.unpack("<H", self.data[offset + 6:offset + 8])[0]
        hour = struct.unpack("<H", self.data[offset + 8:offset + 10])[0]
        minute = struct.unpack("<H", self.data[offset + 10:offset + 12])[0]
        second = struct.unpack("<H", self.data[offset + 12:offset + 14])[0]
        # millisecond = struct.unpack("<H", self.data[offset + 14:offset + 16])[0]

        return _systemtime_to_datetime(year, month, day, hour, minute, second)

    def _read_unicode_string(self, offset: int) -> tuple[str, int]:
        """Read a Unicode string with length prefix."""
        if offset + 2 > len(self.data):
            return "", offset

        char_count = struct.unpack("<H", self.data[offset:offset + 2])[0]
        offset += 2

        if char_count == 0:
            return "", offset

        byte_count = char_count * 2
        if offset + byte_count > len(self.data):
            return "", offset

        try:
            result = self.data[offset:offset + byte_count].decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            result = ""

        return result, offset + byte_count

    def _parse_trigger(self, offset: int) -> TaskTrigger | None:
        """Parse a trigger structure."""
        if offset + 48 > len(self.data):
            return None

        # Trigger size at offset 0
        trigger_size = struct.unpack("<H", self.data[offset:offset + 2])[0]

        # Reserved at offset 2

        # Begin year/month/day
        begin_year = struct.unpack("<H", self.data[offset + 4:offset + 6])[0]
        begin_month = struct.unpack("<H", self.data[offset + 6:offset + 8])[0]
        begin_day = struct.unpack("<H", self.data[offset + 8:offset + 10])[0]

        # End year/month/day
        end_year = struct.unpack("<H", self.data[offset + 10:offset + 12])[0]
        end_month = struct.unpack("<H", self.data[offset + 12:offset + 14])[0]
        end_day = struct.unpack("<H", self.data[offset + 14:offset + 16])[0]

        # Start hour/minute
        start_hour = struct.unpack("<H", self.data[offset + 16:offset + 18])[0]
        start_minute = struct.unpack("<H", self.data[offset + 18:offset + 20])[0]

        # Trigger type at offset 28
        trigger_type = struct.unpack("<I", self.data[offset + 28:offset + 32])[0]

        trigger_name = TRIGGER_NAMES.get(trigger_type, f"Unknown ({trigger_type})")

        start_time = _systemtime_to_datetime(
            begin_year, begin_month, begin_day,
            start_hour, start_minute, 0
        )

        end_time = None
        if end_year > 0:
            end_time = _systemtime_to_datetime(
                end_year, end_month, end_day,
                23, 59, 59
            )

        return TaskTrigger(
            trigger_type=trigger_name,
            start_time=start_time,
            end_time=end_time,
        )


class ScheduledTasksParser:
    """High-level scheduled tasks parser."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename
        self.tasks: list[ScheduledTask] = []
        self._parse()

    def _parse(self) -> None:
        """Parse based on file type."""
        fname = self.filename.lower()

        if fname.endswith(".job"):
            parser = JobFileParser(self.data, self.filename)
            if parser.task:
                self.tasks.append(parser.task)
        else:
            # Try XML format
            parser = XMLTaskParser(self.data, self.filename)
            if parser.task:
                self.tasks.append(parser.task)


@ParserRegistry.register
class ScheduledTasksFileParser(BaseParser):
    """Parser for scheduled task files."""

    name: ClassVar[str] = "scheduledtasks"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "scheduledtasks",
        "tasks",
        "job",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize scheduled tasks parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse scheduled task file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse scheduled task from bytes."""
        parser = ScheduledTasksParser(data, filename)

        record_index = 0
        for task in parser.tasks:
            record_data: dict[str, Any] = {
                "name": task.name,
                "enabled": task.enabled,
                "hidden": task.hidden,
                "source": task.source,
            }

            if task.path:
                record_data["path"] = task.path
            if task.author:
                record_data["author"] = task.author
            if task.description:
                record_data["description"] = task.description
            if task.date_created:
                record_data["date_created"] = task.date_created.isoformat()
            if task.last_run:
                record_data["last_run"] = task.last_run.isoformat()
            if task.next_run:
                record_data["next_run"] = task.next_run.isoformat()
            if task.user_id:
                record_data["user_id"] = task.user_id
            if task.run_level:
                record_data["run_level"] = task.run_level

            # Actions
            actions = []
            for action in task.actions:
                action_data: dict[str, Any] = {"type": action.action_type}
                if action.command:
                    action_data["command"] = action.command
                if action.arguments:
                    action_data["arguments"] = action.arguments
                if action.working_directory:
                    action_data["working_directory"] = action.working_directory
                if action.class_id:
                    action_data["class_id"] = action.class_id
                actions.append(action_data)

            if actions:
                record_data["actions"] = actions

            # Triggers
            triggers = []
            for trigger in task.triggers:
                trigger_data: dict[str, Any] = {
                    "type": trigger.trigger_type,
                    "enabled": trigger.enabled,
                }
                if trigger.start_time:
                    trigger_data["start_time"] = trigger.start_time.isoformat()
                if trigger.end_time:
                    trigger_data["end_time"] = trigger.end_time.isoformat()
                if trigger.user_id:
                    trigger_data["user_id"] = trigger.user_id
                if trigger.repetition_interval:
                    trigger_data["repetition_interval"] = trigger.repetition_interval
                triggers.append(trigger_data)

            if triggers:
                record_data["triggers"] = triggers

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("scheduledtask", task.name, task.path)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=task.date_created or task.last_run,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
