"""Timeline normalizer for chronological event analysis.

Converts parsed records from various artifact types into a unified
TimelineEvent format for cross-artifact timeline analysis.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from scrut.models.record import EvidenceRef, ParsedRecord


@dataclass
class TimelineEvent:
    """A normalized timeline event from any artifact source."""

    timestamp: datetime
    event_type: str
    description: str
    source: str
    actor: str | None = None
    target: str | None = None
    action: str | None = None
    outcome: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    evidence_ref: EvidenceRef | None = None
    tags: list[str] = field(default_factory=list)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result = {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "description": self.description,
            "source": self.source,
            "severity": self.severity,
        }
        if self.actor:
            result["actor"] = self.actor
        if self.target:
            result["target"] = self.target
        if self.action:
            result["action"] = self.action
        if self.outcome:
            result["outcome"] = self.outcome
        if self.details:
            result["details"] = self.details
        if self.evidence_ref:
            result["evidence_ref"] = {
                "target_id": str(self.evidence_ref.target_id),
                "artifact_path": self.evidence_ref.artifact_path,
                "parser_name": self.evidence_ref.parser_name,
            }
        if self.tags:
            result["tags"] = self.tags
        return result


class TimelineNormalizer:
    """Normalizes parsed records into unified TimelineEvent format."""

    EVENT_TYPE_MAP = {
        "evtx": {
            "4624": ("logon", "User Logon"),
            "4625": ("failed_logon", "Failed Logon"),
            "4634": ("logoff", "User Logoff"),
            "4648": ("explicit_logon", "Explicit Credential Logon"),
            "4672": ("privilege_use", "Special Privileges Assigned"),
            "4688": ("process_create", "Process Creation"),
            "4689": ("process_exit", "Process Exit"),
            "4697": ("service_install", "Service Installed"),
            "4698": ("scheduled_task", "Scheduled Task Created"),
            "4699": ("scheduled_task", "Scheduled Task Deleted"),
            "4700": ("scheduled_task", "Scheduled Task Enabled"),
            "4701": ("scheduled_task", "Scheduled Task Disabled"),
            "4702": ("scheduled_task", "Scheduled Task Updated"),
            "4720": ("account", "User Account Created"),
            "4722": ("account", "User Account Enabled"),
            "4725": ("account", "User Account Disabled"),
            "4726": ("account", "User Account Deleted"),
            "4732": ("group", "Member Added to Security Group"),
            "4733": ("group", "Member Removed from Security Group"),
            "7045": ("service_install", "Service Installed"),
        },
        "prefetch": "execution",
        "shimcache": "execution",
        "amcache": "execution",
        "mft": "file_activity",
        "usnjrnl": "file_activity",
        "lnk": "file_access",
        "browser": "web_activity",
        "powershell": "command_execution",
        "scheduledtasks": "persistence",
        "services": "persistence",
        "wmi": "persistence",
    }

    def normalize(self, record: ParsedRecord) -> TimelineEvent | None:
        """Convert a parsed record to a timeline event.

        Args:
            record: ParsedRecord from any parser

        Returns:
            TimelineEvent or None if record cannot be normalized
        """
        if not record.timestamp:
            return None

        parser_name = record.evidence_ref.parser_name if record.evidence_ref else "unknown"

        if parser_name == "evtx":
            return self._normalize_evtx(record)
        elif parser_name == "prefetch":
            return self._normalize_prefetch(record)
        elif parser_name in ("shimcache", "amcache"):
            return self._normalize_execution(record, parser_name)
        elif parser_name == "mft":
            return self._normalize_mft(record)
        elif parser_name == "usnjrnl":
            return self._normalize_usnjrnl(record)
        elif parser_name == "lnk":
            return self._normalize_lnk(record)
        elif parser_name == "browser":
            return self._normalize_browser(record)
        elif parser_name == "powershell":
            return self._normalize_powershell(record)
        elif parser_name in ("scheduledtasks", "services", "wmi"):
            return self._normalize_persistence(record, parser_name)
        else:
            return self._normalize_generic(record)

    def normalize_stream(
        self, records: Iterator[ParsedRecord]
    ) -> Iterator[TimelineEvent]:
        """Normalize a stream of records to timeline events.

        Args:
            records: Iterator of ParsedRecord objects

        Yields:
            TimelineEvent objects (skipping records that can't be normalized)
        """
        for record in records:
            event = self.normalize(record)
            if event:
                yield event

    def _normalize_evtx(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize Windows Event Log record."""
        data = record.data
        event_id = str(data.get("event_id", ""))

        event_info = self.EVENT_TYPE_MAP.get("evtx", {}).get(event_id)
        if event_info:
            event_type, description = event_info
        else:
            event_type = "security_event"
            description = f"Event ID {event_id}"

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type=event_type,
            description=description,
            source="evtx",
            actor=data.get("user") or data.get("subject_user_name"),
            target=data.get("target_user_name") or data.get("target_path"),
            action=f"EventID:{event_id}",
            outcome=data.get("status"),
            details={
                "event_id": event_id,
                "channel": data.get("channel"),
                "provider_name": data.get("provider_name"),
                "record_number": data.get("record_number"),
            },
            evidence_ref=record.evidence_ref,
            severity=self._get_evtx_severity(event_id),
        )

    def _normalize_prefetch(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize Prefetch record."""
        data = record.data
        executable = data.get("executable_name", "unknown")

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="execution",
            description=f"Program executed: {executable}",
            source="prefetch",
            target=executable,
            action="execute",
            details={
                "run_count": data.get("run_count"),
                "last_run_times": data.get("last_run_times"),
                "file_references": data.get("file_references", [])[:10],
            },
            evidence_ref=record.evidence_ref,
            tags=["execution"],
        )

    def _normalize_execution(
        self, record: ParsedRecord, source: str
    ) -> TimelineEvent:
        """Normalize ShimCache/Amcache execution record."""
        data = record.data
        path = data.get("path", data.get("file_path", "unknown"))
        filename = path.split("\\")[-1] if "\\" in path else path

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="execution",
            description=f"Program executed: {filename}",
            source=source,
            target=path,
            action="execute",
            details={
                "full_path": path,
                "sha1": data.get("sha1"),
                "size": data.get("size"),
            },
            evidence_ref=record.evidence_ref,
            tags=["execution"],
        )

    def _normalize_mft(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize MFT record."""
        data = record.data
        filename = data.get("filename", "unknown")
        action = "file_modify"

        if data.get("is_deleted"):
            action = "file_delete"

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="file_activity",
            description=f"File activity: {filename}",
            source="mft",
            target=filename,
            action=action,
            details={
                "parent_dir": data.get("parent_directory"),
                "size": data.get("file_size"),
                "is_deleted": data.get("is_deleted"),
                "timestomping_detected": data.get("timestomping_detected"),
            },
            evidence_ref=record.evidence_ref,
            severity="medium" if data.get("timestomping_detected") else "info",
            tags=["file"] + (["timestomping"] if data.get("timestomping_detected") else []),
        )

    def _normalize_usnjrnl(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize USN Journal record."""
        data = record.data
        filename = data.get("filename", "unknown")
        reason = data.get("reason", [])

        if isinstance(reason, list):
            reason_str = ", ".join(reason)
        else:
            reason_str = str(reason)

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="file_activity",
            description=f"File change: {filename} ({reason_str})",
            source="usnjrnl",
            target=filename,
            action=reason_str,
            details={
                "reason_flags": reason,
                "mft_reference": data.get("mft_reference"),
            },
            evidence_ref=record.evidence_ref,
            tags=["file"],
        )

    def _normalize_lnk(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize LNK shortcut record."""
        data = record.data
        target_path = data.get("target_path", "unknown")

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="file_access",
            description=f"Shortcut accessed: {target_path}",
            source="lnk",
            target=target_path,
            action="shortcut_access",
            details={
                "working_dir": data.get("working_directory"),
                "arguments": data.get("arguments"),
                "volume_serial": data.get("volume_serial_number"),
            },
            evidence_ref=record.evidence_ref,
            tags=["user_activity"],
        )

    def _normalize_browser(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize browser history record."""
        data = record.data
        url = data.get("url", "unknown")
        title = data.get("title", "")

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="web_activity",
            description=f"Web visit: {title or url[:50]}",
            source="browser",
            target=url,
            action="web_visit",
            details={
                "url": url,
                "title": title,
                "visit_count": data.get("visit_count"),
                "browser": data.get("browser"),
            },
            evidence_ref=record.evidence_ref,
            tags=["web"],
        )

    def _normalize_powershell(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize PowerShell history record."""
        data = record.data
        command = data.get("command", "")
        risk_indicators = data.get("risk_indicators", [])

        severity = "info"
        if risk_indicators:
            if any(r in ["encoded_command", "credential_access", "lateral_movement"] for r in risk_indicators):
                severity = "high"
            elif any(r in ["download_activity", "evasion", "persistence"] for r in risk_indicators):
                severity = "medium"
            else:
                severity = "low"

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="command_execution",
            description=f"PowerShell: {command[:80]}{'...' if len(command) > 80 else ''}",
            source="powershell",
            action="execute",
            details={
                "command": command,
                "risk_indicators": risk_indicators,
            },
            evidence_ref=record.evidence_ref,
            severity=severity,
            tags=["powershell"] + risk_indicators,
        )

    def _normalize_persistence(
        self, record: ParsedRecord, source: str
    ) -> TimelineEvent:
        """Normalize persistence mechanism record."""
        data = record.data

        if source == "scheduledtasks":
            name = data.get("task_name", "unknown")
            description = f"Scheduled Task: {name}"
        elif source == "services":
            name = data.get("service_name", "unknown")
            description = f"Service: {name}"
        else:
            name = data.get("name", "unknown")
            description = f"WMI Persistence: {name}"

        risk_indicators = data.get("risk_indicators", [])
        severity = "high" if risk_indicators else "info"

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="persistence",
            description=description,
            source=source,
            target=name,
            action="persistence",
            details=data,
            evidence_ref=record.evidence_ref,
            severity=severity,
            tags=["persistence"] + risk_indicators,
        )

    def _normalize_generic(self, record: ParsedRecord) -> TimelineEvent:
        """Normalize any record with a generic event."""
        source = record.evidence_ref.parser_name if record.evidence_ref else "unknown"

        return TimelineEvent(
            timestamp=record.timestamp,
            event_type="activity",
            description=f"Activity from {source}",
            source=source,
            details=record.data,
            evidence_ref=record.evidence_ref,
        )

    def _get_evtx_severity(self, event_id: str) -> Literal["info", "low", "medium", "high", "critical"]:
        """Get severity level for EVTX event ID."""
        high_severity = {"4625", "4648", "4672", "4697", "4698", "4720", "4726", "7045"}
        medium_severity = {"4624", "4634", "4688", "4689", "4722", "4725", "4732", "4733"}

        if event_id in high_severity:
            return "high"
        elif event_id in medium_severity:
            return "medium"
        return "info"
