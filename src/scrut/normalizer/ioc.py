"""IOC (Indicator of Compromise) extractor for forensic data.

Extracts and classifies IOCs from parsed records including:
- IP addresses (IPv4, IPv6)
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from scrut.models.record import EvidenceRef, ParsedRecord


IOCType = Literal["ip", "domain", "url", "hash", "email"]


PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|edu|gov|mil|int|io|co|uk|de|fr|jp|cn|ru|br|au|in|"
        r"info|biz|xyz|online|site|tech|app|dev|cloud|ai|me|tv|cc|ws|tk|ml|ga|cf|gq)\b",
        re.IGNORECASE,
    ),
    "url": re.compile(
        r"\bhttps?://[^\s<>\"']+\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        re.IGNORECASE,
    ),
}

PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.",
    "169.254.",
)

EXCLUDED_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "schema.org",
}


@dataclass
class IOC:
    """An Indicator of Compromise extracted from forensic data."""

    ioc_type: IOCType
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    occurrence_count: int = 0
    sources: list[str] = field(default_factory=list)
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    defanged: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result = {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "occurrence_count": self.occurrence_count,
        }
        if self.first_seen:
            result["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            result["last_seen"] = self.last_seen.isoformat()
        if self.sources:
            result["sources"] = list(set(self.sources))
        if self.context:
            result["context"] = self.context[:10]
        if self.tags:
            result["tags"] = self.tags
        if self.defanged:
            result["defanged"] = self.defanged
        return result

    @staticmethod
    def defang(value: str, ioc_type: IOCType) -> str:
        """Defang an IOC value for safe sharing."""
        if ioc_type == "ip":
            return value.replace(".", "[.]")
        elif ioc_type == "domain":
            return value.replace(".", "[.]")
        elif ioc_type == "url":
            return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
        elif ioc_type == "email":
            return value.replace("@", "[@]").replace(".", "[.]")
        return value


class IOCExtractor:
    """Extracts and deduplicates IOCs from parsed records."""

    def __init__(
        self,
        include_private_ips: bool = False,
        extract_from_paths: bool = True,
    ) -> None:
        """Initialize the IOC extractor.

        Args:
            include_private_ips: Include private/reserved IP addresses
            extract_from_paths: Extract IOCs from file paths
        """
        self._iocs: dict[str, IOC] = {}
        self._include_private_ips = include_private_ips
        self._extract_from_paths = extract_from_paths

    def process(self, record: ParsedRecord) -> list[IOC]:
        """Extract IOCs from a record.

        Args:
            record: ParsedRecord to process

        Returns:
            List of IOCs extracted
        """
        iocs = []
        parser_name = record.evidence_ref.parser_name if record.evidence_ref else "unknown"

        text_content = self._get_text_content(record.data)

        iocs.extend(self._extract_ips(text_content, record, parser_name))
        iocs.extend(self._extract_domains(text_content, record, parser_name))
        iocs.extend(self._extract_urls(text_content, record, parser_name))
        iocs.extend(self._extract_hashes(text_content, record, parser_name))
        iocs.extend(self._extract_emails(text_content, record, parser_name))

        if parser_name == "browser":
            iocs.extend(self._extract_from_browser(record))
        elif parser_name == "evtx":
            iocs.extend(self._extract_from_evtx(record))

        return iocs

    def process_stream(self, records: Iterator[ParsedRecord]) -> None:
        """Process a stream of records, building IOC collection.

        Args:
            records: Iterator of ParsedRecord objects
        """
        for record in records:
            self.process(record)

    def get_iocs(
        self,
        ioc_type: IOCType | None = None,
        min_occurrences: int = 1,
    ) -> list[IOC]:
        """Get all extracted IOCs.

        Args:
            ioc_type: Filter by IOC type
            min_occurrences: Minimum occurrence count

        Returns:
            List of IOC objects
        """
        iocs = list(self._iocs.values())

        if ioc_type:
            iocs = [i for i in iocs if i.ioc_type == ioc_type]

        if min_occurrences > 1:
            iocs = [i for i in iocs if i.occurrence_count >= min_occurrences]

        return sorted(iocs, key=lambda i: i.occurrence_count, reverse=True)

    def get_ioc(self, value: str) -> IOC | None:
        """Get IOC by value."""
        key = value.lower()
        return self._iocs.get(key)

    def clear(self) -> None:
        """Clear all extracted IOCs."""
        self._iocs.clear()

    def _add_or_update(
        self,
        ioc_type: IOCType,
        value: str,
        record: ParsedRecord,
        source: str,
        context: str | None = None,
        tags: list[str] | None = None,
    ) -> IOC:
        """Add new IOC or update existing."""
        key = value.lower()

        if key in self._iocs:
            ioc = self._iocs[key]
            ioc.occurrence_count += 1
            if record.timestamp:
                if ioc.first_seen is None or record.timestamp < ioc.first_seen:
                    ioc.first_seen = record.timestamp
                if ioc.last_seen is None or record.timestamp > ioc.last_seen:
                    ioc.last_seen = record.timestamp
            if record.evidence_ref and record.evidence_ref not in ioc.evidence_refs:
                ioc.evidence_refs.append(record.evidence_ref)
            if source not in ioc.sources:
                ioc.sources.append(source)
            if context and context not in ioc.context:
                ioc.context.append(context)
            if tags:
                ioc.tags.extend([t for t in tags if t not in ioc.tags])
        else:
            ioc = IOC(
                ioc_type=ioc_type,
                value=value,
                first_seen=record.timestamp,
                last_seen=record.timestamp,
                occurrence_count=1,
                sources=[source],
                evidence_refs=[record.evidence_ref] if record.evidence_ref else [],
                context=[context] if context else [],
                tags=tags or [],
                defanged=IOC.defang(value, ioc_type),
            )
            self._iocs[key] = ioc

        return ioc

    def _get_text_content(self, data: dict[str, Any], prefix: str = "") -> str:
        """Recursively extract all text content from a dict."""
        parts = []
        for key, value in data.items():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, dict):
                parts.append(self._get_text_content(value, f"{prefix}{key}."))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        parts.append(self._get_text_content(item, prefix))
        return " ".join(parts)

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP should be included."""
        if not self._include_private_ips:
            if ip.startswith(PRIVATE_IP_PREFIXES):
                return False
            if ip == "255.255.255.255":
                return False
        return True

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain should be included."""
        domain_lower = domain.lower()
        if domain_lower in EXCLUDED_DOMAINS:
            return False
        if PATTERNS["ipv4"].match(domain):
            return False
        if len(domain) < 4:
            return False
        return True

    def _extract_ips(
        self, text: str, record: ParsedRecord, source: str
    ) -> list[IOC]:
        """Extract IP addresses from text."""
        iocs = []

        for match in PATTERNS["ipv4"].finditer(text):
            ip = match.group()
            if self._is_valid_ip(ip):
                iocs.append(self._add_or_update("ip", ip, record, source))

        for match in PATTERNS["ipv6"].finditer(text):
            ip = match.group()
            if ip.lower() not in ("::1", "::"):
                iocs.append(self._add_or_update("ip", ip, record, source))

        return iocs

    def _extract_domains(
        self, text: str, record: ParsedRecord, source: str
    ) -> list[IOC]:
        """Extract domain names from text."""
        iocs = []

        for match in PATTERNS["domain"].finditer(text):
            domain = match.group()
            if self._is_valid_domain(domain):
                iocs.append(self._add_or_update("domain", domain, record, source))

        return iocs

    def _extract_urls(
        self, text: str, record: ParsedRecord, source: str
    ) -> list[IOC]:
        """Extract URLs from text."""
        iocs = []

        for match in PATTERNS["url"].finditer(text):
            url = match.group().rstrip(".,;:\"')")
            iocs.append(self._add_or_update("url", url, record, source))

        return iocs

    def _extract_hashes(
        self, text: str, record: ParsedRecord, source: str
    ) -> list[IOC]:
        """Extract file hashes from text."""
        iocs = []

        sha256_matches = set()
        for match in PATTERNS["sha256"].finditer(text):
            hash_value = match.group().lower()
            sha256_matches.add(hash_value)
            iocs.append(
                self._add_or_update("hash", hash_value, record, source, tags=["sha256"])
            )

        sha1_matches = set()
        for match in PATTERNS["sha1"].finditer(text):
            hash_value = match.group().lower()
            is_part_of_sha256 = any(hash_value in s for s in sha256_matches)
            if not is_part_of_sha256:
                sha1_matches.add(hash_value)
                iocs.append(
                    self._add_or_update("hash", hash_value, record, source, tags=["sha1"])
                )

        for match in PATTERNS["md5"].finditer(text):
            hash_value = match.group().lower()
            is_part_of_longer = any(hash_value in s for s in sha256_matches | sha1_matches)
            if not is_part_of_longer:
                iocs.append(
                    self._add_or_update("hash", hash_value, record, source, tags=["md5"])
                )

        return iocs

    def _extract_emails(
        self, text: str, record: ParsedRecord, source: str
    ) -> list[IOC]:
        """Extract email addresses from text."""
        iocs = []

        for match in PATTERNS["email"].finditer(text):
            email = match.group().lower()
            if not email.endswith(("@localhost", "@example.com", "@test.com")):
                iocs.append(self._add_or_update("email", email, record, source))

        return iocs

    def _extract_from_browser(self, record: ParsedRecord) -> list[IOC]:
        """Extract IOCs from browser history record."""
        iocs = []
        data = record.data

        url = data.get("url", "")
        if url:
            iocs.append(
                self._add_or_update(
                    "url", url, record, "browser",
                    context=data.get("title"),
                    tags=["browser_history"],
                )
            )

            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                if parsed.netloc and self._is_valid_domain(parsed.netloc):
                    iocs.append(
                        self._add_or_update(
                            "domain", parsed.netloc, record, "browser",
                            tags=["browser_history"],
                        )
                    )
            except Exception:
                pass

        return iocs

    def _extract_from_evtx(self, record: ParsedRecord) -> list[IOC]:
        """Extract IOCs from EVTX record with context."""
        iocs = []
        data = record.data

        ip = data.get("ip_address") or data.get("source_network_address")
        if ip and self._is_valid_ip(ip):
            event_id = str(data.get("event_id", ""))
            iocs.append(
                self._add_or_update(
                    "ip", ip, record, "evtx",
                    context=f"EventID:{event_id}",
                    tags=["network_logon"] if event_id in ("4624", "4625") else [],
                )
            )

        return iocs
