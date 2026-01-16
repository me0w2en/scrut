"""Entity extractor for identifying unique objects in forensic data.

Extracts and deduplicates entities (users, hosts, files, processes, networks)
from parsed records for relationship and behavioral analysis.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from scrut.models.record import EvidenceRef, ParsedRecord


EntityType = Literal["user", "host", "file", "process", "network", "domain", "service"]


@dataclass
class Entity:
    """A unique entity extracted from forensic data."""

    entity_type: EntityType
    entity_id: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    occurrence_count: int = 0
    sources: list[str] = field(default_factory=list)
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    related_entities: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result = {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "name": self.name,
            "occurrence_count": self.occurrence_count,
        }
        if self.attributes:
            result["attributes"] = self.attributes
        if self.first_seen:
            result["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            result["last_seen"] = self.last_seen.isoformat()
        if self.sources:
            result["sources"] = list(set(self.sources))
        if self.related_entities:
            result["related_entities"] = self.related_entities
        if self.tags:
            result["tags"] = self.tags
        return result


class EntityExtractor:
    """Extracts and deduplicates entities from parsed records."""

    def __init__(self) -> None:
        """Initialize the entity extractor."""
        self._entities: dict[str, Entity] = {}

    def process(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from a record.

        Args:
            record: ParsedRecord to process

        Returns:
            List of entities extracted (may be deduplicated with existing)
        """
        entities = []
        parser_name = record.evidence_ref.parser_name if record.evidence_ref else "unknown"

        if parser_name == "evtx":
            entities.extend(self._extract_from_evtx(record))
        elif parser_name == "prefetch":
            entities.extend(self._extract_from_prefetch(record))
        elif parser_name in ("shimcache", "amcache"):
            entities.extend(self._extract_from_execution(record))
        elif parser_name == "browser":
            entities.extend(self._extract_from_browser(record))
        elif parser_name == "services":
            entities.extend(self._extract_from_services(record))
        elif parser_name == "scheduledtasks":
            entities.extend(self._extract_from_scheduledtasks(record))

        return entities

    def process_stream(self, records: Iterator[ParsedRecord]) -> None:
        """Process a stream of records, building entity graph.

        Args:
            records: Iterator of ParsedRecord objects
        """
        for record in records:
            self.process(record)

    def get_entities(
        self,
        entity_type: EntityType | None = None,
        min_occurrences: int = 1,
    ) -> list[Entity]:
        """Get all extracted entities.

        Args:
            entity_type: Filter by entity type
            min_occurrences: Minimum occurrence count

        Returns:
            List of Entity objects
        """
        entities = list(self._entities.values())

        if entity_type:
            entities = [e for e in entities if e.entity_type == entity_type]

        if min_occurrences > 1:
            entities = [e for e in entities if e.occurrence_count >= min_occurrences]

        return sorted(entities, key=lambda e: e.occurrence_count, reverse=True)

    def get_entity(self, entity_id: str) -> Entity | None:
        """Get entity by ID."""
        return self._entities.get(entity_id)

    def clear(self) -> None:
        """Clear all extracted entities."""
        self._entities.clear()

    def _add_or_update(
        self,
        entity_type: EntityType,
        entity_id: str,
        name: str,
        record: ParsedRecord,
        attributes: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        related_entities: list[str] | None = None,
    ) -> Entity:
        """Add new entity or update existing."""
        if entity_id in self._entities:
            entity = self._entities[entity_id]
            entity.occurrence_count += 1
            if record.timestamp:
                if entity.first_seen is None or record.timestamp < entity.first_seen:
                    entity.first_seen = record.timestamp
                if entity.last_seen is None or record.timestamp > entity.last_seen:
                    entity.last_seen = record.timestamp
            if record.evidence_ref and record.evidence_ref not in entity.evidence_refs:
                entity.evidence_refs.append(record.evidence_ref)
            parser_name = record.evidence_ref.parser_name if record.evidence_ref else "unknown"
            if parser_name not in entity.sources:
                entity.sources.append(parser_name)
            if attributes:
                entity.attributes.update(attributes)
            if tags:
                entity.tags.extend([t for t in tags if t not in entity.tags])
            if related_entities:
                entity.related_entities.extend([r for r in related_entities if r not in entity.related_entities])
        else:
            entity = Entity(
                entity_type=entity_type,
                entity_id=entity_id,
                name=name,
                attributes=attributes or {},
                first_seen=record.timestamp,
                last_seen=record.timestamp,
                occurrence_count=1,
                sources=[record.evidence_ref.parser_name] if record.evidence_ref else [],
                evidence_refs=[record.evidence_ref] if record.evidence_ref else [],
                tags=tags or [],
                related_entities=related_entities or [],
            )
            self._entities[entity_id] = entity

        return entity

    def _extract_from_evtx(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from EVTX record."""
        entities = []
        data = record.data

        subject_user = data.get("subject_user_name") or data.get("user")
        if subject_user and subject_user not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            domain = data.get("subject_domain_name", "")
            entity_id = f"user:{domain}\\{subject_user}".lower()
            entities.append(self._add_or_update(
                "user", entity_id, subject_user, record,
                attributes={"domain": domain, "sid": data.get("subject_user_sid")},
            ))

        target_user = data.get("target_user_name")
        if target_user and target_user not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            domain = data.get("target_domain_name", "")
            entity_id = f"user:{domain}\\{target_user}".lower()
            entities.append(self._add_or_update(
                "user", entity_id, target_user, record,
                attributes={"domain": domain, "sid": data.get("target_user_sid")},
            ))

        workstation = data.get("workstation_name")
        if workstation and workstation not in ("-", ""):
            entity_id = f"host:{workstation}".lower()
            entities.append(self._add_or_update(
                "host", entity_id, workstation, record,
            ))

        ip_address = data.get("ip_address") or data.get("source_network_address")
        if ip_address and ip_address not in ("-", "::1", "127.0.0.1", ""):
            entity_id = f"network:{ip_address}"
            entities.append(self._add_or_update(
                "network", entity_id, ip_address, record,
                attributes={"port": data.get("ip_port") or data.get("source_port")},
            ))

        process_name = data.get("process_name") or data.get("new_process_name")
        if process_name and process_name not in ("-", ""):
            filename = process_name.split("\\")[-1]
            entity_id = f"process:{filename}".lower()
            entities.append(self._add_or_update(
                "process", entity_id, filename, record,
                attributes={"full_path": process_name},
            ))

        return entities

    def _extract_from_prefetch(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from Prefetch record."""
        entities = []
        data = record.data

        executable = data.get("executable_name")
        if executable:
            entity_id = f"process:{executable}".lower()
            entities.append(self._add_or_update(
                "process", entity_id, executable, record,
                attributes={
                    "run_count": data.get("run_count"),
                    "prefetch_hash": data.get("prefetch_hash"),
                },
                tags=["executed"],
            ))

        return entities

    def _extract_from_execution(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from ShimCache/Amcache record."""
        entities = []
        data = record.data

        path = data.get("path", data.get("file_path", ""))
        if path:
            filename = path.split("\\")[-1]
            entity_id = f"file:{path}".lower()
            entities.append(self._add_or_update(
                "file", entity_id, filename, record,
                attributes={
                    "full_path": path,
                    "sha1": data.get("sha1"),
                    "size": data.get("size"),
                },
                tags=["executed"],
            ))

            process_id = f"process:{filename}".lower()
            entities.append(self._add_or_update(
                "process", process_id, filename, record,
                attributes={"full_path": path},
                tags=["executed"],
                related_entities=[entity_id],
            ))

        return entities

    def _extract_from_browser(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from browser history record."""
        entities = []
        data = record.data

        url = data.get("url", "")
        if url:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    entity_id = f"domain:{domain}".lower()
                    entities.append(self._add_or_update(
                        "domain", entity_id, domain, record,
                        attributes={"scheme": parsed.scheme},
                        tags=["visited"],
                    ))
            except Exception:
                pass

        return entities

    def _extract_from_services(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from services record."""
        entities = []
        data = record.data

        service_name = data.get("service_name")
        if service_name:
            entity_id = f"service:{service_name}".lower()
            entities.append(self._add_or_update(
                "service", entity_id, service_name, record,
                attributes={
                    "display_name": data.get("display_name"),
                    "image_path": data.get("image_path"),
                    "start_type": data.get("start_type"),
                },
                tags=data.get("risk_indicators", []),
            ))

            image_path = data.get("image_path")
            if image_path:
                filename = image_path.split("\\")[-1].split()[0]
                file_id = f"file:{image_path}".lower()
                entities.append(self._add_or_update(
                    "file", file_id, filename, record,
                    attributes={"full_path": image_path},
                    related_entities=[entity_id],
                ))

        return entities

    def _extract_from_scheduledtasks(self, record: ParsedRecord) -> list[Entity]:
        """Extract entities from scheduled tasks record."""
        entities = []
        data = record.data

        task_name = data.get("task_name")
        if task_name:
            entity_id = f"service:task:{task_name}".lower()
            entities.append(self._add_or_update(
                "service", entity_id, task_name, record,
                attributes={
                    "path": data.get("path"),
                    "command": data.get("command"),
                    "enabled": data.get("enabled"),
                },
                tags=["scheduled_task"],
            ))

        return entities
