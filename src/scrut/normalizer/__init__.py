"""Normalization layer for unified forensic analysis.

Provides normalizers to transform parsed records into:
- TimelineEvents: Chronological events for timeline analysis
- Entities: Unique objects (users, hosts, files, processes)
- IOCs: Indicators of compromise (IPs, domains, hashes, URLs)
"""

from scrut.normalizer.entity import Entity, EntityExtractor
from scrut.normalizer.ioc import IOC, IOCExtractor
from scrut.normalizer.timeline import TimelineEvent, TimelineNormalizer

__all__ = [
    "TimelineNormalizer",
    "TimelineEvent",
    "EntityExtractor",
    "Entity",
    "IOCExtractor",
    "IOC",
]
