"""Amcache.hve parser for program execution artifacts.

Parses the Amcache.hve registry hive to extract information about
executed programs, installed applications, and drivers.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry
from scrut.parsers.registry import RegistryHive

PARSER_VERSION = "0.1.0"


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


def _parse_filetime_str(value: str) -> datetime | None:
    """Parse FILETIME from hex string."""
    try:
        filetime = int(value, 16)
        return _filetime_to_datetime(filetime)
    except (ValueError, TypeError):
        return None


class AmcacheParser:
    """Parser for Amcache.hve registry hive."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with hive data."""
        self.hive = RegistryHive(data)
        self.root = self.hive.get_root_key()

    def _find_key(self, path: str):
        """Find a key by path."""
        if not self.root:
            return None

        parts = path.split("\\")
        current = self.root

        for part in parts:
            if not part:
                continue
            found = False
            for subkey in self.hive.get_subkeys(current):
                if subkey.name.lower() == part.lower():
                    current = subkey
                    found = True
                    break
            if not found:
                return None
        return current

    def parse_inventory_files(self) -> Iterator[dict[str, Any]]:
        """Parse InventoryApplicationFile entries (Windows 10+).

        Path: Root\\InventoryApplicationFile
        """
        inv_files = self._find_key("Root\\InventoryApplicationFile")
        if not inv_files:
            return

        for file_key in self.hive.get_subkeys(inv_files):
            record: dict[str, Any] = {
                "type": "inventory_file",
                "key_name": file_key.name,
            }

            for value in self.hive.get_values(file_key):
                name = value.name.lower()
                data = value.get_data()

                if name == "lowerCaseLongPath":
                    record["path"] = data
                elif name == "name":
                    record["name"] = data
                elif name == "publisher":
                    record["publisher"] = data
                elif name == "version":
                    record["version"] = data
                elif name == "binarytype":
                    record["binary_type"] = data
                elif name == "productname":
                    record["product_name"] = data
                elif name == "productversion":
                    record["product_version"] = data
                elif name == "linkdate":
                    record["link_date"] = data
                elif name == "size":
                    record["size"] = data
                elif name == "language":
                    record["language"] = data
                elif name == "fileid":
                    record["file_id"] = data
                elif name == "programid":
                    record["program_id"] = data
                elif name == "sha1":
                    record["sha1"] = data

            if record.get("path") or record.get("name"):
                yield record

    def parse_inventory_applications(self) -> Iterator[dict[str, Any]]:
        """Parse InventoryApplication entries (installed programs).

        Path: Root\\InventoryApplication
        """
        inv_apps = self._find_key("Root\\InventoryApplication")
        if not inv_apps:
            return

        for app_key in self.hive.get_subkeys(inv_apps):
            record: dict[str, Any] = {
                "type": "inventory_application",
                "key_name": app_key.name,
            }

            for value in self.hive.get_values(app_key):
                name = value.name.lower()
                data = value.get_data()

                if name == "name":
                    record["name"] = data
                elif name == "version":
                    record["version"] = data
                elif name == "publisher":
                    record["publisher"] = data
                elif name == "installdate":
                    record["install_date"] = data
                elif name == "source":
                    record["source"] = data
                elif name == "rootdirpath":
                    record["install_path"] = data
                elif name == "uninstallstring":
                    record["uninstall_string"] = data
                elif name == "type":
                    record["app_type"] = data
                elif name == "programid":
                    record["program_id"] = data
                elif name == "packagefullname":
                    record["package_name"] = data

            if record.get("name"):
                yield record

    def parse_file_entries(self) -> Iterator[dict[str, Any]]:
        """Parse File entries (legacy format, pre-Windows 10).

        Path: Root\\File\\{volume_guid}\\{file_id}
        """
        file_root = self._find_key("Root\\File")
        if not file_root:
            return

        for volume_key in self.hive.get_subkeys(file_root):
            volume_guid = volume_key.name

            for file_key in self.hive.get_subkeys(volume_key):
                record: dict[str, Any] = {
                    "type": "file_entry",
                    "volume_guid": volume_guid,
                    "file_reference": file_key.name,
                }

                for value in self.hive.get_values(file_key):
                    name = value.name.lower()
                    data = value.get_data()

                    # Value names are numeric in legacy format
                    if name == "0" or name == "productname":
                        record["product_name"] = data
                    elif name == "1" or name == "companyname":
                        record["company_name"] = data
                    elif name == "2" or name == "productversion":
                        record["product_version"] = data
                    elif name == "3" or name == "languagecode":
                        record["language"] = data
                    elif name == "5" or name == "fileversion":
                        record["file_version"] = data
                    elif name == "6" or name == "filesize":
                        record["size"] = data
                    elif name == "15" or name == "fullpath":
                        record["path"] = data
                    elif name == "17" or name == "linkerversion":
                        record["linker_version"] = data
                    elif name == "100" or name == "programid":
                        record["program_id"] = data
                    elif name == "101" or name == "sha1":
                        record["sha1"] = data

                if record.get("path") or record.get("product_name"):
                    yield record

    def parse_programs(self) -> Iterator[dict[str, Any]]:
        """Parse Programs entries (legacy installed programs).

        Path: Root\\Programs\\{program_id}
        """
        programs = self._find_key("Root\\Programs")
        if not programs:
            return

        for prog_key in self.hive.get_subkeys(programs):
            record: dict[str, Any] = {
                "type": "program",
                "program_id": prog_key.name,
            }

            for value in self.hive.get_values(prog_key):
                name = value.name.lower()
                data = value.get_data()

                if name == "0" or name == "name":
                    record["name"] = data
                elif name == "1" or name == "version":
                    record["version"] = data
                elif name == "2" or name == "publisher":
                    record["publisher"] = data
                elif name == "6" or name == "installdate":
                    record["install_date"] = data
                elif name == "7" or name == "installsource":
                    record["install_source"] = data
                elif name == "d" or name == "files":
                    record["files"] = data

            if record.get("name"):
                yield record

    def parse_driver_binaries(self) -> Iterator[dict[str, Any]]:
        """Parse InventoryDriverBinary entries.

        Path: Root\\InventoryDriverBinary
        """
        drivers = self._find_key("Root\\InventoryDriverBinary")
        if not drivers:
            return

        for driver_key in self.hive.get_subkeys(drivers):
            record: dict[str, Any] = {
                "type": "driver_binary",
                "key_name": driver_key.name,
            }

            for value in self.hive.get_values(driver_key):
                name = value.name.lower()
                data = value.get_data()

                if name == "drivername":
                    record["driver_name"] = data
                elif name == "driverversion":
                    record["version"] = data
                elif name == "drivercompany":
                    record["company"] = data
                elif name == "driverinbox":
                    record["inbox"] = data
                elif name == "driversigned":
                    record["signed"] = data
                elif name == "drivertimestamp":
                    record["timestamp"] = data
                elif name == "driverchecksum":
                    record["checksum"] = data
                elif name == "service":
                    record["service"] = data

            if record.get("driver_name"):
                yield record

    def parse_all(self) -> Iterator[dict[str, Any]]:
        """Parse all Amcache entries."""
        # Modern format (Windows 10+)
        yield from self.parse_inventory_files()
        yield from self.parse_inventory_applications()
        yield from self.parse_driver_binaries()

        # Legacy format
        yield from self.parse_file_entries()
        yield from self.parse_programs()


@ParserRegistry.register
class AmcacheFileParser(BaseParser):
    """Parser for Amcache.hve files."""

    name: ClassVar[str] = "amcache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["amcache", "amcache.hve"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Amcache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Amcache.hve file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse Amcache from bytes."""
        parser = AmcacheParser(data)

        record_index = 0
        for entry in parser.parse_all():
            # Determine timestamp
            timestamp = None
            if entry.get("install_date"):
                try:
                    # Try parsing as date string (YYYYMMDD or similar)
                    date_str = str(entry["install_date"])
                    if len(date_str) == 8 and date_str.isdigit():
                        timestamp = datetime.strptime(date_str, "%Y%m%d").replace(
                            tzinfo=UTC
                        )
                except Exception:
                    pass

            if timestamp is None and entry.get("link_date"):
                try:
                    # Link date is often a hex timestamp
                    timestamp = _parse_filetime_str(str(entry["link_date"]))
                except Exception:
                    pass

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            entry_type = entry.get("type", "entry")
            entry_name = entry.get("path", entry.get("name", f"entry_{record_index}"))
            record_id = self.create_record_id("amcache", entry_type, record_index, entry_name)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=timestamp,
                data=entry,
                evidence_ref=evidence_ref,
            )

            record_index += 1
