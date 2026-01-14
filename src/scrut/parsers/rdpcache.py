"""RDP Cache parser for Remote Desktop connection tracking.

Parses RDP bitmap cache files and connection history for
lateral movement analysis.

Locations:
- %LOCALAPPDATA%\\Microsoft\\Terminal Server Client\\Cache\
  - bcache*.bmc (legacy bitmap cache)
  - Cache*.bin (modern bitmap cache)
- %USERPROFILE%\\Documents\\Default.rdp (connection settings)
- Registry: HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\
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

# RDP Cache signatures
BMC_SIGNATURE = b"RDP8bmp"  # Windows 8+ bitmap cache
CACHE_BIN_HEADER_SIZE = 12


@dataclass
class RDPCacheEntry:
    """A single RDP cache entry."""

    cache_type: str  # "bitmap", "connection", "server"
    offset: int
    width: int = 0
    height: int = 0
    bpp: int = 0  # bits per pixel
    data_size: int = 0
    server: str = ""
    username: str = ""
    domain: str = ""


@dataclass
class RDPConnection:
    """RDP connection history entry."""

    server: str
    username: str = ""
    domain: str = ""
    port: int = 3389
    username_hint: str = ""
    cert_hash: str = ""


class RDPBitmapCacheParser:
    """Parser for RDP bitmap cache files (.bmc, Cache*.bin)."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename.lower()
        self.entries: list[RDPCacheEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse RDP cache based on format."""
        if len(self.data) < 16:
            return

        # Check for RDP8 format
        if self.data[:7] == BMC_SIGNATURE:
            self._parse_rdp8()
        elif self.filename.endswith(".bin"):
            self._parse_cache_bin()
        elif self.filename.endswith(".bmc"):
            self._parse_legacy_bmc()
        else:
            self._parse_cache_bin()

    def _parse_rdp8(self) -> None:
        """Parse RDP 8+ bitmap cache format."""
        if len(self.data) < 20:
            return

        # RDP8 format header
        # 0-7: "RDP8bmp\x00"
        # 8-11: version
        # 12-15: count
        offset = 16

        while offset + 12 <= len(self.data):
            try:
                # Entry header: width(2), height(2), bpp(2), flags(2), size(4)
                width = struct.unpack("<H", self.data[offset : offset + 2])[0]
                height = struct.unpack("<H", self.data[offset + 2 : offset + 4])[0]
                bpp = struct.unpack("<H", self.data[offset + 4 : offset + 6])[0]
                data_size = struct.unpack("<I", self.data[offset + 8 : offset + 12])[0]

                if width == 0 or height == 0 or data_size == 0:
                    break

                if data_size > len(self.data) - offset:
                    break

                self.entries.append(
                    RDPCacheEntry(
                        cache_type="bitmap",
                        offset=offset,
                        width=width,
                        height=height,
                        bpp=bpp,
                        data_size=data_size,
                    )
                )

                offset += 12 + data_size
            except struct.error:
                break

    def _parse_cache_bin(self) -> None:
        """Parse Cache*.bin format (Windows 7+)."""
        if len(self.data) < CACHE_BIN_HEADER_SIZE:
            return

        offset = 0
        entry_count = 0

        while offset + 12 <= len(self.data):
            try:
                # Cache bin entry: signature(4), size(4), data...
                # Or simple: size(4), width(2), height(2), bpp(2), padding(2), data
                entry_size = struct.unpack("<I", self.data[offset : offset + 4])[0]

                if entry_size == 0 or entry_size > 0x100000:  # Max 1MB per entry
                    # Try alternate format
                    break

                if offset + 4 + entry_size > len(self.data):
                    break

                # Extract dimensions from entry data if possible
                if entry_size >= 8:
                    width = struct.unpack(
                        "<H", self.data[offset + 4 : offset + 6]
                    )[0]
                    height = struct.unpack(
                        "<H", self.data[offset + 6 : offset + 8]
                    )[0]
                else:
                    width = 0
                    height = 0

                self.entries.append(
                    RDPCacheEntry(
                        cache_type="bitmap",
                        offset=offset,
                        width=width if width < 2048 else 0,
                        height=height if height < 2048 else 0,
                        bpp=32,  # Assume 32bpp
                        data_size=entry_size,
                    )
                )

                offset += 4 + entry_size
                entry_count += 1

                if entry_count > 10000:  # Safety limit
                    break
            except struct.error:
                break

    def _parse_legacy_bmc(self) -> None:
        """Parse legacy .bmc format (Windows XP/Vista)."""
        if len(self.data) < 8:
            return

        offset = 0
        entry_count = 0

        while offset + 8 <= len(self.data):
            try:
                # Legacy format: key(8), width(2), height(2), data
                width = struct.unpack("<H", self.data[offset + 8 : offset + 10])[0]
                height = struct.unpack("<H", self.data[offset + 10 : offset + 12])[0]

                if width == 0 or height == 0 or width > 2048 or height > 2048:
                    offset += 1
                    continue

                # Calculate data size (assume 32bpp)
                data_size = width * height * 4

                if offset + 12 + data_size > len(self.data):
                    break

                self.entries.append(
                    RDPCacheEntry(
                        cache_type="bitmap",
                        offset=offset,
                        width=width,
                        height=height,
                        bpp=32,
                        data_size=data_size,
                    )
                )

                offset += 12 + data_size
                entry_count += 1

                if entry_count > 10000:
                    break
            except struct.error:
                break


class RDPDefaultParser:
    """Parser for Default.rdp connection files."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser."""
        self.data = data
        self.connections: list[RDPConnection] = []
        self.settings: dict[str, str] = {}
        self._parse()

    def _parse(self) -> None:
        """Parse Default.rdp file."""
        try:
            try:
                text = self.data.decode("utf-16-le")
            except UnicodeDecodeError:
                try:
                    text = self.data.decode("utf-8")
                except UnicodeDecodeError:
                    text = self.data.decode("latin-1")

            server = ""
            username = ""
            domain = ""
            port = 3389

            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue

                if ":s:" in line:
                    # String setting
                    key, value = line.split(":s:", 1)
                    self.settings[key.strip()] = value.strip()

                    if key.strip().lower() == "full address":
                        server = value.strip()
                        if ":" in server:
                            server, port_str = server.rsplit(":", 1)
                            try:
                                port = int(port_str)
                            except ValueError:
                                pass
                    elif key.strip().lower() == "username":
                        username = value.strip()
                    elif key.strip().lower() == "domain":
                        domain = value.strip()

                elif ":i:" in line:
                    # Integer setting
                    key, value = line.split(":i:", 1)
                    self.settings[key.strip()] = value.strip()

            if server:
                self.connections.append(
                    RDPConnection(
                        server=server,
                        username=username,
                        domain=domain,
                        port=port,
                    )
                )
        except Exception:
            pass


@ParserRegistry.register
class RDPCacheFileParser(BaseParser):
    """Parser for RDP cache and connection files."""

    name: ClassVar[str] = "rdpcache"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "rdpcache",
        "rdp",
        "rdp_cache",
        "terminal_server_client",
        "bmc",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize RDP cache parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse RDP cache file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse RDP cache from bytes."""
        fname_lower = filename.lower()

        if fname_lower.endswith(".rdp") or "default.rdp" in fname_lower:
            yield from self._parse_rdp_file(data, filename)
        else:
            yield from self._parse_cache_file(data, filename)

    def _parse_cache_file(
        self, data: bytes, filename: str
    ) -> Iterator[ParsedRecord]:
        """Parse bitmap cache file."""
        parser = RDPBitmapCacheParser(data, filename)

        record_index = 0
        for entry in parser.entries:
            record_data: dict[str, Any] = {
                "cache_type": entry.cache_type,
                "filename": filename,
                "offset": entry.offset,
                "width": entry.width,
                "height": entry.height,
                "bpp": entry.bpp,
                "data_size": entry.data_size,
            }

            # Calculate approximate tile dimensions for analysis
            if entry.width > 0 and entry.height > 0:
                record_data["dimensions"] = f"{entry.width}x{entry.height}"

            evidence_ref = self.create_evidence_ref(
                record_offset=entry.offset,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "rdpcache_bitmap", record_index, entry.offset
            )

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="raw",
                timestamp=None,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

    def _parse_rdp_file(
        self, data: bytes, filename: str
    ) -> Iterator[ParsedRecord]:
        """Parse .rdp connection file."""
        parser = RDPDefaultParser(data)

        record_index = 0
        for conn in parser.connections:
            record_data: dict[str, Any] = {
                "server": conn.server,
                "port": conn.port,
                "filename": filename,
            }

            if conn.username:
                record_data["username"] = conn.username
            if conn.domain:
                record_data["domain"] = conn.domain

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id(
                "rdp_connection", conn.server, conn.username
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

        # Also emit settings as a record
        if parser.settings:
            record_data = {
                "type": "rdp_settings",
                "filename": filename,
                "settings": parser.settings,
            }

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("rdp_settings", filename)

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="entity",
                timestamp=None,
                data=record_data,
                evidence_ref=evidence_ref,
            )
