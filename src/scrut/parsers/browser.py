"""Browser history parser for web activity tracking.

Parses browser history databases from Chrome, Edge, Firefox, and IE
to extract browsing activity evidence.
"""

import sqlite3
import struct
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# SQLite header signature
SQLITE_SIGNATURE = b"SQLite format 3\x00"


def _webkit_to_datetime(webkit_time: int) -> datetime | None:
    """Convert WebKit/Chrome timestamp to datetime.

    WebKit timestamps are microseconds since 1601-01-01.
    """
    if webkit_time == 0 or webkit_time < 0:
        return None
    try:
        # Convert to Unix timestamp (seconds since 1970)
        unix_time = (webkit_time / 1000000) - 11644473600
        if unix_time < 0:
            return None
        return datetime.fromtimestamp(unix_time, tz=UTC)
    except (OSError, ValueError, OverflowError):
        return None


def _mozilla_to_datetime(mozilla_time: int) -> datetime | None:
    """Convert Mozilla timestamp to datetime.

    Mozilla timestamps are microseconds since Unix epoch.
    """
    if mozilla_time == 0 or mozilla_time < 0:
        return None
    try:
        unix_time = mozilla_time / 1000000
        return datetime.fromtimestamp(unix_time, tz=UTC)
    except (OSError, ValueError, OverflowError):
        return None


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


@dataclass
class BrowserHistoryEntry:
    """A single browser history entry."""

    browser: str
    url: str
    title: str
    visit_time: datetime | None
    visit_count: int = 1
    typed_count: int = 0
    last_visit: datetime | None = None
    from_url: str = ""
    transition: str = ""
    hidden: bool = False


@dataclass
class BrowserDownloadEntry:
    """A single browser download entry."""

    browser: str
    url: str
    target_path: str
    start_time: datetime | None
    end_time: datetime | None = None
    received_bytes: int = 0
    total_bytes: int = 0
    state: str = ""
    danger_type: str = ""
    referrer: str = ""


class ChromeHistoryParser:
    """Parser for Chrome/Edge History SQLite database."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with database data."""
        self.data = data
        self.history: list[BrowserHistoryEntry] = []
        self.downloads: list[BrowserDownloadEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse Chrome history database."""
        if len(self.data) < 100 or self.data[0:16] != SQLITE_SIGNATURE:
            return

        # Write to temp file for SQLite access
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
                f.write(self.data)
                temp_path = f.name

            self._parse_with_sqlite(temp_path)
        except Exception:
            # Fallback to pattern matching if SQLite fails
            self._parse_raw()
        finally:
            try:
                Path(temp_path).unlink()
            except Exception:
                pass

    def _parse_with_sqlite(self, db_path: str) -> None:
        """Parse using SQLite."""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        try:
            # Parse URLs and visits
            cursor = conn.execute("""
                SELECT
                    u.url,
                    u.title,
                    u.visit_count,
                    u.typed_count,
                    u.last_visit_time,
                    u.hidden,
                    v.visit_time,
                    v.from_visit,
                    v.transition
                FROM urls u
                LEFT JOIN visits v ON u.id = v.url
                ORDER BY v.visit_time DESC
            """)

            for row in cursor:
                visit_time = _webkit_to_datetime(row["visit_time"] or 0)
                last_visit = _webkit_to_datetime(row["last_visit_time"] or 0)

                self.history.append(
                    BrowserHistoryEntry(
                        browser="Chrome",
                        url=row["url"] or "",
                        title=row["title"] or "",
                        visit_time=visit_time,
                        visit_count=row["visit_count"] or 0,
                        typed_count=row["typed_count"] or 0,
                        last_visit=last_visit,
                        hidden=bool(row["hidden"]),
                    )
                )

            # Parse downloads
            try:
                cursor = conn.execute("""
                    SELECT
                        url,
                        target_path,
                        start_time,
                        end_time,
                        received_bytes,
                        total_bytes,
                        state,
                        danger_type,
                        referrer
                    FROM downloads
                    ORDER BY start_time DESC
                """)

                for row in cursor:
                    start_time = _webkit_to_datetime(row["start_time"] or 0)
                    end_time = _webkit_to_datetime(row["end_time"] or 0)

                    self.downloads.append(
                        BrowserDownloadEntry(
                            browser="Chrome",
                            url=row["url"] or "",
                            target_path=row["target_path"] or "",
                            start_time=start_time,
                            end_time=end_time,
                            received_bytes=row["received_bytes"] or 0,
                            total_bytes=row["total_bytes"] or 0,
                            state=str(row["state"]) if row["state"] else "",
                            referrer=row["referrer"] or "",
                        )
                    )
            except sqlite3.OperationalError:
                # Downloads table might not exist
                pass

        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def _parse_raw(self) -> None:
        """Parse by looking for URL patterns in raw data."""
        # Simple pattern matching for URLs
        patterns = [b"http://", b"https://", b"file://"]

        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break

                # Extract URL
                end = pos
                while end < len(self.data) and self.data[end] >= 0x20 and self.data[end] < 0x7F:
                    end += 1

                if end - pos > 10:
                    try:
                        url = self.data[pos:end].decode("utf-8", errors="replace")
                        if url and len(url) < 2000:
                            self.history.append(
                                BrowserHistoryEntry(
                                    browser="Chrome",
                                    url=url,
                                    title="",
                                    visit_time=None,
                                )
                            )
                    except Exception:
                        pass

                offset = end


class FirefoxHistoryParser:
    """Parser for Firefox places.sqlite database."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with database data."""
        self.data = data
        self.history: list[BrowserHistoryEntry] = []
        self.downloads: list[BrowserDownloadEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse Firefox history database."""
        if len(self.data) < 100 or self.data[0:16] != SQLITE_SIGNATURE:
            return

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
                f.write(self.data)
                temp_path = f.name

            self._parse_with_sqlite(temp_path)
        except Exception:
            self._parse_raw()
        finally:
            try:
                Path(temp_path).unlink()
            except Exception:
                pass

    def _parse_with_sqlite(self, db_path: str) -> None:
        """Parse using SQLite."""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        try:
            # Parse places and history visits
            cursor = conn.execute("""
                SELECT
                    p.url,
                    p.title,
                    p.visit_count,
                    p.last_visit_date,
                    p.hidden,
                    h.visit_date,
                    h.visit_type,
                    h.from_visit
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                ORDER BY h.visit_date DESC
            """)

            for row in cursor:
                visit_time = _mozilla_to_datetime(row["visit_date"] or 0)
                last_visit = _mozilla_to_datetime(row["last_visit_date"] or 0)

                # Convert visit type to string
                visit_types = {
                    1: "link",
                    2: "typed",
                    3: "bookmark",
                    4: "embed",
                    5: "redirect_permanent",
                    6: "redirect_temporary",
                    7: "download",
                    8: "framed_link",
                }
                visit_type = visit_types.get(row["visit_type"] or 0, "unknown")

                self.history.append(
                    BrowserHistoryEntry(
                        browser="Firefox",
                        url=row["url"] or "",
                        title=row["title"] or "",
                        visit_time=visit_time,
                        visit_count=row["visit_count"] or 0,
                        last_visit=last_visit,
                        hidden=bool(row["hidden"]),
                        transition=visit_type,
                    )
                )

            # Parse downloads from moz_annos/moz_downloads
            try:
                cursor = conn.execute("""
                    SELECT
                        p.url,
                        a.content,
                        a.dateAdded
                    FROM moz_annos a
                    JOIN moz_places p ON a.place_id = p.id
                    WHERE a.anno_attribute_id IN (
                        SELECT id FROM moz_anno_attributes WHERE name = 'downloads/destinationFileURI'
                    )
                    ORDER BY a.dateAdded DESC
                """)

                for row in cursor:
                    start_time = _mozilla_to_datetime(row["dateAdded"] or 0)

                    self.downloads.append(
                        BrowserDownloadEntry(
                            browser="Firefox",
                            url=row["url"] or "",
                            target_path=row["content"] or "",
                            start_time=start_time,
                        )
                    )
            except sqlite3.OperationalError:
                pass

        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def _parse_raw(self) -> None:
        """Parse by looking for URL patterns in raw data."""
        patterns = [b"http://", b"https://"]

        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break

                end = pos
                while end < len(self.data) and self.data[end] >= 0x20 and self.data[end] < 0x7F:
                    end += 1

                if end - pos > 10:
                    try:
                        url = self.data[pos:end].decode("utf-8", errors="replace")
                        if url and len(url) < 2000:
                            self.history.append(
                                BrowserHistoryEntry(
                                    browser="Firefox",
                                    url=url,
                                    title="",
                                    visit_time=None,
                                )
                            )
                    except Exception:
                        pass

                offset = end


class IEHistoryParser:
    """Parser for Internet Explorer history (WebCacheV01.dat / index.dat)."""

    def __init__(self, data: bytes) -> None:
        """Initialize parser with history data."""
        self.data = data
        self.history: list[BrowserHistoryEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse IE history database."""
        # Check for WebCacheV01.dat (ESE database) or index.dat
        if len(self.data) < 4:
            return

        # ESE database signature
        if len(self.data) > 8 and self.data[4:8] == b"\xef\xcd\xab\x89":
            self._parse_webcache()
        else:
            self._parse_indexdat()

    def _parse_webcache(self) -> None:
        """Parse WebCacheV01.dat (ESE database)."""
        # ESE parsing is complex; extract URLs using pattern matching
        self._extract_urls("Internet Explorer")

    def _parse_indexdat(self) -> None:
        """Parse index.dat file."""
        # Look for URL records
        if len(self.data) < 0x5C:
            return

        # Signature check
        if self.data[0:0x1C] not in (b"Client UrlCache MMF Ver 5.2\x00", b"Client UrlCache MMF Ver 4.7\x00"):
            # Try pattern matching
            self._extract_urls("Internet Explorer")
            return

        # Parse records
        offset = struct.unpack("<I", self.data[0x4:0x8])[0]

        while offset < len(self.data) - 4:
            sig = self.data[offset:offset + 4]

            if sig == b"URL ":
                self._parse_url_record(offset)
            elif sig == b"REDR":
                pass  # Redirect record
            elif sig == b"HASH":
                pass  # Hash record

            # Move to next record (records are 128-byte aligned)
            if offset + 4 <= len(self.data) - 4:
                record_size = struct.unpack("<I", self.data[offset + 4:offset + 8])[0]
                if record_size > 0:
                    offset += record_size * 128
                else:
                    offset += 128
            else:
                break

    def _parse_url_record(self, offset: int) -> None:
        """Parse a URL record from index.dat."""
        if offset + 0x68 > len(self.data):
            return

        # Last modified time at offset 8
        mod_time = struct.unpack("<Q", self.data[offset + 8:offset + 16])[0]
        timestamp = _filetime_to_datetime(mod_time)

        # Last accessed time at offset 16
        access_time = struct.unpack("<Q", self.data[offset + 16:offset + 24])[0]
        last_visit = _filetime_to_datetime(access_time)

        # URL offset at 0x34
        url_offset = struct.unpack("<I", self.data[offset + 0x34:offset + 0x38])[0]

        if url_offset > 0 and offset + url_offset < len(self.data):
            url_data = self.data[offset + url_offset:]
            null_pos = url_data.find(b"\x00")
            if null_pos > 0:
                try:
                    url = url_data[:null_pos].decode("ascii", errors="replace")
                    if url:
                        self.history.append(
                            BrowserHistoryEntry(
                                browser="Internet Explorer",
                                url=url,
                                title="",
                                visit_time=timestamp,
                                last_visit=last_visit,
                            )
                        )
                except Exception:
                    pass

    def _extract_urls(self, browser: str) -> None:
        """Extract URLs using pattern matching."""
        patterns = [b"http://", b"https://"]

        found_urls = set()
        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break

                end = pos
                while end < len(self.data) and self.data[end] >= 0x20 and self.data[end] < 0x7F:
                    end += 1

                if end - pos > 10:
                    try:
                        url = self.data[pos:end].decode("utf-8", errors="replace")
                        if url and len(url) < 2000 and url not in found_urls:
                            found_urls.add(url)
                            self.history.append(
                                BrowserHistoryEntry(
                                    browser=browser,
                                    url=url,
                                    title="",
                                    visit_time=None,
                                )
                            )
                    except Exception:
                        pass

                offset = end


class BrowserHistoryParser:
    """Unified browser history parser."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        """Initialize parser."""
        self.data = data
        self.filename = filename.lower()
        self.history: list[BrowserHistoryEntry] = []
        self.downloads: list[BrowserDownloadEntry] = []
        self._parse()

    def _parse(self) -> None:
        """Parse browser history based on filename/content."""
        # Detect browser type
        if "places.sqlite" in self.filename:
            parser = FirefoxHistoryParser(self.data)
            self.history.extend(parser.history)
            self.downloads.extend(parser.downloads)
        elif "history" in self.filename and self.data[0:16] == SQLITE_SIGNATURE:
            # Chrome/Edge History
            parser = ChromeHistoryParser(self.data)
            self.history.extend(parser.history)
            self.downloads.extend(parser.downloads)
        elif "webcachev" in self.filename or "index.dat" in self.filename:
            parser = IEHistoryParser(self.data)
            self.history.extend(parser.history)
        elif self.data[0:16] == SQLITE_SIGNATURE:
            # Try Chrome first, then Firefox
            parser = ChromeHistoryParser(self.data)
            if parser.history:
                self.history.extend(parser.history)
                self.downloads.extend(parser.downloads)
            else:
                parser = FirefoxHistoryParser(self.data)
                self.history.extend(parser.history)
                self.downloads.extend(parser.downloads)
        else:
            # Try IE parser
            parser = IEHistoryParser(self.data)
            self.history.extend(parser.history)


@ParserRegistry.register
class BrowserHistoryFileParser(BaseParser):
    """Parser for browser history files."""

    name: ClassVar[str] = "browser"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = [
        "browser",
        "history",
        "places.sqlite",
        "webcachev01.dat",
        "index.dat",
    ]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize browser history parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse browser history file."""
        with open(file_path, "rb") as f:
            data = f.read()
        yield from self.parse_bytes(data, file_path.name)

    def parse_bytes(
        self, data: bytes, filename: str = ""
    ) -> Iterator[ParsedRecord]:
        """Parse browser history from bytes."""
        parser = BrowserHistoryParser(data, filename)

        record_index = 0

        # Yield history entries
        for entry in parser.history:
            record_data: dict[str, Any] = {
                "browser": entry.browser,
                "url": entry.url,
                "title": entry.title,
            }

            if entry.visit_time:
                record_data["visit_time"] = entry.visit_time.isoformat()
            if entry.last_visit:
                record_data["last_visit"] = entry.last_visit.isoformat()
            if entry.visit_count:
                record_data["visit_count"] = entry.visit_count
            if entry.typed_count:
                record_data["typed_count"] = entry.typed_count
            if entry.from_url:
                record_data["from_url"] = entry.from_url
            if entry.transition:
                record_data["transition"] = entry.transition
            if entry.hidden:
                record_data["hidden"] = entry.hidden

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("browser", "history", record_index, entry.url[:100])

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.visit_time or entry.last_visit,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1

        # Yield download entries
        for entry in parser.downloads:
            record_data = {
                "browser": entry.browser,
                "url": entry.url,
                "target_path": entry.target_path,
            }

            if entry.start_time:
                record_data["start_time"] = entry.start_time.isoformat()
            if entry.end_time:
                record_data["end_time"] = entry.end_time.isoformat()
            if entry.received_bytes:
                record_data["received_bytes"] = entry.received_bytes
            if entry.total_bytes:
                record_data["total_bytes"] = entry.total_bytes
            if entry.state:
                record_data["state"] = entry.state
            if entry.referrer:
                record_data["referrer"] = entry.referrer

            evidence_ref = self.create_evidence_ref(
                record_offset=0,
                record_index=record_index,
            )

            record_id = self.create_record_id("browser", "download", record_index, entry.url[:100])

            yield ParsedRecord(
                record_id=record_id,
                schema_version="v1",
                record_type="timeline",
                timestamp=entry.start_time,
                data=record_data,
                evidence_ref=evidence_ref,
            )

            record_index += 1
