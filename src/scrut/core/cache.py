"""SQLite-based caching for parsed forensic data.

Provides persistent caching to avoid re-parsing large artifacts.
Supports TTL-based expiration and hash-based invalidation.
"""

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel


@dataclass
class CacheEntry:
    """A cached parsing result."""

    key: str
    parser_name: str
    file_hash: str
    record_count: int
    created_at: datetime
    expires_at: datetime | None
    data: list[dict[str, Any]]


class CacheStats(BaseModel):
    """Cache statistics."""

    total_entries: int
    total_records: int
    total_size_bytes: int
    hit_count: int
    miss_count: int
    hit_rate: float
    oldest_entry: datetime | None
    newest_entry: datetime | None


class ParseCache:
    """SQLite-based cache for parsed forensic data."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS cache_entries (
        key TEXT PRIMARY KEY,
        parser_name TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        record_count INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL,
        accessed_at REAL NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_parser_name ON cache_entries(parser_name);
    CREATE INDEX IF NOT EXISTS idx_file_hash ON cache_entries(file_hash);
    CREATE INDEX IF NOT EXISTS idx_expires_at ON cache_entries(expires_at);

    CREATE TABLE IF NOT EXISTS cache_stats (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        hit_count INTEGER DEFAULT 0,
        miss_count INTEGER DEFAULT 0
    );

    INSERT OR IGNORE INTO cache_stats (id, hit_count, miss_count) VALUES (1, 0, 0);
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_hours: int = 24,
        max_size_mb: int = 500,
    ) -> None:
        """Initialize the cache.

        Args:
            cache_dir: Directory for cache database (default: .scrut/cache)
            ttl_hours: Default TTL for cache entries in hours
            max_size_mb: Maximum cache size in MB
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".scrut" / "cache"

        cache_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = cache_dir / "parse_cache.db"
        self._ttl = timedelta(hours=ttl_hours)
        self._max_size = max_size_mb * 1024 * 1024

        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._connection() as conn:
            conn.executescript(self.SCHEMA)

    @contextmanager
    def _connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _make_key(self, file_path: Path, parser_name: str) -> str:
        """Generate cache key from file path and parser."""
        return f"{parser_name}:{file_path}"

    def _compute_hash(self, file_path: Path) -> str:
        """Compute file hash for cache invalidation."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get(
        self,
        file_path: Path,
        parser_name: str,
    ) -> list[dict[str, Any]] | None:
        """Get cached parsing results.

        Args:
            file_path: Path to the parsed file
            parser_name: Name of the parser used

        Returns:
            List of parsed records or None if not cached/expired
        """
        key = self._make_key(file_path, parser_name)
        now = time.time()

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM cache_entries
                WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)
                """,
                (key, now),
            ).fetchone()

            if row is None:
                conn.execute(
                    "UPDATE cache_stats SET miss_count = miss_count + 1 WHERE id = 1"
                )
                return None

            current_hash = self._compute_hash(file_path)
            if current_hash != row["file_hash"]:
                conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                conn.execute(
                    "UPDATE cache_stats SET miss_count = miss_count + 1 WHERE id = 1"
                )
                return None

            conn.execute(
                "UPDATE cache_entries SET accessed_at = ? WHERE key = ?",
                (now, key),
            )
            conn.execute(
                "UPDATE cache_stats SET hit_count = hit_count + 1 WHERE id = 1"
            )

            return json.loads(row["data_json"])

    def put(
        self,
        file_path: Path,
        parser_name: str,
        records: list[dict[str, Any]],
        ttl: timedelta | None = None,
    ) -> None:
        """Cache parsing results.

        Args:
            file_path: Path to the parsed file
            parser_name: Name of the parser used
            records: Parsed records to cache
            ttl: Optional custom TTL (uses default if not specified)
        """
        key = self._make_key(file_path, parser_name)
        file_hash = self._compute_hash(file_path)
        now = time.time()

        if ttl is None:
            ttl = self._ttl

        expires_at = now + ttl.total_seconds() if ttl else None
        data_json = json.dumps(records, default=str)

        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache_entries
                (key, parser_name, file_hash, record_count, data_json, created_at, expires_at, accessed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (key, parser_name, file_hash, len(records), data_json, now, expires_at, now),
            )

        self._maybe_evict()

    def invalidate(self, file_path: Path, parser_name: str | None = None) -> int:
        """Invalidate cache entries for a file.

        Args:
            file_path: Path to the file
            parser_name: Optional parser name (all parsers if not specified)

        Returns:
            Number of entries invalidated
        """
        with self._connection() as conn:
            if parser_name:
                key = self._make_key(file_path, parser_name)
                result = conn.execute(
                    "DELETE FROM cache_entries WHERE key = ?", (key,)
                )
            else:
                result = conn.execute(
                    "DELETE FROM cache_entries WHERE key LIKE ?",
                    (f"%:{file_path}",),
                )
            return result.rowcount

    def invalidate_parser(self, parser_name: str) -> int:
        """Invalidate all cache entries for a parser.

        Args:
            parser_name: Name of the parser

        Returns:
            Number of entries invalidated
        """
        with self._connection() as conn:
            result = conn.execute(
                "DELETE FROM cache_entries WHERE parser_name = ?",
                (parser_name,),
            )
            return result.rowcount

    def clear(self) -> int:
        """Clear all cache entries.

        Returns:
            Number of entries cleared
        """
        with self._connection() as conn:
            result = conn.execute("DELETE FROM cache_entries")
            conn.execute(
                "UPDATE cache_stats SET hit_count = 0, miss_count = 0 WHERE id = 1"
            )
            return result.rowcount

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        now = time.time()
        with self._connection() as conn:
            result = conn.execute(
                "DELETE FROM cache_entries WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            return result.rowcount

    def get_stats(self) -> CacheStats:
        """Get cache statistics.

        Returns:
            CacheStats with current cache state
        """
        with self._connection() as conn:
            entry_stats = conn.execute(
                """
                SELECT
                    COUNT(*) as total_entries,
                    COALESCE(SUM(record_count), 0) as total_records,
                    COALESCE(SUM(LENGTH(data_json)), 0) as total_size,
                    MIN(created_at) as oldest,
                    MAX(created_at) as newest
                FROM cache_entries
                """
            ).fetchone()

            hit_stats = conn.execute(
                "SELECT hit_count, miss_count FROM cache_stats WHERE id = 1"
            ).fetchone()

            hit_count = hit_stats["hit_count"]
            miss_count = hit_stats["miss_count"]
            total_requests = hit_count + miss_count
            hit_rate = hit_count / total_requests if total_requests > 0 else 0.0

            return CacheStats(
                total_entries=entry_stats["total_entries"],
                total_records=entry_stats["total_records"],
                total_size_bytes=entry_stats["total_size"],
                hit_count=hit_count,
                miss_count=miss_count,
                hit_rate=hit_rate,
                oldest_entry=(
                    datetime.fromtimestamp(entry_stats["oldest"])
                    if entry_stats["oldest"]
                    else None
                ),
                newest_entry=(
                    datetime.fromtimestamp(entry_stats["newest"])
                    if entry_stats["newest"]
                    else None
                ),
            )

    def _maybe_evict(self) -> None:
        """Evict old entries if cache exceeds max size."""
        with self._connection() as conn:
            size_row = conn.execute(
                "SELECT SUM(LENGTH(data_json)) as total FROM cache_entries"
            ).fetchone()

            current_size = size_row["total"] or 0

            if current_size > self._max_size:
                target_size = int(self._max_size * 0.8)  # Target 80% of max

                while current_size > target_size:
                    oldest = conn.execute(
                        "SELECT key, LENGTH(data_json) as size FROM cache_entries ORDER BY accessed_at LIMIT 1"
                    ).fetchone()

                    if oldest:
                        conn.execute(
                            "DELETE FROM cache_entries WHERE key = ?",
                            (oldest["key"],),
                        )
                        current_size -= oldest["size"]
                    else:
                        break

    def iter_entries(
        self,
        parser_name: str | None = None,
    ) -> Iterator[CacheEntry]:
        """Iterate over cache entries.

        Args:
            parser_name: Optional filter by parser name

        Yields:
            CacheEntry objects
        """
        with self._connection() as conn:
            if parser_name:
                rows = conn.execute(
                    "SELECT * FROM cache_entries WHERE parser_name = ? ORDER BY created_at DESC",
                    (parser_name,),
                )
            else:
                rows = conn.execute(
                    "SELECT * FROM cache_entries ORDER BY created_at DESC"
                )

            for row in rows:
                yield CacheEntry(
                    key=row["key"],
                    parser_name=row["parser_name"],
                    file_hash=row["file_hash"],
                    record_count=row["record_count"],
                    created_at=datetime.fromtimestamp(row["created_at"]),
                    expires_at=(
                        datetime.fromtimestamp(row["expires_at"])
                        if row["expires_at"]
                        else None
                    ),
                    data=json.loads(row["data_json"]),
                )


_cache: ParseCache | None = None


def get_cache() -> ParseCache:
    """Get the global cache instance."""
    global _cache
    if _cache is None:
        _cache = ParseCache()
    return _cache


def set_cache(cache: ParseCache) -> None:
    """Set the global cache instance."""
    global _cache
    _cache = cache
