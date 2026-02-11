"""Parse CLI commands for Scrut DFIR CLI."""

import hashlib
import time
from pathlib import Path
from uuid import UUID

import click

# Import all parsers to trigger registration
import scrut.parsers.activitiescache  # noqa: F401
import scrut.parsers.amcache  # noqa: F401
import scrut.parsers.bam  # noqa: F401
import scrut.parsers.bits  # noqa: F401
import scrut.parsers.browser  # noqa: F401
import scrut.parsers.defender  # noqa: F401
import scrut.parsers.etl  # noqa: F401
import scrut.parsers.evtx  # noqa: F401
import scrut.parsers.firewall  # noqa: F401
import scrut.parsers.jumplists  # noqa: F401
import scrut.parsers.lnk  # noqa: F401
import scrut.parsers.mft  # noqa: F401
import scrut.parsers.muicache  # noqa: F401
import scrut.parsers.networkconfig  # noqa: F401
import scrut.parsers.notifications  # noqa: F401
import scrut.parsers.powershell  # noqa: F401
import scrut.parsers.prefetch  # noqa: F401
import scrut.parsers.rdpcache  # noqa: F401
import scrut.parsers.recentapps  # noqa: F401
import scrut.parsers.recyclebin  # noqa: F401
import scrut.parsers.registry  # noqa: F401
import scrut.parsers.scheduledtasks  # noqa: F401
import scrut.parsers.searchhistory  # noqa: F401
import scrut.parsers.services  # noqa: F401
import scrut.parsers.shellbags  # noqa: F401
import scrut.parsers.shimcache  # noqa: F401
import scrut.parsers.srum  # noqa: F401
import scrut.parsers.syscache  # noqa: F401
import scrut.parsers.thumbcache  # noqa: F401
import scrut.parsers.typedurls  # noqa: F401
import scrut.parsers.usnjrnl  # noqa: F401
import scrut.parsers.wer  # noqa: F401
import scrut.parsers.wmi  # noqa: F401
from scrut.cli.output import OutputFormatter
from scrut.core.cache import get_cache
from scrut.core.errors import ScrutError
from scrut.core.pagination import CursorGenerator, Paginator, parse_time_filter
from scrut.core.target import TargetManager
from scrut.models.case import TargetType
from scrut.models.metrics import StepMetrics
from scrut.parsers.base import ParserRegistry


@click.group()
def parse() -> None:
    """Parse forensic artifacts to normalized JSON/JSONL."""
    pass


def _generic_parse(
    ctx: click.Context,
    artifact_type: str,
    artifact_path: Path | None,
    target_id: str | None,
    image_artifact_path: str | None,
    limit: int | None,
    since: str | None,
    until: str | None,
    cursor: str | None,
    summary: bool,
    no_cache: bool = False,
) -> None:
    """Generic parser execution with pagination support.

    This function handles the common logic for all artifact parsers,
    including pagination, time filtering, caching, and metrics.
    """
    formatter: OutputFormatter = ctx.obj["formatter"]

    # Validate arguments
    if target_id and not image_artifact_path:
        raise click.ClickException(
            "--target requires --artifact to specify the file path inside the image"
        )

    if image_artifact_path and not target_id:
        raise click.ClickException(
            "--artifact requires --target to specify which image to read from"
        )

    if not target_id and not artifact_path:
        raise click.ClickException(
            "Provide either:\n"
            "  1. --target <id> --artifact <path> to parse from an image\n"
            "  2. A local file path as argument"
        )

    # Get parser class from registry
    parser_class = ParserRegistry.get(artifact_type)
    if parser_class is None:
        supported = ParserRegistry.supported_types()
        raise click.ClickException(
            f"Unknown artifact type: {artifact_type}\n"
            f"Supported types: {', '.join(sorted(set(supported)))}"
        )

    try:
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        parser = parser_class(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        use_cache = not no_cache and artifact_path is not None and not target_id
        cached_records = None

        if use_cache:
            try:
                cache = get_cache()
                cached_records = cache.get(artifact_path, artifact_type)
                if cached_records is not None:
                    click.echo(f"Cache hit: {artifact_type} ({len(cached_records)} records)", err=True)
                else:
                    click.echo(f"Cache miss: {artifact_type}", err=True)
            except Exception:
                cached_records = None

        # Setup pagination
        paginator = Paginator(limit=limit, cursor=cursor)
        since_dt = parse_time_filter(since)
        until_dt = parse_time_filter(until)

        start_time = time.time()
        records_processed = 0
        records_output = 0
        last_timestamp = None
        last_record_id = None

        if cached_records is not None:
            for record_dict in cached_records:
                records_processed += 1

                if paginator.should_skip(records_processed - 1):
                    continue

                ts = record_dict.get("timestamp")
                if since_dt and ts and ts < since_dt.isoformat():
                    continue
                if until_dt and ts and ts > until_dt.isoformat():
                    continue

                if not summary:
                    formatter.output(record_dict)

                records_output += 1
                last_timestamp = ts
                last_record_id = record_dict.get("record_id")

                if paginator.should_stop():
                    break
        else:
            all_record_dicts: list[dict] = [] if use_cache else None

            for record in parser.parse_bytes(data):
                records_processed += 1
                record_dict = record.model_dump(mode="json", exclude_none=True)

                if all_record_dicts is not None:
                    all_record_dicts.append(record_dict)

                if paginator.should_skip(records_processed - 1):
                    continue

                if since_dt and record.timestamp and record.timestamp < since_dt:
                    continue

                if until_dt and record.timestamp and record.timestamp > until_dt:
                    continue

                if not summary:
                    formatter.output(record_dict)

                records_output += 1
                last_timestamp = record.timestamp
                last_record_id = record.record_id

                if paginator.should_stop():
                    break

            if use_cache and all_record_dicts is not None:
                try:
                    cache = get_cache()
                    cache.put(artifact_path, artifact_type, all_record_dicts)
                except Exception:
                    pass

        # Generate pagination metadata
        has_more = limit is not None and records_output >= limit
        next_cursor = None
        if has_more:
            next_cursor = CursorGenerator.create_next_cursor(
                current_offset=paginator.offset + records_output,
                last_timestamp=last_timestamp,
                last_record_id=last_record_id,
            )

        duration_ms = int((time.time() - start_time) * 1000)

        # Record metrics
        StepMetrics(
            run_id=tid,
            step_name=f"parse_{artifact_type}",
            duration_ms=duration_ms,
            records_processed=records_processed,
            records_output=records_output,
            bytes_read=bytes_read,
            bytes_written=0,
            warnings=0,
            errors=0,
            skipped=records_processed - records_output,
        )

        if summary:
            formatter.output({
                "artifact_type": artifact_type,
                "records_count": records_output,
                "records_processed": records_processed,
                "duration_ms": duration_ms,
            })
        else:
            formatter.flush_table(title=f"{artifact_type.upper()} Records ({records_output} total)")

        formatter.pagination(
            has_more=has_more,
            cursor=next_cursor,
            records_returned=records_output,
        )

        click.echo(f"Parsed {records_output} {artifact_type} record(s) in {duration_ms}ms", err=True)

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except click.ClickException:
        raise
    except Exception as e:
        formatter.error({
            "code": "PARSE_ERROR",
            "message": str(e),
            "remediation": f"Check that the file is a valid {artifact_type} artifact",
            "retryable": False,
        })
        ctx.exit(1)


# ============================================================================
# Generic artifact type commands - dynamically generated for all parsers
# ============================================================================

def _create_parser_command(artifact_type: str, description: str) -> click.Command:
    """Factory function to create a parse command for an artifact type."""

    @click.command(artifact_type)
    @click.argument("artifact_path", type=click.Path(path_type=Path), required=False)
    @click.option(
        "--target", "-t", "target_id",
        help="Target ID (image) to parse from. Use with --artifact."
    )
    @click.option(
        "--artifact", "-a", "image_artifact_path",
        help="Path inside the image"
    )
    @click.option("--limit", "-l", type=int, default=None, help="Limit number of records")
    @click.option("--since", type=str, default=None, help="Filter records since timestamp (ISO-8601 or relative: 7d, 24h)")
    @click.option("--until", type=str, default=None, help="Filter records until timestamp")
    @click.option("--cursor", type=str, default=None, help="Pagination cursor from previous request")
    @click.option("--summary", is_flag=True, help="Output count only, no records")
    @click.option("--no-cache", is_flag=True, default=False, help="Disable cache for this parse")
    @click.pass_context
    def cmd(
        ctx: click.Context,
        artifact_path: Path | None,
        target_id: str | None,
        image_artifact_path: str | None,
        limit: int | None,
        since: str | None,
        until: str | None,
        cursor: str | None,
        summary: bool,
        no_cache: bool,
    ) -> None:
        _generic_parse(
            ctx, artifact_type, artifact_path, target_id, image_artifact_path,
            limit, since, until, cursor, summary, no_cache
        )

    cmd.__doc__ = description
    return cmd


# Register all parser commands
_PARSER_DESCRIPTIONS = {
    "shimcache": "Parse ShimCache (AppCompatCache) for program execution evidence.",
    "amcache": "Parse Amcache.hve for application execution history with SHA1 hashes.",
    "mft": "Parse $MFT for file metadata and timestomping detection.",
    "usnjrnl": "Parse USN Journal ($J) for file system change history.",
    "lnk": "Parse Windows shortcut (LNK) files.",
    "shellbags": "Parse ShellBags for folder navigation history.",
    "jumplists": "Parse Jump Lists for recent/pinned items.",
    "browser": "Parse browser history (Chrome, Edge, Firefox).",
    "scheduledtasks": "Parse Scheduled Tasks XML definitions.",
    "recyclebin": "Parse Recycle Bin ($I files, INFO2).",
    "srum": "Parse SRUM (System Resource Usage Monitor) database.",
    "powershell": "Parse PowerShell console history with risk analysis.",
    "rdpcache": "Parse RDP bitmap cache and connection files.",
    "defender": "Parse Windows Defender logs (MPLog, Quarantine).",
    "bits": "Parse BITS (Background Intelligent Transfer Service) jobs.",
    "activitiescache": "Parse Windows Timeline (ActivitiesCache.db).",
    "wmi": "Parse WMI persistence mechanisms (OBJECTS.DATA).",
    "etl": "Parse ETL (Event Trace Log) files.",
    "services": "Parse Windows Services configuration from SYSTEM hive.",
    "firewall": "Parse Windows Firewall rules from registry.",
    "networkconfig": "Parse network interface and profile configuration.",
    "muicache": "Parse MUICache for program execution evidence.",
    "wer": "Parse Windows Error Reporting files for crash data.",
    "notifications": "Parse Windows notification database (wpndatabase.db).",
    "thumbcache": "Parse thumbnail cache (thumbcache_*.db) files.",
    "bam": "Parse BAM/DAM (Background Activity Moderator) for execution times.",
    "searchhistory": "Parse search history (WordWheelQuery, TypedPaths, RunMRU).",
    "typedurls": "Parse IE/Edge typed URL history.",
    "recentapps": "Parse recent apps with timestamps (Windows 10+).",
    "syscache": "Parse syscache.hve ObjectTable (Windows 7).",
}

for _artifact_type, _description in _PARSER_DESCRIPTIONS.items():
    parse.add_command(_create_parser_command(_artifact_type, _description))


@parse.command("types")
@click.pass_context
def list_types(ctx: click.Context) -> None:
    """List all available artifact types that can be parsed."""
    formatter: OutputFormatter = ctx.obj["formatter"]

    types_list = []
    all_types = ParserRegistry.supported_types()
    seen = set()

    for artifact_type in sorted(all_types):
        if artifact_type in seen:
            continue
        seen.add(artifact_type)

        parser_class = ParserRegistry.get(artifact_type)
        if parser_class:
            types_list.append({
                "type": artifact_type,
                "parser": parser_class.name,
                "version": parser_class.version,
            })

    for item in types_list:
        formatter.output(item)

    if formatter.is_human():
        formatter.flush_table(title="Available Parser Types")

    click.echo(f"Found {len(types_list)} parser types", err=True)


def _get_artifact_data(
    ctx: click.Context,
    target_id: str | None,
    artifact_path: str | None,
    local_file: Path | None,
) -> tuple[bytes, str, UUID, int]:
    """Get artifact data from target image or local file.

    Args:
        ctx: Click context
        target_id: Target ID to use
        artifact_path: Path inside the image
        local_file: Local file path (alternative to target)

    Returns:
        Tuple of (data, source_hash, target_uuid, size_bytes)
    """
    case_path = Path(ctx.obj.get("case_path", "."))
    ctx.obj["formatter"]

    if target_id and artifact_path:
        try:
            target_manager = TargetManager(case_path=case_path)
            target = target_manager.info(target_id)
        except ScrutError:
            raise click.ClickException(f"Target not found: {target_id}") from None

        if target.type != TargetType.IMAGE:
            raise click.ClickException(
                f"Target '{target.name}' is not an image (type: {target.type.value}). "
                "Use a local file path instead."
            )

        from scrut.images import open_image

        image_path = Path(target.path)
        if not image_path.exists():
            raise click.ClickException(f"Image file not found: {target.path}")

        click.echo(f"Opening image: {target.name} ({target.format or 'auto'})", err=True)

        try:
            image = open_image(image_path)
        except Exception as e:
            raise click.ClickException(f"Failed to open image: {e}") from e

        try:
            partitions = image.get_partitions()
            if not partitions:
                raise click.ClickException("No partitions found in image")

            click.echo(f"Found {len(partitions)} partition(s)", err=True)

            data = None
            for partition in partitions:
                try:
                    fs = image.get_filesystem(partition["index"])
                    if fs.exists(artifact_path):
                        click.echo(
                            f"Reading from partition {partition['index']} ({partition['type']}): {artifact_path}",
                            err=True,
                        )
                        data = fs.read_file(artifact_path)
                        break
                except Exception:
                    continue

            if data is None:
                raise click.ClickException(
                    f"Artifact not found in image: {artifact_path}\n"
                    "Hint: Use forward slashes and no leading slash, e.g., "
                    "'Windows/System32/winevt/Logs/Security.evtx'"
                )

            source_hash = hashlib.sha256(data).hexdigest()
            return data, source_hash, target.target_id, len(data)

        finally:
            image.close()

    elif local_file:
        if not local_file.exists():
            raise click.ClickException(f"File not found: {local_file}")

        data = local_file.read_bytes()
        source_hash = hashlib.sha256(data).hexdigest()

        tid = None
        try:
            target_manager = TargetManager(case_path=case_path)
            for t in target_manager.list():
                if t.hash_sha256 == source_hash:
                    tid = t.target_id
                    break
        except Exception:
            pass

        if tid is None:
            import uuid
            tid = uuid.uuid5(uuid.NAMESPACE_DNS, source_hash)

        return data, source_hash, tid, len(data)

    else:
        raise click.ClickException(
            "Either provide --target with --artifact, or specify a local file path"
        )


@parse.command()
@click.argument("artifact_path", type=click.Path(path_type=Path), required=False)
@click.option(
    "--target", "-t", "target_id",
    help="Target ID (image) to parse from. Use with --artifact."
)
@click.option(
    "--artifact", "-a", "image_artifact_path",
    help="Path inside the image (e.g., 'Windows/System32/winevt/Logs/Security.evtx')"
)
@click.option(
    "--partition", "-p", "partition_index",
    type=int, default=None,
    help="Partition index (0-based). Auto-detected if not specified."
)
@click.option("--limit", "-l", type=int, default=None, help="Limit number of records")
@click.option("--since", type=str, default=None, help="Filter records since timestamp (ISO-8601 or relative: 7d, 24h)")
@click.option("--until", type=str, default=None, help="Filter records until timestamp (ISO-8601 or relative)")
@click.option("--cursor", type=str, default=None, help="Pagination cursor from previous request")
@click.option("--summary", is_flag=True, help="Output count only, no records")
@click.pass_context
def evtx(
    ctx: click.Context,
    artifact_path: Path | None,
    target_id: str | None,
    image_artifact_path: str | None,
    partition_index: int | None,
    limit: int | None,
    since: str | None,
    until: str | None,
    cursor: str | None,
    summary: bool,
) -> None:
    """Parse Windows Event Log (EVTX) file to JSONL.

    \b
    Usage modes:
      1. From image:  scrut parse evtx --target <id> --artifact <path>
      2. Local file:  scrut parse evtx /path/to/file.evtx

    \b
    Examples:
      # Parse EVTX from inside E01 image
      scrut parse evtx --target abc123 --artifact "Windows/System32/winevt/Logs/Security.evtx"

      # Parse local EVTX file
      scrut parse evtx /evidence/Security.evtx --limit 100

    Output is streamed to stdout as JSONL (one JSON record per line).
    Progress and metrics are written to stderr.
    """
    formatter: OutputFormatter = ctx.obj["formatter"]

    if target_id and not image_artifact_path:
        raise click.ClickException(
            "--target requires --artifact to specify the file path inside the image"
        )

    if image_artifact_path and not target_id:
        raise click.ClickException(
            "--artifact requires --target to specify which image to read from"
        )

    if not target_id and not artifact_path:
        raise click.ClickException(
            "Provide either:\n"
            "  1. --target <id> --artifact <path> to parse from an image\n"
            "  2. A local file path as argument"
        )

    try:
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        try:
            from scrut.parsers.evtx import EvtxParser
        except RuntimeError as e:
            formatter.error({
                "code": "PARSER_NOT_AVAILABLE",
                "message": str(e),
                "remediation": "Install forensics dependencies: pip install scrut[forensics]",
                "retryable": False,
            })
            ctx.exit(1)
            return

        parser = EvtxParser(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        from scrut.core.pagination import CursorGenerator, Paginator, parse_time_filter

        paginator = Paginator(limit=limit, cursor=cursor)
        since_dt = parse_time_filter(since)
        until_dt = parse_time_filter(until)

        start_time = time.time()
        records_processed = 0
        records_output = 0
        last_timestamp = None
        last_record_id = None

        for record in parser.parse_bytes(data):
            records_processed += 1

            if paginator.should_skip(records_processed - 1):
                continue

            if since_dt and record.timestamp and record.timestamp < since_dt:
                continue

            if until_dt and record.timestamp and record.timestamp > until_dt:
                continue

            if not summary:
                formatter.output(record.model_dump(mode="json", exclude_none=True))

            records_output += 1
            last_timestamp = record.timestamp
            last_record_id = record.record_id

            if paginator.should_stop():
                break

        has_more = limit is not None and records_output >= limit
        next_cursor = None
        if has_more:
            next_cursor = CursorGenerator.create_next_cursor(
                current_offset=paginator.offset + records_output,
                last_timestamp=last_timestamp,
                last_record_id=last_record_id,
            )

        duration_ms = int((time.time() - start_time) * 1000)

        StepMetrics(
            run_id=tid,
            step_name="parse_evtx",
            duration_ms=duration_ms,
            records_processed=records_processed,
            records_output=records_output,
            bytes_read=bytes_read,
            bytes_written=0,
            warnings=0,
            errors=0,
            skipped=records_processed - records_output,
        )

        if summary:
            formatter.output({
                "artifact_type": "evtx",
                "records_count": records_output,
                "records_processed": records_processed,
                "duration_ms": duration_ms,
            })
        else:
            formatter.flush_table(title=f"EVTX Records ({records_output} total)")

        formatter.pagination(
            has_more=has_more,
            cursor=next_cursor,
            records_returned=records_output,
        )

        click.echo(f"Parsed {records_output} records in {duration_ms}ms", err=True)

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except click.ClickException:
        raise
    except Exception as e:
        formatter.error({
            "code": "PARSE_ERROR",
            "message": str(e),
            "remediation": "Check that the file is a valid EVTX file",
            "retryable": False,
        })
        ctx.exit(1)


@parse.command()
@click.argument("artifact_path", type=click.Path(path_type=Path), required=False)
@click.option(
    "--target", "-t", "target_id",
    help="Target ID (image) to parse from. Use with --artifact."
)
@click.option(
    "--artifact", "-a", "image_artifact_path",
    help="Path inside the image (e.g., 'Windows/Prefetch/CMD.EXE-4A81B364.pf')"
)
@click.option(
    "--partition", "-p", "partition_index",
    type=int, default=None,
    help="Partition index (0-based). Auto-detected if not specified."
)
@click.option("--limit", "-l", type=int, default=None, help="Limit number of records")
@click.option("--since", type=str, default=None, help="Filter records since timestamp (ISO-8601)")
@click.pass_context
def prefetch(
    ctx: click.Context,
    artifact_path: Path | None,
    target_id: str | None,
    image_artifact_path: str | None,
    partition_index: int | None,
    limit: int | None,
    since: str | None,
) -> None:
    """Parse Windows Prefetch file to JSONL.

    \b
    Usage modes:
      1. From image:  scrut parse prefetch --target <id> --artifact <path>
      2. Local file:  scrut parse prefetch /path/to/file.pf

    \b
    Examples:
      # Parse Prefetch from inside E01 image
      scrut parse prefetch --target abc123 --artifact "Windows/Prefetch/CMD.EXE-4A81B364.pf"

      # Parse local Prefetch file
      scrut parse prefetch /evidence/CMD.EXE-4A81B364.pf

    Output is streamed to stdout as JSONL (one JSON record per line).
    Progress and metrics are written to stderr.
    """
    formatter: OutputFormatter = ctx.obj["formatter"]

    if target_id and not image_artifact_path:
        raise click.ClickException(
            "--target requires --artifact to specify the file path inside the image"
        )

    if image_artifact_path and not target_id:
        raise click.ClickException(
            "--artifact requires --target to specify which image to read from"
        )

    if not target_id and not artifact_path:
        raise click.ClickException(
            "Provide either:\n"
            "  1. --target <id> --artifact <path> to parse from an image\n"
            "  2. A local file path as argument"
        )

    try:
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        try:
            from scrut.parsers.prefetch import PrefetchParser
        except RuntimeError as e:
            formatter.error({
                "code": "PARSER_NOT_AVAILABLE",
                "message": str(e),
                "remediation": "Install forensics dependencies: pip install scrut[forensics]",
                "retryable": False,
            })
            ctx.exit(1)
            return

        parser = PrefetchParser(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        start_time = time.time()
        records_processed = 0
        records_output = 0

        for record in parser.parse_bytes(data):
            records_processed += 1

            if since and record.timestamp:
                from datetime import datetime
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                if record.timestamp < since_dt:
                    continue

            formatter.output(record.model_dump(mode="json", exclude_none=True))
            records_output += 1

            if limit and records_output >= limit:
                break

        duration_ms = int((time.time() - start_time) * 1000)

        StepMetrics(
            run_id=tid,
            step_name="parse_prefetch",
            duration_ms=duration_ms,
            records_processed=records_processed,
            records_output=records_output,
            bytes_read=bytes_read,
            bytes_written=0,
            warnings=0,
            errors=0,
            skipped=records_processed - records_output,
        )

        formatter.flush_table(title=f"Prefetch Records ({records_output} total)")

        click.echo(f"Parsed {records_output} prefetch record(s) in {duration_ms}ms", err=True)

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except click.ClickException:
        raise
    except Exception as e:
        formatter.error({
            "code": "PARSE_ERROR",
            "message": str(e),
            "remediation": "Check that the file is a valid Prefetch file",
            "retryable": False,
        })
        ctx.exit(1)


@parse.command()
@click.argument("artifact_path", type=click.Path(path_type=Path), required=False)
@click.option(
    "--target", "-t", "target_id",
    help="Target ID (image) to parse from. Use with --artifact."
)
@click.option(
    "--artifact", "-a", "image_artifact_path",
    help="Path inside the image (e.g., 'Windows/System32/config/SYSTEM')"
)
@click.option(
    "--partition", "-p", "partition_index",
    type=int, default=None,
    help="Partition index (0-based). Auto-detected if not specified."
)
@click.option("--limit", "-l", type=int, default=None, help="Limit number of records")
@click.option("--key-filter", "-k", type=str, default=None, help="Filter by key path (substring match)")
@click.pass_context
def registry(
    ctx: click.Context,
    artifact_path: Path | None,
    target_id: str | None,
    image_artifact_path: str | None,
    partition_index: int | None,
    limit: int | None,
    key_filter: str | None,
) -> None:
    """Parse Windows Registry hive file to JSONL.

    \\b
    Usage modes:
      1. From image:  scrut parse registry --target <id> --artifact <path>
      2. Local file:  scrut parse registry /path/to/hive

    \\b
    Examples:
      # Parse SYSTEM hive from inside E01 image
      scrut parse registry --target abc123 --artifact "Windows/System32/config/SYSTEM"

      # Parse local NTUSER.DAT file
      scrut parse registry /evidence/NTUSER.DAT --limit 100

      # Filter by key path
      scrut parse registry /evidence/SOFTWARE -k "Microsoft\\\\Windows\\\\CurrentVersion"

    Output is streamed to stdout as JSONL (one JSON record per line).
    Progress and metrics are written to stderr.
    """
    formatter: OutputFormatter = ctx.obj["formatter"]

    if target_id and not image_artifact_path:
        raise click.ClickException(
            "--target requires --artifact to specify the file path inside the image"
        )

    if image_artifact_path and not target_id:
        raise click.ClickException(
            "--artifact requires --target to specify which image to read from"
        )

    if not target_id and not artifact_path:
        raise click.ClickException(
            "Provide either:\\n"
            "  1. --target <id> --artifact <path> to parse from an image\\n"
            "  2. A local file path as argument"
        )

    try:
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        from scrut.parsers.registry import RegistryParser

        parser = RegistryParser(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        start_time = time.time()
        records_processed = 0
        records_output = 0

        for record in parser.parse_bytes(data):
            records_processed += 1

            if key_filter:
                key_path = record.data.get("key_path", "")
                if key_filter.lower() not in key_path.lower():
                    continue

            formatter.output(record.model_dump(mode="json", exclude_none=True))
            records_output += 1

            if limit and records_output >= limit:
                break

        duration_ms = int((time.time() - start_time) * 1000)

        StepMetrics(
            run_id=tid,
            step_name="parse_registry",
            duration_ms=duration_ms,
            records_processed=records_processed,
            records_output=records_output,
            bytes_read=bytes_read,
            bytes_written=0,
            warnings=0,
            errors=0,
            skipped=records_processed - records_output,
        )

        formatter.flush_table(title=f"Registry Records ({records_output} total)")

        click.echo(f"Parsed {records_output} registry key(s) in {duration_ms}ms", err=True)

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except click.ClickException:
        raise
    except Exception as e:
        formatter.error({
            "code": "PARSE_ERROR",
            "message": str(e),
            "remediation": "Check that the file is a valid Registry hive",
            "retryable": False,
        })
        ctx.exit(1)


@parse.command("list-artifacts")
@click.option("--target", "-t", "target_id", required=True, help="Target ID (image)")
@click.option("--type", "-T", "artifact_type", default="evtx", help="Artifact type to find (evtx, prefetch, registry)")
@click.option("--partition", "-p", "partition_index", type=int, default=None, help="Partition index")
@click.pass_context
def list_artifacts(
    ctx: click.Context,
    target_id: str,
    artifact_type: str,
    partition_index: int | None,
) -> None:
    """List available artifacts in an image.

    \b
    Examples:
      # List all EVTX files
      scrut parse list-artifacts --target abc123 --type evtx

      # List prefetch files
      scrut parse list-artifacts --target abc123 --type prefetch
    """
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    patterns = {
        "evtx": ("*.evtx", ["Windows/System32/winevt/Logs"]),
        "prefetch": ("*.pf", ["Windows/Prefetch"]),
        "registry": ("*", ["Windows/System32/config"]),
    }

    if artifact_type not in patterns:
        raise click.ClickException(
            f"Unknown artifact type: {artifact_type}. "
            f"Supported: {', '.join(patterns.keys())}"
        )

    pattern, search_paths = patterns[artifact_type]

    try:
        target_manager = TargetManager(case_path=case_path)
        target = target_manager.info(target_id)

        if target.type != TargetType.IMAGE:
            raise click.ClickException(f"Target is not an image: {target.type.value}")

        from scrut.images import open_image

        image = open_image(Path(target.path))

        try:
            partitions = image.get_partitions()
            found_artifacts = []

            for partition in partitions:
                if partition_index is not None and partition["index"] != partition_index:
                    continue

                try:
                    fs = image.get_filesystem(partition["index"])

                    for search_path in search_paths:
                        if not fs.exists(search_path):
                            continue

                        for artifact_path in fs.find_files(pattern, search_path):
                            info = fs.get_file_info(artifact_path)
                            found_artifacts.append({
                                "path": artifact_path,
                                "size": info.size,
                                "partition": partition["index"],
                                "modified": info.modified_time.isoformat() if info.modified_time else None,
                            })

                except Exception:
                    continue

            if formatter.format == "jsonl":
                for artifact in found_artifacts:
                    formatter.output(artifact)
            else:
                formatter.output(found_artifacts)

            click.echo(f"Found {len(found_artifacts)} {artifact_type} artifact(s)", err=True)

        finally:
            image.close()

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except click.ClickException:
        raise
    except Exception as e:
        formatter.error({
            "code": "LIST_ERROR",
            "message": str(e),
            "remediation": "Check that the target is a valid image",
            "retryable": False,
        })
        ctx.exit(1)
