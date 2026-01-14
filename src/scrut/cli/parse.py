"""Parse CLI commands for Scrut DFIR CLI."""

import hashlib
import time
from pathlib import Path
from uuid import UUID

import click

from scrut.cli.output import OutputFormatter
from scrut.core.errors import ScrutError
from scrut.core.target import TargetManager
from scrut.models.case import TargetType
from scrut.models.metrics import StepMetrics


@click.group()
def parse() -> None:
    """Parse forensic artifacts to normalized JSON/JSONL."""
    pass


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
    formatter: OutputFormatter = ctx.obj["formatter"]

    if target_id and artifact_path:
        # Read from inside the image
        try:
            target_manager = TargetManager(case_path=case_path)
            target = target_manager.info(target_id)
        except ScrutError:
            raise click.ClickException(f"Target not found: {target_id}")

        if target.type != TargetType.IMAGE:
            raise click.ClickException(
                f"Target '{target.name}' is not an image (type: {target.type.value}). "
                "Use a local file path instead."
            )

        # Open the image and read the file
        from scrut.images import open_image

        image_path = Path(target.path)
        if not image_path.exists():
            raise click.ClickException(f"Image file not found: {target.path}")

        click.echo(f"Opening image: {target.name} ({target.format or 'auto'})", err=True)

        try:
            image = open_image(image_path)
        except Exception as e:
            raise click.ClickException(f"Failed to open image: {e}")

        try:
            # Get filesystem (first partition by default)
            partitions = image.get_partitions()
            if not partitions:
                raise click.ClickException("No partitions found in image")

            click.echo(f"Found {len(partitions)} partition(s)", err=True)

            # Try to find the file in each partition
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
                    # Try next partition
                    continue

            if data is None:
                raise click.ClickException(
                    f"Artifact not found in image: {artifact_path}\n"
                    "Hint: Use forward slashes and no leading slash, e.g., "
                    "'Windows/System32/winevt/Logs/Security.evtx'"
                )

            # Compute hash of the data
            source_hash = hashlib.sha256(data).hexdigest()
            return data, source_hash, target.target_id, len(data)

        finally:
            image.close()

    elif local_file:
        # Read from local file
        if not local_file.exists():
            raise click.ClickException(f"File not found: {local_file}")

        data = local_file.read_bytes()
        source_hash = hashlib.sha256(data).hexdigest()

        # Try to find matching target
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
@click.option("--since", type=str, default=None, help="Filter records since timestamp (ISO-8601)")
@click.pass_context
def evtx(
    ctx: click.Context,
    artifact_path: Path | None,
    target_id: str | None,
    image_artifact_path: str | None,
    partition_index: int | None,
    limit: int | None,
    since: str | None,
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

    try:
        # Get artifact data
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        # Import parser
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

        # Create parser
        parser = EvtxParser(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        # Track metrics
        start_time = time.time()
        records_processed = 0
        records_output = 0

        # Parse from bytes
        for record in parser.parse_bytes(data):
            records_processed += 1

            # Apply filters
            if since and record.timestamp:
                from datetime import datetime
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                if record.timestamp < since_dt:
                    continue

            # Output record
            formatter.output(record.model_dump(mode="json", exclude_none=True))
            records_output += 1

            # Apply limit
            if limit and records_output >= limit:
                break

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Emit metrics to stderr
        metrics = StepMetrics(
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

        # Flush table output for human format
        formatter.flush_table(title=f"EVTX Records ({records_output} total)")

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

    try:
        # Get artifact data
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        # Import parser
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

        # Create parser
        parser = PrefetchParser(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        # Track metrics
        start_time = time.time()
        records_processed = 0
        records_output = 0

        # Parse from bytes
        for record in parser.parse_bytes(data):
            records_processed += 1

            # Apply filters
            if since and record.timestamp:
                from datetime import datetime
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                if record.timestamp < since_dt:
                    continue

            # Output record
            formatter.output(record.model_dump(mode="json", exclude_none=True))
            records_output += 1

            # Apply limit
            if limit and records_output >= limit:
                break

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Emit metrics to stderr
        metrics = StepMetrics(
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

        # Flush table output for human format
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
            "Provide either:\\n"
            "  1. --target <id> --artifact <path> to parse from an image\\n"
            "  2. A local file path as argument"
        )

    try:
        # Get artifact data
        data, source_hash, tid, bytes_read = _get_artifact_data(
            ctx, target_id, image_artifact_path, artifact_path
        )

        # Import parser
        from scrut.parsers.registry import RegistryParser

        # Create parser
        parser = RegistryParser(
            target_id=tid,
            artifact_path=image_artifact_path or str(artifact_path),
            source_hash=source_hash,
            timezone_str=ctx.obj.get("timezone", "UTC"),
        )

        # Track metrics
        start_time = time.time()
        records_processed = 0
        records_output = 0

        # Parse from bytes
        for record in parser.parse_bytes(data):
            records_processed += 1

            # Apply key filter
            if key_filter:
                key_path = record.data.get("key_path", "")
                if key_filter.lower() not in key_path.lower():
                    continue

            # Output record
            formatter.output(record.model_dump(mode="json", exclude_none=True))
            records_output += 1

            # Apply limit
            if limit and records_output >= limit:
                break

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Emit metrics to stderr
        metrics = StepMetrics(
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

        # Flush table output for human format
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

    # Artifact patterns
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
        # Get target
        target_manager = TargetManager(case_path=case_path)
        target = target_manager.info(target_id)

        if target.type != TargetType.IMAGE:
            raise click.ClickException(f"Target is not an image: {target.type.value}")

        # Open image
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

            # Output results
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
