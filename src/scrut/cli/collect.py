"""Collect CLI commands for artifact acquisition."""

from pathlib import Path

import click

from scrut.cli.output import OutputFormatter
from scrut.collectors.scope import PredefinedScope, ScopeBuilder
from scrut.collectors.windows import WindowsCollector
from scrut.core.errors import ScrutError
from scrut.core.target import TargetManager
from scrut.images.base import open_image
from scrut.models.case import TargetType


@click.group()
def collect() -> None:
    """Collect forensic artifacts from targets."""
    pass


@collect.command()
@click.option("--target", "-t", "target_id", required=True, help="Target ID to collect from")
@click.option(
    "--scope",
    "-s",
    "scope_name",
    type=click.Choice([s.value for s in PredefinedScope]),
    default="standard",
    help="Collection scope (default: standard)",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path),
    default="./collected",
    help="Output directory for collected artifacts",
)
@click.pass_context
def run(
    ctx: click.Context,
    target_id: str,
    scope_name: str,
    output_dir: Path,
) -> None:
    """Collect artifacts from a target image."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))
    quiet = ctx.obj.get("quiet", False)

    try:
        manager = TargetManager(case_path=case_path)
        target_obj = manager.info(target_id)

        scope = ScopeBuilder.from_predefined(PredefinedScope(scope_name)).build()
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        target_path = Path(target_obj.path)

        if target_obj.type == TargetType.IMAGE:
            image = open_image(target_path)
            try:
                filesystem = image.get_filesystem()
                collector = WindowsCollector(
                    system_root=target_path,
                    output_dir=output_dir,
                    scope=scope,
                    filesystem=filesystem,
                )

                def progress(name: str, current: int, total: int) -> None:
                    if not quiet:
                        click.echo(
                            f"[{current}/{total}] Collecting {name}...", err=True
                        )

                result = collector.collect(progress_callback=progress)
            finally:
                image.close()
        else:
            collector = WindowsCollector(
                system_root=target_path,
                output_dir=output_dir,
                scope=scope,
            )

            def progress(name: str, current: int, total: int) -> None:
                if not quiet:
                    click.echo(f"[{current}/{total}] Collecting {name}...", err=True)

            result = collector.collect(progress_callback=progress)

        if not quiet:
            click.echo(
                f"\nCollection complete: {result.total_files} files, "
                f"{result.total_bytes} bytes",
                err=True,
            )
            if result.errors:
                click.echo(f"Errors: {len(result.errors)}", err=True)
            if result.skipped:
                click.echo(f"Skipped: {len(result.skipped)}", err=True)

        formatter.output(result.model_dump(mode="json"))

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@collect.command("list")
@click.option("--target", "-t", "target_id", required=True, help="Target ID to list artifacts for")
@click.option(
    "--scope",
    "-s",
    "scope_name",
    type=click.Choice([s.value for s in PredefinedScope]),
    default="standard",
    help="Collection scope (default: standard)",
)
@click.pass_context
def list_artifacts(
    ctx: click.Context,
    target_id: str,
    scope_name: str,
) -> None:
    """List artifacts that would be collected (dry-run)."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = TargetManager(case_path=case_path)
        manager.info(target_id)  # Validate target exists

        scope = ScopeBuilder.from_predefined(PredefinedScope(scope_name)).build()

        collector = WindowsCollector(
            system_root=Path("."),
            output_dir=Path("."),
            scope=scope,
        )
        artifacts = collector.get_artifacts()

        output_list = [
            {
                "artifact_type": a.artifact_type.value,
                "name": a.name,
                "category": a.category.value,
                "paths": a.paths,
                "priority": a.priority,
            }
            for a in artifacts
        ]

        formatter.output(output_list)

    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@collect.command()
@click.pass_context
def scopes(ctx: click.Context) -> None:
    """List available collection scopes."""
    formatter: OutputFormatter = ctx.obj["formatter"]

    scope_list = []
    for ps in PredefinedScope:
        scope = ScopeBuilder.from_predefined(ps).build()
        scope_list.append(
            {
                "name": ps.value,
                "description": scope.description,
                "categories": [c.value for c in scope.categories],
                "max_file_size_mb": scope.max_file_size_mb,
            }
        )

    formatter.output(scope_list)
