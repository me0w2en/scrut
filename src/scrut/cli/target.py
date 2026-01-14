"""Target CLI commands."""

from pathlib import Path

import click

from scrut.cli.output import OutputFormatter
from scrut.core.errors import ScrutError
from scrut.core.target import TargetManager
from scrut.models.case import TargetType


@click.group()
def target() -> None:
    """Manage evidence targets."""
    pass


@target.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--name", "-n", required=True, help="Target display name")
@click.option(
    "--type",
    "-t",
    "target_type",
    type=click.Choice(["image", "folder", "collection", "output"]),
    default=None,
    help="Target type (auto-detected if not specified)",
)
@click.option("--format", "-f", "format_", default=None, help="Target format (e.g., E01, VMDK)")
@click.pass_context
def add(
    ctx: click.Context,
    path: Path,
    name: str,
    target_type: str | None,
    format_: str | None,
) -> None:
    """Add a target to the case."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = TargetManager(case_path=case_path)

        type_enum = TargetType(target_type) if target_type else None

        target_obj = manager.add(
            path=path,
            name=name,
            target_type=type_enum,
            format=format_,
        )
        formatter.output(target_obj.to_json_dict())
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@target.command("list")
@click.pass_context
def list_targets(ctx: click.Context) -> None:
    """List all targets in the case."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = TargetManager(case_path=case_path)
        targets = manager.list()

        if formatter.format == "jsonl":
            for t in targets:
                formatter.output(t.to_json_dict())
        else:
            formatter.output([t.to_json_dict() for t in targets])
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@target.command()
@click.argument("target_id")
@click.pass_context
def info(ctx: click.Context, target_id: str) -> None:
    """Show target information."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = TargetManager(case_path=case_path)
        target_obj = manager.info(target_id)
        formatter.output(target_obj.to_json_dict())
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
