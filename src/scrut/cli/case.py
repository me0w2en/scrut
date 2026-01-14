"""Case CLI commands."""

from pathlib import Path

import click

from scrut.cli.output import OutputFormatter
from scrut.core.case import CaseManager
from scrut.core.errors import ScrutError


@click.group()
def case() -> None:
    """Manage investigation cases."""
    pass


@case.command()
@click.option("--name", "-n", required=True, help="Case name")
@click.option("--description", "-d", default=None, help="Case description")
@click.option("--analyst", "-a", default=None, help="Analyst identifier")
@click.option("--timezone", "-z", default="UTC", help="Case timezone (IANA format)")
@click.option("--tag", "-t", multiple=True, help="Classification tag (can be repeated)")
@click.pass_context
def init(
    ctx: click.Context,
    name: str,
    description: str | None,
    analyst: str | None,
    timezone: str,
    tag: tuple[str, ...],
) -> None:
    """Initialize a new investigation case."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = CaseManager(base_path=case_path)
        case_obj = manager.init(
            name=name,
            description=description,
            analyst=analyst,
            timezone=timezone,
            tags=list(tag),
        )
        formatter.output(case_obj.to_json_dict())
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@case.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Show case information."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = CaseManager(base_path=case_path)
        case_obj = manager.info()
        formatter.output(case_obj.to_json_dict())
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@case.command()
@click.pass_context
def activate(ctx: click.Context) -> None:
    """Activate a draft case."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = CaseManager(base_path=case_path)
        case_obj = manager.activate()
        formatter.output(case_obj.to_json_dict())
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@case.command()
@click.pass_context
def archive(ctx: click.Context) -> None:
    """Archive an active case."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        manager = CaseManager(base_path=case_path)
        case_obj = manager.archive()
        formatter.output(case_obj.to_json_dict())
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
