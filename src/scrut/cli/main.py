"""Scrut CLI entry point and global options."""

import sys
from pathlib import Path
from typing import Literal

import click

from scrut import __version__
from scrut.cli.bundle import bundle
from scrut.cli.case import case
from scrut.cli.output import OutputFormat, OutputFormatter, set_output_format
from scrut.cli.parse import parse
from scrut.cli.target import target
from scrut.core.logging import configure_logging, set_verbose


class GlobalContext:
    """Global context passed to all commands."""

    def __init__(
        self,
        format: OutputFormat = "json",
        timezone: str = "UTC",
        verbose: bool = False,
        quiet: bool = False,
        log_format: Literal["text", "json"] = "text",
    ):
        self.format = format
        self.timezone = timezone
        self.verbose = verbose
        self.quiet = quiet
        self.log_format = log_format


pass_context = click.make_pass_decorator(GlobalContext, ensure=True)


@click.group()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "jsonl", "human"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--timezone",
    "-tz",
    default="UTC",
    help="Output timezone in IANA format (default: UTC)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging to stderr",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help="Suppress progress output",
)
@click.option(
    "--log-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Log format for stderr (default: text)",
)
@click.option(
    "--case-path",
    "-C",
    type=click.Path(path_type=Path),
    default=".",
    help="Path to case directory (default: current directory)",
)
@click.version_option(version=__version__, prog_name="scrut")
@click.pass_context
def cli(
    ctx: click.Context,
    format: OutputFormat,
    timezone: str,
    verbose: bool,
    quiet: bool,
    log_format: Literal["text", "json"],
    case_path: Path,
) -> None:
    """Scrut: Evidence-first, MCP/LLM-native DFIR CLI orchestrator.

    Standardizes Windows forensic collection and parsing into strict,
    versioned JSON/JSONL with reproducible, audit-ready evidence packages.
    """
    ctx.ensure_object(dict)
    ctx.obj = {
        "format": format,
        "timezone": timezone,
        "verbose": verbose,
        "quiet": quiet,
        "log_format": log_format,
        "case_path": case_path,
        "formatter": OutputFormatter(format=format),
    }

    # Configure global settings
    set_output_format(format)
    set_verbose(verbose)
    configure_logging(log_format=log_format, quiet=quiet)


# Register command groups
cli.add_command(case)
cli.add_command(target)
cli.add_command(parse)
cli.add_command(bundle)


# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_INVALID_ARGS = 2
EXIT_TARGET_NOT_FOUND = 3
EXIT_PARSE_ERROR = 4
EXIT_PERMISSION_DENIED = 5
EXIT_TIMEOUT = 10
EXIT_RESOURCE_EXHAUSTED = 11


def main() -> None:
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
