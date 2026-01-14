"""Scrut CLI layer."""

__all__ = ["cli"]


def cli() -> None:
    """Lazy import and run the CLI."""
    from scrut.cli.main import cli as _cli

    _cli()
