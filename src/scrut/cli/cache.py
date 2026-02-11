"""Cache management CLI commands for Scrut."""

import click

from scrut.cli.output import OutputFormatter
from scrut.core.cache import get_cache


@click.group()
def cache() -> None:
    """Manage the parse result cache."""
    pass


@cache.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show cache statistics."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    cache_instance = get_cache()
    cache_stats = cache_instance.get_stats()

    stats_dict = cache_stats.model_dump(mode="json")
    formatter.output(stats_dict)

    if formatter.is_human():
        formatter.flush_table(title="Cache Statistics")

    click.echo(
        f"Cache: {cache_stats.total_entries} entries, "
        f"{cache_stats.total_records} records, "
        f"hit rate: {cache_stats.hit_rate:.1%}",
        err=True,
    )


@cache.command()
@click.confirmation_option(prompt="Are you sure you want to clear the entire cache?")
@click.pass_context
def clear(ctx: click.Context) -> None:
    """Clear all cached parse results."""
    cache_instance = get_cache()
    removed = cache_instance.clear()
    click.echo(f"Cleared {removed} cache entries", err=True)


@cache.command()
@click.pass_context
def cleanup(ctx: click.Context) -> None:
    """Remove expired cache entries."""
    cache_instance = get_cache()
    removed = cache_instance.cleanup_expired()
    click.echo(f"Removed {removed} expired cache entries", err=True)
