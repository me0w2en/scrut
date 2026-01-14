"""Bundle CLI commands for creating and verifying evidence packages."""

from datetime import datetime
from pathlib import Path
from uuid import UUID

import click

from scrut.cli.output import OutputFormatter
from scrut.core.case import CaseManager
from scrut.evidence.bundle import BundleCreator, BundleVerifier


@click.group()
def bundle() -> None:
    """Manage evidence bundles for reproducibility."""
    pass


@bundle.command()
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(path_type=Path),
    required=True,
    help="Output path for the bundle directory",
)
@click.option(
    "--name",
    "-n",
    "bundle_name",
    default=None,
    help="Bundle name (defaults to case name with timestamp)",
)
@click.option(
    "--include-results",
    "-r",
    "result_files",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Result files to include in bundle",
)
@click.option(
    "--since",
    type=click.DateTime(),
    default=None,
    help="Include commands executed since this time",
)
@click.pass_context
def create(
    ctx: click.Context,
    output_path: Path,
    bundle_name: str | None,
    result_files: tuple[Path, ...],
    since: datetime | None,
) -> None:
    """Create an evidence bundle with results and provenance metadata.

    The bundle includes:
    - All specified result files
    - manifest.json with full provenance metadata
    - Command history for reproducibility
    - Environment information
    """
    formatter: OutputFormatter = ctx.obj.get("formatter", OutputFormatter())
    case_path: Path = ctx.obj.get("case_path", Path.cwd())

    try:
        # Load case info
        case_manager = CaseManager(case_path)
        case_info = case_manager.get_case_info()

        if not case_info:
            formatter.error({
                "code": "NO_CASE",
                "message": "No case found in current directory",
                "remediation": "Run 'scrut case init' first or use --case-path",
                "retryable": False,
            })
            ctx.exit(1)
            return

        # Get targets
        targets = case_manager.list_targets()

        # Create bundle
        creator = BundleCreator(case_path)
        bundle = creator.create_bundle(
            output_path=output_path,
            case_id=UUID(case_info["case_id"]),
            case_name=case_info.get("name", "Unknown Case"),
            analyst=case_info.get("analyst", "unknown"),
            targets=targets,
            result_files=list(result_files) if result_files else None,
            include_commands_since=since,
        )

        # Output result
        result = {
            "status": "created",
            "bundle_id": str(bundle.bundle_id),
            "bundle_path": str(output_path.absolute()),
            "case_id": str(bundle.case_id),
            "results_count": len(bundle.manifest.results),
            "commands_count": len(bundle.manifest.commands),
            "targets_count": len(bundle.manifest.targets),
        }

        formatter.output(result)
        click.echo(
            f"Bundle created: {output_path.absolute()} "
            f"({len(bundle.manifest.results)} results, "
            f"{len(bundle.manifest.commands)} commands)",
            err=True,
        )

    except Exception as e:
        formatter.error({
            "code": "BUNDLE_ERROR",
            "message": str(e),
            "remediation": "Check that the case directory is valid",
            "retryable": False,
        })
        ctx.exit(1)


@bundle.command()
@click.argument("bundle_path", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def verify(ctx: click.Context, bundle_path: Path) -> None:
    """Verify the integrity of an evidence bundle.

    Checks:
    - Manifest is valid and parseable
    - All result files exist and match recorded hashes
    - Bundle hash matches (if recorded)
    """
    formatter: OutputFormatter = ctx.obj.get("formatter", OutputFormatter())

    try:
        verifier = BundleVerifier(bundle_path)
        results = verifier.verify_integrity()

        # Add manifest info to output
        manifest = verifier.load_manifest()
        if manifest:
            results["bundle_id"] = str(manifest.bundle_id)
            results["case_id"] = str(manifest.case_id)
            results["case_name"] = manifest.case_name
            results["created_at"] = manifest.created_at.isoformat()
            results["created_by"] = manifest.created_by

        formatter.output(results)

        if results["valid"]:
            click.echo("Bundle verification: PASSED", err=True)
        else:
            click.echo("Bundle verification: FAILED", err=True)
            for error in results.get("errors", []):
                click.echo(f"  - {error}", err=True)
            ctx.exit(1)

    except Exception as e:
        formatter.error({
            "code": "VERIFY_ERROR",
            "message": str(e),
            "remediation": "Check that the bundle path is valid",
            "retryable": False,
        })
        ctx.exit(1)


@bundle.command()
@click.argument("bundle_path", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def info(ctx: click.Context, bundle_path: Path) -> None:
    """Show information about an evidence bundle."""
    formatter: OutputFormatter = ctx.obj.get("formatter", OutputFormatter())

    try:
        verifier = BundleVerifier(bundle_path)
        manifest = verifier.load_manifest()

        if not manifest:
            formatter.error({
                "code": "INVALID_BUNDLE",
                "message": "Could not load bundle manifest",
                "remediation": "Check that the path contains a valid bundle",
                "retryable": False,
            })
            ctx.exit(1)
            return

        info = {
            "bundle_id": str(manifest.bundle_id),
            "case_id": str(manifest.case_id),
            "case_name": manifest.case_name,
            "created_at": manifest.created_at.isoformat(),
            "created_by": manifest.created_by,
            "environment": {
                "scrut_version": manifest.environment.scrut_version,
                "python_version": manifest.environment.python_version.split()[0],
                "platform": manifest.environment.platform,
            },
            "targets_count": len(manifest.targets),
            "results_count": len(manifest.results),
            "commands_count": len(manifest.commands),
            "results": [
                {
                    "filename": r.filename,
                    "artifact_type": r.artifact_type,
                    "record_count": r.record_count,
                }
                for r in manifest.results
            ],
        }

        formatter.output(info)

    except Exception as e:
        formatter.error({
            "code": "INFO_ERROR",
            "message": str(e),
            "remediation": "Check that the bundle path is valid",
            "retryable": False,
        })
        ctx.exit(1)


@bundle.command("replay")
@click.argument("bundle_path", type=click.Path(exists=True, path_type=Path))
@click.option("--dry-run", is_flag=True, help="Show commands without executing")
@click.pass_context
def replay(ctx: click.Context, bundle_path: Path, dry_run: bool) -> None:
    """Show or replay commands from a bundle for reproducibility.

    With --dry-run, shows the commands without executing them.
    """
    formatter: OutputFormatter = ctx.obj.get("formatter", OutputFormatter())

    try:
        verifier = BundleVerifier(bundle_path)
        commands = verifier.get_reproducibility_commands()

        if not commands:
            click.echo("No commands recorded in bundle", err=True)
            return

        if dry_run:
            result = {
                "mode": "dry-run",
                "command_count": len(commands),
                "commands": commands,
            }
            formatter.output(result)
            click.echo(f"Would execute {len(commands)} commands:", err=True)
            for cmd in commands:
                click.echo(f"  $ {cmd}", err=True)
        else:
            click.echo(
                "Replay execution not yet implemented. Use --dry-run to see commands.",
                err=True,
            )

    except Exception as e:
        formatter.error({
            "code": "REPLAY_ERROR",
            "message": str(e),
            "remediation": "Check that the bundle path is valid",
            "retryable": False,
        })
        ctx.exit(1)
