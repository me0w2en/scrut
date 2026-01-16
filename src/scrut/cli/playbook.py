"""CLI commands for playbook execution.

Provides commands to list, explain, and run playbooks for automated
forensic investigations.
"""

from pathlib import Path
from uuid import UUID

import click

from scrut.cli.output import OutputFormatter
from scrut.core.errors import ScrutError
from scrut.core.target import TargetManager
from scrut.models.playbook import PlaybookRunStatus
from scrut.playbook.executor import PlaybookExecutor
from scrut.playbook.loader import PlaybookLoader, PlaybookNotFoundError
from scrut.playbook.state import PlaybookStateManager


@click.group()
def playbook() -> None:
    """Execute playbook-driven investigations.

    Playbooks define reusable sequences of forensic analysis steps
    that can be run against evidence targets.
    """
    pass


@playbook.command("list")
@click.option(
    "--path",
    "-p",
    "playbook_path",
    type=click.Path(exists=True, path_type=Path),
    help="Additional playbook directory to search",
)
@click.pass_context
def list_playbooks(ctx: click.Context, playbook_path: Path | None) -> None:
    """List available playbooks."""
    formatter: OutputFormatter = ctx.obj["formatter"]

    paths = [playbook_path] if playbook_path else None
    loader = PlaybookLoader(playbook_paths=paths)
    playbooks = loader.list_playbooks()

    if not playbooks:
        click.echo("No playbooks found.", err=True)
        ctx.exit(0)

    for pb in playbooks:
        formatter.output(pb)

    if formatter.is_human():
        formatter.flush_table(title="Available Playbooks")


@playbook.command("explain")
@click.argument("playbook_name")
@click.option(
    "--target",
    "-t",
    "target_id",
    required=True,
    help="Target UUID to analyze",
)
@click.option(
    "--path",
    "-p",
    "playbook_path",
    type=click.Path(exists=True, path_type=Path),
    help="Additional playbook directory to search",
)
@click.option(
    "--var",
    "-v",
    "variables",
    multiple=True,
    help="Variable override in KEY=VALUE format",
)
@click.pass_context
def explain_playbook(
    ctx: click.Context,
    playbook_name: str,
    target_id: str,
    playbook_path: Path | None,
    variables: tuple[str, ...],
) -> None:
    """Show execution plan for a playbook (dry-run).

    Displays what steps would be executed, their order, and estimated
    duration without actually running anything.
    """
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        target_uuid = UUID(target_id)
    except ValueError:
        formatter.error({
            "code": "INVALID_TARGET_ID",
            "message": f"Invalid target ID: {target_id}",
            "remediation": "Provide a valid UUID for the target",
        })
        ctx.exit(1)

    var_dict = {}
    for var in variables:
        if "=" in var:
            key, value = var.split("=", 1)
            var_dict[key] = value

    try:
        paths = [playbook_path] if playbook_path else None
        loader = PlaybookLoader(playbook_paths=paths)
        pb = loader.load(playbook_name, variables=var_dict)

        executor = PlaybookExecutor(
            playbook=pb,
            target_id=target_uuid,
            case_path=case_path,
            variables=var_dict,
        )
        result = executor.explain()

        formatter.output(result.model_dump(mode="json", exclude_none=True))

        if formatter.is_human():
            click.echo(f"\nPlaybook: {result.playbook_name} v{result.playbook_version}", err=True)
            click.echo(f"Target: {result.target_id}", err=True)
            click.echo(f"Steps: {result.total_steps}", err=True)
            if result.estimated_duration_seconds:
                click.echo(f"Estimated duration: {result.estimated_duration_seconds}s", err=True)
            if result.warnings:
                click.echo("\nWarnings:", err=True)
                for warning in result.warnings:
                    click.echo(f"  - {warning}", err=True)
            click.echo("\nExecution plan:", err=True)
            for i, step in enumerate(result.steps, 1):
                click.echo(f"  {i}. [{step['step_id']}] {step['name']}", err=True)
                click.echo(f"     Command: {step['command']}", err=True)

    except PlaybookNotFoundError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)


@playbook.command("run")
@click.argument("playbook_name")
@click.option(
    "--target",
    "-t",
    "target_id",
    required=True,
    help="Target UUID to analyze",
)
@click.option(
    "--path",
    "-p",
    "playbook_path",
    type=click.Path(exists=True, path_type=Path),
    help="Additional playbook directory to search",
)
@click.option(
    "--var",
    "-v",
    "variables",
    multiple=True,
    help="Variable override in KEY=VALUE format",
)
@click.option(
    "--resume",
    "resume_id",
    type=str,
    help="Resume a paused run by its ID",
)
@click.option(
    "--step",
    "step_filter",
    type=str,
    help="Run only a specific step by ID",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Simulate execution without running commands",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    help="Directory for step outputs",
)
@click.pass_context
def run_playbook(
    ctx: click.Context,
    playbook_name: str,
    target_id: str,
    playbook_path: Path | None,
    variables: tuple[str, ...],
    resume_id: str | None,
    step_filter: str | None,
    dry_run: bool,
    output_dir: Path | None,
) -> None:
    """Execute a playbook against a target.

    Runs each step in the playbook sequentially, reporting progress
    to stderr and outputting results to stdout.
    """
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    try:
        target_uuid = UUID(target_id)
    except ValueError:
        formatter.error({
            "code": "INVALID_TARGET_ID",
            "message": f"Invalid target ID: {target_id}",
            "remediation": "Provide a valid UUID for the target",
        })
        ctx.exit(1)

    var_dict = {}
    for var in variables:
        if "=" in var:
            key, value = var.split("=", 1)
            var_dict[key] = value

    state_manager = PlaybookStateManager(case_path)

    resume_run = None
    if resume_id:
        resume_run = state_manager.load_state(resume_id)
        if not resume_run:
            formatter.error({
                "code": "RUN_NOT_FOUND",
                "message": f"Run '{resume_id}' not found",
                "remediation": "Use 'scrut playbook runs' to list available runs",
            })
            ctx.exit(1)

    try:
        paths = [playbook_path] if playbook_path else None
        loader = PlaybookLoader(playbook_paths=paths)
        pb = loader.load(playbook_name, variables=var_dict)

        if dry_run:
            click.echo(f"[DRY RUN] Simulating playbook: {pb.name}", err=True)

        executor = PlaybookExecutor(
            playbook=pb,
            target_id=target_uuid,
            case_path=case_path,
            output_dir=output_dir,
            variables=var_dict,
        )

        success_count = 0
        fail_count = 0
        skip_count = 0

        for step, result in executor.execute(
            resume_run=resume_run,
            step_filter=step_filter,
            dry_run=dry_run,
        ):
            step_output = {
                "step_id": step.step_id,
                "step_name": step.name,
                "status": result.status,
                "duration_ms": result.duration_ms,
                "records_processed": result.records_processed,
            }
            if result.output_file:
                step_output["output_file"] = result.output_file
            if result.error_message:
                step_output["error_message"] = result.error_message

            formatter.output(step_output)

            if result.status == "success":
                success_count += 1
            elif result.status == "failed":
                fail_count += 1
            else:
                skip_count += 1

        run = executor.get_run()
        if run:
            state_manager.save_state(run)

            click.echo("", err=True)
            click.echo(f"Playbook '{pb.name}' completed", err=True)
            click.echo(f"  Status: {run.status.value}", err=True)
            click.echo(f"  Steps: {success_count} success, {fail_count} failed, {skip_count} skipped", err=True)
            if run.duration_ms:
                click.echo(f"  Duration: {run.duration_ms}ms", err=True)
            click.echo(f"  Run ID: {run.run_id}", err=True)

            if run.status == PlaybookRunStatus.FAILED:
                ctx.exit(1)

    except PlaybookNotFoundError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except ScrutError as e:
        formatter.error(e.to_structured_error())
        ctx.exit(1)
    except KeyboardInterrupt:
        click.echo("\nInterrupted. Saving state...", err=True)
        run = executor.pause()
        if run:
            state_manager.save_state(run)
            click.echo(f"Run paused. Resume with: scrut playbook run {playbook_name} --resume {run.run_id}", err=True)
        ctx.exit(130)


@playbook.command("runs")
@click.option(
    "--status",
    "-s",
    type=click.Choice(["pending", "running", "paused", "completed", "failed", "cancelled"]),
    help="Filter by status",
)
@click.option(
    "--playbook",
    "-p",
    "playbook_id",
    help="Filter by playbook ID",
)
@click.pass_context
def list_runs(
    ctx: click.Context,
    status: str | None,
    playbook_id: str | None,
) -> None:
    """List playbook runs."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    state_manager = PlaybookStateManager(case_path)
    runs = state_manager.list_runs(status=status, playbook_id=playbook_id)

    if not runs:
        click.echo("No runs found.", err=True)
        ctx.exit(0)

    for run in runs:
        run_data = {
            "run_id": str(run.run_id),
            "playbook_id": run.playbook_id,
            "playbook_version": run.playbook_version,
            "target_id": str(run.target_id),
            "status": run.status.value,
            "completed_steps": len(run.completed_steps),
            "total_steps": len(run.step_results) + len(run.completed_steps),
        }
        if run.started_at:
            run_data["started_at"] = run.started_at.isoformat()
        if run.duration_ms:
            run_data["duration_ms"] = run.duration_ms

        formatter.output(run_data)

    if formatter.is_human():
        formatter.flush_table(title="Playbook Runs")


@playbook.command("cancel")
@click.argument("run_id")
@click.pass_context
def cancel_run(ctx: click.Context, run_id: str) -> None:
    """Cancel a paused or running playbook run."""
    formatter: OutputFormatter = ctx.obj["formatter"]
    case_path = Path(ctx.obj.get("case_path", "."))

    state_manager = PlaybookStateManager(case_path)
    run = state_manager.load_state(run_id)

    if not run:
        formatter.error({
            "code": "RUN_NOT_FOUND",
            "message": f"Run '{run_id}' not found",
            "remediation": "Use 'scrut playbook runs' to list available runs",
        })
        ctx.exit(1)

    if run.is_complete:
        formatter.error({
            "code": "RUN_ALREADY_COMPLETE",
            "message": f"Run '{run_id}' is already {run.status.value}",
            "remediation": "Cannot cancel a completed run",
        })
        ctx.exit(1)

    run.status = PlaybookRunStatus.CANCELLED
    state_manager.save_state(run)

    formatter.output({
        "run_id": str(run.run_id),
        "status": "cancelled",
        "message": "Run cancelled successfully",
    })

    click.echo(f"Run {run_id} cancelled.", err=True)
