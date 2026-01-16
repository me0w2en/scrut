"""Isolated plugin execution in subprocess.

Runs plugins in separate processes for security and stability.
Supports resource limits and timeout enforcement.
"""

import json
import multiprocessing
import os
import resource
import signal
import sys
import tempfile
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from scrut.plugins.interface import (
    ParserPlugin,
    PluginContext,
    PluginExecutionError,
    PluginRecord,
    PluginResult,
)
from scrut.plugins.loader import PluginLoader
from scrut.plugins.manifest import PluginManifest


def _run_plugin_in_process(
    plugin_name: str,
    context_dict: dict[str, Any],
    manifest_dict: dict[str, Any],
    install_path: str,
    output_file: str,
    max_memory_mb: int,
) -> None:
    """Run plugin in isolated process.

    This function runs in a subprocess and writes results to output_file.
    """
    try:
        if hasattr(resource, "RLIMIT_AS"):
            max_bytes = max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))

        manifest = PluginManifest(**manifest_dict)
        context = PluginContext(
            file_path=Path(context_dict["file_path"]),
            artifact_type=context_dict["artifact_type"],
            options=context_dict.get("options", {}),
            timeout_seconds=context_dict.get("timeout_seconds", 300),
            max_records=context_dict.get("max_records"),
        )

        loader = PluginLoader()
        plugin = loader._load_plugin_class(Path(install_path), manifest)
        plugin.initialize()

        start_time = datetime.now()
        records = []
        errors = []
        warnings = []

        try:
            for record in plugin.parse(context):
                records.append({
                    "timestamp": record.timestamp.isoformat() if record.timestamp else None,
                    "data": record.data,
                    "record_type": record.record_type,
                    "severity": record.severity,
                    "tags": record.tags,
                })

                if context.max_records and len(records) >= context.max_records:
                    warnings.append(f"Record limit reached: {context.max_records}")
                    break

        except Exception as e:
            errors.append(f"Parse error: {e}")
            errors.append(traceback.format_exc())

        finally:
            plugin.cleanup()

        execution_time = int((datetime.now() - start_time).total_seconds() * 1000)

        result = {
            "success": len(errors) == 0,
            "records": records,
            "record_count": len(records),
            "errors": errors,
            "warnings": warnings,
            "metadata": {},
            "execution_time_ms": execution_time,
        }

        with open(output_file, "w") as f:
            json.dump(result, f)

    except Exception as e:
        result = {
            "success": False,
            "records": [],
            "record_count": 0,
            "errors": [str(e), traceback.format_exc()],
            "warnings": [],
            "metadata": {},
            "execution_time_ms": 0,
        }
        with open(output_file, "w") as f:
            json.dump(result, f)


class PluginRunner:
    """Runs plugins in isolated subprocess."""

    def __init__(
        self,
        loader: PluginLoader | None = None,
        sandbox: bool = True,
    ) -> None:
        """Initialize the plugin runner.

        Args:
            loader: PluginLoader instance
            sandbox: Whether to run in sandbox mode
        """
        self._loader = loader or PluginLoader()
        self._sandbox = sandbox

    def run(
        self,
        plugin_name: str,
        context: PluginContext,
    ) -> PluginResult:
        """Run a plugin and return results.

        Args:
            plugin_name: Name of the plugin to run
            context: PluginContext with execution parameters

        Returns:
            PluginResult with records and status

        Raises:
            PluginExecutionError: If execution fails
        """
        installed = self._loader.registry.get(plugin_name)
        if not installed:
            raise PluginExecutionError(plugin_name, "Plugin not installed")

        if not installed.enabled:
            raise PluginExecutionError(plugin_name, "Plugin is disabled")

        manifest = installed.manifest

        if self._sandbox:
            return self._run_sandboxed(plugin_name, context, manifest, installed.install_path)
        else:
            return self._run_direct(plugin_name, context)

    def _run_sandboxed(
        self,
        plugin_name: str,
        context: PluginContext,
        manifest: PluginManifest,
        install_path: str,
    ) -> PluginResult:
        """Run plugin in sandboxed subprocess."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            context_dict = {
                "file_path": str(context.file_path),
                "artifact_type": context.artifact_type,
                "options": context.options,
                "timeout_seconds": context.timeout_seconds,
                "max_records": context.max_records,
            }

            process = multiprocessing.Process(
                target=_run_plugin_in_process,
                args=(
                    plugin_name,
                    context_dict,
                    manifest.model_dump(),
                    install_path,
                    output_file,
                    manifest.max_memory_mb,
                ),
            )

            process.start()
            timeout = min(context.timeout_seconds, manifest.max_execution_seconds)
            process.join(timeout=timeout)

            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
                raise PluginExecutionError(
                    plugin_name, f"Execution timed out after {timeout}s"
                )

            if process.exitcode != 0:
                raise PluginExecutionError(
                    plugin_name, f"Process exited with code {process.exitcode}"
                )

            with open(output_file) as f:
                result_data = json.load(f)

            records = [
                PluginRecord(
                    timestamp=(
                        datetime.fromisoformat(r["timestamp"])
                        if r["timestamp"]
                        else None
                    ),
                    data=r["data"],
                    record_type=r["record_type"],
                    severity=r["severity"],
                    tags=r["tags"],
                )
                for r in result_data["records"]
            ]

            return PluginResult(
                success=result_data["success"],
                records=records,
                record_count=result_data["record_count"],
                errors=result_data["errors"],
                warnings=result_data["warnings"],
                metadata=result_data["metadata"],
                execution_time_ms=result_data["execution_time_ms"],
            )

        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    def _run_direct(
        self,
        plugin_name: str,
        context: PluginContext,
    ) -> PluginResult:
        """Run plugin directly (not sandboxed)."""
        start_time = datetime.now()
        records = []
        errors = []
        warnings = []

        try:
            plugin = self._loader.load(plugin_name)

            for record in plugin.parse(context):
                records.append(record)

                if context.max_records and len(records) >= context.max_records:
                    warnings.append(f"Record limit reached: {context.max_records}")
                    break

        except Exception as e:
            errors.append(str(e))

        execution_time = int((datetime.now() - start_time).total_seconds() * 1000)

        return PluginResult(
            success=len(errors) == 0,
            records=records,
            record_count=len(records),
            errors=errors,
            warnings=warnings,
            execution_time_ms=execution_time,
        )

    def run_batch(
        self,
        plugin_name: str,
        contexts: list[PluginContext],
        max_workers: int = 4,
    ) -> list[PluginResult]:
        """Run plugin on multiple files in parallel.

        Args:
            plugin_name: Name of the plugin to run
            contexts: List of PluginContext for each file
            max_workers: Maximum parallel workers

        Returns:
            List of PluginResult for each context
        """
        results = []

        for context in contexts:
            try:
                result = self.run(plugin_name, context)
                results.append(result)
            except PluginExecutionError as e:
                results.append(
                    PluginResult(
                        success=False,
                        records=[],
                        record_count=0,
                        errors=[str(e)],
                    )
                )

        return results
