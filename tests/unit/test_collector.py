"""Unit tests for WindowsCollector with filesystem and scope support."""

from collections.abc import Iterator
from pathlib import Path

from scrut.collectors.scope import (
    ArtifactCategory,
    PredefinedScope,
    ScopeBuilder,
)
from scrut.collectors.windows import (
    WINDOWS_ARTIFACTS,
    WindowsArtifactType,
    WindowsCollector,
)
from scrut.images.filesystem.base import FileInfo


class FakeFilesystemReader:
    """Fake FilesystemReader for testing image-based collection."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    def exists(self, path: str) -> bool:
        if path in ("", "."):
            return True
        if path in self._files:
            return True
        prefix = path.rstrip("/") + "/"
        return any(f.startswith(prefix) or f == path for f in self._files)

    def is_file(self, path: str) -> bool:
        return path in self._files

    def is_directory(self, path: str) -> bool:
        if path in ("", "."):
            return True
        if path in self._files:
            return False
        prefix = path.rstrip("/") + "/"
        return any(f.startswith(prefix) for f in self._files)

    def get_file_info(self, path: str) -> FileInfo:
        if path not in self._files:
            raise FileNotFoundError(path)
        data = self._files[path]
        name = path.rsplit("/", 1)[-1] if "/" in path else path
        return FileInfo(
            name=name,
            path=path,
            size=len(data),
            is_directory=False,
            is_file=True,
        )

    def read_file(self, path: str) -> bytes:
        if path not in self._files:
            raise FileNotFoundError(path)
        return self._files[path]

    def list_dir(self, path: str) -> Iterator[str]:
        prefix = path.rstrip("/") + "/" if path else ""
        seen = set()
        for f in self._files:
            if f.startswith(prefix):
                rest = f[len(prefix):]
                entry = rest.split("/")[0]
                if entry and entry not in seen:
                    seen.add(entry)
                    yield entry

    def walk(self, path: str = "") -> Iterator[tuple[str, list[str], list[str]]]:
        dirs_at: dict[str, tuple[set[str], set[str]]] = {}
        prefix = path.rstrip("/") + "/" if path else ""

        for f in self._files:
            if prefix and not f.startswith(prefix):
                continue
            rel = f[len(prefix):] if prefix else f
            parts = rel.split("/")
            current = path
            for _i, part in enumerate(parts[:-1]):
                parent = current
                current = f"{parent}/{part}" if parent else part
                if parent not in dirs_at:
                    dirs_at[parent] = (set(), set())
                dirs_at[parent][0].add(part)
            file_dir = "/".join([path] + parts[:-1]) if parts[:-1] else path
            if prefix and not path:
                file_dir = "/".join(parts[:-1])
            if file_dir not in dirs_at:
                dirs_at[file_dir] = (set(), set())
            dirs_at[file_dir][1].add(parts[-1])

        queue = [path]
        visited = set()
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            subdirs, files = dirs_at.get(current, (set(), set()))
            yield current, sorted(subdirs), sorted(files)
            for d in sorted(subdirs):
                child = f"{current}/{d}" if current else d
                queue.append(child)

    def find_files(self, pattern: str, path: str = "") -> Iterator[str]:
        import fnmatch

        for dirpath, _dirnames, filenames in self.walk(path):
            for filename in filenames:
                if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                    if dirpath:
                        yield f"{dirpath}/{filename}"
                    else:
                        yield filename



class TestWindowsCollectorLocal:
    def test_collect_single_file(self, tmp_path: Path) -> None:
        system_root = tmp_path / "system"
        system_root.mkdir()
        evtx_dir = system_root / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        (evtx_dir / "Security.evtx").write_bytes(b"fake evtx data")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("evtx_security").build()
        collector = WindowsCollector(
            system_root=system_root, output_dir=output_dir, scope=scope
        )
        result = collector.collect()

        assert result.total_files == 1
        assert result.collected_files[0].artifact_type == "evtx_security"
        assert result.collected_files[0].size_bytes == 14

    def test_collect_glob_pattern(self, tmp_path: Path) -> None:
        system_root = tmp_path / "system"
        system_root.mkdir()
        prefetch_dir = system_root / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        (prefetch_dir / "CMD.EXE-1234.pf").write_bytes(b"pf1")
        (prefetch_dir / "NOTEPAD.EXE-5678.pf").write_bytes(b"pf2")
        (prefetch_dir / "notaprefetch.txt").write_bytes(b"txt")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("prefetch").build()
        collector = WindowsCollector(
            system_root=system_root, output_dir=output_dir, scope=scope
        )
        result = collector.collect()

        assert result.total_files == 2
        names = {f.source_path.split("/")[-1] for f in result.collected_files}
        assert names == {"CMD.EXE-1234.pf", "NOTEPAD.EXE-5678.pf"}

    def test_scope_filters_artifacts(self, tmp_path: Path) -> None:
        system_root = tmp_path / "system"
        system_root.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = (
            ScopeBuilder("test")
            .categories(ArtifactCategory.EXECUTION)
            .artifact_types("prefetch")
            .build()
        )
        collector = WindowsCollector(
            system_root=system_root, output_dir=output_dir, scope=scope
        )
        artifacts = collector.get_artifacts()

        types = {a.artifact_type for a in artifacts}
        assert WindowsArtifactType.PREFETCH in types
        assert WindowsArtifactType.EVTX_SECURITY not in types

    def test_file_size_limit(self, tmp_path: Path) -> None:
        system_root = tmp_path / "system"
        system_root.mkdir()
        evtx_dir = system_root / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        (evtx_dir / "Security.evtx").write_bytes(b"x" * (2 * 1024 * 1024))

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = (
            ScopeBuilder("test")
            .artifact_types("evtx_security")
            .max_file_size(1)
            .build()
        )
        collector = WindowsCollector(
            system_root=system_root, output_dir=output_dir, scope=scope
        )
        result = collector.collect()

        assert result.total_files == 0
        assert any("exceeds size limit" in s for s in result.skipped)

    def test_missing_file_is_skipped(self, tmp_path: Path) -> None:
        system_root = tmp_path / "system"
        system_root.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("evtx_security").build()
        collector = WindowsCollector(
            system_root=system_root, output_dir=output_dir, scope=scope
        )
        result = collector.collect()

        assert result.total_files == 0
        assert any("not found" in s for s in result.skipped)



class TestWindowsCollectorImage:
    def test_collect_single_file_from_image(self, tmp_path: Path) -> None:
        fs = FakeFilesystemReader(
            {
                "Windows/System32/winevt/Logs/Security.evtx": b"fake evtx data",
            }
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("evtx_security").build()
        collector = WindowsCollector(
            system_root=Path("/fake"),
            output_dir=output_dir,
            scope=scope,
            filesystem=fs,
        )
        result = collector.collect()

        assert result.total_files == 1
        assert result.collected_files[0].artifact_type == "evtx_security"
        assert result.collected_files[0].size_bytes == 14
        extracted = Path(result.collected_files[0].dest_path)
        assert extracted.exists()
        assert extracted.read_bytes() == b"fake evtx data"

    def test_collect_directory_artifact_from_image(self, tmp_path: Path) -> None:
        fs = FakeFilesystemReader(
            {
                "Windows/Prefetch/CMD.EXE-1234.pf": b"pf1",
                "Windows/Prefetch/NOTEPAD.EXE-5678.pf": b"pf2",
                "Windows/Prefetch/other.txt": b"other",
            }
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("prefetch").build()
        collector = WindowsCollector(
            system_root=Path("/fake"),
            output_dir=output_dir,
            scope=scope,
            filesystem=fs,
        )
        result = collector.collect()

        assert result.total_files == 2
        names = {Path(f.dest_path).name for f in result.collected_files}
        assert names == {"CMD.EXE-1234.pf", "NOTEPAD.EXE-5678.pf"}

    def test_missing_file_in_image_is_skipped(self, tmp_path: Path) -> None:
        fs = FakeFilesystemReader({})
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("evtx_security").build()
        collector = WindowsCollector(
            system_root=Path("/fake"),
            output_dir=output_dir,
            scope=scope,
            filesystem=fs,
        )
        result = collector.collect()

        assert result.total_files == 0
        assert any("not found in image" in s for s in result.skipped)

    def test_file_size_limit_in_image(self, tmp_path: Path) -> None:
        fs = FakeFilesystemReader(
            {
                "Windows/System32/winevt/Logs/Security.evtx": b"x" * (2 * 1024 * 1024),
            }
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = (
            ScopeBuilder("test")
            .artifact_types("evtx_security")
            .max_file_size(1)
            .build()
        )
        collector = WindowsCollector(
            system_root=Path("/fake"),
            output_dir=output_dir,
            scope=scope,
            filesystem=fs,
        )
        result = collector.collect()

        assert result.total_files == 0
        assert any("exceeds size limit" in s for s in result.skipped)

    def test_hash_integrity(self, tmp_path: Path) -> None:
        import hashlib

        data = b"test file contents"
        fs = FakeFilesystemReader(
            {"Windows/System32/winevt/Logs/Security.evtx": data}
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        scope = ScopeBuilder("test").artifact_types("evtx_security").build()
        collector = WindowsCollector(
            system_root=Path("/fake"),
            output_dir=output_dir,
            scope=scope,
            filesystem=fs,
        )
        result = collector.collect()

        assert result.total_files == 1
        assert result.collected_files[0].md5 == hashlib.md5(data).hexdigest()
        assert result.collected_files[0].sha256 == hashlib.sha256(data).hexdigest()



class TestScopeFiltering:
    def test_predefined_minimal_scope(self) -> None:
        scope = ScopeBuilder.from_predefined(PredefinedScope.MINIMAL).build()
        collector = WindowsCollector(
            system_root=Path("."), output_dir=Path("."), scope=scope
        )
        artifacts = collector.get_artifacts()

        types = {a.artifact_type.value for a in artifacts}
        assert "evtx_security" in types
        assert "prefetch" in types

    def test_predefined_malware_scope(self) -> None:
        scope = ScopeBuilder.from_predefined(PredefinedScope.MALWARE).build()
        collector = WindowsCollector(
            system_root=Path("."), output_dir=Path("."), scope=scope
        )
        artifacts = collector.get_artifacts()

        types = {a.artifact_type.value for a in artifacts}
        assert "prefetch" in types
        assert "amcache" in types
        assert "evtx_powershell" in types

    def test_no_scope_returns_all(self) -> None:
        collector = WindowsCollector(
            system_root=Path("."), output_dir=Path(".")
        )
        artifacts = collector.get_artifacts()

        assert len(artifacts) == len(WINDOWS_ARTIFACTS)

    def test_comprehensive_scope_returns_all(self) -> None:
        scope = ScopeBuilder.from_predefined(PredefinedScope.COMPREHENSIVE).build()
        collector = WindowsCollector(
            system_root=Path("."), output_dir=Path("."), scope=scope
        )
        artifacts = collector.get_artifacts()

        assert len(artifacts) == len(WINDOWS_ARTIFACTS)

    def test_iter_artifacts(self) -> None:
        scope = ScopeBuilder.from_predefined(PredefinedScope.MINIMAL).build()
        collector = WindowsCollector(
            system_root=Path("."), output_dir=Path("."), scope=scope
        )
        artifact_list = list(collector.iter_artifacts())

        assert len(artifact_list) == len(collector.get_artifacts())

    def test_collect_specific_artifact_type(self, tmp_path: Path) -> None:
        system_root = tmp_path / "system"
        system_root.mkdir()
        evtx_dir = system_root / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        (evtx_dir / "Security.evtx").write_bytes(b"data")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        collector = WindowsCollector(
            system_root=system_root, output_dir=output_dir
        )
        files = collector.collect_artifact(WindowsArtifactType.EVTX_SECURITY)

        assert len(files) == 1
        assert files[0].artifact_type == "evtx_security"
