<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/parsers-38%20artifacts-orange.svg" alt="38 Parsers">
  <img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="Alpha">
</p>

<h1 align="center">Scrut</h1>

<p align="center">
  <strong>Evidence-first DFIR artifact parser for modern forensic workflows</strong>
</p>

<p align="center">
  Parse Windows forensic images directly &mdash; no mounting, no root, no extra tools.<br>
  38 artifact parsers. Normalized JSON output. Built for analysts and AI agents alike.
</p>

<p align="center">
  <a href="README.ko.md">한국어</a>
</p>

---

## Demo

![demo](https://github.com/user-attachments/assets/d8b06b5f-4df4-4138-90bd-71d452a10c4c)

<details>
<summary>What the demo covers</summary>

1. **Case initialization** &mdash; create a case with analyst metadata
2. **E01 image registration** &mdash; SHA-256 hash auto-computed for a 20GB image
3. **Artifact discovery** &mdash; list 161 EVTX files inside E01 without mounting
4. **Event log parsing** &mdash; parse 20,363 Security.evtx records in 2.4 seconds
5. **Prefetch analysis** &mdash; extract execution history with run counts and timestamps
6. **Human-readable output** &mdash; table format for interactive analysis
7. **JSONL pipeline** &mdash; pipe to `jq` for ad-hoc aggregation
8. **Cache management** &mdash; SQLite-backed parse cache with automatic invalidation

</details>

---

## Features

- **Direct image access** &mdash; read E01, VMDK, and raw images without mounting or root privileges
- **38 artifact parsers** &mdash; EVTX, Prefetch, MFT, Registry, Amcache, ShimCache, USN Journal, and more
- **Normalized JSON output** &mdash; every record follows a consistent schema with `evidence_ref` provenance
- **AI/LLM-native design** &mdash; strict stdout/stderr separation, pagination, structured errors
- **Playbook engine** &mdash; declarative YAML workflows for automated investigations
- **Evidence bundles** &mdash; reproducible, verifiable analysis packages for third-party review
- **Parse caching** &mdash; SHA-256-based SQLite cache with automatic invalidation

---

## Quick Start

```bash
git clone https://github.com/me0w2en/scrut.git
cd scrut
pip install -e ".[dev]"
```

```bash
scrut case init --name "IR-2026-001" --analyst "analyst@example.com"

scrut target add /evidence/disk.E01 --name "Suspect-PC" --format E01

scrut parse evtx --target <TARGET_ID> \
  --artifact "Windows/System32/winevt/Logs/Security.evtx" \
  --limit 100

scrut playbook run ransomware-triage --target <TARGET_ID>

scrut bundle create --output ./bundle --include-results results.jsonl
```

---

## Supported Artifacts

38 parsers across 7 categories:

| Category | Parsers |
|----------|---------|
| **Execution** | `prefetch` `amcache` `shimcache` `bam` `recentapps` `muicache` `syscache` |
| **Event Logs** | `evtx` |
| **Filesystem** | `mft` `usnjrnl` `recyclebin` |
| **User Activity** | `browser` `lnk` `shellbags` `jumplists` `typedurls` `searchhistory` `activitiescache` `thumbcache` |
| **Network** | `networkconfig` `firewall` `rdpcache` |
| **Persistence** | `services` `scheduledtasks` `registry` `wmi` |
| **System** | `srum` `etl` `wer` `notifications` `powershell` `defender` `bits` |

Supported image formats: **E01** (split, zlib), **VMDK**, **Raw/DD**. NTFS and FAT32 filesystems are read directly from the image.

---

## How It Works

### Parse Modes

**Local file** &mdash; parse an artifact file directly:

```bash
scrut parse evtx /evidence/Security.evtx
```

**Image target** &mdash; parse from inside a forensic image without mounting:

```bash
scrut parse evtx --target <TARGET_ID> \
  --artifact "Windows/System32/winevt/Logs/Security.evtx"
```

### Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| JSON | `-f json` (default) | Structured analysis, LLM ingestion |
| JSONL | `-f jsonl` | Streaming pipelines, `jq` integration |
| Human | `-f human` | Interactive terminal review |

### Record Structure

Every parsed record includes full evidence provenance:

```json
{
  "record_id": "evtx:security:4624:12345",
  "schema_version": "v1",
  "record_type": "timeline",
  "timestamp": "2026-01-15T14:32:01Z",
  "data": { "event_id": 4624, "logon_type": 10 },
  "evidence_ref": {
    "target_id": "550e8400-...",
    "artifact_path": "Windows/System32/winevt/Logs/Security.evtx",
    "record_offset": 2048,
    "record_index": 42,
    "parser_name": "evtx",
    "parser_version": "0.2.0",
    "source_hash": "a1b2c3d4..."
  }
}
```

### Pagination

Control output volume with `--limit`, `--cursor`, `--since`, and `--until`:

```bash
scrut parse evtx /file.evtx --limit 100
scrut parse evtx /file.evtx --limit 100 --cursor "abc123..."
scrut parse evtx /file.evtx --since "24h" --until "12h"
scrut parse evtx /file.evtx --summary
```

---

## AI/LLM-Native Design

Scrut is architected from the ground up for AI agent integration, not retrofitted with wrappers.

| Principle | Implementation | Benefit |
|-----------|----------------|---------|
| Stream discipline | stdout = JSON results, stderr = logs | Safe machine parsing |
| Pagination | `--limit`, `--cursor`, `--since` | Token budget control |
| Evidence provenance | `evidence_ref` on every record | Traceable AI conclusions |
| Deterministic output | Sorted records, normalized timestamps | Reproducible analysis |
| Structured errors | `code`, `remediation`, `retryable` | Autonomous error recovery |
| Schema versioning | `schema_version: "v1"` | Backward compatibility |
| Metrics | stderr JSON metrics | Performance monitoring |
| Parse caching | SHA-256-based SQLite cache | Efficient repeated queries |
| Evidence bundles | Commands + hashes + environment | Third-party verification |

```json
{
  "code": "TARGET_NOT_FOUND",
  "message": "Target with ID abc123 not found",
  "remediation": "Run 'scrut target list' to see available targets",
  "retryable": false
}
```

---

## Workflows

### Rapid Triage

```bash
scrut case init --name "IR-2026-001" --analyst "analyst@example.com"
scrut target add /evidence/disk.E01 --name "Suspect-PC"
scrut playbook run ransomware-triage --target <TARGET_ID> | tee results.jsonl
scrut bundle create --output ./bundle --include-results results.jsonl
```

### Built-in Playbooks

| Playbook | Description |
|----------|-------------|
| `ransomware-triage` | Ransomware indicator detection |
| `persistence-hunt` | Persistence mechanism discovery |
| `lateral-movement` | Lateral movement artifact analysis |

```bash
scrut playbook list
scrut playbook explain ransomware-triage --target <TARGET_ID>
scrut playbook run ransomware-triage --target <TARGET_ID> --var "since=2026-01-01"
```

### Collection Scopes

Collect artifacts from images with predefined or custom scopes:

| Scope | Duration | Coverage |
|-------|----------|----------|
| `minimal` | < 5 min | Event logs, Prefetch, Registry hives, MFT, ShimCache |
| `standard` | < 30 min | + Browser history, Jump Lists, ShellBags, Services, Scheduled Tasks |
| `comprehensive` | > 1 hr | All 38 artifact types |
| `custom` | varies | User-defined |

```bash
scrut collect run --target <TARGET_ID> --scope standard
scrut collect list --target <TARGET_ID> --scope standard  # dry-run preview
```

### Evidence Bundles

Package analysis results into reproducible, verifiable bundles:

```bash
scrut bundle create --output /evidence/bundle --include-results results.jsonl
scrut bundle verify /path/to/bundle
scrut bundle replay /path/to/bundle --dry-run
```

---

## Installation

```bash
git clone https://github.com/me0w2en/scrut.git
cd scrut
pip install -e ".[dev]"
```

---

## CLI Reference

```
scrut
├── case init / info / activate / archive
├── target add / list / info
├── parse <type> [path] [--target --artifact --limit --since --until --cursor --summary]
│   ├── types                  # list supported parsers
│   └── list-artifacts         # discover artifacts inside an image
├── collect run / list / scopes
├── cache stats / clear / cleanup
├── bundle create / verify / info / replay
└── playbook run / list / explain / runs / cancel
```

### Global Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `jsonl`, `human` |
| `--timezone` | `-tz` | `UTC` | IANA timezone for timestamps |
| `--verbose` | `-v` | &mdash; | Enable verbose logging (stderr) |
| `--quiet` | `-q` | &mdash; | Suppress progress messages |
| `--case-path` | `-C` | `.` | Case directory path |

---

## License

[MIT](LICENSE) &copy; 2026 me0w2en
