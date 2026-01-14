<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

<h1 align="center">Scrut</h1>

<p align="center">
  <strong>Evidence-first DFIR artifact parser for modern forensic workflows</strong>
</p>

<p align="center">
  Parse Windows forensic images. Extract timeline artifacts. Output structured JSON.<br>
  Built for analysts who want fast, scriptable, and reproducible forensic triage.
</p>

---

## Quick Start

```bash
# Install
pip install scrut

# Initialize a case
scrut case init --name "<case_name>" --analyst "<email@example.com>"

# Add forensic image as target
scrut target add <file_path> --name "<image_name>"

# Parse all artifacts
scrut parse --target <image_name>

# Parse specific artifacts only
scrut parse --target <image_name> --artifact evtx,prefetch,amcache

# Output to file
scrut parse --target <image_name> --output timeline.jsonl
```

## Supported Artifacts

| Category | Artifacts |
|----------|-----------|
| **Execution** | Prefetch, Amcache, ShimCache, BAM/DAM, RecentApps, MUICache |
| **Event Logs** | EVTX (Security, System, Application, PowerShell, etc.) |
| **File System** | MFT, USNJrnl, Recycle Bin, Shellbags |
| **User Activity** | Browser History (Chrome/Edge/Firefox), JumpLists, LNK files, TypedURLs |
| **Network** | Network Profiles, Firewall Logs, RDP Cache |
| **Persistence** | Services, Scheduled Tasks, Registry Run Keys |
| **System** | SRUM, WMI, Windows Error Reports, Defender Logs |
| **Other** | Notifications, Thumbcache, Search History, ETL Traces |


## Output Example

```json
{"record_id": "...", "record_type": "timeline", "timestamp": "2026-01-10T14:32:01Z", "data": {"event_id": 4624, ...}}
```

## Installation

```bash
git clone https://github.com/me0w2en/scrut.git
cd scrut
pip install -e .
```
