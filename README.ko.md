<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/parsers-38%20artifacts-orange.svg" alt="38 Parsers">
  <img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="Alpha">
</p>

<h1 align="center">Scrut</h1>

<p align="center">
  <strong>증거 중심의 DFIR 아티팩트 파서</strong>
</p>

<p align="center">
  Windows 포렌식 이미지를 직접 파싱 &mdash; 마운트 불필요, 루트 권한 불필요, 별도 도구 불필요.<br>
  38종 아티팩트 파서. 정규화된 JSON 출력. 분석가와 AI 에이전트 모두를 위한 설계.
</p>

<p align="center">
  <a href="README.md">English</a>
</p>

---

## 데모

![demo](https://github.com/user-attachments/assets/d8b06b5f-4df4-4138-90bd-71d452a10c4c)

<details>
<summary>데모 내용</summary>

1. **케이스 초기화** &mdash; 분석가 메타데이터로 케이스 생성
2. **E01 이미지 등록** &mdash; 20GB 이미지의 SHA-256 해시 자동 계산
3. **아티팩트 탐색** &mdash; 마운트 없이 E01 내부 161개 EVTX 파일 목록 확인
4. **이벤트 로그 파싱** &mdash; Security.evtx 20,363건을 2.4초에 파싱
5. **Prefetch 분석** &mdash; 실행 횟수, 타임스탬프 등 실행 이력 추출
6. **Human-readable 출력** &mdash; 대화형 분석을 위한 테이블 형식
7. **JSONL 파이프라인** &mdash; `jq`로 파이프하여 즉석 집계
8. **캐시 관리** &mdash; 자동 무효화를 지원하는 SQLite 기반 파싱 캐시

</details>

---

## 주요 기능

- **이미지 직접 접근** &mdash; E01, VMDK, Raw 이미지를 마운트나 루트 권한 없이 읽기
- **38종 아티팩트 파서** &mdash; EVTX, Prefetch, MFT, Registry, Amcache, ShimCache, USN Journal 등
- **정규화된 JSON 출력** &mdash; 모든 레코드에 `evidence_ref` 증거 출처 포함
- **AI/LLM 네이티브 설계** &mdash; stdout/stderr 분리, 페이지네이션, 구조화된 에러
- **플레이북 엔진** &mdash; 선언적 YAML 워크플로우로 자동화된 조사
- **증거 번들** &mdash; 제3자 검증이 가능한 재현 가능 분석 패키지
- **파싱 캐시** &mdash; SHA-256 기반 SQLite 캐시, 자동 무효화

---

## 빠른 시작

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

## 지원 아티팩트

7개 카테고리, 38종 파서:

| 카테고리 | 파서 |
|----------|------|
| **실행 흔적** | `prefetch` `amcache` `shimcache` `bam` `recentapps` `muicache` `syscache` |
| **이벤트 로그** | `evtx` |
| **파일시스템** | `mft` `usnjrnl` `recyclebin` |
| **사용자 활동** | `browser` `lnk` `shellbags` `jumplists` `typedurls` `searchhistory` `activitiescache` `thumbcache` |
| **네트워크** | `networkconfig` `firewall` `rdpcache` |
| **지속성** | `services` `scheduledtasks` `registry` `wmi` |
| **시스템** | `srum` `etl` `wer` `notifications` `powershell` `defender` `bits` |

지원 이미지 형식: **E01** (분할, zlib 압축), **VMDK**, **Raw/DD**. 이미지 내 NTFS, FAT32 파일시스템을 직접 읽습니다.

---

## 동작 방식

### 파싱 모드

**로컬 파일** &mdash; 아티팩트 파일을 직접 파싱:

```bash
scrut parse evtx /evidence/Security.evtx
```

**이미지 타겟** &mdash; 포렌식 이미지 내부에서 마운트 없이 파싱:

```bash
scrut parse evtx --target <TARGET_ID> \
  --artifact "Windows/System32/winevt/Logs/Security.evtx"
```

### 출력 형식

| 형식 | 플래그 | 용도 |
|------|--------|------|
| JSON | `-f json` (기본) | 구조화된 분석, LLM 입력 |
| JSONL | `-f jsonl` | 스트리밍 파이프라인, `jq` 연계 |
| Human | `-f human` | 대화형 터미널 리뷰 |

### 레코드 구조

모든 파싱 레코드에 증거 출처 정보가 포함됩니다:

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

### 페이지네이션

`--limit`, `--cursor`, `--since`, `--until`로 출력량을 제어합니다:

```bash
scrut parse evtx /file.evtx --limit 100
scrut parse evtx /file.evtx --limit 100 --cursor "abc123..."
scrut parse evtx /file.evtx --since "24h" --until "12h"
scrut parse evtx /file.evtx --summary
```

---

## AI/LLM 네이티브 설계

Scrut는 기존 도구를 래핑한 것이 아니라, 처음부터 AI 에이전트 통합을 전제로 설계되었습니다.

| 원칙 | 구현 | 이점 |
|------|------|------|
| 스트림 분리 | stdout = JSON 결과, stderr = 로그 | 안전한 머신 파싱 |
| 페이지네이션 | `--limit`, `--cursor`, `--since` | 토큰 예산 제어 |
| 증거 추적 | 모든 레코드에 `evidence_ref` | AI 분석 결과 역추적 |
| 결정적 출력 | 정렬된 레코드, 정규화된 타임스탬프 | 재현 가능한 분석 |
| 구조화된 에러 | `code`, `remediation`, `retryable` | 자율적 에러 복구 |
| 스키마 버전 | `schema_version: "v1"` | 하위호환 보장 |
| 메트릭스 | stderr JSON 메트릭스 | 성능 모니터링 |
| 파싱 캐시 | SHA-256 기반 SQLite 캐시 | 반복 쿼리 최적화 |
| 증거 번들 | 명령어 + 해시 + 환경 패키징 | 제3자 검증 |

```json
{
  "code": "TARGET_NOT_FOUND",
  "message": "Target with ID abc123 not found",
  "remediation": "Run 'scrut target list' to see available targets",
  "retryable": false
}
```

---

## 워크플로우

### 빠른 트리아지

```bash
scrut case init --name "IR-2026-001" --analyst "analyst@example.com"
scrut target add /evidence/disk.E01 --name "Suspect-PC"
scrut playbook run ransomware-triage --target <TARGET_ID> | tee results.jsonl
scrut bundle create --output ./bundle --include-results results.jsonl
```

### 기본 제공 플레이북

| 플레이북 | 설명 |
|----------|------|
| `ransomware-triage` | 랜섬웨어 지표 탐지 |
| `persistence-hunt` | 지속성 메커니즘 탐색 |
| `lateral-movement` | 횡적 이동 아티팩트 분석 |

```bash
scrut playbook list
scrut playbook explain ransomware-triage --target <TARGET_ID>
scrut playbook run ransomware-triage --target <TARGET_ID> --var "since=2026-01-01"
```

### 수집 범위

사전 정의된 범위 또는 사용자 정의 범위로 이미지에서 아티팩트를 수집합니다:

| 범위 | 소요 시간 | 수집 내용 |
|------|-----------|-----------|
| `minimal` | < 5분 | 이벤트 로그, Prefetch, 레지스트리 하이브, MFT, ShimCache |
| `standard` | < 30분 | + 브라우저 히스토리, Jump Lists, ShellBags, 서비스, 예약 작업 |
| `comprehensive` | > 1시간 | 전체 38종 아티팩트 |
| `custom` | 가변 | 사용자 정의 |

```bash
scrut collect run --target <TARGET_ID> --scope standard
scrut collect list --target <TARGET_ID> --scope standard  # dry-run 미리보기
```

### 증거 번들

분석 결과를 재현 가능하고 검증 가능한 번들로 패키징합니다:

```bash
scrut bundle create --output /evidence/bundle --include-results results.jsonl
scrut bundle verify /path/to/bundle
scrut bundle replay /path/to/bundle --dry-run
```

---

## 설치

```bash
git clone https://github.com/me0w2en/scrut.git
cd scrut
pip install -e ".[dev]"
```

---

## CLI 레퍼런스

```
scrut
├── case init / info / activate / archive
├── target add / list / info
├── parse <type> [path] [--target --artifact --limit --since --until --cursor --summary]
│   ├── types                  # 지원 파서 목록
│   └── list-artifacts         # 이미지 내 아티팩트 탐색
├── collect run / list / scopes
├── cache stats / clear / cleanup
├── bundle create / verify / info / replay
└── playbook run / list / explain / runs / cancel
```

### 글로벌 옵션

| 옵션 | 단축 | 기본값 | 설명 |
|------|------|--------|------|
| `--format` | `-f` | `json` | 출력 형식: `json`, `jsonl`, `human` |
| `--timezone` | `-tz` | `UTC` | 타임스탬프에 사용할 IANA 타임존 |
| `--verbose` | `-v` | &mdash; | 상세 로그 활성화 (stderr) |
| `--quiet` | `-q` | &mdash; | 진행 메시지 비활성화 |
| `--case-path` | `-C` | `.` | 케이스 디렉토리 경로 |

---

## 라이선스

[MIT](LICENSE) &copy; 2026 me0w2en
