# CAT - Cyber Activity Tracker

CAT 0.2.0은 Windows EVTX/XML 로그를 로컬에서 분석하고, LM Studio의 OpenAI 호환 API로 Qwen3.6-35B-A3B 조사 보고서를 생성하는 웹 애플리케이션입니다. 규칙 기반 보고서는 LLM 연결 없이도 동작합니다.

## 독립망 배포 범위

CAT 운영 릴리스에는 애플리케이션 소스, 정적 UI, 오프라인 Python wheel, 설치/실행 스크립트와 smoke test만 들어갑니다. 다음 항목은 포함되지 않으므로 독립망 반입 전에 별도로 준비해야 합니다.

- Python 3.9 이상 Windows x64 전체 오프라인 설치본(`venv`, `ensurepip` 포함)
- Windows PowerShell 5.1 이상
- LM Studio 0.4.8 이상 설치본
- 선택한 GPU/CPU용 LM Studio 추론 runtime/engine
- 운용할 Qwen3.6-35B-A3B 모델 전체 파일, 모델 원본 SHA-256, 양자화 정보와 라이선스
- GPU 드라이버 및 선택한 양자화/컨텍스트 길이에 맞는 RAM·VRAM·디스크

Windows에서는 ZIP 릴리스를 권장합니다. `tar.gz`는 Linux/macOS용으로 함께 생성됩니다.

## 릴리스 패키지 생성

인터넷이 허용된 준비 환경에서 wheelhouse를 먼저 완성하고, 깨끗한 Git 작업 트리에서 패키지를 만듭니다. 패키징에는 Bash 3.2 이상, Python 3.9 이상, `tar`, `sha256sum` 또는 `shasum`이 필요합니다.

```bash
./scripts/build_wheelhouse.sh
REQUIRE_CLEAN=1 OUT_DIR=/tmp/cat-release ./scripts/make_release_archive.sh
```

출력:

- `cat-0.2.0-<commit>.zip`
- `cat-0.2.0-<commit>.tar.gz`
- `cat-0.2.0-<commit>.archive-SHA256SUMS`

기존 `dist/cat-test.tar.gz`는 0.2.0 Windows 운영 릴리스가 아닌 구 검증 산출물이므로 반입하지 않습니다. 위 형식의 versioned ZIP을 깨끗한 commit에서 새로 생성한 경우에만 승인합니다.

각 아카이브에는 `RELEASE-MANIFEST.json`과 파일별 `SHA256SUMS`가 포함됩니다. 패키징 스크립트는 명시적 운영 allowlist만 복사하며 `reports/`, `.agents/`, `.codex/`, `Zone.Identifier`, 캐시, Codex·성능·wheel 빌드 도구를 제외합니다. 같은 이름의 산출물이 있으면 덮어쓰지 않고 실패합니다.

```bash
python3 scripts/verify_release_package.py \
  /tmp/cat-release/cat-0.2.0-<commit>.zip \
  /tmp/cat-release/cat-0.2.0-<commit>.tar.gz

cd /tmp/cat-release
sha256sum -c cat-0.2.0-<commit>.archive-SHA256SUMS
```

## Windows 최초 설치

외부에서 계산한 아카이브 SHA-256과 반입된 `*.archive-SHA256SUMS`를 대조한 뒤 ZIP을 새 디렉터리에 풉니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
py -3 --version
.\scripts\bootstrap_offline.ps1
```

부트스트랩은 다음을 검증합니다.

- Python 3.9 이상 Windows x64
- wheelhouse의 SHA-256 및 목록 완결성
- `--no-index` 설치와 `pip check`
- `tzdata` 기반 `Asia/Seoul` 시간대
- 실제 EVTX 파싱과 XML/규칙 기반 보고서 smoke test

상세 반입 절차와 Windows E2E 체크리스트는 [독립망 배포 안내](docs/AIRGAP.md)를 참고하세요.

## LM Studio와 Qwen3.6 설정

LM Studio에서 Qwen3.6-35B-A3B 모델을 로드하고 OpenAI 호환 서버를 시작합니다. CAT의 canonical 기본 모델 ID는 `qwen/qwen3.6-35b-a3b`이고, 기본 endpoint는 `http://172.16.100.51:1234/v1/chat/completions`입니다. LM Studio가 같은 Windows 호스트에서 실행되면 일반적으로 `127.0.0.1`을 사용합니다.

표시 이름이 아니라 `/v1/models`가 반환하는 정확한 모델 ID를 사용해야 합니다. 독립망에 반입한 모델의 ID가 canonical 기본값과 다르면 `LM_STUDIO_MODEL`로 반환값을 설정합니다.

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py --models-only

$env:LM_STUDIO_MODEL = "<위 목록의 정확한 모델 ID>"
$env:CAT_AGENT_BACKEND = "lmstudio"
$env:CAT_ENABLE_CODEX_DEV = "false"
$env:CAT_ALLOW_CUSTOM_LM_URL = "false"
$env:CAT_LM_USE_PROXY = "false"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py
```

두 번째 점검은 축약형 문자열 probe가 아니라 CAT의 실제 운영 보고서 생성 함수를 호출합니다. 실제 Chat Completions 요청과 strict JSON Schema, 두 의심 이벤트의 단계별 시나리오, 원본 시각·관측값, `event_ref`, 9개 고정 보고서 섹션까지 모두 검증합니다. API 인증을 켰다면 `LM_STUDIO_API_KEY` 또는 `CAT_LM_API_KEY`를 설정합니다. 잘못된 `LM_STUDIO_URL`은 서버 시작 시 명확한 오류로 거부됩니다.

Qwen3.6 운용 파라미터 전체는 [에이전트 백엔드 안내](docs/AGENT_BACKEND.md)를 참고하세요.

## 실행

Windows:

```powershell
.\scripts\run.ps1
```

Linux/macOS:

```bash
./scripts/bootstrap_offline.sh
./scripts/run.sh
```

브라우저에서 `http://127.0.0.1:8000`을 엽니다. 다른 장비에서 접속하게 하려면 방화벽·인증·망 분리를 검토한 뒤에만 bind 주소를 변경합니다.

```powershell
.\scripts\run.ps1 -BindHost 0.0.0.0 -Port 8000
```

기본 에이전트는 LM Studio이며 Codex 개발 백엔드와 사용자 지정 LLM URL은 비활성화되어 있습니다. `규칙 기반 보고서`를 선택하면 네트워크 호출 없이 결정적 분석 결과를 생성합니다.

## 입력과 제한

- `.evtx`: bundled `python-evtx==0.8.1`로 파싱합니다.
- `.xml`: Windows Event Viewer에서 내보낸 이벤트 XML을 지원합니다.
- naive 시간 입력은 UI 시간대, 기본 `Asia/Seoul`, 기준으로 UTC 변환합니다.
- 시작·종료 시간은 필수입니다.
- 브라우저 업로드 총량은 기본 512MB까지이며 분석은 한 번에 하나씩 수행합니다.
- 업로드 파일은 임시 디렉터리에 저장되고 분석 종료 시 삭제됩니다.

## 분석 출력과 UI

`POST /api/analyze`는 `report_markdown`, `analysis`, `llm`을 반환합니다. `analysis`의 주요 구조화 출력 계약은 다음과 같습니다.

- `findings`: 기존 규칙별 탐지 결과입니다. 이전 CAT UI·연동과의 호환을 위해 유지합니다.
- `suspicious_events`: 규칙에 매칭된 개별 이벤트입니다. 각 항목은 `event_ref`, 시간·원본 위치, Event ID, 호스트·계정·IP·프로세스, `severity`, `confidence`, `rule_ids`, `reasons`를 포함합니다.
- `scenario_candidates`: 같은 호스트에서 60분 이내에 발생하고 의미 있는 공통 엔티티 또는 명시적 행위 전이로 연결되며, 서로 다른 규칙·공격 단계를 포함하는 이벤트의 공격 시나리오 후보입니다. 다른 호스트끼리는 `TargetServerName`·`TargetInfo`·`WorkstationName`에 명시적인 원본/대상 관계가 있을 때만 연결합니다. 각 항목은 `scenario_id`, `title`, `confidence`, `event_refs`, 순서가 있는 `stages`, `link_reasons`, `hypothesis`, `alternative_explanations`, `evidence_gaps`를 포함합니다.

UI의 기존 `탐지 결과` 탭은 `의심 이벤트`와 `공격 시나리오 후보`를 함께 표시합니다. 구버전 서버가 `suspicious_events`를 반환하지 않으면 `findings`를 표시하므로 단계적 업그레이드가 가능합니다. Qwen 응답은 원시 Markdown으로 신뢰하지 않고 고정 JSON schema와 `event_ref` 참조 무결성을 검증한 뒤 9개 고정 섹션의 `report_markdown`으로 렌더링합니다. Qwen은 규칙 엔진이 만든 `scenario_candidates`를 빠뜨리거나 새로 만들거나 시간순 참조를 뒤집을 수 없고, `scenario_id`·제목·신뢰도도 바꿀 수 없습니다. 시간·관측 사실·관련 엔티티는 실제 참조 이벤트와 일치해야 하며, 의심 이벤트 목록에는 CAT가 canonical EVTX 관측 사실을 항상 덧붙입니다. 정상 생성된 최종 침해 시나리오는 `이벤트 기반 공격 시나리오` 섹션에서 확인합니다.

의심 이벤트는 규칙 매칭 결과이고 시나리오 후보는 시간·호스트·계정 등 제한된 근거를 연결한 조사 가설입니다. 둘 다 침해 사실의 확정 판정이 아닙니다. 빈 `scenario_candidates`는 오류가 아니라 현재 근거로 안전하게 연결할 시나리오가 없다는 뜻입니다. `alternative_explanations`와 `evidence_gaps`를 확인하고 원본 EVTX, 중앙 로그, EDR·네트워크 기록으로 재검증해야 합니다. LLM 호출, 미완결 응답, JSON/schema 검증 또는 참조 검증이 실패하면 구조화 분석은 유지되지만 최종 Qwen 시나리오 대신 규칙 기반 보고서가 표시됩니다.

## 주요 탐지 범위

- 이벤트 로그 삭제: Security 1102, Microsoft-Windows-Eventlog/System 104
- 서비스·예약 작업 설치 또는 변경
- 계정·권한 그룹 변경, 원격 로그온과 반복 인증 실패
- 의심 프로세스 및 PowerShell 명령
- Defender 탐지·설정 변경
- WMI 활동

동일 Event ID라도 provider/channel이 다르면 다른 의미로 취급합니다. 규칙 및 LLM 결과는 원본 EVTX, 중앙 로그, EDR·방화벽 기록으로 재검증해야 합니다.
