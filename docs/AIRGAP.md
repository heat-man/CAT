# Windows 독립망 배포 안내

이 문서는 인터넷이 차단된 Windows 운용망에 CAT 0.2.0과 LM Studio Qwen3.6-35B-A3B를 반입하고 검증하는 기준입니다.

## 1. 통신 기준

정상 운용에 필요한 통신은 다음 두 흐름뿐입니다.

- 브라우저 → CAT 웹 서버: 기본 `http://127.0.0.1:8000`
- CAT 서버 → LM Studio OpenAI 호환 API: 구성한 `LM_STUDIO_URL`

PyPI, GitHub, CDN, npm registry, Codex 서비스는 런타임에 필요하지 않습니다. `CAT_LM_USE_PROXY=false`가 기본이므로 Python 환경 변수와 Windows 시스템 프록시를 우회하고 LM Studio에 직접 연결합니다. 프록시를 반드시 사용해야 할 때만 `CAT_LM_USE_PROXY=true`로 변경하고 해당 프록시를 독립망 허용 목록에 넣습니다.

CAT와 LM Studio가 다른 호스트라면 TCP 1234를 CAT 호스트에서 LM Studio 호스트 방향으로만 허용합니다. HTTP를 쓰면 조사 근거가 평문으로 전송되므로 신뢰할 수 있는 전용 구간을 사용하거나 내부 TLS 종단을 구성합니다.

## 2. 외부 준비 환경에서 반입할 항목

다음 항목을 각각 SHA-256과 함께 준비합니다.

1. CAT Windows ZIP과 `*.archive-SHA256SUMS`
2. Python 3.9 이상 Windows x64 전체 오프라인 설치본(`venv`, `ensurepip` 포함)
3. LM Studio 0.4.8 이상 Windows 설치본
4. 선택한 GPU/CPU용 LM Studio 추론 runtime/engine 전체 파일
5. Qwen3.6-35B-A3B 선택 revision의 GGUF 등 모델 전체 파일
6. GPU 드라이버 또는 오프라인 드라이버 패키지
7. 모델·runtime의 출처, 라이선스, 버전, 양자화, 컨텍스트 길이와 SHA-256 기록

CAT 패키지에는 Python, LM Studio, 추론 runtime, 모델 가중치와 GPU 드라이버가 포함되지 않습니다. LM Studio 설치본과 모델만 복사하면 최초 load 시 호환 runtime 다운로드를 시도할 수 있으므로, 인터넷 허용 준비 환경에서 실제 모델을 한 번 load한 뒤 필요한 runtime까지 내려받아 네트워크를 끈 상태로 재기동·probe하고 그 파일 집합을 반입합니다.

### CAT 패키지 생성

준비 환경 요구사항은 Bash 3.2 이상, Python 3.9 이상, `tar`, `sha256sum` 또는 `shasum`입니다.

```bash
./scripts/build_wheelhouse.sh
REQUIRE_CLEAN=1 OUT_DIR=/tmp/cat-release ./scripts/make_release_archive.sh
```

패키징 스크립트는 운영 파일을 개별 allowlist로 지정합니다. 다음 항목은 포함하지 않습니다.

- `reports/`, `.agents/`, `.codex/`, `.git/`, `.venv/`, `dist/`
- `Zone.Identifier`, `__pycache__`, 테스트·도구 캐시
- Codex 실행, 프롬프트 export, 성능 측정, wheelhouse 빌드 스크립트
- 작업 트리의 임의 untracked 파일

생성된 ZIP과 tar.gz에는 같은 단일 최상위 디렉터리, `RELEASE-MANIFEST.json`, 파일별 `SHA256SUMS`가 들어갑니다. 외부 `*.archive-SHA256SUMS`는 전송 중 아카이브 전체 무결성을 확인합니다.

```bash
python3 scripts/verify_release_package.py \
  /tmp/cat-release/cat-0.2.0-<commit>.zip \
  /tmp/cat-release/cat-0.2.0-<commit>.tar.gz

cd /tmp/cat-release
sha256sum -c cat-0.2.0-<commit>.archive-SHA256SUMS
```

`RELEASE-MANIFEST.json`의 `git_dirty`는 정식 릴리스에서 `false`여야 합니다. 스크립트는 기존 산출물을 덮어쓰지 않습니다.
저장소에 남아 있는 구 `dist/cat-test.tar.gz`는 Windows 0.2.0 운영 반입물로 사용하지 않습니다.

## 3. Windows 반입 무결성 확인

Windows에는 ZIP을 권장합니다. 외부 준비 환경에서 별도 전달받은 SHA-256과 운용망에서 계산한 값을 먼저 비교합니다.

```powershell
$Archive = ".\cat-0.2.0-<commit>.zip"
(Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
Get-Content ".\cat-0.2.0-<commit>.archive-SHA256SUMS"
```

압축 해제 후 내부 파일도 안전하게 검사할 수 있습니다.

```powershell
.\python-installer.exe
py -3 --version
py -3 .\cat-0.2.0-<commit>\scripts\verify_release_package.py $Archive
```

검증기는 압축을 풀지 않고 경로 순회, 절대경로, 중복, symlink/특수 파일, `reports`, `.agents`, `.codex`, `Zone.Identifier`, SHA-256 변조를 거부합니다.

## 4. Windows 최초 설치

ZIP을 새 전용 디렉터리에 푼 뒤 그 디렉터리에서 실행합니다. 기존 설치 위에 덮어 풀지 않습니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd C:\CAT\cat-0.2.0-<commit>
py -3 --version
.\scripts\bootstrap_offline.ps1
```

필요하면 Python 경로와 가상환경 위치를 명시합니다.

```powershell
$env:PYTHON_BIN = "C:\Program Files\Python313\python.exe"
$env:VENV_DIR = "C:\CAT\venv"
.\scripts\bootstrap_offline.ps1
```

부트스트랩은 인터넷 index를 사용하지 않고 `vendor\wheels`만 사용합니다. 다음 검증 중 하나라도 실패하면 완료로 간주하지 않습니다.

- Python 3.9 이상 Windows x64 확인
- wheel 목록 및 `vendor\wheels\SHA256SUMS` 확인
- `pip install --no-index`와 `pip check`
- `tzdata==2026.3`, `Asia/Seoul` UTC+09:00 확인
- `from Evtx.Evtx import Evtx`와 실제 EVTX fixture 파싱
- XML 탐지 및 규칙 기반 보고서 생성

## 5. LM Studio 및 정확한 모델 ID

LM Studio 0.4.8 이상에서 반입한 Qwen3.6-35B-A3B를 로드하고 OpenAI 호환 로컬 서버를 시작합니다. CAT의 canonical 기본 모델 ID는 `qwen/qwen3.6-35b-a3b`입니다. 마케팅 이름이나 파일명이 아니라 `/v1/models`의 `id`를 CAT 모델 값으로 사용하며, 독립망 서버가 다른 ID를 반환하면 `LM_STUDIO_MODEL`로 그 값을 설정합니다.

같은 호스트 예시:

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"
$env:CAT_LM_USE_PROXY = "false"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py --models-only

$env:LM_STUDIO_MODEL = "<정확한 /v1/models ID>"
$env:CAT_AGENT_BACKEND = "lmstudio"
$env:CAT_ENABLE_CODEX_DEV = "false"
$env:CAT_ALLOW_CUSTOM_LM_URL = "false"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py
```

마지막 명령은 CAT의 실제 운영 보고서 생성 함수를 통해 Chat Completions와 strict JSON Schema를 적용합니다. `EVT-0001`과 `EVT-0002`를 순서대로 연결한 2단계 시나리오뿐 아니라 원본 시각·관측값, 참조 무결성, 증거 한계, 9개 고정 보고서 섹션을 모두 확인합니다. 단순 문자열 또는 축약형 schema만 성공한 경우에는 운용 승인을 내리지 않습니다. API 인증을 사용하면 실행 전에 키를 설정합니다.

```powershell
$env:LM_STUDIO_API_KEY = "<내부에서 발급한 키>"
```

## 6. CAT 실행

같은 PowerShell 세션에서 운용 환경 변수를 유지하고 실행합니다.

```powershell
.\scripts\run.ps1
```

브라우저에서 `http://127.0.0.1:8000`을 열고 health 정보의 endpoint와 모델 ID가 설정값과 같은지 확인합니다. 기본적으로 URL 필드는 읽기 전용이고 Codex 개발 백엔드는 노출되지 않습니다.

다른 장비에 UI를 제공해야 할 때만 bind를 변경합니다.

```powershell
.\scripts\run.ps1 -BindHost 0.0.0.0 -Port 8000
```

이 경우 Windows 방화벽 원본 IP 제한, 역방향 프록시 인증, TLS, 업로드 로그 접근 통제를 별도로 구성합니다.

## 7. Windows 독립망 E2E 승인 체크리스트

- [ ] CAT ZIP의 외부 SHA-256이 준비망 원본과 일치한다.
- [ ] release verifier가 ZIP을 통과시킨다.
- [ ] `RELEASE-MANIFEST.json`의 버전·commit이 승인 대상과 같고 `git_dirty=false`이다.
- [ ] Python이 3.9 이상 Windows x64이며 `venv`와 bundled `pip`가 동작한다.
- [ ] bootstrap의 wheel SHA, `pip check`, 시간대, 실제 EVTX smoke가 모두 통과한다.
- [ ] LM Studio가 0.4.8 이상이고 승인된 추론 runtime과 모델 SHA-256·양자화를 사용한다.
- [ ] `/v1/models`의 정확한 ID가 `LM_STUDIO_MODEL`과 일치한다.
- [ ] `check_lmstudio.py`의 production structured scenario probe와 9개 보고서 섹션 검증이 통과한다.
- [ ] 샘플 XML과 승인된 비민감 EVTX를 UI에서 분석하고 Qwen 보고서를 받는다.
- [ ] LM Studio 중지 시 규칙 기반 fallback과 오류 표시가 정상이다.
- [ ] Windows 재부팅 후 동일 환경 변수/서비스 계정으로 재기동된다.
- [ ] 방화벽/프록시 로그에서 허가된 CAT↔LM Studio 통신 외 인터넷 시도가 없다.
- [ ] 운영 로그, 임시 업로드, API key의 접근 권한과 보존 정책을 확인했다.

## 8. 장애 분류

- 설치 실패: Python 버전·x64 여부, wheel SHA/list, `pip check`, PowerShell 실행 정책을 확인합니다.
- 모델 load가 다운로드를 요구함: 해당 모델·장치용 LM Studio 추론 runtime이 준비망에서 완전히 내려받아졌는지 확인합니다.
- 시간대 실패: `tzdata==2026.3` 설치 여부와 `ZoneInfo("Asia/Seoul")`을 확인합니다.
- 모델 목록 실패: LM Studio 서버 bind, 포트, 방화벽, API key를 확인합니다.
- production structured scenario probe 실패: 정확한 모델 ID, 모델 로드 상태, LM Studio 0.4.8 이상, JSON Schema 지원 엔진, timeout을 확인합니다. 오류에 표시된 누락 섹션·이벤트 참조·관측 사실 불일치도 함께 확인합니다.
- CAT 시작 실패: `LM_STUDIO_URL` scheme/host/port/path 형식과 환경 변수 값을 확인합니다.
- 300초 timeout: GPU offload, 컨텍스트 길이, 양자화와 `CAT_LM_TIMEOUT_SECONDS`를 성능 승인 범위 안에서 조정합니다.
