# CAT - Cyber Activity Tracker

CAT 0.2.0은 Windows EVTX/XML 로그를 로컬에서 분석하고, LM Studio의 OpenAI 호환 API로 조사 보고서를 만드는 웹 애플리케이션입니다. LM Studio를 사용할 수 없을 때는 규칙 기반 보고서만으로도 분석할 수 있습니다.

> CAT 웹 서버는 기본적으로 `0.0.0.0:8000`에 바인딩됩니다. CAT가 실행 중인 VM에서는 `http://127.0.0.1:8000`, 다른 단말에서는 VM의 실제 IP(예: `http://192.168.100.1:8000`)로 접속합니다.

## 구성

```text
조사 단말의 브라우저  ── TCP 8000 ──>  CAT 서버  ── HTTP(S) 1234 ──>  LM Studio
                                            │
                                            └─ 규칙 기반 분석은 LM Studio 없이 동작
```

`LM_STUDIO_URL`은 브라우저가 아니라 **CAT 서버가 접속할 주소**입니다. 따라서 CAT와 LM Studio가 서로 다른 장비에 있다면 `127.0.0.1`을 사용할 수 없습니다.

## 5분 빠른 시작

아래 절차는 Windows VM과 배포 ZIP을 기준으로 합니다. 명령은 별도 표시가 없는 한 **같은 PowerShell 창**에서 순서대로 실행하세요. `$env:...`로 설정한 값은 현재 PowerShell 세션에만 적용됩니다.

### 1. 준비 사항

다음을 먼저 준비합니다.

- Python 3.9 이상 Windows x64 전체 설치본(`venv`, `ensurepip` 포함)
- Windows PowerShell 5.1 이상
- LM Studio 0.4.8 이상(LM Studio 분석을 사용할 때만 필요)
- LM Studio에 로드할 Qwen3.6-35B-A3B 모델(LM Studio 분석을 사용할 때만 필요)
- 압축을 푼 CAT 폴더

### 2. CAT 설치

배포 ZIP을 사용하는 경우 `C:\CAT`을 실제로 압축을 푼 경로로 바꾸세요.

```powershell
Set-Location C:\CAT
```

인터넷이 연결된 준비 환경에서 Git 소스를 처음 받는 경우에는 다음 명령을 사용합니다. 이미 clone한 저장소는 `git pull --ff-only`로 갱신할 수 있습니다.

```powershell
git clone https://github.com/heat-man/CAT.git
Set-Location .\CAT
# 기존 clone을 갱신할 때만 실행
git pull --ff-only
```

CAT 저장소 루트에서 오프라인 부트스트랩을 실행합니다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
py -3 --version
.\scripts\bootstrap_offline.ps1
```

부트스트랩은 인터넷에 접속하지 않고 동봉된 wheel을 검증·설치한 뒤 EVTX/XML smoke test를 실행합니다. 이후에는 `run.ps1`만 실행해도 가상환경이 없거나 올바르지 않을 때 자동으로 다시 부트스트랩합니다.

### 3. LM Studio 설정

LM Studio에서 모델을 로드하고 OpenAI 호환 API 서버를 시작합니다.

CAT와 LM Studio가 **같은 VM 또는 PC**에 있으면 다음 주소를 사용합니다.

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py --models-only
```

출력된 목록에서 표시 이름이 아닌 정확한 `id`를 복사합니다.

```powershell
$env:LM_STUDIO_MODEL = "<위 명령이 반환한 정확한 id>"
```

CAT와 LM Studio가 **다른 장비**에 있으면 [LM Studio가 다른 호스트에 있는 경우](#lm-studio가-다른-호스트에-있는-경우)를 먼저 설정하세요.

선택 사항으로 실제 구조화 보고서까지 엄격하게 점검할 수 있습니다.

```powershell
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py
```

이 점검은 strict 검증을 사용합니다. 점검이 실패해도 웹의 기본 완화 모드는 일부 형식 차이를 보정해 정상 결과를 표시할 수 있으므로, 오류 메시지와 웹의 `응답 보정 안내`를 구분해서 확인하세요.

### 4. CAT 실행

```powershell
.\scripts\run.ps1 -BindHost 0.0.0.0 -Port 8000
```

정상적으로 시작되면 다음과 비슷하게 표시됩니다.

```text
CAT web interface (local): http://127.0.0.1:8000
CAT web interface (VM/LAN): http://192.168.100.1:8000
CAT is listening on all IPv4 interfaces (0.0.0.0).
```

`Ctrl+C`를 누르면 서버가 종료됩니다.

Linux/macOS에서는 다음 명령을 사용합니다.

```bash
./scripts/bootstrap_offline.sh
export LM_STUDIO_URL="http://127.0.0.1:1234/v1"
export LM_STUDIO_MODEL="<정확한 모델 id>"
./scripts/run.sh
```

### 5. 브라우저에서 접속

| 브라우저 위치 | 접속 주소 | 설명 |
|---|---|---|
| CAT가 실행 중인 VM 내부 | `http://127.0.0.1:8000` | `127.0.0.1`은 현재 장비 자신을 뜻합니다. |
| VM을 실행하는 호스트 PC | `http://<VM의 실제 IP>:8000` | 예: VM에 실제로 할당된 주소가 `192.168.100.1`이면 `http://192.168.100.1:8000` |
| 같은 승인 네트워크의 다른 단말 | `http://<VM의 실제 IP>:8000` | VM 네트워크와 방화벽에서 TCP 8000 접근이 허용되어야 합니다. |

`0.0.0.0`은 모든 IPv4 인터페이스에서 요청을 받겠다는 **바인드 값**이며 브라우저에 입력하는 주소가 아닙니다. 또한 CAT가 `192.168.100.1`을 새로 만들지는 않습니다. 그 주소가 VM에 실제로 할당되어 있어야 합니다.

### 6. 웹에서 로그 분석

1. `파일 선택`에서 하나 이상의 `.evtx` 또는 `.xml` 파일을 선택합니다.
2. 필수 항목인 `시작 시간`, `종료 시간`과 로그 기준 `시간대`를 지정합니다.
3. 필요한 경우 `최대 레코드`를 조정합니다. 기본값은 20,000개입니다.
4. `보고서 에이전트`에서 `LM Studio Qwen` 또는 `규칙 기반 보고서`를 선택합니다.
5. LM Studio를 선택했다면 URL과 `/v1/models`가 반환한 정확한 모델 ID를 확인합니다.
6. `분석 실행`을 누른 뒤 `보고서`, `탐지 결과`, `요약` 탭과 화면 상단의 경고를 확인합니다.

브라우저에서 변경한 LM Studio URL과 모델 ID는 해당 브라우저의 로컬 저장소에 보존됩니다. 서버 환경 변수를 바꾼 뒤 예전 값이 계속 보이면 입력값을 다시 수정하거나 해당 사이트의 저장 데이터를 지우세요.

## 접속 주소와 네트워크 확인

Windows VM에서 실제 IPv4 주소와 CAT 상태를 확인합니다.

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object {$_.IPAddress -notlike "169.254.*"}

Get-NetTCPConnection -State Listen -LocalPort 8000
Invoke-RestMethod http://127.0.0.1:8000/api/health |
  ConvertTo-Json -Depth 5
```

호스트 PC 또는 다른 조사 단말에서는 VM 주소까지 연결되는지 확인합니다.

```powershell
Test-NetConnection 192.168.100.1 -Port 8000
```

연결되지 않으면 다음을 확인합니다.

- VM에 `192.168.100.1`이 실제로 할당되어 있는지
- VM NIC가 목적에 맞는 Host-only, Bridged 또는 NAT 구성을 사용하는지
- `run.ps1`이 `0.0.0.0`에 바인딩되어 있는지
- Windows 방화벽과 하이퍼바이저 방화벽이 TCP 8000을 허용하는지
- 호스트 PC에서 VM 주소로 라우팅할 수 있는지

Windows 방화벽 규칙이 필요하면 관리자 PowerShell에서 승인된 조사 단말 IP만 허용하세요.
먼저 `Get-NetConnectionProfile`로 VM NIC의 실제 프로필을 확인하고 아래 `$CatNetworkProfile`을 `Private` 또는 `Public` 중 해당 값으로 바꾸세요.

```powershell
Get-NetConnectionProfile
$AnalystIp = "192.168.100.2"  # 실제 승인된 조사 단말 IP로 변경
$CatNetworkProfile = "Private"  # Get-NetConnectionProfile 결과에 맞게 변경
New-NetFirewallRule `
  -DisplayName "CAT TCP 8000" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8000 `
  -RemoteAddress $AnalystIp `
  -Action Allow `
  -Profile $CatNetworkProfile
```

## LM Studio 주소 설정

CAT는 다음 세 형식을 모두 받아 실제 Chat Completions endpoint로 정규화합니다.

- base URL: `http://192.168.100.20:1234`
- `/v1` URL: `http://192.168.100.20:1234/v1`
- 전체 URL: `http://192.168.100.20:1234/v1/chat/completions`

### LM Studio가 CAT와 같은 호스트에 있는 경우

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1"
```

기본 포트 1234의 loopback 주소는 별도 허용 목록 없이 사용할 수 있습니다.

### LM Studio가 다른 호스트에 있는 경우

예를 들어 CAT VM은 `192.168.100.1`, LM Studio 호스트는 `192.168.100.20`이라고 가정합니다.

1. LM Studio API가 loopback 전용이 아닌, CAT VM에서 도달 가능한 인터페이스에서 수신하도록 설정합니다.
2. LM Studio 호스트의 방화벽에서 **CAT 서버 IP → TCP 1234**만 허용합니다.
3. CAT VM에서 연결을 확인합니다.

```powershell
Test-NetConnection 192.168.100.20 -Port 1234
```

4. CAT를 시작할 같은 PowerShell 창에서 주 endpoint를 설정합니다.

```powershell
$env:LM_STUDIO_URL = "http://192.168.100.20:1234/v1"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py --models-only
$env:LM_STUDIO_MODEL = "<정확한 모델 id>"
.\scripts\run.ps1
```

`LM_STUDIO_URL`로 지정한 **주 endpoint는 자동 허용**되므로 `CAT_LM_ALLOWED_ORIGINS`에 다시 넣을 필요가 없습니다.

### 웹에서 추가 주소를 선택하는 경우

브라우저에서 주 endpoint와 다른 내부 LM Studio 주소를 선택하려면, CAT 시작 전에 그 주소의 정확한 origin을 허용합니다. origin에는 path를 넣지 않으며 scheme, host, port가 모두 일치해야 합니다.

```powershell
$env:CAT_ALLOW_CUSTOM_LM_URL = "true"
$env:CAT_LM_ALLOWED_ORIGINS = "http://192.168.100.20:1234,http://192.168.100.21:1234"
.\scripts\run.ps1
```

변경 후에는 CAT 서버를 재시작해야 합니다. UI의 주소 변경을 막고 서버의 주 endpoint만 사용하려면 다음과 같이 설정합니다.

```powershell
$env:CAT_ALLOW_CUSTOM_LM_URL = "false"
```

API key는 기본적으로 주 `LM_STUDIO_URL`에만 전달됩니다. 신뢰한 추가 endpoint에도 key가 필요하면 전체 endpoint를 `CAT_LM_API_KEY_ALLOWED_ENDPOINTS`에 정확히 지정하세요. 자세한 인증 설정은 [에이전트 백엔드 안내](docs/AGENT_BACKEND.md)를 참고하세요.

## 자주 사용하는 환경 변수

환경 변수 변경은 CAT를 다시 시작한 뒤 적용됩니다.

| 변수 | 기본값 | 용도 |
|---|---|---|
| `CAT_HOST` | `0.0.0.0` | CAT 웹 서버 바인드 주소 |
| `PORT` | `8000` | CAT 웹 서버 포트 |
| `LM_STUDIO_URL` | `http://127.0.0.1:1234/v1/chat/completions` | CAT 서버가 사용할 주 LM Studio endpoint |
| `LM_STUDIO_MODEL` | `qwen/qwen3.6-35b-a3b` | `/v1/models`의 정확한 모델 ID |
| `CAT_ALLOW_CUSTOM_LM_URL` | `true` | 브라우저에서 LM Studio 주소 변경 허용 |
| `CAT_LM_ALLOWED_ORIGINS` | 빈값 | UI에서 선택할 추가 LM origin 목록 |
| `CAT_LM_TIMEOUT_SECONDS` | `900` | LM Studio 요청 제한 시간 |
| `CAT_LM_STRICT_VALIDATION` | `false` | `true`이면 보정 없이 fail-fast 검증 |
| `CAT_LM_USE_PROXY` | `false` | LM 요청에 환경/시스템 프록시 사용 |
| `CAT_BROWSER_ALLOWED_ORIGINS` | 빈값 | HTTPS 역방향 프록시의 정확한 공개 origin 목록 |
| `CAT_UPLOAD_TIMEOUT_SECONDS` | `900` | 업로드 본문 전체 수신 제한 시간 |

다시 CAT 웹을 loopback 전용으로 제한하려면 다음 중 하나를 사용합니다.

```powershell
$env:CAT_HOST = "127.0.0.1"
.\scripts\run.ps1
```

또는:

```powershell
.\scripts\run.ps1 -BindHost 127.0.0.1
```

## LM Studio 결과가 표시되는 방식

웹 운용의 기본값은 호환성을 높인 **완화 검증 모드**입니다.

- code fence, BOM, JSON 앞뒤 설명과 일부 형식 차이가 있어도 유효한 내용을 추출합니다.
- 일부 섹션, 이벤트 또는 시나리오 필드가 빠지면 CAT가 원본 분석의 canonical 사실로 보충합니다.
- 모델이 바꾼 시각·관측값·참조·시나리오 순서는 CAT 원본을 기준으로 복원합니다.
- 알 수 없는 참조와 관측되지 않은 엔티티만 제외하고, 모델의 유효한 해석은 보존합니다.
- 구조화 JSON은 아니지만 정상 완료된 실질적인 원문은 `검증되지 않은 모델 해석`임을 표시해 웹에 보여 줍니다.
- 보정이 발생하면 결과를 버리지 않고 `응답 보정 안내`를 표시합니다.
- 연결 실패, 빈 응답 또는 복구할 수 없이 잘린 응답처럼 사용할 결과가 없을 때만 규칙 기반 보고서로 fallback합니다.

이전처럼 계약 불일치 시 즉시 실패하게 하려는 경우에만 `CAT_LM_STRICT_VALIDATION=true`를 사용하세요.

## 문제 해결

| 증상 | 확인 및 조치 |
|---|---|
| CAT VM에서도 페이지가 열리지 않음 | `run.ps1` 창의 오류, `Get-NetTCPConnection -LocalPort 8000`, `/api/health`를 확인합니다. 포트 충돌이면 `.\scripts\run.ps1 -Port 8080`처럼 다른 포트를 사용합니다. |
| `127.0.0.1`은 되지만 VM 밖에서 접속되지 않음 | VM 실제 IP, `0.0.0.0` 바인드, VM NIC/라우팅, Windows 방화벽을 확인하고 외부 단말에서 `Test-NetConnection <VM-IP> -Port 8000`을 실행합니다. |
| LM Studio 연결 거부 또는 timeout | LM Studio API 서버와 모델 로드 상태를 확인합니다. CAT 서버에서 LM 호스트의 TCP 1234와 `/v1/models`에 도달할 수 있어야 합니다. |
| `허용되지 않은 LM endpoint` 오류 | 주 주소는 `LM_STUDIO_URL`로 지정합니다. UI에서 고를 추가 주소는 exact origin을 `CAT_LM_ALLOWED_ORIGINS`에 넣고 CAT를 재시작합니다. |
| 모델을 찾지 못함 | `check_lmstudio.py --models-only`가 반환한 정확한 `id`를 환경 변수와 UI에 복사합니다. |
| LM Studio에서는 완료됐지만 웹에 보정 안내가 표시됨 | 안내는 결과 폐기가 아니라 보정 내역입니다. 보고서와 함께 누락 섹션·참조·관측 사실 차이를 검토하세요. strict 검증은 필요한 경우에만 켭니다. |
| LM Studio 완료 후에도 웹 요청이 끊김 | 역방향 프록시의 request/read timeout을 업로드·EVTX/XML 파싱·LM 추론·응답 전송을 합친 전체 분석 예상 시간보다 충분히 길게 설정합니다. `CAT_LM_TIMEOUT_SECONDS`는 이 중 LM 호출 제한만 나타냅니다. 브라우저 개발자 도구와 프록시 로그도 확인합니다. |
| HTTPS 프록시 뒤에서 분석 요청이 403 | 브라우저가 실제 사용하는 정확한 origin을 `CAT_BROWSER_ALLOWED_ORIGINS`에 넣습니다. 직접 HTTP 접속도 병행하려면 각 HTTP origin도 함께 넣습니다. |
| 업로드가 408 | 전송 속도와 프록시 제한을 확인합니다. 필요할 때만 `CAT_UPLOAD_TIMEOUT_SECONDS`를 늘립니다. |
| 업로드가 413 | 기본 총 업로드 512MB 또는 XML 개별 제한을 초과했습니다. 파일 묶음을 나누거나 분석 범위를 줄입니다. |
| 분석 요청이 429 | CAT는 한 번에 하나의 분석만 수행합니다. 기존 분석이 끝난 뒤 다시 시도합니다. |
| XML 일부만 분석되고 경고가 표시됨 | 파일/이벤트/텍스트/시간 제한 중 어느 항목에 걸렸는지 `입력 파싱 경고`를 확인합니다. |
| PowerShell 스크립트 실행이 차단됨 | 같은 PowerShell 창에서 `Set-ExecutionPolicy -Scope Process Bypass`를 실행합니다. |
| UI에 예전 LM URL이나 모델이 계속 표시됨 | 입력값을 수정하거나 브라우저의 CAT 사이트 저장 데이터를 지웁니다. |

## 입력 형식과 기본 제한

- `.evtx`: 동봉된 `python-evtx==0.8.1`로 파싱합니다.
- `.xml`: Windows Event Viewer에서 내보낸 이벤트 XML을 지원합니다.
- 시작·종료 시간은 필수이며, timezone 정보가 없는 입력은 UI 시간대(기본 `Asia/Seoul`)를 기준으로 UTC로 변환합니다.
- 기본 최대 레코드는 20,000개, 브라우저 업로드 총량은 512MB입니다.
- 분석은 한 번에 하나만 실행하며, 대기 중인 새 분석은 본문 수신 전에 429로 거부합니다.
- 업로드는 임시 파일로 스트리밍되고 분석 종료 시 삭제됩니다. multipart 처리에는 업로드 크기의 최대 약 2배에 해당하는 임시 디스크 여유가 필요합니다.
- XML은 전체 트리를 메모리에 올리지 않고 스트리밍하며 DTD와 과도한 파일·이벤트·텍스트·토큰 크기를 제한합니다.
- HTTP 헤더, 업로드, LM 응답, 결과 전송에 각각 유한한 timeout을 적용합니다.

XML/HTTP 세부 제한과 조정 변수는 [에이전트 백엔드 안내](docs/AGENT_BACKEND.md)와 [독립망 배포 안내](docs/AIRGAP.md)를 참고하세요.

## 분석 결과 해석

`POST /api/analyze`는 `report_markdown`, `analysis`, `llm`을 반환합니다. UI에서는 다음 결과를 확인할 수 있습니다.

- `보고서`: LM Studio 또는 규칙 기반 조사 보고서
- `탐지 결과`: 규칙에 매칭된 개별 `suspicious_events`와 연결 근거가 있는 `scenario_candidates`
- `요약`: 분석 범위, 입력 처리 상태와 주요 통계
- `응답 보정 안내`: LM 결과에서 CAT가 보충·복원한 항목
- `입력 파싱 경고`: 일부 파일 또는 레코드가 제외되었을 가능성

의심 이벤트는 규칙 매칭 결과이고 시나리오 후보는 시간·호스트·계정 등 제한된 근거를 연결한 조사 가설입니다. 둘 다 침해 사실의 확정 판정이 아닙니다. 빈 `scenario_candidates`는 오류가 아니라 현재 근거로 안전하게 연결할 시나리오가 없다는 뜻입니다. 원본 EVTX, 중앙 로그, EDR·네트워크 기록으로 반드시 재검증하세요.

## 주요 탐지 범위

- 이벤트 로그 삭제: Security 1102, Microsoft-Windows-Eventlog/System 104
- 서비스·예약 작업 설치 또는 변경
- 계정·권한 그룹 변경, 원격 로그온과 반복 인증 실패
- 의심 프로세스 및 PowerShell 명령
- Defender 탐지·설정 변경
- WMI 활동

동일 Event ID라도 provider/channel이 다르면 다른 의미로 취급합니다.

## 보안 주의 사항

- CAT 내장 웹 서버에는 자체 인증과 TLS가 없습니다. 인터넷에 직접 노출하지 마세요.
- `0.0.0.0`으로 운영할 때는 TCP 8000을 승인된 조사 단말 원본으로만 제한하세요.
- 브라우저 교차 출처 POST 차단은 사용자 인증을 대신하지 않습니다.
- CAT와 LM Studio 사이에 HTTP를 사용하면 조사 데이터가 평문으로 전송됩니다. 신뢰할 수 있는 전용 구간을 사용하거나 내부 TLS 종단을 구성하세요.
- HTTPS 역방향 프록시를 사용하면 `CAT_BROWSER_ALLOWED_ORIGINS=https://cat.internal`처럼 공개 origin을 정확히 지정하세요. 이 목록을 설정하면 목록에 있는 origin만 허용됩니다.
- 직접 HTTP 접속도 함께 유지하려면 `http://127.0.0.1:8000,http://192.168.100.1:8000` 등 실제 허용할 각 origin을 같은 목록에 추가하세요.

## 독립망 배포

운영 릴리스에는 애플리케이션 소스, 정적 UI, 오프라인 Python wheel, 설치/실행 스크립트와 smoke test가 포함됩니다. 다음 항목은 별도로 준비해야 합니다.

- Python 3.9 이상 Windows x64 전체 오프라인 설치본
- LM Studio 설치본과 선택한 GPU/CPU용 추론 runtime/engine
- 모델 전체 파일, 원본 SHA-256, 양자화 정보와 라이선스
- GPU 드라이버 및 승인한 모델 설정에 맞는 RAM·VRAM·디스크

Windows에서는 ZIP 릴리스를 권장합니다. 상세 반입·설치·E2E 절차는 [독립망 배포 안내](docs/AIRGAP.md)를 따르세요.

### 릴리스 패키지 생성

인터넷이 허용된 준비 환경에서 wheelhouse를 완성하고, 깨끗한 Git 작업 트리에서 패키지를 만듭니다.

```bash
./scripts/build_wheelhouse.sh
REQUIRE_CLEAN=1 OUT_DIR=/tmp/cat-release ./scripts/make_release_archive.sh
```

생성 파일:

- `cat-0.2.0-<commit>.zip`
- `cat-0.2.0-<commit>.tar.gz`
- `cat-0.2.0-<commit>.archive-SHA256SUMS`

기존 `dist/cat-test.tar.gz`는 0.2.0 Windows 운영 릴리스가 아닌 구 검증 산출물이므로 반입하지 않습니다. 각 아카이브에는 `RELEASE-MANIFEST.json`과 파일별 `SHA256SUMS`가 포함됩니다.

```bash
python3 scripts/verify_release_package.py \
  /tmp/cat-release/cat-0.2.0-<commit>.zip \
  /tmp/cat-release/cat-0.2.0-<commit>.tar.gz

cd /tmp/cat-release
sha256sum -c cat-0.2.0-<commit>.archive-SHA256SUMS
```

## 상세 문서

- [독립망 배포 및 Windows E2E 체크리스트](docs/AIRGAP.md)
- [LM Studio/Qwen 설정과 보고서 계약](docs/AGENT_BACKEND.md)
