# 에이전트 백엔드와 Qwen3.6 운용 설정

CAT 0.2.0의 기본 보고서 에이전트는 LM Studio 0.4.8 이상에서 제공하는 OpenAI 호환 Chat Completions API입니다. 기본 모델 프로필은 Qwen3.6-35B-A3B이고 canonical 기본 ID는 `qwen/qwen3.6-35b-a3b`입니다. 실제 요청의 `model`에는 `/v1/models`가 반환한 정확한 ID를 사용하며 독립망 서버가 다른 ID를 반환하면 `LM_STUDIO_MODEL`로 재설정합니다.

## 운용 백엔드

- `lmstudio`: 기본값. 구조화된 CAT 분석 JSON을 Qwen에 전달해 한국어 조사 보고서를 만듭니다.
- `rule`: 네트워크 호출 없이 CAT 규칙 엔진만으로 결정적 Markdown 보고서를 만듭니다.
- `codex_dev`: 소스 개발 검증 전용이며 운영 릴리스와 UI에서 기본 비활성화됩니다.

HTTP 연결 실패나 빈 응답처럼 사용할 모델 결과가 없으면 분석 결과는 버리지 않고 규칙 기반 보고서로 fallback합니다. 기본 자유 형식 모드에서는 JSON Schema를 요청하지 않으며 JSON, Markdown, 일반 텍스트 content를 모두 보고서로 사용할 수 있습니다.

## 기본 endpoint

```text
http://127.0.0.1:1234/v1/chat/completions
```

LM Studio가 CAT와 같은 Windows 호스트에 있으면 다음처럼 loopback을 권장합니다.

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"
```

`LM_STUDIO_URL`은 `http` 또는 `https`, 유효한 host/port, query와 fragment가 없는 URL이어야 합니다. base URL, `/v1`, 완전한 `/v1/chat/completions` 형식을 받을 수 있으며 CAT가 endpoint를 정규화합니다. 잘못된 값은 서버 시작 시 실패합니다.

`CAT_ALLOW_CUSTOM_LM_URL=true`가 기본이므로 브라우저에서 endpoint를 바꿀 수 있고 마지막 URL과 모델 ID를 해당 브라우저에 저장합니다. 고정 endpoint만 허용하려면 `false`로 설정합니다. 서버에 설정한 `LM_STUDIO_URL`과 포트 1234의 loopback 주소는 기본 허용합니다. 다른 private IP나 내부 hostname은 `CAT_LM_ALLOWED_ORIGINS=http://192.168.100.20:1234,https://lm.internal:5678`처럼 scheme·host·port가 모두 일치하는 origin 허용 목록에 넣어야 합니다. 호스트와 포트를 분리하지 않으므로 허용하지 않은 조합이 새로 생기지 않습니다. 임의 endpoint는 CAT 서버가 접근 가능한 주소에 POST를 보내므로 외부 노출 시에도 방화벽·인증을 적용해야 합니다. `LM_STUDIO_API_KEY`/`CAT_LM_API_KEY`는 기본 `LM_STUDIO_URL`에만 전달됩니다. 신뢰한 추가 endpoint에 키가 필요하면 `CAT_LM_API_KEY_ALLOWED_ENDPOINTS`에 정규화 가능한 전체 URL을 정확히 지정합니다.

## Qwen3.6-35B-A3B 기본 파라미터

| 환경 변수 | 기본값 | 설명 |
|---|---:|---|
| `LM_STUDIO_MODEL` | `qwen/qwen3.6-35b-a3b` | `/v1/models`의 정확한 ID로 재설정 |
| `LM_STUDIO_API_KEY` | 없음 | 선택적 Bearer token |
| `CAT_LM_API_KEY` | 없음 | API key 별칭; `LM_STUDIO_API_KEY`가 우선 |
| `CAT_LM_TIMEOUT_SECONDS` | `900` | 1~7200초 요청 제한 |
| `CAT_LM_MAX_TOKENS` | `32768` | 최대 출력 token |
| `CAT_LM_TEMPERATURE` | `0.7` | sampling temperature |
| `CAT_LM_TOP_P` | `0.8` | nucleus sampling |
| `CAT_LM_TOP_K` | `20` | top-k sampling |
| `CAT_LM_PRESENCE_PENALTY` | `1.5` | 반복 억제 |
| `CAT_LM_ENABLE_THINKING` | `false` | Qwen thinking 비활성 |
| `CAT_LM_REASONING_EFFORT` | 빈값, 미전송 | 환경 변수로 명시한 경우에만 요청에 포함 |
| `CAT_LM_MAX_INPUT_CHARS` | `49152` | 선별 분석 JSON 문자 예산, tokenizer 없이 64k context를 보수적으로 보호, 최대 8MiB |
| `CAT_LM_MAX_FIELD_CHARS` | `8192` | 개별 로그 문자열 문자 제한, 최대 131072자 |
| `CAT_LM_MAX_RESPONSE_BYTES` | `33554432` | 최대 응답 JSON 32MiB, 최대 256MiB |
| `CAT_LM_MAX_FINDINGS` | `50` | LLM 입력 finding 수, 1~1000 |
| `CAT_LM_MAX_EVIDENCE_PER_FINDING` | `12` | finding별 근거 수, 1~256 |
| `CAT_LM_MAX_SUSPICIOUS_EVENTS` | `100` | LLM 입력 의심 이벤트 수, 1~2000 |
| `CAT_LM_MAX_SCENARIO_CANDIDATES` | `50` | LLM 입력 시나리오 후보 수, 1~500 |
| `CAT_LM_MAX_TIMELINE_EVENTS` | `200` | LLM 입력 timeline 수, 1~5000 |
| `CAT_LM_USE_PROXY` | `false` | 환경/Windows 시스템 프록시 사용 여부 |
| `CAT_ALLOW_CUSTOM_LM_URL` | `true` | UI 임의 endpoint 허용 여부 |
| `CAT_LM_ALLOWED_ORIGINS` | 빈값 | 쉼표로 구분한 추가 endpoint origin(`scheme://host:port`) 허용 목록 |
| `CAT_LM_API_KEY_ALLOWED_ENDPOINTS` | 빈값 | 설정 API key를 전달할 신뢰 endpoint 전체 URL 목록 |
| `CAT_LM_STRICT_VALIDATION` | `false` | `false`: 자유 형식 응답, `true`: JSON Schema/required section 강제 검증 |
| `CAT_BROWSER_ALLOWED_ORIGINS` | 빈값 | HTTPS 역방향 프록시 등에서 허용할 공개 웹 origin(`scheme://host:port`) 목록 |
| `CAT_UPLOAD_TIMEOUT_SECONDS` | `900` | 업로드 본문 전체 수신 제한, 10~7200초 |
| `CAT_XML_MAX_FILE_BYTES` | `134217728` | 단일 XML 파일 제한, 최대 512MiB |
| `CAT_XML_MAX_EVENT_BYTES` | `4194304` | 단일 XML/EVTX 이벤트 XML 제한, 최대 32MiB |
| `CAT_XML_MAX_EVENT_TEXT_CHARS` | `524288` | 이벤트 전체 텍스트 제한, 최대 8MiB 문자 |
| `CAT_XML_MAX_RAW_CHARS` | `1048576` | 레코드에 보관할 raw XML 문자 제한, 최대 8MiB 문자 |
| `CAT_XML_MAX_RETAINED_CHARS_PER_ANALYSIS` | `67108864` | 분석 결과에 누적 보관할 raw XML·필드·시스템 문자열 합계, 최대 512MiB 문자 |
| `CAT_XML_MAX_RETAINED_FIELDS_PER_ANALYSIS` | `262144` | 분석 결과에 누적 보관할 EventData/UserData 필드 수, 최대 2,000,000개 |
| `CAT_XML_MAX_TOKEN_BYTES` | `262144` | 파서 콜백 전 단일 속성/태그/주석 등 XML 토큰 제한, 최대 1MiB |
| `CAT_XML_MAX_NAME_CHARS` | `1024` | namespace가 확장된 단일 태그/속성 이름 제한 |
| `CAT_XML_MAX_ATTRIBUTE_CHARS` | `65536` | 단일 XML 속성값 문자 제한 |
| `CAT_XML_MAX_NAMESPACE_CHARS` | `256` | namespace URI 문자 제한 |
| `CAT_XML_MAX_ATTRIBUTES_PER_ELEMENT` | `256` | 요소 하나의 속성 수 제한 |
| `CAT_XML_MAX_IN_SCOPE_NAMESPACES` | `64` | 동시에 유효한 namespace 선언 수 제한 |
| `CAT_XML_MAX_FIELD_KEY_CHARS` | `1024` | 평탄화된 EventData/UserData 필드 키 제한 |
| `CAT_XML_MAX_EXTRACTED_FIELDS_PER_EVENT` | `4096` | 이벤트별 추출 필드 수 제한 |
| `CAT_XML_MAX_EXTRACTED_CHARS_PER_EVENT` | `1048576` | 이벤트별 추출 키+값 누적 문자 제한 |
| `CAT_XML_MAX_EXPANDED_CHARS_PER_EVENT` | `2097152` | 이벤트별 확장 이름·속성 누적 문자 제한 |
| `CAT_XML_MAX_EXPANDED_CHARS_PER_FILE` | `33554432` | 파일별 확장 이름·속성 누적 문자 제한 |
| `CAT_XML_MAX_ELEMENTS_PER_EVENT` | `20000` | 이벤트 요소 수 제한 |
| `CAT_XML_MAX_ELEMENTS_PER_FILE` | `5000000` | XML 파일 전체 요소 수 제한 |
| `CAT_XML_MAX_DEPTH` | `128` | XML 중첩 깊이 제한 |
| `CAT_XML_PARSE_TIMEOUT_SECONDS` | `300` | XML 스트림 절대 제한 및 EVTX 변환 단계 누적 예산, 1~1800초 |
| `CAT_HTTP_HEADER_TIMEOUT_SECONDS` | `15` | 요청 라인과 헤더의 절대 수신 제한, 1~120초 |
| `CAT_RESPONSE_WRITE_TIMEOUT_SECONDS` | `60` | 응답 전송 제한, 1~600초 |
| `CAT_MAX_CONNECTIONS` | `32` | 동시 HTTP 연결/handler 상한, 1~1024 |
| `CAT_MAX_LARGE_RESPONSES` | `2` | 메모리에 직렬화해 전송하는 분석 응답 상한, 1~32 |
| `CAT_ENABLE_CODEX_DEV` | `false` | Codex 개발 backend 노출 여부 |

선택적 `reasoning_effort` 지원을 위해 LM Studio 0.4.8 이상을 운용 기준으로 사용합니다. 기본 non-thinking 요청은 `enable_thinking=false`만 보내고 `reasoning_effort`는 보내지 않습니다. thinking 또는 reasoning effort를 켜면 지연, token 사용량과 보고서 형식을 별도로 승인하고 값을 명시적으로 고정합니다.

운용 예:

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"
$env:LM_STUDIO_MODEL = "<정확한 /v1/models ID>"
$env:CAT_LM_TIMEOUT_SECONDS = "900"
$env:CAT_LM_MAX_TOKENS = "32768"
$env:CAT_LM_TEMPERATURE = "0.7"
$env:CAT_LM_TOP_P = "0.8"
$env:CAT_LM_TOP_K = "20"
$env:CAT_LM_PRESENCE_PENALTY = "1.5"
$env:CAT_LM_ENABLE_THINKING = "false"
Remove-Item Env:CAT_LM_REASONING_EFFORT -ErrorAction SilentlyContinue
$env:CAT_LM_MAX_INPUT_CHARS = "49152"
$env:CAT_LM_MAX_FIELD_CHARS = "8192"
$env:CAT_LM_MAX_RESPONSE_BYTES = "33554432"
$env:CAT_LM_MAX_FINDINGS = "50"
$env:CAT_LM_MAX_EVIDENCE_PER_FINDING = "12"
$env:CAT_LM_MAX_SUSPICIOUS_EVENTS = "100"
$env:CAT_LM_MAX_SCENARIO_CANDIDATES = "50"
$env:CAT_LM_MAX_TIMELINE_EVENTS = "200"
$env:CAT_LM_USE_PROXY = "false"
$env:CAT_ALLOW_CUSTOM_LM_URL = "true"
$env:CAT_LM_ALLOWED_ORIGINS = "http://192.168.100.20:1234"
$env:CAT_LM_API_KEY_ALLOWED_ENDPOINTS = ""
$env:CAT_LM_STRICT_VALIDATION = "false"
$env:CAT_BROWSER_ALLOWED_ORIGINS = ""
$env:CAT_UPLOAD_TIMEOUT_SECONDS = "900"
$env:CAT_XML_MAX_FILE_BYTES = "134217728"
$env:CAT_XML_MAX_EVENT_BYTES = "4194304"
$env:CAT_XML_MAX_EVENT_TEXT_CHARS = "524288"
$env:CAT_XML_MAX_RAW_CHARS = "1048576"
$env:CAT_XML_MAX_RETAINED_CHARS_PER_ANALYSIS = "67108864"
$env:CAT_XML_MAX_RETAINED_FIELDS_PER_ANALYSIS = "262144"
$env:CAT_XML_MAX_TOKEN_BYTES = "262144"
$env:CAT_XML_MAX_NAME_CHARS = "1024"
$env:CAT_XML_MAX_ATTRIBUTE_CHARS = "65536"
$env:CAT_XML_MAX_NAMESPACE_CHARS = "256"
$env:CAT_XML_MAX_ATTRIBUTES_PER_ELEMENT = "256"
$env:CAT_XML_MAX_IN_SCOPE_NAMESPACES = "64"
$env:CAT_XML_MAX_FIELD_KEY_CHARS = "1024"
$env:CAT_XML_MAX_EXTRACTED_FIELDS_PER_EVENT = "4096"
$env:CAT_XML_MAX_EXTRACTED_CHARS_PER_EVENT = "1048576"
$env:CAT_XML_MAX_EXPANDED_CHARS_PER_EVENT = "2097152"
$env:CAT_XML_MAX_EXPANDED_CHARS_PER_FILE = "33554432"
$env:CAT_XML_MAX_ELEMENTS_PER_EVENT = "20000"
$env:CAT_XML_MAX_ELEMENTS_PER_FILE = "5000000"
$env:CAT_XML_MAX_DEPTH = "128"
$env:CAT_XML_PARSE_TIMEOUT_SECONDS = "300"
$env:CAT_HTTP_HEADER_TIMEOUT_SECONDS = "15"
$env:CAT_RESPONSE_WRITE_TIMEOUT_SECONDS = "60"
$env:CAT_MAX_CONNECTIONS = "32"
$env:CAT_MAX_LARGE_RESPONSES = "2"
$env:CAT_ENABLE_CODEX_DEV = "false"
```

## 정확한 모델 ID와 chat probe

먼저 모델 목록만 조회합니다.

```powershell
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py --models-only
```

출력된 ID를 `LM_STUDIO_MODEL`에 그대로 넣고 실제 probe를 수행합니다.

```powershell
$env:LM_STUDIO_MODEL = "<정확한 ID>"
.\.venv\Scripts\python.exe .\scripts\check_lmstudio.py
```

`--base-url`이 환경 변수 `LM_STUDIO_URL`과 다른 endpoint이고 그 서버에도 같은 API key를 명시적으로 전달해야 할 때만 `--forward-api-key`를 추가합니다.

기본 점검은 다음을 모두 확인합니다.

1. `/v1/models` JSON 형식
2. 구성한 모델 ID
3. CAT `generate_report` 경로를 통한 `/v1/chat/completions` 실제 요청
4. 호환성 완화와 별개인 승인 점검용 strict `response_format.type=json_schema` 적용
5. 두 의심 이벤트의 2단계 공격 시나리오와 `event_ref` 순서
6. 이벤트의 실제 시각·canonical observation·관련 엔티티 일치
7. 9개 고정 Markdown 보고서 섹션
8. Qwen 응답 content와 finish reason 파싱
9. timeout, 응답 크기, HTTP/JSON 오류 처리

`--models-only` 또는 단순 문자열 응답 성공만으로 운용 승인을 내리지 않습니다.

## 모델 반입 기록

CAT 릴리스에는 모델 가중치가 포함되지 않습니다. 독립망 모델 승인 기록에는 최소한 다음 값을 남깁니다.

- 외부 원본 URL 또는 공급 경로
- 모델 파일명과 SHA-256
- Qwen3.6-35B-A3B 변형 및 양자화
- 컨텍스트 길이
- LM Studio 버전
- GPU 드라이버, GPU offload 설정, RAM/VRAM
- `/v1/models` 실제 ID
- CAT 파라미터와 chat probe 결과

동일한 마케팅 이름이라도 파일, 양자화 또는 ID가 다르면 별도 승인 대상으로 취급합니다.

## 데이터 흐름

1. CAT가 업로드 본문과 EVTX/XML 파트를 메모리에 통째로 복제하지 않고 로컬 임시 디렉터리로 스트리밍한 뒤 파싱합니다.
2. 시간 범위와 최대 레코드를 적용합니다.
3. 규칙 엔진이 finding, 의심 이벤트, 공격 시나리오 후보, entity, timeline을 구조화합니다.
4. finding과 시나리오에 연결된 evidence를 먼저 선택하고, high severity·high confidence·명령줄/IP/프로세스 등 실제 관측값이 풍부한 의심 이벤트를 우선합니다.
5. 반복되는 낮은 우선순위 Sysmon/timeline 항목은 대표 항목만 남기고, finding·의심 이벤트·시나리오·timeline의 개수 제한과 개별 필드 제한을 적용합니다.
6. 전체 선별 JSON을 기본 49,152자 예산 안으로 줄이고 `_input_limits` 및 LM 상태 metadata에 원본/포함 개수와 축약 여부를 기록합니다. 전체 범위 이벤트가 대표 근거보다 많아도 축약으로 표시합니다.
7. `strict=false`이면 `response_format` 없이 근거 기반 한국어 자유 보고서를 요청합니다. 일부 JSON, Markdown, code fence와 일반 텍스트를 모두 허용합니다. 완전한 기존 CAT JSON은 검증 renderer로, 호환 가능한 CAT 부분 구조는 canonical 사실로 보정한 renderer로 처리하며 그 밖의 응답은 원문으로 사용합니다.
8. `strict=true`이면 기존 `response_format=json_schema`, required section, event/scenario 참조 검증과 고정 Markdown renderer를 사용합니다.
9. 입력이 축약된 경우 LM 프롬프트, 자유 `report_markdown`의 `CAT 입력 증거 범위`(구조화 보고서는 8번 증거 한계), API metadata와 UI에 전체 이벤트 중 일부 대표 근거만 제공됐음을 명시합니다.

EVTX 필드와 명령줄은 공격자가 조작할 수 있는 비신뢰 데이터로 취급하며, 그 안의 지시를 따르지 않도록 system/user 경계를 함께 둡니다. 프롬프트는 제공된 이벤트 근거 밖의 판단을 가설로 표시하도록 요구합니다. Qwen 보고서는 원본 EVTX와 중앙 로그로 재검증해야 합니다.

## 비정상 통신과 원인 프로세스 분석

네트워크 분석의 canonical 입력은 provider/channel까지 확인한 다음 이벤트별 필드를 정규화합니다.

| 원본 | 주요 필드 | 의미와 제한 |
|---|---|---|
| Sysmon 1 | `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `ParentImage` | 프로세스 생성 원인과 부모 관계. 네트워크 자체를 증명하지 않음 |
| Sysmon 3 | `ProcessGuid`, `ProcessId`, `Image`, `User`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Protocol` | 프로세스 단위 네트워크 연결. Event ID 3 수집이 설정돼 있어야 함 |
| Sysmon 22 | `ProcessGuid`, `ProcessId`, `Image`, `QueryName`, `QueryStatus`, `QueryResults` | 프로세스 단위 DNS 질의. 실제 연결 또는 응답 사용을 증명하지 않음 |
| Security 5156 | `ProcessID`, `Application`, `Direction`, `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `Protocol` | WFP가 허용한 연결. payload·세션 성공과 Sysmon Process GUID는 제공하지 않음 |

분석 결과의 evidence와 `suspicious_events`에는 소스가 제공하는 범위에서 다음 canonical 필드를 둡니다.

- `source_ip`, `source_port`
- `destination_ip`, `destination_port`, `destination_hostname`
- `query_name`, `protocol`, `initiated`, `network_direction`
- `process`, `command_line`, `process_id`, `process_guid`

값을 추출할 수 없으면 빈 값으로 남기며 다른 이벤트의 값을 관측 사실처럼 복사하지 않습니다. UI는 canonical 키를 우선하고 구버전 응답과 raw `fields`의 Sysmon/Security 키를 방어적으로 읽습니다. 모든 값은 HTML escape 후 표시합니다.

상관 분석은 같은 호스트의 Sysmon 이벤트에 대해 동일 `ProcessGuid`를 가장 강한 연결 근거로 사용합니다. GUID가 없을 때만 동일 호스트·PID·프로세스 경로와 10분 시간창으로 프로세스 생성을 연결합니다. DNS는 동일 GUID 또는 PID와 5분 시간창을 요구하고, 연결 이벤트에 hostname이 있으면 질의 이름도 일치해야 합니다. Security 5156은 `Application`, Process ID와 근접한 시간을 보조 근거로 사용할 수 있지만 PID 재사용과 로그 지연 가능성이 있으므로 더 낮은 확신으로 취급합니다. DNS 이름과 목적지 IP가 같은 시간대에 관찰됐다는 사실만으로 둘 사이의 해석되지 않은 매핑을 만들지 않습니다.

고위험·비표준 목적지 포트, 사용자 쓰기 가능 경로의 프로세스, 의심 명령줄, 알려진 터널 도구(`plink`, `chisel`, `ngrok`, `frpc` 등), 서버 프로세스에서 loopback 원격 관리 포트로 향하는 연결, 6회 이상 규칙적인 간격의 반복 통신은 조사 우선순위를 높이는 단서입니다. 결과 rule ID는 일반 후보 `suspicious_network_connection`, 주기 후보 `possible_network_beacon`, DNS 패턴 후보 `suspicious_dns_network_activity` 중 하나입니다. 외부 목적지라는 사실만으로 finding을 만들지 않으며 단일 약한 특징으로 악성 여부를 확정하지 않습니다. 정상 가능성과 추가 확인 항목을 finding에 함께 두고, loopback·link-local·multicast·private address나 잘 알려진 서비스도 다른 강한 근거가 있으면 무조건 제외하지 않습니다.

CAT는 네트워크 평판, WHOIS, GeoIP, ASN, TLS 인증서, packet payload를 자체 조회하지 않습니다. NAT·프록시·VPN·DoH, 프로세스 주입, Sysmon 필터, Security 감사 정책 미설정과 시간 범위 잘림은 원인 귀속의 대표적인 한계입니다. LM 입력 축약 시에는 네트워크 finding과 직접 연결된 evidence를 먼저 보존하고 반복 통신은 대표 항목과 관측 횟수·최초/최종 시각을 우선 전달해야 합니다.

Sysmon Event ID 3은 높은 로그량 때문에 기본적으로 비활성일 수 있습니다. 운영 전 승인한 Sysmon 설정에서 Event ID 1·3·22가 함께 생성되는지 확인하고, 정상 프로세스라는 이유만으로 브라우저·`svchost.exe`·서명 파일의 통신 전체를 제외하지 않습니다. Security 5156은 고급 감사 정책의 Filtering Platform Connection 성공 감사가 사고 전에 켜져 있어야 하며, 중앙 수집 용량을 먼저 산정해야 합니다.

top-level `analysis.network_activity`에는 finding 임계값을 넘지 않은 연결까지 프로세스·목적지·프로토콜·방향 단위로 묶은 대표 그룹, 전체/외부/의심 통신 수, 상위 DNS 질의, 축약 여부와 한계를 둡니다. 기본적으로 최대 64개 대표 통신 그룹과 24개 네트워크 finding을 유지하므로 `truncated=true`일 때는 원본 로그와 중앙 네트워크 기록을 조회해야 합니다.

공개 EVTX 회귀 검증에서는 샘플을 저장소에 무조건 재배포하지 않습니다. 원본 URL, commit, 라이선스와 SHA-256을 기록하고 `Get-WinEvent -Path <sample>`로 실제 Event ID와 최초·최종 시간을 확인합니다. CAT 규칙 backend로 먼저 실행해 parser 통계, record ID, canonical 네트워크 필드와 상관 근거를 원본 이벤트에 대조한 다음 LM backend를 점검합니다. 샘플에 3·22·5156이 없거나 규칙 조건을 충족하지 않아 finding이 없는 것은 파싱 실패와 구분해야 합니다.

## 구조화 분석 출력 계약

`POST /api/analyze` 응답의 canonical 구조는 다음과 같습니다. 아래 배열은 LLM이 작성하는 자유 형식 결과가 아니라 CAT 규칙·상관 분석 결과입니다.

```json
{
  "report_markdown": "Qwen 또는 규칙 기반 Markdown 보고서",
  "analysis": {
    "network_activity": {
      "connection_event_count": 12,
      "dns_query_event_count": 4,
      "external_connection_count": 10,
      "unique_external_destination_count": 2,
      "group_count": 3,
      "included_group_count": 3,
      "suspicious_group_count": 1,
      "included_finding_count": 1,
      "truncated": false,
      "limitation": "외부 평판 없이 로컬 이벤트 특징만 평가",
      "top_dns_queries": [{"value": "example.test", "count": 4}],
      "connections": [
        {
          "first_seen": "UTC ISO-8601 시간",
          "last_seen": "UTC ISO-8601 시간",
          "process": "process",
          "process_guid": "Sysmon ProcessGuid",
          "destination_ip": "destination IP",
          "destination_port": 443,
          "destination_hostname": "destination hostname",
          "protocol": "tcp",
          "connection_count": 6,
          "dns_queries": ["example.test"],
          "correlation_reasons": ["ProcessGuid/PID와 시간 기반 연결 근거"],
          "anomaly_signals": ["관측된 우선순위 근거"],
          "possible_beacon": false,
          "suspicious": false
        }
      ]
    },
    "findings": [],
    "suspicious_events": [
      {
        "event_ref": "EVT-0001",
        "time": "UTC ISO-8601 시간",
        "source_file": "원본 파일명",
        "record_id": "Windows record ID",
        "event_id": "Windows Event ID",
        "provider": "provider",
        "channel": "channel",
        "host": "host",
        "account": "account",
        "source_ip": "source IP",
        "source_port": "source port",
        "destination_ip": "destination IP",
        "destination_port": "destination port",
        "destination_hostname": "destination hostname",
        "query_name": "DNS query name",
        "protocol": "network protocol",
        "initiated": "true|false or source value",
        "network_direction": "outbound|inbound|unknown",
        "process": "process",
        "process_id": "process ID",
        "process_guid": "Sysmon ProcessGuid",
        "command_line": "command line",
        "fields": {},
        "severity": "info|low|medium|high|critical",
        "confidence": "low|medium|high",
        "rule_ids": ["매칭 규칙 ID"],
        "reasons": [
          {
            "rule_id": "매칭 규칙 ID",
            "title": "탐지 제목",
            "description": "이 이벤트가 의심스러운 이유"
          }
        ]
      }
    ],
    "suspicious_event_scope": {
      "included_count": 1,
      "finding_event_count": 1,
      "evidence_truncated": false,
      "note": "대표 근거 범위 설명"
    },
    "scenario_candidates": [
      {
        "scenario_id": "SCN-001",
        "title": "후보 제목",
        "confidence": "low|medium|high",
        "event_refs": ["EVT-0001", "EVT-0002"],
        "stages": [
          {
            "order": 1,
            "phase": "공격 단계",
            "event_ref": "EVT-0001",
            "description": "관측된 행위"
          }
        ],
        "link_reasons": ["이벤트 연결 근거"],
        "hypothesis": "근거로부터 도출한 제한적 가설",
        "alternative_explanations": ["가능한 정상 또는 다른 설명"],
        "evidence_gaps": ["추가로 필요한 증거"]
      }
    ]
  },
  "llm": {
    "used": true,
    "backend": "lmstudio"
  }
}
```

`event_ref`는 한 응답 안에서 의심 이벤트를 참조하는 식별자이며, `scenario_candidates[].event_refs`와 `stages[].event_ref`는 같은 응답의 `suspicious_events[].event_ref`를 가리킵니다. 소비자는 배열 순서를 영구 식별자로 사용하면 안 됩니다. `suspicious_event_scope.evidence_truncated=true`이면 대량 탐지의 전체 이벤트가 아니라 finding별 대표 근거만 구조화 배열에 포함된 것입니다. `findings`는 기존 연동 호환 필드이고, 새 UI는 `suspicious_events`를 우선 표시한 뒤 키가 없거나 배열이 비어 있으면 `findings`로 fallback합니다.

서버의 canonical 시나리오 키는 `scenario_candidates`입니다. UI는 단계적 배포 중 이전 구조를 읽을 수 있도록 `attack_scenarios`와 `event_uid` 기반 객체도 방어적으로 처리하지만, 새 연동은 canonical 키를 생성해야 합니다. Qwen이 최종 정리한 침해 시나리오는 구조화 후보를 대체하지 않고 `report_markdown`에 포함됩니다.

빈 `suspicious_events` 또는 `scenario_candidates` 배열은 유효합니다. 현재 일반 상관 규칙은 같은 호스트의 60분 이내 이벤트에 한정하고, 의미 있는 동일 계정·원본 IP·Logon ID·프로세스 관계 또는 명시적 행위 전이가 있어야 연결합니다. `0x3e7` 같은 well-known system Logon ID와 같은 규칙·단계의 단순 반복은 다단계 시나리오 근거로 사용하지 않습니다. cross-host 이벤트는 계정명이나 프로세스 경로가 같다는 이유만으로 연결하지 않고 `TargetServerName`, `TargetInfo`, `WorkstationName` 중 하나가 상대 호스트를 명시할 때만 연결합니다. 후보는 여러 이벤트의 시간·엔티티·행위 연관성을 조사하기 위한 가설이며 침해 확정 판정이 아닙니다. `hypothesis`와 관측 사실을 혼동하지 말고 `alternative_explanations`, `evidence_gaps`를 보고서에 유지해야 합니다. 모델 호출 실패, timeout 또는 빈 content이면 `analysis`는 그대로 반환되고 규칙 기반 `report_markdown`으로 fallback합니다. `strict=false`에서는 `finish_reason=length` 같은 잘림 표시가 있어도 non-empty content를 보고서로 사용하고 경고 metadata를 남기며, `strict=true`에서는 완결되지 않은 응답을 기존처럼 거부합니다.

## strict=true Qwen 최종 보고서 계약

이 절의 고정 계약은 `CAT_LM_STRICT_VALIDATION=true`에서만 적용됩니다. CAT는 LM Studio 요청에 JSON Schema를 전달하고, 응답 JSON을 다시 검증한 다음 고정 Markdown 형식으로 렌더링합니다. 완전한 strict 응답의 `schema_version`은 `1`이며 다음 필드가 필수입니다.

- `analysis_scope`, `executive_summary`
- 입력의 모든 `event_ref`를 정확히 한 번씩 포함한 `suspicious_events`
- `major_findings`, `timeline`, `related_entities`
- 최종 가설인 `attack_scenarios`
- `evidence_limitations`, `recommendations`
- 시나리오가 없을 때 그 이유를 담는 `no_scenario_reason`

최종 `attack_scenarios`는 규칙 엔진의 `analysis.scenario_candidates`를 Qwen이 설명한 보고서 계층입니다. 각 최종 시나리오는 결정적 후보 하나와 정확히 같은 `scenario_id`, 제목, 신뢰도, `event_refs` 집합 및 시간순 순서를 가져야 하며, 후보를 누락·중복·변경하거나 후보에 없는 시나리오를 새로 만들 수 없습니다. CAT는 규칙 엔진의 가설·연결 근거·대안 설명·증거 공백을 서버 소유 문구로 렌더링하고 모델의 단계 해석은 `Qwen 추가 해석(검증되지 않은 가설)`로 분리합니다. 검증된 결과는 `report_markdown`의 `## 6. 이벤트 기반 공격 시나리오`로 렌더링되고, 원본 결정적 후보는 API의 `analysis`에 그대로 남습니다.

각 최종 시나리오는 입력에 실제 존재하는 서로 다른 `event_ref`를 최소 2개 사용해야 합니다. 단계 순서는 1부터 연속하며 각 참조를 정확히 한 번 사용합니다. 단계의 `observed`와 타임라인의 시각·설명은 CAT가 만든 canonical event observation과 같아야 하고, 관련 엔티티 값도 참조 이벤트의 실제 필드에 있어야 합니다. 시나리오가 없으면 `attack_scenarios=[]`와 구체적인 `no_scenario_reason`이 필요합니다.

기본값인 `strict=false`에서는 이 필드나 9개 섹션을 요구하지 않습니다. CAT는 JSON 파싱을 먼저 시도해 완전한 기존 구조면 renderer를 재사용하고, 부분 JSON이나 임의 JSON이면 누락 필드를 이유로 실패시키지 않습니다. Markdown과 일반 텍스트도 원문을 그대로 `report_markdown`으로 사용하며 정상 자유 응답에 고정된 “검증되지 않음” 제목을 붙이지 않습니다. 완전히 빈 content만 오류입니다.

strict 검증된 `report_markdown`은 다음 9개 섹션을 항상 같은 순서로 가집니다.

1. 분석 범위
2. 핵심 요약
3. 의심 이벤트 목록
4. 주요 이상 활동 상세 분석
5. 시간순 타임라인
6. 이벤트 기반 공격 시나리오
7. 관련 계정/호스트/IP/프로세스
8. 증거 한계 및 확인 필요 사항
9. 추가 수집 및 대응 권고

LLM 입력은 `CAT_LM_MAX_INPUT_CHARS`와 `CAT_LM_MAX_FIELD_CHARS`를 적용하므로 전체 API `analysis`보다 적을 수 있습니다. 실제 포함·원본 개수와 잘림 여부는 `llm.input_*`, `llm.input_source_*` metadata와 입력의 `_input_limits`에 남습니다. 이 축소는 UI에 반환되는 원본 구조화 분석을 변경하지 않습니다. 128k context를 승인해도 기본 49,152자 예산은 그대로 안전 여유로 사용할 수 있으며, 값을 늘릴 때는 모델 context와 최대 출력 token을 함께 검토해야 합니다.

LM timeout은 기본 900초이고 환경변수로 최대 7200초까지 조정할 수 있습니다. timeout 로그에는 안전하게 정규화된 endpoint, 모델 ID, 요청 메시지 문자 수와 경과시간만 기록하며 prompt, 원본 증거, HTTP 오류 body와 API key는 기록하지 않습니다.

## 독립망 보안 기본값

- `CAT_LM_USE_PROXY=false`: 시스템/환경 프록시 우회
- `CAT_ALLOW_CUSTOM_LM_URL=true`: 브라우저에서 endpoint 변경 허용; 고정 운용은 `false`로 잠금
- `CAT_LM_ALLOWED_ORIGINS`: 신뢰한 LM Studio의 scheme·host·port 조합만 정확히 지정해 임의 내부 목적지 요청 제한
- `CAT_LM_API_KEY_ALLOWED_ENDPOINTS`: 기본 endpoint 외 Bearer token을 받을 주소를 전체 endpoint 단위로 제한
- HTTP redirect 거부: 고정 endpoint 우회와 Bearer token 전달 차단
- `CAT_ENABLE_CODEX_DEV=false`: 운영망 Codex subprocess 차단
- `CAT_AGENT_BACKEND=lmstudio`: 기본 운용 backend 고정

규칙 전용 운용은 다음과 같이 설정할 수 있습니다.

```powershell
$env:CAT_AGENT_BACKEND = "rule"
.\scripts\run.ps1
```

## Codex 개발 검증

Codex 경로는 인터넷 허용 개발 환경에서만 사용합니다. 운영 ZIP은 Codex 실행 및 프롬프트 export 스크립트를 포함하지 않습니다. 소스 저장소에서 명시적으로 `CAT_ENABLE_CODEX_DEV=true`를 설정한 경우에만 UI와 서버가 backend를 허용합니다.
