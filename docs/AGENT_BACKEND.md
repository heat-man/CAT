# 에이전트 백엔드와 Qwen3.6 운용 설정

CAT 0.2.0의 기본 보고서 에이전트는 LM Studio 0.4.8 이상에서 제공하는 OpenAI 호환 Chat Completions API입니다. 기본 모델 프로필은 Qwen3.6-35B-A3B이고 canonical 기본 ID는 `qwen/qwen3.6-35b-a3b`입니다. 실제 요청의 `model`에는 `/v1/models`가 반환한 정확한 ID를 사용하며 독립망 서버가 다른 ID를 반환하면 `LM_STUDIO_MODEL`로 재설정합니다.

## 운용 백엔드

- `lmstudio`: 기본값. 구조화된 CAT 분석 JSON을 Qwen에 전달해 한국어 조사 보고서를 만듭니다.
- `rule`: 네트워크 호출 없이 CAT 규칙 엔진만으로 결정적 Markdown 보고서를 만듭니다.
- `codex_dev`: 소스 개발 검증 전용이며 운영 릴리스와 UI에서 기본 비활성화됩니다.

LLM 호출 또는 응답 검증이 실패하면 분석 결과는 버리지 않고 규칙 기반 보고서로 fallback합니다. UI에는 LLM 사용 여부와 오류가 표시됩니다.

## 기본 endpoint

```text
http://172.16.100.51:1234/v1/chat/completions
```

LM Studio가 CAT와 같은 Windows 호스트에 있으면 다음처럼 loopback을 권장합니다.

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"
```

`LM_STUDIO_URL`은 `http` 또는 `https`, 유효한 host/port, query와 fragment가 없는 URL이어야 합니다. base URL, `/v1`, 완전한 `/v1/chat/completions` 형식을 받을 수 있으며 CAT가 endpoint를 정규화합니다. 잘못된 값은 서버 시작 시 실패합니다.

`CAT_ALLOW_CUSTOM_LM_URL=false`가 기본이므로 브라우저는 서버 환경 변수로 정한 endpoint만 사용합니다. 개발 환경에서 임의 URL 입력이 정말 필요할 때만 `true`로 설정합니다.

## Qwen3.6-35B-A3B 기본 파라미터

| 환경 변수 | 기본값 | 설명 |
|---|---:|---|
| `LM_STUDIO_MODEL` | `qwen/qwen3.6-35b-a3b` | `/v1/models`의 정확한 ID로 재설정 |
| `LM_STUDIO_API_KEY` | 없음 | 선택적 Bearer token |
| `CAT_LM_API_KEY` | 없음 | API key 별칭; `LM_STUDIO_API_KEY`가 우선 |
| `CAT_LM_TIMEOUT_SECONDS` | `300` | 1~3600초 요청 제한 |
| `CAT_LM_MAX_TOKENS` | `32768` | 최대 출력 token |
| `CAT_LM_TEMPERATURE` | `0.7` | sampling temperature |
| `CAT_LM_TOP_P` | `0.8` | nucleus sampling |
| `CAT_LM_TOP_K` | `20` | top-k sampling |
| `CAT_LM_PRESENCE_PENALTY` | `1.5` | 반복 억제 |
| `CAT_LM_ENABLE_THINKING` | `false` | Qwen thinking 비활성 |
| `CAT_LM_REASONING_EFFORT` | 빈값, 미전송 | 환경 변수로 명시한 경우에만 요청에 포함 |
| `CAT_LM_MAX_INPUT_CHARS` | `65536` | JSON 분석 입력 전체 문자 제한 |
| `CAT_LM_MAX_FIELD_CHARS` | `2000` | 개별 로그 문자열 문자 제한 |
| `CAT_LM_MAX_RESPONSE_BYTES` | `8388608` | 최대 응답 JSON 8MiB |
| `CAT_LM_USE_PROXY` | `false` | 환경/Windows 시스템 프록시 사용 여부 |
| `CAT_ALLOW_CUSTOM_LM_URL` | `false` | UI 임의 endpoint 허용 여부 |
| `CAT_ENABLE_CODEX_DEV` | `false` | Codex 개발 backend 노출 여부 |

선택적 `reasoning_effort` 지원을 위해 LM Studio 0.4.8 이상을 운용 기준으로 사용합니다. 기본 non-thinking 요청은 `enable_thinking=false`만 보내고 `reasoning_effort`는 보내지 않습니다. thinking 또는 reasoning effort를 켜면 지연, token 사용량과 보고서 형식을 별도로 승인하고 값을 명시적으로 고정합니다.

운용 예:

```powershell
$env:LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"
$env:LM_STUDIO_MODEL = "<정확한 /v1/models ID>"
$env:CAT_LM_TIMEOUT_SECONDS = "300"
$env:CAT_LM_MAX_TOKENS = "32768"
$env:CAT_LM_TEMPERATURE = "0.7"
$env:CAT_LM_TOP_P = "0.8"
$env:CAT_LM_TOP_K = "20"
$env:CAT_LM_PRESENCE_PENALTY = "1.5"
$env:CAT_LM_ENABLE_THINKING = "false"
Remove-Item Env:CAT_LM_REASONING_EFFORT -ErrorAction SilentlyContinue
$env:CAT_LM_MAX_INPUT_CHARS = "65536"
$env:CAT_LM_MAX_FIELD_CHARS = "2000"
$env:CAT_LM_MAX_RESPONSE_BYTES = "8388608"
$env:CAT_LM_USE_PROXY = "false"
$env:CAT_ALLOW_CUSTOM_LM_URL = "false"
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

기본 점검은 다음을 모두 확인합니다.

1. `/v1/models` JSON 형식
2. 구성한 모델 ID
3. CAT 운영 `generate_report` 경로를 통한 `/v1/chat/completions` 실제 요청
4. 운영과 동일한 strict `response_format.type=json_schema` 적용
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

1. CAT가 업로드된 EVTX/XML을 로컬 임시 디렉터리에서 파싱합니다.
2. 시간 범위와 최대 레코드를 적용합니다.
3. 규칙 엔진이 finding, 의심 이벤트, 공격 시나리오 후보, entity, timeline을 구조화합니다.
4. 최대 20개 finding, finding별 최대 6개 근거, 최대 40개 의심 이벤트, 최대 20개 시나리오 후보, 최대 80개 timeline을 우선 선택합니다.
5. 개별 문자열과 전체 JSON을 설정된 입력 한도에 맞춰 축소하고 `_input_limits`에 포함·잘림 수를 기록합니다.
6. Qwen이 근거 기반 한국어 보고서를 반환합니다.
7. CAT가 응답 크기·JSON·content를 검증하고 UI에 표시합니다.

EVTX 필드와 명령줄은 공격자가 조작할 수 있는 비신뢰 데이터로 취급하며, 그 안의 지시를 따르지 않도록 system/user 경계를 함께 둡니다. 프롬프트는 제공된 이벤트 근거 밖의 판단을 가설로 표시하도록 요구합니다. Qwen 보고서는 원본 EVTX와 중앙 로그로 재검증해야 합니다.

## 구조화 분석 출력 계약

`POST /api/analyze` 응답의 canonical 구조는 다음과 같습니다. 아래 배열은 LLM이 작성하는 자유 형식 결과가 아니라 CAT 규칙·상관 분석 결과입니다.

```json
{
  "report_markdown": "Qwen 또는 규칙 기반 Markdown 보고서",
  "analysis": {
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
        "process": "process",
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

빈 `suspicious_events` 또는 `scenario_candidates` 배열은 유효합니다. 현재 일반 상관 규칙은 같은 호스트의 60분 이내 이벤트에 한정하고, 의미 있는 동일 계정·원본 IP·Logon ID·프로세스 관계 또는 명시적 행위 전이가 있어야 연결합니다. `0x3e7` 같은 well-known system Logon ID와 같은 규칙·단계의 단순 반복은 다단계 시나리오 근거로 사용하지 않습니다. cross-host 이벤트는 계정명이나 프로세스 경로가 같다는 이유만으로 연결하지 않고 `TargetServerName`, `TargetInfo`, `WorkstationName` 중 하나가 상대 호스트를 명시할 때만 연결합니다. 후보는 여러 이벤트의 시간·엔티티·행위 연관성을 조사하기 위한 가설이며 침해 확정 판정이 아닙니다. `hypothesis`와 관측 사실을 혼동하지 말고 `alternative_explanations`, `evidence_gaps`를 보고서에 유지해야 합니다. 모델 호출 실패, timeout, 잘린 응답 또는 응답 검증 실패 시 `analysis`는 그대로 반환되고 규칙 기반 `report_markdown`으로 fallback합니다.

## Qwen 최종 보고서 계약

CAT는 Qwen이 반환한 문자열을 그대로 보고서로 표시하지 않습니다. LM Studio 요청에 JSON schema를 전달하고, 응답 JSON을 다시 검증한 다음 CAT가 고정 Markdown 형식으로 렌더링합니다. 모델 응답의 `schema_version`은 `1`이며 다음 필드가 필수입니다.

- `analysis_scope`, `executive_summary`
- 입력의 모든 `event_ref`를 정확히 한 번씩 포함한 `suspicious_events`
- `major_findings`, `timeline`, `related_entities`
- 최종 가설인 `attack_scenarios`
- `evidence_limitations`, `recommendations`
- 시나리오가 없을 때 그 이유를 담는 `no_scenario_reason`

최종 `attack_scenarios`는 규칙 엔진의 `analysis.scenario_candidates`를 Qwen이 설명한 보고서 계층입니다. 각 최종 시나리오는 결정적 후보 하나와 정확히 같은 `scenario_id`, 제목, 신뢰도, `event_refs` 집합 및 시간순 순서를 가져야 하며, 후보를 누락·중복·변경하거나 후보에 없는 시나리오를 새로 만들 수 없습니다. CAT는 규칙 엔진의 가설·연결 근거·대안 설명·증거 공백을 서버 소유 문구로 렌더링하고 모델의 단계 해석은 `Qwen 추가 해석(검증되지 않은 가설)`로 분리합니다. 검증된 결과는 `report_markdown`의 `## 6. 이벤트 기반 공격 시나리오`로 렌더링되고, 원본 결정적 후보는 API의 `analysis`에 그대로 남습니다.

각 최종 시나리오는 입력에 실제 존재하는 서로 다른 `event_ref`를 최소 2개 사용해야 합니다. 단계 순서는 1부터 연속하며 각 참조를 정확히 한 번 사용합니다. 단계의 `observed`와 타임라인의 시각·설명은 CAT가 만든 canonical event observation과 정확히 같아야 하고, 관련 엔티티 값도 참조 이벤트의 실제 필드에 있어야 합니다. 시나리오가 없으면 `attack_scenarios=[]`와 구체적인 `no_scenario_reason`이 필요합니다. 허용되지 않은 참조, 후보 누락·추가·중복, 의심 이벤트 누락·중복, 관측 사실 불일치, 필수 섹션 누락, `finish_reason` 미완결, 빈 content, 잘못된 JSON 또는 schema 불일치는 모두 실패로 처리하고 규칙 기반 보고서로 fallback합니다.

검증된 `report_markdown`은 다음 9개 섹션을 항상 같은 순서로 가집니다.

1. 분석 범위
2. 핵심 요약
3. 의심 이벤트 목록
4. 주요 이상 활동 상세 분석
5. 시간순 타임라인
6. 이벤트 기반 공격 시나리오
7. 관련 계정/호스트/IP/프로세스
8. 증거 한계 및 확인 필요 사항
9. 추가 수집 및 대응 권고

LLM 입력은 `CAT_LM_MAX_INPUT_CHARS`와 `CAT_LM_MAX_FIELD_CHARS`를 적용하므로 전체 API `analysis`보다 적을 수 있습니다. 실제 포함·잘림 수는 LLM 상태 metadata와 입력의 `_input_limits`로 관리됩니다. 이 축소는 UI에 반환되는 원본 구조화 분석을 변경하지 않습니다.

## 독립망 보안 기본값

- `CAT_LM_USE_PROXY=false`: 시스템/환경 프록시 우회
- `CAT_ALLOW_CUSTOM_LM_URL=false`: 브라우저 임의 URL 차단
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
