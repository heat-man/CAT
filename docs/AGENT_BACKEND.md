# 에이전트 백엔드

현재 CAT의 런타임 에이전트 인터페이스는 OpenAI 호환 Chat Completions API입니다.

기본 대상:

```text
http://172.16.100.51:1234/v1/chat/completions
```

운영 모델은 LM Studio에 로드된 Qwen 계열 모델입니다. CAT의 기본 모델명은 `qwen`이며, 실제 LM Studio의 모델 ID가 다르면 UI의 모델 입력값이나 `LM_STUDIO_MODEL` 환경 변수로 맞춥니다.

LM Studio에서 OpenAI 호환 서버를 켜면 CAT는 다음 흐름으로 동작합니다.

1. 업로드된 EVTX/XML 로그를 로컬에서 파싱합니다.
2. 분석 시간대 기준으로 이벤트를 필터링합니다.
3. 룰 기반 탐지로 주요 이상 활동, 엔티티, 타임라인을 구조화합니다.
4. 구조화된 JSON 근거만 LLM에 전달합니다.
5. LLM은 근거 기반 한국어 조사 보고서를 작성합니다.

LLM 호출에 실패하면 CAT는 분석을 중단하지 않고 규칙 기반 Markdown 보고서를 반환합니다.

## 규칙 기반 보고서

웹 UI에서 `규칙 기반 보고서`를 선택하면 CAT는 외부 LLM을 호출하지 않습니다. EVTX/XML 파싱 결과에 대해 내장 규칙 엔진을 실행하고, 탐지된 finding, 근거 이벤트, 원인/행위 분석 가이드, 한계 및 추가 확인 사항을 Markdown 보고서로 작성합니다.

이 모드는 다음 상황에 사용합니다.

- LM Studio 연결 없이 빠르게 1차 이상 탐지 결과를 확인할 때
- LLM 보고서 생성 실패 시 대체 보고서가 필요할 때
- 동일 로그에 대해 결정적이고 재현 가능한 규칙 기반 결과가 필요할 때

## Codex 개발 검증 역할

개발 환경에서는 `172.16.100.51:1234` 접속이 제한되는 것이 정상 조건입니다. 이 단계에서는 Codex가 코드 작성, 성능 측정 결과 해석, 보고서 품질 검증 에이전트 역할을 할 수 있습니다. 웹 서버의 기본 에이전트는 운영 기준에 맞춰 `LM Studio Qwen`이며, Codex 검증이 필요하면 UI에서 `Codex 개발 검증`을 선택하거나 `CAT_AGENT_BACKEND=codex_dev`로 실행합니다.

Codex 검증 흐름:

1. CAT가 EVTX/XML을 파싱하고 룰 기반 분석 결과를 생성합니다.
2. `scripts/export_codex_agent_package.py`가 분석 JSON, 규칙 기반 보고서, Qwen/Codex 공용 에이전트 프롬프트를 `reports/`에 저장합니다.
3. `scripts/run_codex_agent_review.py`가 선택적으로 `codex exec`를 호출해 Codex를 실제 개발 에이전트로 실행합니다.
4. Codex가 해당 산출물을 기준으로 보고서 품질, 탐지 누락, 성능 병목을 검토합니다.

```bash
.venv/bin/python scripts/export_codex_agent_package.py tests/sample_events.xml
```

Codex CLI 실행:

```bash
.venv/bin/python scripts/run_codex_agent_review.py reports/<생성된>.agent-prompt.md
```

성능 측정은 다음 명령을 사용합니다.

```bash
.venv/bin/python scripts/perf_test.py tests/sample_events.xml --iterations 3
```

현재 저장소의 기본 검증 기준은 다음과 같습니다.

- `tests/smoke_test.py`가 샘플 Windows 이벤트 XML을 파싱해야 합니다.
- 로그 삭제, 신규 서비스 설치, encoded PowerShell 실행을 탐지해야 합니다.
- LLM 없이도 조사 보고서가 생성되어야 합니다.
- 오프라인 wheelhouse만으로 새 가상환경 설치가 성공해야 합니다.

실제 독립망 운영 단계에서는 Codex가 필요하지 않으며, `172.16.100.51:1234`의 Qwen 로컬 LLM이 보고서 작성 에이전트 역할을 수행합니다.

기본 에이전트는 LM Studio입니다. Codex 개발 검증을 강제로 지정하려면 다음처럼 실행합니다.

```bash
CAT_AGENT_BACKEND=codex_dev ./scripts/run.sh
```
