# CAT - Cyber Activity Tracker

CAT는 Windows EVTX 로그와 분석 대상 시간대를 입력받아 이상 활동을 탐지하고, 로컬 LM Studio를 통해 침해사고 조사 보고서를 작성하는 웹 인터페이스입니다.

## 실행

인터넷이 없는 독립망에서도 실행할 수 있도록 필요한 wheel 파일을 `vendor/wheels`에 포함합니다.

```bash
./scripts/bootstrap_offline.sh
./scripts/run.sh
```

브라우저에서 `http://127.0.0.1:8000`을 엽니다.

## LM Studio

기본 연결 대상은 `http://172.16.100.51:1234`입니다. LM Studio의 OpenAI 호환 서버가 켜져 있어야 하며, CAT는 내부적으로 `/v1/chat/completions` 엔드포인트를 호출합니다.

환경 변수로 기본값을 바꿀 수 있습니다.

```bash
LM_STUDIO_URL=http://172.16.100.51:1234
LM_STUDIO_MODEL=qwen
python3 run.py
```

LM Studio 연결 확인:

```bash
.venv/bin/python scripts/check_lmstudio.py
```

## 독립망 배포

독립망에서는 Git 저장소 전체를 복사한 뒤 `./scripts/bootstrap_offline.sh`를 실행합니다. 런타임 외부 통신은 LM Studio 주소 `172.16.100.51:1234`만 필요합니다.

자세한 내용은 [docs/AIRGAP.md](docs/AIRGAP.md)를 참고하세요.

반입용 아카이브를 만들려면 다음 명령을 사용합니다.

```bash
./scripts/make_release_archive.sh
```

## 에이전트 백엔드

웹 UI의 기본 에이전트는 `LM Studio Qwen`입니다. 실제 운영 단계에서는 LM Studio의 Qwen 모델이 OpenAI 호환 Chat Completions API를 통해 보고서 작성 에이전트 역할을 합니다. 현재 개발 환경에서 `172.16.100.51:1234` 접속이 제한되는 것은 정상 조건이므로, 성능/품질 검증이 필요하면 UI에서 `Codex 개발 검증`을 선택하거나 `CAT_AGENT_BACKEND=codex_dev`로 실행합니다.

`규칙 기반 보고서`를 선택하면 LM Studio/Codex를 호출하지 않고 CAT 내장 규칙 엔진의 탐지 결과만으로 Markdown 보고서를 생성합니다. 이 모드는 LLM 연결 장애 시 대체 보고서로도 사용됩니다.

자세한 내용은 [docs/AGENT_BACKEND.md](docs/AGENT_BACKEND.md)를 참고하세요.

Codex 검증용 산출물 생성:

```bash
.venv/bin/python scripts/export_codex_agent_package.py tests/sample_events.xml
```

Codex CLI를 실제 개발 에이전트로 실행:

```bash
.venv/bin/python scripts/run_codex_agent_review.py reports/<생성된>.agent-prompt.md
```

로컬 파싱/탐지 성능 측정:

```bash
.venv/bin/python scripts/perf_test.py tests/sample_events.xml --iterations 3
```

## 입력

- `.evtx`: `python-evtx` 패키지가 필요합니다.
- `.xml`: Windows Event Viewer에서 내보낸 XML 로그도 분석할 수 있습니다.
- 시간 입력값이 시간대 정보를 포함하지 않으면 UI의 시간대 값, 기본 `Asia/Seoul`, 기준으로 UTC 변환 후 필터링합니다.
- 시작 시간과 종료 시간은 필수입니다. 시간 범위를 지정하지 않으면 분석이 제한됩니다.
- 브라우저 업로드는 기본 512MB까지 허용됩니다. 제한을 넘는 경우 파일 묶음을 나누어 실행하세요.
- 업로드된 로그는 분석 중 임시 디렉터리에만 저장되며, 분석 완료/오류 종료 시 즉시 삭제됩니다. 이전 실행이 비정상 종료되어 남은 CAT 임시 디렉터리는 다음 서버 시작 시 정리됩니다.

## 탐지 범위

초기 룰셋은 다음 조사 신호를 우선 탐지합니다.

- 이벤트 로그 삭제: Security 1102, Microsoft-Windows-Eventlog/System 104, `wevtutil cl`, `Clear-EventLog`
- 서비스 설치: 4697, 7045
- 예약 작업 생성/변경: 4698, 4702, 106, 140, 141
- 계정 생성/활성화/암호 변경/권한 그룹 변경: 4720, 4722, 4723, 4724, 4728, 4732, 4738, 4756
- 원격 로그온과 명시적 자격증명 사용: 4624, 4648, 4672
- 로그온 실패 반복: 4625, 4771, 4776
- 의심 프로세스/PowerShell 명령: 4688, Sysmon 1, 4103, 4104
- Defender 탐지 및 설정 변경: Microsoft-Windows-Windows Defender provider/channel의 1116, 1117, 1118, 1119, 5007, 5013, 5015
- WMI 활동: Microsoft-Windows-WMI-Activity provider/channel의 5857-5861 또는 명시적 WMI 실행 명령

동일한 Event ID라도 provider/channel이 다르면 다른 의미의 이벤트로 취급합니다. 예를 들어 Kernel-Cache 104나 PushNotifications 1117은 각각 이벤트 로그 삭제, Defender 탐지로 단정하지 않습니다.
