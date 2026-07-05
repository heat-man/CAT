# 독립망 배포 안내

CAT는 독립망에서 외부 인터넷 없이 실행되도록 구성되어 있습니다. 런타임에 필요한 Python 패키지는 `vendor/wheels`에 포함되어 있고, 웹 UI는 `static` 디렉터리의 정적 파일만 사용합니다.

## 독립망에서 필요한 통신

- CAT 웹 브라우저 접속: 사용자가 CAT 서버에 접속
- CAT 서버 -> LM Studio: `http://172.16.100.51:1234`

그 외 인터넷, GitHub, PyPI, CDN, npm registry 접근은 실행에 필요하지 않습니다.

## 복사해야 할 항목

Git 저장소 전체를 복사합니다. 단, `.venv`, `__pycache__`, `.pytest_cache`는 복사할 필요가 없습니다.

필수 항목:

- `cat_app/`
- `static/`
- `tests/`
- `vendor/wheels/`
- `requirements.offline.txt`
- `run.py`
- `scripts/`

파일 묶음으로 반입할 경우 인터넷이 되는 준비 환경에서 다음 명령으로 아카이브를 만들 수 있습니다.

```bash
./scripts/make_release_archive.sh
```

## 최초 설치

```bash
./scripts/bootstrap_offline.sh
```

이 명령은 다음을 수행합니다.

- `.venv` 생성
- `vendor/wheels`만 사용해 패키지 설치
- 샘플 로그 스모크 테스트 실행

## 실행

```bash
./scripts/run.sh
```

기본 주소는 `http://127.0.0.1:8000`입니다.

다른 호스트/포트를 사용하려면 다음처럼 실행합니다.

```bash
HOST=0.0.0.0 PORT=8000 ./scripts/run.sh
```

## LM Studio 연결 확인

```bash
.venv/bin/python scripts/check_lmstudio.py
```

기본 대상은 `http://172.16.100.51:1234`입니다.

독립망 LM Studio에는 Qwen 계열 모델이 로드되어 있어야 합니다. CAT의 기본 모델명은 `qwen`이며, LM Studio의 실제 모델 ID가 다르면 실행 전에 `LM_STUDIO_MODEL`을 설정하거나 웹 UI에서 모델 값을 변경합니다.

독립망 운영 기본 에이전트는 LM Studio입니다.

```bash
./scripts/run.sh
```

다른 URL을 테스트하려면 다음처럼 실행합니다.

```bash
LM_STUDIO_URL=http://172.16.100.51:1234 .venv/bin/python scripts/check_lmstudio.py
```

## wheelhouse 갱신

인터넷이 되는 준비 환경에서만 실행합니다.

```bash
./scripts/build_wheelhouse.sh
```

갱신 후 `vendor/wheels/SHA256SUMS`도 함께 갱신해야 합니다.
