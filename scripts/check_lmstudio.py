from __future__ import annotations

import json
import os
import sys
from urllib import request
from urllib.error import HTTPError, URLError


def main() -> int:
    base_url = os.getenv("LM_STUDIO_URL", "http://172.16.100.51:1234").rstrip("/")
    if base_url.endswith("/v1"):
        models_url = f"{base_url}/models"
    else:
        models_url = f"{base_url}/v1/models"

    req = request.Request(models_url, headers={"Accept": "application/json"}, method="GET")
    try:
        with request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        print(f"LM Studio HTTP error: {exc.code}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"LM Studio connection failed: {exc.reason}", file=sys.stderr)
        return 1
    except TimeoutError:
        print("LM Studio connection timed out", file=sys.stderr)
        return 1

    models = payload.get("data", [])
    print(f"LM Studio reachable: {models_url}")
    if models:
        for model in models:
            print(f"- {model.get('id', 'unknown')}")
    else:
        print("- no models returned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
