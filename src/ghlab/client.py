"""Client for the ghlab daemon (stdlib only)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .protocol import DEFAULT_HOST, DEFAULT_PORT


class RemoteError(RuntimeError):
    def __init__(self, message: str, trace: str = ""):
        super().__init__(message)
        self.trace = trace


class Client:
    def __init__(self, url: str | None = None, timeout: float | None = None):
        self.url = url or os.environ.get(
            "GHLAB_URL", f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/"
        )
        # GHLAB_TIMEOUT lets an MCP/editor integration set its own budget without
        # passing it through every call.
        self.timeout = float(timeout or os.environ.get("GHLAB_TIMEOUT", 300))

    def raw(self, request: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(request, ensure_ascii=False).encode()
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as ex:
            try:
                payload = json.loads(ex.read())
            except Exception:  # noqa: BLE001
                raise RemoteError(f"HTTP {ex.code}: {ex.reason}") from ex
        except urllib.error.URLError as ex:
            raise RemoteError(
                f"cannot reach {self.url} ({ex.reason}); start it with `ghlab start`"
            ) from ex
        if not payload.get("ok"):
            raise RemoteError(payload.get("error", "unknown error"), payload.get("trace", ""))
        return payload

    def call(self, cmd: str, **params: Any) -> Any:
        return self.raw({"cmd": cmd, **params})["result"]

    def info(self) -> dict[str, Any]:
        with urllib.request.urlopen(self.url, timeout=5) as resp:
            return json.loads(resp.read())

    def alive(self) -> bool:
        try:
            return bool(self.info().get("ok"))
        except Exception:  # noqa: BLE001
            return False
