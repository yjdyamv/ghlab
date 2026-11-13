"""Client for the ghlab daemon (stdlib only)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .protocol import DEFAULT_HOST, DEFAULT_PORT


class RemoteError(RuntimeError):
    def __init__(self, message: str, trace: str = ""):
        super().__init__(message)
        self.trace = trace


class Client:
    def __init__(self, url: str | None = None, timeout: float | None = None):
        self.url = url or os.environ.get("GHLAB_URL", f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/")
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
        except TimeoutError as ex:
            raise RemoteError(
                f"the daemon did not answer within {self.timeout:g}s; a long analysis may "
                f"still be running -- `ghlab job --list` or `ghlab ping` show what it is doing"
            ) from ex
        except urllib.error.URLError as ex:
            # The OS message is localised (and mojibake in a non-UTF console), so name the
            # situation instead: an agent reading this needs the next command, not errno text.
            reason = getattr(ex, "reason", ex)
            debug = bool(os.environ.get("GHLAB_DEBUG"))
            if isinstance(reason, ConnectionRefusedError):
                message = f"nothing is listening on {self.url}"
            else:
                message = f"cannot reach {self.url}"
            if debug:
                message += f" ({reason})"
            port = self._port()
            message += (
                f"; start it with `ghlab start --port {port}`"
                if port
                else "; start it with `ghlab start`"
            )
            raise RemoteError(message) from ex
        if not payload.get("ok"):
            raise RemoteError(payload.get("error", "unknown error"), payload.get("trace", ""))
        return payload

    def _port(self) -> int:
        """The port in `self.url`, or 0: useful for "start it with --port N"."""
        try:
            return int(urllib.parse.urlsplit(self.url).port or 0)
        except ValueError:
            return 0

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
