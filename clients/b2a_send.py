"""HTTP/2-safe request helper for scripted probing through burp2api.

Why this exists (issue #19)
---------------------------
When the upstream origin serves HTTP/2 and a probe is routed through the Burp
proxy, a ``python-requests`` / ``urllib3`` client aborts the proxied response
with::

    ('Connection aborted.', UnknownProtocol('HTTP/2'))

``urllib3`` speaks only HTTP/1.1, so every probe errors *client-side* and
returns no status -- a whole batch reads as "endpoint broken" when it is really
a client limitation.

burp2api already exposes ``POST /proxy/send``, which issues the request through
Burp's own HTTP stack (which negotiates HTTP/2 natively) and returns the parsed
response. This module is a thin, dependency-free client for that endpoint: the
fuzzer talks plain HTTP/1.1 JSON to burp2api on ``127.0.0.1:7850`` while Burp
handles the HTTP/2 upstream, so ``UnknownProtocol('HTTP/2')`` cannot occur.

Drop-in usage
-------------
>>> from b2a_send import Session
>>> s = Session()                       # http://127.0.0.1:7850
>>> r = s.get("https://h2-origin.example/api/v1/resource")
>>> r.status_code, r.http_version
(200, 'HTTP/2')
>>> r.json()["id"]

The :class:`Response` mirrors the small slice of the ``requests`` API that
scripted probing actually uses: ``status_code``, ``headers`` (case-insensitive),
``text``, ``content`` (bytes), ``json()`` and ``ok``.

Requires only the Python standard library. Python 3.8+.
"""

from __future__ import annotations

import argparse
import base64
import json as _json
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

__all__ = ["Session", "Response", "B2AError", "send"]

DEFAULT_BASE_URL = "http://127.0.0.1:7850"
DEFAULT_TIMEOUT = 30.0

# Public states a native (httproxy) operation can reach; used only when a send returns 202.
_TERMINAL_STATES = frozenset(
    {"succeeded", "failed", "cancelled", "outcome_unknown"}
)


def _resolve_token(explicit: Optional[str]) -> Optional[str]:
    """Resolve the optional bearer token for a token-required backend (e.g. httproxy).

    Precedence: an explicit value, then a token-FILE path (``B2A_TOKEN_FILE`` /
    ``HTTPROXY_TOKEN_FILE``), then a token VALUE env var (``B2A_TOKEN`` /
    ``HTTPROXY_TOKEN``). Returns ``None`` when nothing is configured, so a token-less
    backend such as burp2api on loopback keeps working unchanged. The token is never
    placed in a CLI argument, printed, or logged.
    """
    import os

    if explicit:
        return explicit.strip()
    for var in ("B2A_TOKEN_FILE", "HTTPROXY_TOKEN_FILE"):
        path = os.environ.get(var)
        if path:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return handle.read().strip()
            except OSError as exc:
                raise B2AError(f"cannot read bearer token file ({exc.strerror})") from None
    for var in ("B2A_TOKEN", "HTTPROXY_TOKEN"):
        value = os.environ.get(var)
        if value:
            return value.strip()
    return None


class B2AError(RuntimeError):
    """A request could not be issued through burp2api.

    Raised when burp2api itself is unreachable (Burp not running / wrong port)
    or when ``/proxy/send`` returns a non-2xx control response (400/500/503).
    A response *from the target* -- including a 4xx/5xx target status -- is a
    successful send and is returned as a :class:`Response`, never raised.
    """


class _CaseInsensitiveDict(dict):
    """Minimal case-insensitive header mapping (like requests' own)."""

    def __init__(self, pairs: Optional[List[Tuple[str, str]]] = None) -> None:
        super().__init__()
        self._lower: Dict[str, str] = {}
        for name, value in pairs or []:
            self[name] = value

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key, value)
        self._lower[key.lower()] = key

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(self._lower.get(key.lower(), key))

    def __contains__(self, key: object) -> bool:  # type: ignore[override]
        return isinstance(key, str) and key.lower() in self._lower

    def get(self, key: str, default: Any = None) -> Any:
        real = self._lower.get(key.lower())
        return super().__getitem__(real) if real is not None else default


class Response:
    """The parsed target response returned by ``/proxy/send``.

    Attributes
    ----------
    status_code : int
        The status the target returned.
    headers : Mapping[str, str]
        Case-insensitive view of the response headers.
    content : bytes
        Raw body bytes (Base64 is decoded transparently for binary bodies).
    text : str
        Body decoded as UTF-8 (``errors='replace'``).
    http_version : str
        ``"HTTP/2"``, ``"HTTP/1.1"`` etc., as negotiated by Burp upstream.
    request_id : Optional[int]
        The ``proxy_traffic.id`` burp2api stored for this send (usable with
        ``/proxy/replay``), or ``None`` if the row was not persisted.
    redirects : List[dict]
        The redirect trail when ``follow_redirects`` was set, else empty.
    raw : dict
        The full decoded ``/proxy/send`` JSON payload.
    """

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.raw: Dict[str, Any] = dict(payload)
        block = payload.get("response") or {}
        self.status_code: int = int(block.get("status_code", 0))
        self.http_version: str = block.get("http_version", "")
        # burp2api returns an int id; httproxy returns the canonical string flow id. Accept both.
        self.request_id: Optional[Union[int, str]] = payload.get("request_id")
        self.redirects: List[Dict[str, Any]] = list(payload.get("redirects", []) or [])

        pairs: List[Tuple[str, str]] = []
        for item in block.get("headers_list") or []:
            name = item.get("name")
            if name is not None:
                pairs.append((name, item.get("value", "")))
        self.headers: _CaseInsensitiveDict = _CaseInsensitiveDict(pairs)
        # Fall back to the raw header blob only when headers_list is absent.
        self._headers_blob: str = block.get("headers", "")

        body = block.get("body", "") or ""
        if block.get("body_encoding") == "base64":
            self.content: bytes = base64.b64decode(body) if body else b""
        else:
            self.content = body.encode("utf-8")

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    def json(self, **kwargs: Any) -> Any:
        """Parse the body as JSON (mirrors ``requests.Response.json``)."""
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self) -> "Response":
        if self.status_code >= 400:
            raise B2AError(f"target returned HTTP {self.status_code}")
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] {self.http_version}>"


HeadersArg = Union[Mapping[str, str], List[Tuple[str, str]], None]
BodyArg = Union[str, bytes, None]


class Session:
    """A reusable client for burp2api ``/proxy/send``.

    Parameters
    ----------
    base_url : str
        Where burp2api listens. Default ``http://127.0.0.1:7850``.
    session_tag : Optional[str]
        Tag stored with the traffic and used to key the server-side cookie jar.
    cookie_jar : str
        ``"off"`` (default, stateless), ``"use"`` (apply+update the jar under
        ``session_tag``), or ``"reset"`` (clear it first, then use).
    timeout : float
        Per-request timeout, in seconds, for the local call to burp2api.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        session_tag: Optional[str] = None,
        cookie_jar: str = "off",
        timeout: float = DEFAULT_TIMEOUT,
        token: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session_tag = session_tag
        self.cookie_jar = cookie_jar
        self.timeout = timeout
        # Optional bearer for a token-required backend (httproxy). Absent → token-less
        # loopback (burp2api) works unchanged.
        self._token = _resolve_token(token)

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    # -- core --------------------------------------------------------------
    def send(
        self,
        method: str,
        url: str,
        *,
        headers: HeadersArg = None,
        body: BodyArg = None,
        follow_redirects: bool = False,
        max_redirects: Optional[int] = None,
        cookie_jar: Optional[str] = None,
        session_tag: Optional[str] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> Response:
        """Issue ``method url`` through Burp and return the target response.

        ``headers`` accepts a dict or a list of ``(name, value)`` pairs (use the
        list form to send a repeated header such as multiple ``Cookie`` lines).
        ``body`` may be ``str`` or ``bytes``; bytes are sent verbatim as text.

        ``idempotency_key`` sets the ``Idempotency-Key`` sent on the POST. A
        token-required native backend (httproxy) MANDATES this key; each logical
        call gets one fresh key by default (a random UUID), and passing an explicit
        value lets a caller re-issue the SAME logical call so the backend dedups it
        to exactly one target effect. It is harmless (an unknown header) to
        burp2api, so it is always sent.
        """
        payload: Dict[str, Any] = {"method": method.upper(), "url": url}

        if headers is not None:
            payload["headers"] = _headers_to_pairs(headers)
        if body is not None:
            payload["body"] = body.decode("utf-8", errors="surrogateescape") if isinstance(body, bytes) else body

        jar = cookie_jar if cookie_jar is not None else self.cookie_jar
        if jar and jar != "off":
            payload["cookie_jar"] = jar
        tag = session_tag if session_tag is not None else self.session_tag
        if tag is not None:
            payload["session_tag"] = tag
        if follow_redirects:
            payload["follow_redirects"] = True
            if max_redirects is not None:
                payload["max_redirects"] = max_redirects

        data = _json.dumps(payload).encode("utf-8")
        request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        # One stable Idempotency-Key per logical call (a fresh UUID unless the caller pinned one),
        # reused across this call's internal poll cycle. httproxy requires it; burp2api ignores it.
        request_headers["Idempotency-Key"] = idempotency_key or uuid.uuid4().hex
        request_headers.update(self._auth_headers())
        req = urllib.request.Request(
            f"{self.base_url}/proxy/send",
            data=data,
            method="POST",
            headers=request_headers,
        )
        deadline = _monotonic() + (timeout or self.timeout)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                status = getattr(resp, "status", None) or 200
                decoded = _json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # A control error from the backend itself (400/500/503), not a target
            # status. Surface its message rather than masquerading as a Response.
            detail = _error_detail(exc)
            raise B2AError(f"/proxy/send returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise B2AError(
                f"cannot reach burp2api at {self.base_url} ({exc.reason}); "
                "is the backend (burp2api / httproxy) running?"
            ) from exc

        # A synchronous backend (burp2api) always returns the completed response. A native
        # (httproxy) backend may accept the operation and return 202 with a poll reference; poll
        # it under the same overall timeout, then present the completed legacy response.
        if status == 202:
            decoded = self._poll_operation(decoded, deadline)
        return Response(decoded)

    def _poll_operation(self, accepted: Dict[str, Any], deadline: float) -> Dict[str, Any]:
        """Poll a native operation to a terminal state and return the legacy send payload."""
        poll_url = accepted.get("poll_url")
        operation_id = accepted.get("operation_id")
        if not poll_url:
            if operation_id is None:
                raise B2AError("send was accepted but no poll reference was returned")
            poll_url = f"/api/v1/operations/{operation_id}"
        while True:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise B2AError(
                    f"operation {operation_id} did not complete within the timeout; "
                    "poll it again with a longer timeout"
                )
            wait_ms = max(1, min(30000, int(remaining * 1000)))
            sep = "&" if "?" in poll_url else "?"
            req = urllib.request.Request(
                f"{self.base_url}{poll_url}{sep}wait_ms={wait_ms}",
                method="GET",
                headers={"Accept": "application/json", **self._auth_headers()},
            )
            try:
                with urllib.request.urlopen(req, timeout=remaining) as resp:
                    view = _json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raise B2AError(
                    f"polling operation returned HTTP {exc.code}: {_error_detail(exc)}"
                ) from exc
            except urllib.error.URLError as exc:
                raise B2AError(f"cannot reach the proxy API while polling ({exc.reason})") from exc
            if view.get("state") in _TERMINAL_STATES:
                return _operation_view_to_payload(view)

    # -- verb helpers ------------------------------------------------------
    def get(self, url: str, **kwargs: Any) -> Response:
        return self.send("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.send("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self.send("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Response:
        return self.send("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.send("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self.send("HEAD", url, **kwargs)


def _operation_view_to_payload(view: Dict[str, Any]) -> Dict[str, Any]:
    """Map a native operation view to the legacy /proxy/send payload the Response parses."""
    result = view.get("result") or {}
    body = result.get("body") or {}
    payload: Dict[str, Any] = {
        "request_id": view.get("flow_id"),
        "redirects": result.get("redirects", []) or [],
    }
    if view.get("state") == "succeeded" and result:
        payload["response"] = {
            "status_code": result.get("status", 0),
            "http_version": _protocol_to_version(result.get("protocol", "")),
            "headers_list": [
                {"name": h.get("name", ""), "value": h.get("value", "")}
                for h in result.get("headers", []) or []
            ],
            "body": body.get("data", ""),
            "body_encoding": body.get("encoding", "utf-8"),
        }
    else:
        payload["error"] = view.get("error")
    return payload


def _protocol_to_version(protocol: str) -> str:
    mapping = {"http/1.0": "HTTP/1.0", "http/1.1": "HTTP/1.1", "h2": "HTTP/2", "http/2": "HTTP/2"}
    return mapping.get(protocol, "HTTP/1.1")


def _monotonic() -> float:
    import time

    return time.monotonic()


def send(method: str, url: str, *, base_url: str = DEFAULT_BASE_URL, **kwargs: Any) -> Response:
    """One-shot convenience wrapper around :meth:`Session.send`."""
    return Session(base_url).send(method, url, **kwargs)


def _headers_to_pairs(headers: HeadersArg) -> List[List[str]]:
    """Normalize headers to the ``[[name, value], ...]`` form /proxy/send takes."""
    if headers is None:
        return []
    items = headers.items() if isinstance(headers, Mapping) else headers
    return [[str(name), str(value)] for name, value in items]


def _error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        body = _json.loads(exc.read().decode("utf-8"))
        return body.get("message") or body.get("error") or exc.reason
    except Exception:
        return str(exc.reason)


# --------------------------------------------------------------------------
# CLI: an HTTP/2-safe curl-lite for one-off checks.
# --------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="b2a_send",
        description=(
            "HTTP/2-safe request through burp2api's /proxy/send. Routes the "
            "request through Burp (which speaks HTTP/2) so scripted probing does "
            "not break with UnknownProtocol('HTTP/2') the way python-requests does."
        ),
    )
    p.add_argument("url", help="Target URL")
    p.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument(
        "-H", "--header", action="append", default=[], metavar="NAME: VALUE",
        help="Request header; repeatable",
    )
    p.add_argument("-d", "--data", help="Request body")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"proxy API base URL (burp2api or httproxy; default: {DEFAULT_BASE_URL})")
    p.add_argument(
        "--token-file",
        metavar="PATH",
        help="File holding a bearer token for a token-required backend (httproxy). "
        "The token value is never accepted on the command line; env "
        "B2A_TOKEN_FILE / HTTPROXY_TOKEN_FILE / B2A_TOKEN / HTTPROXY_TOKEN also work.",
    )
    p.add_argument(
        "--idempotency-key",
        metavar="KEY",
        help="Idempotency-Key for POST /proxy/send. httproxy requires one; a fresh UUID is used per "
        "call by default. Pin a value (or set env B2A_IDEMPOTENCY_KEY) to re-issue the SAME logical "
        "call so the backend dedups it to exactly one target effect.",
    )
    p.add_argument("--session-tag", help="Traffic/cookie-jar session tag")
    p.add_argument(
        "--cookie-jar", choices=["off", "use", "reset"], default="off",
        help="Server-side cookie jar mode (default: off)",
    )
    p.add_argument("-L", "--location", action="store_true", help="Follow redirects")
    p.add_argument("--max-redirects", type=int, help="Redirect hop limit (with -L)")
    p.add_argument("-i", "--include", action="store_true", help="Print status line and headers before the body")
    p.add_argument("--json", action="store_true", help="Print the full /proxy/send JSON instead of the body")
    return p


def _parse_header(raw: str) -> Tuple[str, str]:
    name, sep, value = raw.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError(f"invalid header {raw!r}; expected 'Name: value'")
    return name.strip(), value.strip()


def main(argv: Optional[List[str]] = None) -> int:
    import os

    args = _build_parser().parse_args(argv)
    headers = [_parse_header(h) for h in args.header] if args.header else None
    idempotency_key = args.idempotency_key or os.environ.get("B2A_IDEMPOTENCY_KEY")
    token = None
    if args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            print(f"error: cannot read token file ({exc.strerror})", file=sys.stderr)
            return 2
    try:
        r = Session(
            args.base_url,
            session_tag=args.session_tag,
            cookie_jar=args.cookie_jar,
            token=token,
        ).send(
            args.method,
            args.url,
            headers=headers,
            body=args.data,
            follow_redirects=args.location,
            max_redirects=args.max_redirects,
            idempotency_key=idempotency_key,
        )
    except B2AError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(_json.dumps(r.raw, indent=2))
        return 0
    if args.include:
        print(f"{r.http_version} {r.status_code}")
        for name in r.headers:
            print(f"{name}: {r.headers[name]}")
        print()
    sys.stdout.buffer.write(r.content)
    if r.content and not r.content.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
