"""Offline tests for the b2a_send HTTP/2-safe client (issue #19).

No network: ``urllib.request.urlopen`` is patched to return canned /proxy/send
payloads, so these assert the client's request-building and response-parsing
without a live Burp.
"""

import base64
import io
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT / "clients"))

import b2a_send  # noqa: E402


def _payload(status=200, body="", body_encoding="utf-8", headers_list=None,
             http_version="HTTP/2", request_id=42, extra=None):
    block = {
        "status_code": status,
        "headers": "",
        "headers_list": headers_list if headers_list is not None else [],
        "body": body,
        "body_encoding": body_encoding,
        "length": len(body),
        "http_version": http_version,
    }
    out = {"request_id": request_id, "response": block}
    if extra:
        out.update(extra)
    return out


class _FakeResponse:
    """Context-manager stand-in for the object urlopen returns."""

    def __init__(self, payload):
        self._data = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


class _Capture:
    """Patches urlopen, captures the outgoing Request, replies with `payload`."""

    def __init__(self, payload):
        self.payload = payload
        self.request = None

    def __call__(self, req, timeout=None):
        self.request = req
        self.timeout = timeout
        return _FakeResponse(self.payload)

    def sent_json(self):
        return json.loads(self.request.data.decode("utf-8"))


class SendRequestBuildingTests(unittest.TestCase):
    def test_minimal_get_builds_method_and_url(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().get("https://h2.example/api")
        sent = cap.sent_json()
        self.assertEqual(sent["method"], "GET")
        self.assertEqual(sent["url"], "https://h2.example/api")
        # No jar/tag/redirect noise when unset.
        self.assertNotIn("cookie_jar", sent)
        self.assertNotIn("session_tag", sent)
        self.assertNotIn("follow_redirects", sent)
        self.assertEqual(cap.request.get_method(), "POST")
        self.assertTrue(cap.request.full_url.endswith("/proxy/send"))

    def test_dict_headers_normalized_to_pairs(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().post(
                "https://h2.example/api",
                headers={"Authorization": "Bearer x", "Content-Type": "application/json"},
                body='{"a":1}',
            )
        sent = cap.sent_json()
        self.assertEqual(sent["method"], "POST")
        self.assertIn(["Authorization", "Bearer x"], sent["headers"])
        self.assertIn(["Content-Type", "application/json"], sent["headers"])
        self.assertEqual(sent["body"], '{"a":1}')

    def test_pair_headers_preserve_duplicates(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().get(
                "https://h2.example/api",
                headers=[("Cookie", "a=1"), ("Cookie", "b=2")],
            )
        self.assertEqual(
            cap.sent_json()["headers"], [["Cookie", "a=1"], ["Cookie", "b=2"]]
        )

    def test_bytes_body_sent_as_text(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().post("https://h2.example/api", body=b"raw-bytes")
        self.assertEqual(cap.sent_json()["body"], "raw-bytes")

    def test_cookie_jar_and_session_tag_propagate(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session(session_tag="engA", cookie_jar="use").get("https://h2.example/api")
        sent = cap.sent_json()
        self.assertEqual(sent["cookie_jar"], "use")
        self.assertEqual(sent["session_tag"], "engA")

    def test_follow_redirects_and_max(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().get(
                "https://h2.example/api", follow_redirects=True, max_redirects=3
            )
        sent = cap.sent_json()
        self.assertTrue(sent["follow_redirects"])
        self.assertEqual(sent["max_redirects"], 3)

    def test_base_url_trailing_slash_stripped(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session("http://127.0.0.1:7850/").get("https://h2.example/api")
        self.assertEqual(cap.request.full_url, "http://127.0.0.1:7850/proxy/send")


class ResponseParsingTests(unittest.TestCase):
    def test_utf8_body_and_status(self):
        payload = _payload(status=201, body="hello", http_version="HTTP/2")
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://h2.example/api")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.text, "hello")
        self.assertEqual(r.content, b"hello")
        self.assertEqual(r.http_version, "HTTP/2")
        self.assertEqual(r.request_id, 42)
        self.assertTrue(r.ok)

    def test_base64_body_decoded(self):
        raw = bytes(range(256))
        payload = _payload(body=base64.b64encode(raw).decode(), body_encoding="base64")
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://h2.example/bin")
        self.assertEqual(r.content, raw)

    def test_headers_case_insensitive(self):
        payload = _payload(headers_list=[
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Set-Cookie", "value": "s=1"},
        ])
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://h2.example/api")
        self.assertEqual(r.headers["content-type"], "application/json")
        self.assertEqual(r.headers.get("CONTENT-TYPE"), "application/json")
        self.assertIn("set-cookie", r.headers)
        self.assertIsNone(r.headers.get("missing"))

    def test_json_helper(self):
        payload = _payload(body='{"id": 7, "ok": true}')
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://h2.example/api")
        self.assertEqual(r.json(), {"id": 7, "ok": True})

    def test_error_status_is_response_not_exception(self):
        payload = _payload(status=500, body="boom")
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://h2.example/api")
        self.assertEqual(r.status_code, 500)
        self.assertFalse(r.ok)
        with self.assertRaises(b2a_send.B2AError):
            r.raise_for_status()

    def test_redirect_trail_exposed(self):
        payload = _payload(extra={"redirects": [
            {"status_code": 302, "from": "https://a/", "location": "https://b/"}
        ]})
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://a/", follow_redirects=True)
        self.assertEqual(len(r.redirects), 1)
        self.assertEqual(r.redirects[0]["location"], "https://b/")

    def test_missing_request_id_is_none(self):
        payload = _payload()
        del payload["request_id"]
        with mock.patch("urllib.request.urlopen", _Capture(payload)):
            r = b2a_send.Session().get("https://h2.example/api")
        self.assertIsNone(r.request_id)


class ErrorHandlingTests(unittest.TestCase):
    def test_burp2api_unreachable_raises_b2aerror(self):
        def boom(req, timeout=None):
            raise urllib.error.URLError("Connection refused")

        with mock.patch("urllib.request.urlopen", boom):
            with self.assertRaises(b2a_send.B2AError) as ctx:
                b2a_send.Session().get("https://h2.example/api")
        self.assertIn("cannot reach burp2api", str(ctx.exception))

    def test_control_http_error_surfaces_message(self):
        def boom(req, timeout=None):
            body = io.BytesIO(json.dumps({"message": "Burp API is not available."}).encode())
            raise urllib.error.HTTPError(req.full_url, 503, "Service Unavailable", {}, body)

        with mock.patch("urllib.request.urlopen", boom):
            with self.assertRaises(b2a_send.B2AError) as ctx:
                b2a_send.Session().get("https://h2.example/api")
        self.assertIn("503", str(ctx.exception))
        self.assertIn("Burp API is not available", str(ctx.exception))


class _FakeStdout(io.TextIOWrapper):
    """Real text stream over an in-memory buffer, so argparse's color probe
    (``os.isatty(stdout.fileno())`` on 3.14) works without a live terminal."""

    def __init__(self):
        self._raw = io.BytesIO()
        super().__init__(self._raw, encoding="utf-8", newline="")

    def fileno(self):
        raise io.UnsupportedOperation  # not a tty -> can_colorize() -> False

    def isatty(self):
        return False

    def getvalue(self):
        self.flush()
        return self._raw.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        # Keep argparse from probing the (mocked) stdout for color support.
        patcher = mock.patch.dict(os.environ, {"NO_COLOR": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _stdout(self):
        out = _FakeStdout()
        self.addCleanup(out.close)
        return out

    def test_cli_prints_body(self):
        payload = _payload(body="pong")
        out = self._stdout()
        with mock.patch("urllib.request.urlopen", _Capture(payload)), \
                mock.patch.object(b2a_send.sys, "stdout", out):
            rc = b2a_send.main(["https://h2.example/api"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), b"pong\n")

    def test_cli_header_and_method_parsed(self):
        cap = _Capture(_payload(body="x"))
        out = self._stdout()
        with mock.patch("urllib.request.urlopen", cap), \
                mock.patch.object(b2a_send.sys, "stdout", out):
            rc = b2a_send.main(["-X", "POST", "-H", "Authorization: Bearer t", "-d", "q", "https://h2.example/api"])
        self.assertEqual(rc, 0)
        sent = cap.sent_json()
        self.assertEqual(sent["method"], "POST")
        self.assertIn(["Authorization", "Bearer t"], sent["headers"])
        self.assertEqual(sent["body"], "q")

    def test_cli_idempotency_key_flag(self):
        cap = _Capture(_payload(body="x"))
        out = self._stdout()
        with mock.patch("urllib.request.urlopen", cap), \
                mock.patch.object(b2a_send.sys, "stdout", out):
            rc = b2a_send.main(["--idempotency-key", "cli-key", "https://h2.example/api"])
        self.assertEqual(rc, 0)
        self.assertEqual(cap.request.get_header("Idempotency-key"), "cli-key")

    def test_cli_reports_unreachable(self):
        def boom(req, timeout=None):
            raise urllib.error.URLError("refused")

        with mock.patch("urllib.request.urlopen", boom), \
                mock.patch.object(b2a_send.sys, "stderr", io.StringIO()) as err:
            rc = b2a_send.main(["https://h2.example/api"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot reach burp2api", err.getvalue())


class _StatusResponse:
    """A urlopen stand-in that also carries an HTTP status (for the 202 async path)."""

    def __init__(self, payload, status=200):
        self._data = json.dumps(payload).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


class _Script:
    """Patches urlopen with a scripted sequence of (status, payload) replies."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        status, payload = self.steps.pop(0)
        return _StatusResponse(payload, status)


class HttproxyCompatibilityTests(unittest.TestCase):
    """Additive httproxy support that must not regress burp2api behavior (#37)."""

    def test_no_token_sends_no_authorization_header(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().get("https://h/a")
        self.assertIsNone(cap.request.get_header("Authorization"))

    def test_configured_token_is_sent_only_in_authorization(self):
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session(token="s3cr3t").get("https://h/a")
        self.assertEqual(cap.request.get_header("Authorization"), "Bearer s3cr3t")
        # The token never leaks into the request body.
        self.assertNotIn("s3cr3t", cap.request.data.decode("utf-8"))

    def test_token_file_env_is_read(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".tok", delete=False) as handle:
            handle.write("filetoken\n")
            path = handle.name
        cap = _Capture(_payload())
        with mock.patch.dict(os.environ, {"HTTPROXY_TOKEN_FILE": path}, clear=False):
            with mock.patch("urllib.request.urlopen", cap):
                b2a_send.Session().get("https://h/a")
        os.unlink(path)
        self.assertEqual(cap.request.get_header("Authorization"), "Bearer filetoken")

    def test_string_request_id_is_accepted(self):
        payload = _payload()
        payload["request_id"] = "01a00000-0000-7000-8000-00000000abcd"
        cap = _Capture(payload)
        with mock.patch("urllib.request.urlopen", cap):
            r = b2a_send.Session().get("https://h/a")
        self.assertEqual(r.request_id, "01a00000-0000-7000-8000-00000000abcd")

    def test_send_carries_an_idempotency_key(self):
        # httproxy mandates an Idempotency-Key on POST /proxy/send; the client always sends one so a
        # token-required native backend accepts the call (#37). Harmless for burp2api.
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().get("https://h/a")
        self.assertTrue(
            cap.request.get_header("Idempotency-key"),
            "a POST /proxy/send carries an Idempotency-Key",
        )

    def test_distinct_calls_use_distinct_idempotency_keys(self):
        # Each LOGICAL call gets its own key, so two independent sends are two operations.
        cap1 = _Capture(_payload())
        cap2 = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap1):
            b2a_send.Session().get("https://h/a")
        with mock.patch("urllib.request.urlopen", cap2):
            b2a_send.Session().get("https://h/a")
        self.assertNotEqual(
            cap1.request.get_header("Idempotency-key"),
            cap2.request.get_header("Idempotency-key"),
        )

    def test_explicit_idempotency_key_is_used_verbatim(self):
        # An explicit key lets a caller (or the release harness) pin one logical call across a
        # retry, so httproxy dedups it to EXACTLY ONE target effect.
        cap = _Capture(_payload())
        with mock.patch("urllib.request.urlopen", cap):
            b2a_send.Session().get("https://h/a", idempotency_key="fixed-123")
        self.assertEqual(cap.request.get_header("Idempotency-key"), "fixed-123")

    def test_idempotency_key_is_on_the_post_of_the_async_path(self):
        # The POST that admits the operation carries the key; the subsequent polls are GETs.
        accepted = {"operation_id": "op-1", "poll_url": "/api/v1/operations/op-1"}
        done = {
            "operation_id": "op-1",
            "state": "succeeded",
            "flow_id": "flow-1",
            "result": {
                "protocol": "h2",
                "status": 200,
                "headers": [],
                "body": {"data": "", "encoding": "utf-8"},
                "redirects": [],
            },
        }
        script = _Script([(202, accepted), (200, done)])
        with mock.patch("urllib.request.urlopen", script):
            b2a_send.Session().get("https://h/a", idempotency_key="k9")
        self.assertEqual(script.requests[0].get_method(), "POST")
        self.assertEqual(script.requests[0].get_header("Idempotency-key"), "k9")

    def test_202_is_polled_to_completion(self):
        accepted = {"operation_id": "op-1", "poll_url": "/api/v1/operations/op-1"}
        running = {"operation_id": "op-1", "state": "running"}
        done = {
            "operation_id": "op-1",
            "state": "succeeded",
            "flow_id": "flow-1",
            "result": {
                "protocol": "h2",
                "status": 200,
                "headers": [{"name": "X-Done", "value": "1", "value_encoding": "utf8"}],
                "body": {"data": "hi", "encoding": "utf-8"},
                "redirects": [],
            },
        }
        script = _Script([(202, accepted), (200, running), (200, done)])
        with mock.patch("urllib.request.urlopen", script):
            r = b2a_send.Session().get("https://h/a")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.http_version, "HTTP/2")
        self.assertEqual(r.request_id, "flow-1")
        self.assertEqual(r.text, "hi")
        # The first call was the POST, the rest were polls of the operation.
        self.assertEqual(len(script.requests), 3)


if __name__ == "__main__":
    unittest.main()
