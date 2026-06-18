"""Abuse-hardening tests for the relay server (src/retalk/server.py).

These are independent of the 14 stateful acceptance criteria in
test_e2ee.py; each test starts its own server process with the relevant
hardening config and asserts:

  A. An oversized request body is rejected with HTTP 413 before the server
     reads or dispatches it, while a normal-sized request still works.
  B. With a low per-fingerprint rate limit set, a burst of valid signed
     requests from one caller eventually trips HTTP 429, while staying
     under the limit passes (the limit is per minute, so normal traffic
     well below the cap is unaffected).

Run from the repo root:
  .venv/bin/python -m unittest discover -s tests   (all test files)
  .venv/bin/python tests/test_hardening.py         (this file directly)
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

PORT_BODY = 8771
PORT_RATE = 8772


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


def start_server(db: str, port: int, **extra_env) -> subprocess.Popen:
    env = dict(os.environ, RETALK_SERVER_DB=db, RETALK_SERVER_HOST="127.0.0.1",
               RETALK_SERVER_PORT=str(port),
               RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{port}", **extra_env)
    proc = subprocess.Popen(
        [sys.executable, "-m", "retalk.server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_port(port)
    return proc


def raw_post(url: str, body: bytes, content_length: int | None = None):
    """POST raw bytes; optionally lie about Content-Length to exercise the
    body-size cap without actually transferring a huge payload.

    Returns (status, parsed_json_body)."""
    length = len(body) if content_length is None else content_length
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"content-type": "application/json",
                 "content-length": str(length)})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class TestBodySizeCap(unittest.TestCase):
    def test_oversized_body_rejected_413(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            # cap small enough to test cheaply, large enough for a real
            # publish() (which uploads a batch of one-time keys, ~7 KiB)
            cap = 20000
            proc = start_server(db, PORT_BODY, RETALK_SERVER_MAX_BODY=str(cap))
            url = f"http://127.0.0.1:{PORT_BODY}"
            try:
                # a normal signed request stays well under the cap and works
                u = User(url, "secret", name="alice", store=os.path.join(tmp, "a.db"))
                u.publish()
                self.assertIsInstance(u._call("count_keys"), dict)

                # an oversized body is rejected with 413 and never dispatched
                big = json.dumps({"tool": "count_keys",
                                  "args": {"junk": "x" * (cap + 10000)}}).encode()
                self.assertGreater(len(big), cap)
                status, payload = raw_post(url, big)
                self.assertEqual(status, 413, payload)
                self.assertIn("error", payload)

                # the cap is enforced from Content-Length alone: even a huge
                # declared length is rejected without the body being read
                status, payload = raw_post(url, b"{}", content_length=10_000_000)
                self.assertEqual(status, 413, payload)
            finally:
                proc.terminate()
                proc.wait(timeout=10)


class TestRateLimit(unittest.TestCase):
    def test_rate_limit_trips_429_then_normal_traffic_passes(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            limit = 5
            proc = start_server(db, PORT_RATE,
                                RETALK_SERVER_RATE_LIMIT=str(limit))
            url = f"http://127.0.0.1:{PORT_RATE}"
            try:
                u = User(url, "secret", name="alice", store=os.path.join(tmp, "a.db"))
                u.publish()  # first request from this fingerprint

                # publish() already consumed at least one slot; keep calling
                # count_keys (fresh nonce each time, so not a replay) until the
                # per-fingerprint limit trips with HTTP 429.
                tripped = False
                for _ in range(limit + 5):
                    try:
                        u._call("count_keys")
                    except RuntimeError as e:
                        # _call_raw wraps HTTPError 429 as a RuntimeError whose
                        # message carries the server's {"error": ...} text
                        self.assertIn("rate limit", str(e), e)
                        tripped = True
                        break
                self.assertTrue(tripped, "rate limit never tripped under a burst")
            finally:
                proc.terminate()
                proc.wait(timeout=10)

    def test_normal_traffic_under_limit_passes(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            # generous limit; a handful of requests must all succeed
            proc = start_server(db, PORT_RATE + 10,
                                RETALK_SERVER_RATE_LIMIT="100")
            url = f"http://127.0.0.1:{PORT_RATE + 10}"
            try:
                u = User(url, "secret", name="alice", store=os.path.join(tmp, "a.db"))
                u.publish()
                for _ in range(10):
                    self.assertIsInstance(u._call("count_keys"), dict)
            finally:
                proc.terminate()
                proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
