"""Tests for the optional /admin endpoint and API-key access control
(src/retalk/server.py + client wiring in user.py/cli.py).

Each test starts its own server process with the relevant config and asserts:

  A. /admin is disabled (404) unless an admin password is set; with a password
     it requires HTTP Basic auth (401 on missing/wrong creds) and then mints,
     lists, disables, and deletes keys — all over HTTP.
  B. With --require-api-key, tool requests without a valid key are rejected
     (401); a client carrying a minted key works; disabling/deleting the key
     locks it out again. The key is stored hashed (never as plaintext).

These are independent of the 14 stateful acceptance criteria in test_e2ee.py.

Run from the repo root:
  .venv/bin/python -m unittest discover -s tests
  .venv/bin/python tests/test_admin_api_keys.py
"""

import base64
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

PORT_DISABLED = 8790
PORT_ADMIN = 8791
PORT_ENFORCE = 8792
PORT_PREFIX = 8793
PORT_XKEY = 8794
PORT_LOCKDOWN = 8795


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


def http(method: str, url: str, *, basic: tuple | None = None,
         body: dict | None = None, extra: dict | None = None):
    """Make an HTTP request; return (status, parsed-or-text). `basic` is an
    optional (user, password) tuple for HTTP Basic auth; `extra` adds raw
    headers (e.g. an API-key header)."""
    headers = dict(extra or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    if basic is not None:
        cred = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        headers["authorization"] = f"Basic {cred}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")


class TestAdminDisabledByDefault(unittest.TestCase):
    def test_admin_404_and_open_relay_works(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT_DISABLED)  # no admin password
            url = f"http://127.0.0.1:{PORT_DISABLED}"
            try:
                # /admin is disabled when no password is configured
                self.assertEqual(http("GET", url + "/admin")[0], 404)
                self.assertEqual(
                    http("POST", url + "/admin", body={"action": "list"})[0], 404)
                # and the relay is fully usable without any key (open default)
                u = User(url, "s", name="a", store=os.path.join(tmp, "a.db"))
                u.publish()
                self.assertIsInstance(u._call("count_keys"), dict)
            finally:
                proc.terminate()
                proc.wait(timeout=10)


class TestAdminAuthAndKeyManagement(unittest.TestCase):
    def test_basic_auth_and_crud(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            pw = "hunter2"
            proc = start_server(db, PORT_ADMIN,
                                RETALK_SERVER_ADMIN_PASSWORD=pw)
            url = f"http://127.0.0.1:{PORT_ADMIN}"
            admin = url + "/admin"
            try:
                # missing creds -> 401; wrong password -> 401
                self.assertEqual(
                    http("POST", admin, body={"action": "list"})[0], 401)
                self.assertEqual(
                    http("POST", admin, basic=("admin", "nope"),
                         body={"action": "list"})[0], 401)

                # correct password: list is empty, then create a key
                st, payload = http("POST", admin, basic=("admin", pw),
                                   body={"action": "list"})
                self.assertEqual(st, 200, payload)
                self.assertEqual(payload["keys"], [])

                st, created = http("POST", admin, basic=("admin", pw),
                                   body={"action": "create", "label": "alice"})
                self.assertEqual(st, 200, created)
                self.assertIn("key", created)        # raw key returned once
                self.assertIn("key_hash", created)
                raw_key, kh = created["key"], created["key_hash"]

                # list shows the key by hash/label, never the raw value
                st, payload = http("POST", admin, basic=("admin", pw),
                                   body={"action": "list"})
                self.assertEqual(len(payload["keys"]), 1, payload)
                self.assertEqual(payload["keys"][0]["label"], "alice")
                self.assertNotIn(raw_key, json.dumps(payload))

                # stored hashed: DB holds sha256(key), not the raw key
                row = sqlite3.connect(db).execute(
                    "SELECT key_hash FROM api_keys").fetchone()
                self.assertEqual(row[0], hashlib.sha256(raw_key.encode()).hexdigest())
                self.assertEqual(row[0], kh)

                # the GET page renders and shows the hash, not the raw key
                st, page = http("GET", admin, basic=("admin", pw))
                self.assertEqual(st, 200, page)
                self.assertIn(kh, page)
                self.assertNotIn(raw_key, page)

                # delete it; list is empty again
                st, out = http("POST", admin, basic=("admin", pw),
                               body={"action": "delete", "key_hash": kh})
                self.assertEqual((st, out.get("deleted")), (200, 1))
                self.assertEqual(
                    http("POST", admin, basic=("admin", pw),
                         body={"action": "list"})[1]["keys"], [])
            finally:
                proc.terminate()
                proc.wait(timeout=10)

    def test_path_prefix_and_malformed_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            pw = "pw"
            proc = start_server(db, PORT_PREFIX, RETALK_SERVER_ADMIN_PASSWORD=pw)
            url = f"http://127.0.0.1:{PORT_PREFIX}"
            try:
                # /admin is matched by its path suffix, so it also works behind
                # a prefix (a proxy mounting the relay at /v1/relay)
                st, payload = http("POST", url + "/v1/relay/admin",
                                   basic=("admin", pw), body={"action": "list"})
                self.assertEqual(st, 200, payload)
                self.assertEqual(payload["keys"], [])

                # unknown action -> 400 with a helpful error
                st, payload = http("POST", url + "/admin", basic=("admin", pw),
                                   body={"action": "frobnicate"})
                self.assertEqual(st, 400, payload)
                self.assertIn("unknown admin action", payload["error"])

                # disable/delete of a non-existent key_hash -> 0 rows affected
                st, payload = http("POST", url + "/admin", basic=("admin", pw),
                                   body={"action": "disable",
                                         "key_hash": "deadbeef"})
                self.assertEqual((st, payload.get("updated")), (200, 0))
                st, payload = http("POST", url + "/admin", basic=("admin", pw),
                                   body={"action": "delete",
                                         "key_hash": "deadbeef"})
                self.assertEqual((st, payload.get("deleted")), (200, 0))
            finally:
                proc.terminate()
                proc.wait(timeout=10)


class TestApiKeyEnforcement(unittest.TestCase):
    def test_enforced_relay_requires_valid_key(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            pw = "admin-pw"
            proc = start_server(db, PORT_ENFORCE,
                                RETALK_SERVER_ADMIN_PASSWORD=pw,
                                RETALK_SERVER_REQUIRE_API_KEY="1")
            url = f"http://127.0.0.1:{PORT_ENFORCE}"
            admin = url + "/admin"
            try:
                # no key -> tool requests are rejected (publish -> 401)
                u_nokey = User(url, "s", name="a", store=os.path.join(tmp, "a.db"))
                with self.assertRaises(RuntimeError) as cm:
                    u_nokey.publish()
                self.assertIn("API key", str(cm.exception))

                # admin mints a key
                _, created = http("POST", admin, basic=("admin", pw),
                                  body={"action": "create", "label": "bot"})
                key, kh = created["key"], created["key_hash"]

                # a client carrying the key can use the relay
                u = User(url, "s", name="a", store=os.path.join(tmp, "b.db"),
                         api_key=key)
                u.publish()
                self.assertIsInstance(u._call("count_keys"), dict)

                # a bogus key is rejected
                u_bad = User(url, "s", name="a", store=os.path.join(tmp, "c.db"),
                             api_key="not-a-real-key")
                with self.assertRaises(RuntimeError):
                    u_bad.publish()

                # disabling the key locks the good client out...
                http("POST", admin, basic=("admin", pw),
                     body={"action": "disable", "key_hash": kh})
                with self.assertRaises(RuntimeError):
                    u._call("count_keys")

                # ...re-enabling restores access
                http("POST", admin, basic=("admin", pw),
                     body={"action": "enable", "key_hash": kh})
                self.assertIsInstance(u._call("count_keys"), dict)
            finally:
                proc.terminate()
                proc.wait(timeout=10)

    def test_xkey_header_and_delete_revokes(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            pw = "pw"
            proc = start_server(db, PORT_XKEY, RETALK_SERVER_ADMIN_PASSWORD=pw,
                                RETALK_SERVER_REQUIRE_API_KEY="1")
            url = f"http://127.0.0.1:{PORT_XKEY}"
            try:
                _, created = http("POST", url + "/admin", basic=("admin", pw),
                                  body={"action": "create", "label": "x"})
                key, kh = created["key"], created["key_hash"]

                # the key is accepted via the X-Retalk-Key header (the Bearer
                # alternative). Build a valid signed request and send it with
                # that header only.
                u = User(url, "s", name="a", store=os.path.join(tmp, "a.db"),
                         api_key=key)
                body = {"tool": "count_keys",
                        "args": {"auth": u._auth_fields("count_keys", {})}}
                st, payload = http("POST", url, body=body,
                                   extra={"x-retalk-key": key})
                self.assertEqual(st, 200, payload)
                self.assertIn("unclaimed", payload)

                # the same valid request with NO key header at all -> 401
                body = {"tool": "count_keys",
                        "args": {"auth": u._auth_fields("count_keys", {})}}
                st, payload = http("POST", url, body=body)
                self.assertEqual(st, 401, payload)

                # deleting the key revokes a client that was using it (Bearer)
                u.publish()
                http("POST", url + "/admin", basic=("admin", pw),
                     body={"action": "delete", "key_hash": kh})
                with self.assertRaises(RuntimeError):
                    u._call("count_keys")
            finally:
                proc.terminate()
                proc.wait(timeout=10)


class TestEnforceWithAdminDisabled(unittest.TestCase):
    def test_minted_keys_work_after_admin_disabled(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            pw = "pw"
            # boot 1: /admin enabled (to mint a key), enforcement off
            p1 = start_server(db, PORT_LOCKDOWN, RETALK_SERVER_ADMIN_PASSWORD=pw)
            url = f"http://127.0.0.1:{PORT_LOCKDOWN}"
            try:
                _, created = http("POST", url + "/admin", basic=("admin", pw),
                                  body={"action": "create", "label": "bot"})
                key = created["key"]
            finally:
                p1.terminate()
                p1.wait(timeout=10)

            # boot 2: SAME db, enforcement ON, /admin DISABLED (no password)
            p2 = start_server(db, PORT_LOCKDOWN,
                              RETALK_SERVER_REQUIRE_API_KEY="1")
            try:
                # /admin is gone (404) — no admin surface exposed at all
                self.assertEqual(http("GET", url + "/admin")[0], 404)
                self.assertEqual(
                    http("POST", url + "/admin", body={"action": "list"})[0], 404)
                # but the previously-minted key still gates access correctly
                u = User(url, "s", name="a", store=os.path.join(tmp, "a.db"),
                         api_key=key)
                u.publish()
                self.assertIsInstance(u._call("count_keys"), dict)
                # and a client with no key is still rejected
                u2 = User(url, "s", name="a", store=os.path.join(tmp, "b.db"))
                with self.assertRaises(RuntimeError):
                    u2.publish()
            finally:
                p2.terminate()
                p2.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
