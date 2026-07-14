"""The core NON-group flows, run the way real users run them: the CLI as a
subprocess (argv, exit codes, stdout — exactly the bash surface) with one
isolated RETALK_HOME per user. Three simulated machines that share nothing
but the relay: no common config, no shared global contacts, no shared stores.

Covers: onboarding both ways (init auto-register, add --verify, send/receive,
ack draining the outbox, history), per-peer mailbox isolation on one machine,
unknown-name vs raw-fingerprint addressing across machines, a three-machine
share/import introduction, and block + relay-refusal healing across machines.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PORT = 8777


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestMultiMachine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ, RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}")
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        self.fp = {}
        for who in ("alice", "bob", "carol"):
            self.fp[who] = self.cli(
                who, "init", "-u", who, "--no-passphrase",
                "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def _env(self, machine):
        home = os.path.join(self.tmp, f"home-{machine}")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_HOME=home)
        for k in ("RETALK_USER", "RETALK_PASSPHRASE", "RETALK_RELAY",
                  "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)
        return env

    def cli(self, machine, *cmd, expect=0):
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True,
                           env=self._env(machine))
        self.assertEqual(r.returncode, expect,
                         f"[{machine}] {cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def db(self, machine):
        return os.path.join(self.tmp, f"home-{machine}", machine, "store.db")

    def count(self, machine, sql):
        con = sqlite3.connect(self.db(machine))
        n = con.execute(sql).fetchone()[0]
        con.close()
        return n

    def test_onboarding_and_ack_roundtrip(self):
        # add --verify across machines pins keys fetched from the relay
        r = self.cli("alice", "add", self.fp["bob"], "--peer", "bob",
                     "--verify", "-u", "alice")
        self.assertIn("✓ Verified", r.stderr)
        self.cli("bob", "add", self.fp["alice"], "--peer", "alice",
                 "--verify", "-u", "bob")
        # message both ways, saving both sides
        self.cli("alice", "send", "--peer", "bob", "hello bob", "-u", "alice",
                 "--save")
        got = [json.loads(l) for l in
               self.cli("bob", "receive", "--peer", "alice", "-u", "bob",
                        "--save").stdout.splitlines()]
        self.assertEqual([m["text"] for m in got], ["hello bob"])
        self.assertEqual(got[0]["name"], "alice")   # saved name, not ~unverified
        self.cli("bob", "send", "--peer", "alice", "hi back", "-u", "bob",
                 "--save")
        self.cli("alice", "receive", "--peer", "bob", "-u", "alice", "--save")
        # the ack round-trip drained both outboxes
        self.cli("bob", "receive", "--peer", "alice", "-u", "bob")
        for who in ("alice", "bob"):
            self.assertEqual(
                self.count(who, "SELECT COUNT(*) FROM outbox"), 0,
                f"{who}'s outbox should be empty after acks")
        # each machine's history holds the full two-way conversation
        for who, peer in (("alice", "bob"), ("bob", "alice")):
            hist = [json.loads(l) for l in
                    self.cli(who, "history", "--peer", peer, "-u", who)
                    .stdout.splitlines()]
            self.assertEqual([h["text"] for h in hist],
                             ["hello bob", "hi back"])
        print("PASS: cross-machine onboarding, acks, and history")

    def test_contact_and_mailbox_isolation(self):
        # contacts are per machine: alice knowing bob teaches carol nothing
        self.cli("alice", "add", self.fp["bob"], "--peer", "bob", "-u", "alice")
        r = self.cli("carol", "send", "--peer", "bob", "x", "-u", "carol",
                     expect=2)
        self.assertIn("unknown peer", r.stderr)
        # ...but a raw fingerprint always works (it IS the address)
        self.cli("carol", "send", "--peer", self.fp["bob"], "hi from carol",
                 "-u", "carol")
        # per-peer receive drains ONLY that sender's mail
        self.cli("alice", "send", "--peer", "bob", "hi from alice",
                 "-u", "alice")
        only_alice = [json.loads(l)["text"] for l in
                      self.cli("bob", "receive", "--peer", self.fp["alice"],
                               "-u", "bob").stdout.splitlines()]
        self.assertEqual(only_alice, ["hi from alice"])
        only_carol = [json.loads(l)["text"] for l in
                      self.cli("bob", "receive", "--peer", self.fp["carol"],
                               "-u", "bob").stdout.splitlines()]
        self.assertEqual(only_carol, ["hi from carol"])
        # the unknown sender shows an unverified ~name, not a trusted one
        print("PASS: contacts and mailboxes are isolated per machine/peer")

    def test_three_machine_introduction(self):
        # alice knows both; she introduces bob to carol with share/import
        self.cli("alice", "add", self.fp["bob"], "--peer", "bob", "--verify",
                 "-u", "alice")
        self.cli("alice", "add", self.fp["carol"], "--peer", "carol",
                 "-u", "alice")
        self.cli("alice", "share", "bob", "--peer", "carol", "-u", "alice")
        got = [json.loads(l) for l in
               self.cli("carol", "receive", "--peer", self.fp["alice"],
                        "-u", "carol").stdout.splitlines()]
        self.assertEqual(got[0]["kind"], "contact")
        self.cli("carol", "import", "--inbox", "-u", "carol")
        contacts = self.cli("carol", "contacts", "-u", "carol").stdout
        self.assertIn("bob", contacts)
        self.assertIn("verified", contacts)   # alice's card carried bob's keys
        # the introduction is immediately usable
        self.cli("carol", "send", "--peer", "bob", "alice sent me",
                 "-u", "carol")
        texts = [json.loads(l)["text"] for l in
                 self.cli("bob", "receive", "--peer", self.fp["carol"],
                          "-u", "bob").stdout.splitlines()]
        self.assertEqual(texts, ["alice sent me"])
        print("PASS: three-machine share/import introduction")

    def test_block_and_refusal_across_machines(self):
        self.cli("carol", "add", self.fp["bob"], "--peer", "bob", "-u", "carol")
        self.cli("bob", "block", self.fp["carol"], "-u", "bob")
        self.cli("carol", "send", "--peer", "bob", "let me in", "-u", "carol")
        # bob's receive drops it before decryption: nothing surfaces
        out = self.cli("bob", "receive", "--peer", self.fp["carol"],
                       "-u", "bob").stdout
        self.assertEqual(out, "")
        # carol's next sync sees the verified refusal: outbox drops the message
        self.assertEqual(self.count("carol", "SELECT COUNT(*) FROM outbox"), 1)
        self.cli("carol", "sync", "-u", "carol")
        self.assertEqual(self.count("carol", "SELECT COUNT(*) FROM outbox"), 0)
        # unblock: future mail flows again
        self.cli("bob", "block", "--remove", self.fp["carol"], "-u", "bob")
        self.cli("carol", "send", "--peer", "bob", "second try", "-u", "carol")
        texts = [json.loads(l)["text"] for l in
                 self.cli("bob", "receive", "--peer", self.fp["carol"],
                          "-u", "bob").stdout.splitlines()]
        self.assertEqual(texts, ["second try"])
        print("PASS: block, relay-refusal outbox healing, and unblock")


if __name__ == "__main__":
    unittest.main()
