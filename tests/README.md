# Tests

## Running

From the repo root, all test files (standard unittest discovery):

```
uv run python -m unittest discover -s tests -v
```

or a single file:

```
uv run tests/test_e2ee.py
```

The cases use plain `assert`s inside `unittest`. The run exits non-zero on
failure and prints `PASS n: ...` per criterion.

## Continuous integration

`.github/workflows/run-tests.yaml` runs the same discovery command on every
push and pull request to `main`/`dev*` (via `uv sync` from
`pyproject.toml`/`uv.lock`), so GitHub blocks regressions automatically once
the repo is pushed there.

## What it needs and touches

- Starts server subprocesses on localhost ports in the range **8767-8799**; the
  *Port registry* below lists which file binds which. It fails fast if a port
  it needs is taken.
- All state (server DBs, user stores) lives in a temporary directory that's
  deleted afterward, so your real stores are never touched.
- Spawns two extra OS processes during the concurrency test (criterion 8).
- Typical runtime: ~30 seconds.

## Adding a test file

Name it `tests/test_<topic>.py` with a `unittest.TestCase` (or plain
`TestCase`), and both discovery and CI pick it up automatically. Conventions:
keep all state in a `tempfile.TemporaryDirectory()`, and if it starts servers,
give them ports not used by any other test file. Files run sequentially today,
but unique ports keep parallel running possible, so take the next free port
from the registry below and add your file to it in the same commit.

### Port registry

Every file that binds a port, and every port it binds. Files not listed start
no server: `test_add_fingerprint.py`, `test_global_contacts.py`,
`test_invite.py`, `test_passphrase_file.py`.

| Ports | File |
| --- | --- |
| 8767-8768 | `test_e2ee.py` |
| 8769 | `test_cli.py` |
| 8770-8771 | `test_block.py` |
| 8772 | `test_contacts.py` |
| 8773 | `test_share.py` |
| 8774 | `test_crossed_sessions.py` |
| 8775 | `test_show.py` |
| 8776 | `test_groups.py` |
| 8777 | `test_multi_machine.py` |
| 8778-8779 | `test_hardening.py` |
| 8780 | `test_mailbox_cap.py` |
| 8781-8782 | `test_multi_audience.py` |
| 8786-8787 | `test_show_web.py` |
| 8788 | `test_library_api.py` |
| 8790-8795 | `test_admin_api_keys.py` |
| 8796-8797 | `test_sync.py` |
| 8798 | `test_receive_multi.py` |
| 8799 | `test_invite_codes.py` |

Free inside the range: 8783-8785 and 8789.

Note that `test_e2ee.py` wraps its 14 criteria in a *single* test method on
purpose: they're one ordered, stateful scenario, not 14 independent tests.

## What it proves

The suite is the project's acceptance criteria, 14 of them, covering E2EE
round-trips, no plaintext at the server, MITM refusal on tampered keys,
fallback keys and rotation grace windows, key replenishment, multi-process
store sharing, server migration with surviving sessions, delivery acks and
outbox recovery with duplicate rejection, and the three signed-request attack
defenses (replay, stale timestamp, cross-server). The full list is in the
docstring at the top of `test_e2ee.py`.
