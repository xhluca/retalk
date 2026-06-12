# Tests

## Running

From the repo root — all test files (standard unittest discovery):

```
uv run python -m unittest discover -s tests -v
```

or a single file:

```
uv run tests/test_e2ee.py
```

Plain `assert`s inside `unittest` cases; the run exits non-zero on
failure and prints `PASS n: ...` per criterion.

## Continuous integration

`.github/workflows/run-tests.yaml` runs the same discovery command on
every push and pull request to `main`/`dev*` (via `uv sync` from
`pyproject.toml`/`uv.lock`), so GitHub blocks regressions automatically
once the repo is pushed there.

## What it needs / touches

- Starts two server subprocesses on localhost ports **8767-8768** (test_e2ee) and **8769** (test_cli)
  (fails fast if they are taken).
- All state (server DBs, user stores) lives in a temporary directory that
  is deleted afterwards — your real stores are never touched.
- Spawns two extra OS processes during the concurrency test (criterion 8).
- Typical runtime: ~30 seconds.

## Adding a test file

Name it `tests/test_<topic>.py` with a `unittest.TestCase` (or
plain `TestCase`) and both discovery and CI pick it up
automatically. Conventions: keep all state in a
`tempfile.TemporaryDirectory()`, and if it starts servers, give them
ports not used by other test files (test_e2ee.py uses **8767-8768**) —
files run sequentially today, but unique ports keep parallel running
possible. Note `test_e2ee.py` wraps its 14 criteria in a *single* test
method on purpose: they are one deliberately ordered, stateful scenario,
not 14 independent tests.

## What it proves

The suite is the project's acceptance criteria — 14 of them, covering
E2EE round-trips, no plaintext at the server, MITM refusal on tampered
keys, fallback keys and rotation grace windows, key replenishment,
multi-process store sharing, server migration with surviving sessions,
delivery acks and outbox recovery with duplicate rejection, and the three
signed-request attack defenses (replay, stale timestamp, cross-server).
The full list is in the docstring at the top of `test_e2ee.py`.
