# Contributing to retalk

Thanks for helping improve retalk. This page covers a development setup, running
the test suite, and cutting a release.

## Ground rules

- **Disclose AI-generated code.** If a PR contains code produced by an AI
  tool, say so in the PR description.
- **Bug fixes come with a regression test** that fails before the fix and
  passes after it.
- **No secrets or PII** in code, tests, docs, or recordings: no real keys,
  tokens, emails, usernames, home paths, or fingerprints of real identities.
  Record demos in isolated throwaway environments.

## Development setup

Work from a clone of the repository:

```sh
git clone https://github.com/xhluca/retalk
cd retalk
uv sync
uv run retalk --help
```

Without uv, run `pip install -e .` inside the clone for an editable install.

## Running the tests

From the repository root:

```sh
uv run python -m unittest discover -s tests -v
```

The tests use stdlib `unittest` and start their own local servers on ports
8767-8769, keeping all state in temporary directories so they never touch real
stores. CI runs the same discovery on every push and pull request. See
[../tests/README.md](../tests/README.md) for the full list of what is covered.

## Releasing

Publishing is automated. Creating a GitHub Release triggers
`.github/workflows/publish.yaml`, which checks that the tag matches the package
version, runs the tests, builds with uv, and publishes to PyPI through trusted
publishing.

To cut a release:

1. Bump `version` in `pyproject.toml` and `src/retalk/__init__.py`.
2. Commit and push.
3. Create a release whose tag is the version, optionally prefixed with `v`.

```sh
gh release create v0.0.1 --title v0.0.1 --notes "first beta"
```

Maintainers only need to do PyPI setup once: on pypi.org, add a trusted
publisher for project `retalk` pointing at this repository, workflow
`publish.yaml`, environment `pypi`.
