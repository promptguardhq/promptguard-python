# AGENTS.md

| Owner | Last reviewed |
|---|---|
| @cto | 2026-11-09 |

Python SDK for PromptGuard, published to PyPI as `promptguard-sdk`; the Node SDK
(`promptguard-node`) is its deliberate mirror. Domain vocabulary lives in
`CONTEXT.md`; layout, dependencies and tool config live in `pyproject.toml`.

## Setup

```bash
pip install -e ".[dev]"
pre-commit install               # once per clone: wires the commit AND push hooks
```

Keep API keys, tokens and credentials out of every commit. The repo is public
and on PyPI, so a credential that reaches `main` is world-readable at once and
has to be rotated, not reverted. The push hook runs gitleaks over the commits
being pushed; CI's `secret-scan.yml` is the backstop. A fixture that must look
like a credential gets a path exemption in `.gitleaks.toml`, where it is
reviewable, instead of a `--no-verify`. Why the scan covers only the pushed
range: `scripts/hooks/gitleaks-push.sh`.

## Checks

After editing Python, run `ruff check --fix .` and `ruff format .`. **Before
you hand back a change, run `bash scripts/check.sh`**: ruff, mypy and the
suite with CI's coverage floor, about five seconds. The pre-push hook runs it.
In a worktree it uses the main checkout's `.venv` and puts the worktree first
on the import path.

The suite is fully mocked and offline. `pytest` turns warnings into errors and
runs pytest-asyncio in strict mode, so every async test needs
`@pytest.mark.asyncio`. Code must run on Python 3.10, the oldest CI leg.

## Coding standards

- Type hints on every public function and method.
- The SDK stays lightweight: a new runtime dependency needs discussion first.
- The public surface is `__all__` in `promptguard/__init__.py`; keep it small,
  and change or remove a name there only with a major version bump.

## The guard contract and generated types

`tests/guard-contract.json` holds the cases both SDKs must pass, and
`promptguard/generated/` is built from the published OpenAPI spec. Both arrive
through the scheduled `sync-from-api.yml` PR; hand-edits fail the suite (the
contract lock) or get overwritten (the types). A behaviour change that both
SDKs share starts upstream in the contract. Before touching either, read
`docs/adr/0001-shared-guard-contract.md`.

## Commit messages

Conventional prefix plus imperative mood (`fix: drop a session id over 255
characters`), describing the change as a user sees it, with the issue reference
where there is one (`(promptguard#956)`, `(#945)`).

## GitHub holds no secrets

**Change a secret in Secret Manager; GitHub holds none.** Workflows read every
secret at run time from Google Secret Manager (`promptguard-production-472014`),
signed in as this repository through Workload Identity; GitHub keeps only
identifiers, as variables (`vars.*`). A workflow that names any `secrets.*` but
`GITHUB_TOKEN` fails CI (`scripts/check_no_github_secrets.py`). The inventory,
and how to add a secret with its per-secret grant:
[`ENVIRONMENT_VARIABLES.md` § CI/CD-only](https://github.com/promptguardhq/promptguard/blob/main/docs/04_engineering/reference/ENVIRONMENT_VARIABLES.md#cicd-only)
in the platform repo.

`.claude/settings.json` (committed) denies Claude Code reads of real `.env` files, and hand-edits of generated API types and the synced guard contract (regenerate them with the sync workflow's commands instead). Machine-only permissions go in `.claude/settings.local.json`.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues, worked via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, each label string equal to its name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` plus `docs/adr/` at the repo root; add to them as terms and decisions settle. See `docs/agents/domain.md`.
