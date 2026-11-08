#!/usr/bin/env bash
# The local gate: what .github/workflows/ci.yml runs, as one command. Run it
# before you hand back a change; the pre-push hook runs it too.
#
#   bash scripts/check.sh
#
# Not covered: CI's API-contract job, which fetches the published spec over the
# network, and the oldest-Python and dependency-floor legs.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
step() { printf '==> %s\n' "$*"; }

step "GitHub holds no secrets; agent files load and resolve; no em or en dashes"
python3 scripts/check_no_github_secrets.py --check
python3 scripts/check_agent_files.py --check
python3 scripts/check_no_dashes.py --check

# A worktree has no virtualenv of its own: use the main checkout's, and put
# this checkout first on the import path, or the tests import the main
# checkout's code through its editable install.
common=$(git rev-parse --path-format=absolute --git-common-dir)
bin=""
for d in .venv "$common/../.venv"; do
  if [ -x "$d/bin/python" ]; then bin="$d/bin/"; break; fi
done
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

step "ruff"
"${bin}ruff" check .
"${bin}ruff" format --check .
step "mypy"
"${bin}mypy" promptguard
step "pytest (coverage floor as CI)"
"${bin}pytest" tests/ -q --cov --cov-fail-under=60
echo "check: all passed"
