#!/usr/bin/env bash
# The local gate: what .github/workflows/ci.yml runs, as one command. Run it
# before you hand back a change; the pre-push hook runs it too.
#
#   bash scripts/check.sh
#   bash scripts/check.sh --live   # then tests/live against staging; needs
#                                  # PROMPTGUARD_LIVE_API_KEY
#
# Not covered: CI's API-contract job, which fetches the published spec over the
# network, and the oldest-Python and dependency-floor legs.
set -euo pipefail
live=0
case "${1:-}" in
  --live) live=1 ;;
  "") ;;
  *) echo "usage: $0 [--live]" >&2; exit 2 ;;
esac
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
if [ "$live" = 1 ]; then
  step "live tests against ${PROMPTGUARD_LIVE_BASE_URL:-staging}"
  if [ -z "${PROMPTGUARD_LIVE_API_KEY:-}" ]; then
    echo "PROMPTGUARD_LIVE_API_KEY is not set" >&2; exit 1
  fi
  "${bin}pytest" -m live tests/live -q -rs
fi
echo "check: all passed"
