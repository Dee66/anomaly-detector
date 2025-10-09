#!/usr/bin/env bash
# Lightweight pre-commit hook for local dev: compile check + fast tests
set -euo pipefail
echo "Running lightweight pre-commit checks..."

# Compile check for all python files in the repo
python -m py_compile $(git ls-files '*.py')

# Fast smoke tests: run a subset to catch import/syntax issues quickly
.venv/bin/pytest -q tests/test_cdk_infrastructure.py -q

echo "Pre-commit checks passed."