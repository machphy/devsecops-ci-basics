#!/bin/bash
set -euo pipefail

# Simple local CI/CD pipeline demo script.
# Run it from the repository root: bash scripts/ci_cd_demo.sh

if [ -z "${API_KEY:-}" ]; then
  echo "ERROR: API_KEY is not set. Set it with 'export API_KEY=your_value' and try again."
  exit 1
fi

echo "=== CI/CD Demo: Secrets check ==="
echo "API_KEY is set."

python -m pip install --upgrade pip
python -m pip install bandit safety

echo "=== CI/CD Demo: Static code analysis ==="
bandit -r .

echo "=== CI/CD Demo: Dependency scan ==="
safety check

echo "=== CI/CD Demo complete ==="
