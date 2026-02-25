#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_ROOT="${ROOT_DIR}/.cache/mock-gitlab"
REPO_DIR="${MOCK_ROOT}/repos/sec-team/contract-risk-lab"
ENV_FILE="${MOCK_ROOT}/env.sh"

mkdir -p "${REPO_DIR}/contracts" "${REPO_DIR}/.sec"

cat > "${REPO_DIR}/contracts/Vault.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(tx.origin == owner, "only owner");
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
        if (amount > 10 ether) {
            selfdestruct(payable(msg.sender));
        }
    }
}
EOF

cat > "${REPO_DIR}/README.md" <<'EOF'
# contract-risk-lab

This repository is a local contract project used for SCaudit GitLab integration testing.
EOF

cat > "${REPO_DIR}/.sec/project_meta.yml" <<'EOF'
project:
  id: gitlab_1001
  name: Contract Risk Lab
  alias: CRL
  department: Security
  team: AppSec
  owner: sec-owner
  security_owner: sec-lead
EOF

if [ ! -d "${REPO_DIR}/.git" ]; then
  git -C "${REPO_DIR}" init -b main >/dev/null
  git -C "${REPO_DIR}" config user.name "Mock GitLab"
  git -C "${REPO_DIR}" config user.email "mock-gitlab@local.test"
fi

git -C "${REPO_DIR}" add -A
if ! git -C "${REPO_DIR}" diff --cached --quiet; then
  git -C "${REPO_DIR}" commit -m "seed contract project for scaudit integration test" >/dev/null
fi
git -C "${REPO_DIR}" branch -M main >/dev/null

cat > "${ENV_FILE}" <<EOF
export MOCK_GITLAB_ADDR="127.0.0.1:18080"
export MOCK_GITLAB_EXTERNAL_URL="http://127.0.0.1:18080"
export MOCK_GITLAB_TOKEN="mock-token"
export MOCK_GITLAB_PROJECT_ID="1001"
export MOCK_GITLAB_NAMESPACE="sec-team"
export MOCK_GITLAB_PROJECT="contract-risk-lab"
export MOCK_GITLAB_BRANCH="main"
export MOCK_GITLAB_REPO_PATH="${REPO_DIR}"
EOF

cat <<EOF
Mock contract repository is ready:
  ${REPO_DIR}

Env file:
  ${ENV_FILE}

Start mock GitLab API server:
  source "${ENV_FILE}"
  go run ./scripts/mock_gitlab_server.go
EOF

