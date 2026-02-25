#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8088}"
MOCK_ENV="${MOCK_ENV:-${ROOT_DIR}/.cache/mock-gitlab/env.sh}"

if [ ! -f "${MOCK_ENV}" ]; then
  echo "missing mock env file: ${MOCK_ENV}" >&2
  echo "run: ./scripts/setup_mock_gitlab_contract.sh" >&2
  exit 1
fi
source "${MOCK_ENV}"

require_ok() {
  local json="$1"
  local hint="$2"
  if [ "$(echo "${json}" | jq -r '.ok // false')" != "true" ]; then
    echo "[FAIL] ${hint}" >&2
    echo "${json}" | jq . >&2
    exit 1
  fi
}

echo "[1/7] check health"
curl -fsS "${BASE_URL}/health" >/dev/null
curl -fsS "http://${MOCK_GITLAB_ADDR}/health" >/dev/null

echo "[2/7] configure platform gitlab settings"
settings_payload="$(cat <<EOF
{
  "gitlab_url": "http://${MOCK_GITLAB_ADDR}",
  "gitlab_token": "${MOCK_GITLAB_TOKEN}",
  "scan_engine": "builtin",
  "n8n_enabled": false
}
EOF
)"
settings_resp="$(curl -sS -X POST "${BASE_URL}/api/settings" \
  -H "Content-Type: application/json" \
  -d "${settings_payload}")"
require_ok "${settings_resp}" "save settings"

echo "[3/7] test gitlab connectivity"
test_resp="$(curl -sS "${BASE_URL}/api/settings/test")"
require_ok "${test_resp}" "gitlab connectivity"
project_count="$(echo "${test_resp}" | jq -r '.data.project_count // 0')"
echo "  project_count=${project_count}"

echo "[4/7] list projects"
projects_resp="$(curl -sS "${BASE_URL}/api/projects")"
require_ok "${projects_resp}" "list projects"
project_id="$(echo "${projects_resp}" | jq -r '.data[0].id')"
project_name="$(echo "${projects_resp}" | jq -r '.data[0].path_with_namespace')"
echo "  project_id=${project_id} project=${project_name}"

echo "[5/7] list branches"
branches_payload="$(cat <<EOF
{"project_id": ${project_id}}
EOF
)"
branches_resp="$(curl -sS -X POST "${BASE_URL}/api/branches" \
  -H "Content-Type: application/json" \
  -d "${branches_payload}")"
require_ok "${branches_resp}" "list branches"
branch_name="$(echo "${branches_resp}" | jq -r '.data[0].name')"
echo "  branch=${branch_name}"

echo "[6/7] load rules"
rules_resp="$(curl -sS "${BASE_URL}/api/rules")"
require_ok "${rules_resp}" "load rules"
rule_ids="$(echo "${rules_resp}" | jq -c '[.data[] | select(.enabled==true and (.id=="slither-tx-origin" or .id=="slither-suicidal" or .id=="slither-reentrancy-eth" or .id=="slither-timestamp")) | .id]')"
if [ "${rule_ids}" = "[]" ]; then
  rule_ids="$(echo "${rules_resp}" | jq -c '[.data[] | select(.enabled==true) | .id][0:6]')"
fi
if [ "${rule_ids}" = "[]" ]; then
  echo "[FAIL] no enabled rules found" >&2
  exit 1
fi
echo "  rule_ids=${rule_ids}"

echo "[7/7] run gitlab contract scan"
scan_payload="$(jq -n \
  --argjson project_id "${project_id}" \
  --arg branch "${branch_name}" \
  --argjson rule_ids "${rule_ids}" \
  '{
    source_type: "gitlab",
    project_id: $project_id,
    branch: $branch,
    rule_ids: $rule_ids,
    engine: "builtin"
  }')"
scan_resp="$(curl -sS -X POST "${BASE_URL}/api/scan" \
  -H "Content-Type: application/json" \
  -d "${scan_payload}")"
require_ok "${scan_resp}" "run gitlab scan"
scan_id="$(echo "${scan_resp}" | jq -r '.data.scan_id')"
p0="$(echo "${scan_resp}" | jq -r '.data.summary.p0 // 0')"
p1="$(echo "${scan_resp}" | jq -r '.data.summary.p1 // 0')"
p2="$(echo "${scan_resp}" | jq -r '.data.summary.p2 // 0')"
total="$(echo "${scan_resp}" | jq -r '.data.summary.total // 0')"
json_report="$(echo "${scan_resp}" | jq -r '.data.json_report')"
md_report="$(echo "${scan_resp}" | jq -r '.data.md_report')"

echo
echo "[PASS] gitlab integration flow is working"
echo "  scan_id=${scan_id}"
echo "  summary: total=${total} p0=${p0} p1=${p1} p2=${p2}"
echo "  json_report=${json_report}"
echo "  md_report=${md_report}"
