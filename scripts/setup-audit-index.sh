#!/usr/bin/env bash
# setup-audit-index.sh — grant soc-ai's analyst-class user the privileges
# needed to write to the daily soc-ai-audit-* indices.
#
# Without this grant the orchestrator's audit logger drops every event with
# a 403 (action [indices:admin/auto_create] is unauthorized for ... [analyst]
# on indices [soc-ai-audit-YYYY.MM.dd]). Audit failures are non-fatal so
# investigations still complete; this script just unlocks the forensic trail.
#
# Run on the Security Onion manager node as a user with sudo. The script
# uses so-elasticsearch-query, which authenticates against the local
# Elasticsearch via /opt/so/conf/elasticsearch/curl.config (root-only).
#
# Usage:
#   ssh analyst@<so-host> 'sudo bash -s' < scripts/setup-audit-index.sh
#
# OR (interactive on the SO box):
#   sudo bash scripts/setup-audit-index.sh

set -euo pipefail

if ! command -v so-elasticsearch-query >/dev/null 2>&1; then
    echo "ERROR: so-elasticsearch-query not on PATH. Run on the SO manager node." >&2
    exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root (so-elasticsearch-query needs the curl.config)." >&2
    exit 2
fi

ROLE="${ROLE:-analyst}"
INDEX_PATTERN="${INDEX_PATTERN:-soc-ai-audit-*}"

echo "[1/3] fetching current ${ROLE} role definition..."
CUR_JSON=$(so-elasticsearch-query "_security/role/${ROLE}")

# Extract the role body (top-level key is the role name).
BODY=$(python3 -c "
import json, sys
src = json.loads('''${CUR_JSON}''')
role = src['${ROLE}']
# Drop fields the PUT API rejects.
role.pop('transient_metadata', None)

# Add or update the soc-ai-audit-* index block.
indices = role.get('indices', [])
indices = [
    block for block in indices
    if '${INDEX_PATTERN}' not in block.get('names', [])
]
indices.append({
    'names': ['${INDEX_PATTERN}'],
    'privileges': [
        'auto_configure', 'create_index', 'index', 'read',
        'view_index_metadata', 'write',
    ],
    'allow_restricted_indices': False,
})
role['indices'] = indices
print(json.dumps(role))
")

echo "[2/3] writing updated role with ${INDEX_PATTERN} grant..."
RESP=$(so-elasticsearch-query "_security/role/${ROLE}" -X PUT -d "${BODY}")
echo "    response: ${RESP}"

echo "[3/3] verifying grant by issuing a bootstrap PUT for today's index..."
TODAY=$(date -u +%Y.%m.%d)
INDEX="soc-ai-audit-${TODAY}"
BOOT_RESP=$(so-elasticsearch-query "${INDEX}" -X PUT -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' || true)
echo "    bootstrap response: ${BOOT_RESP}"

cat <<'EOF'

Done. Re-run a soc-ai investigation; the warning lines starting with
"audit log write failed (event dropped)" should disappear from the
journalctl -u soc-ai output.

EOF
