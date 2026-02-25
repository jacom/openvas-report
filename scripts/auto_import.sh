#!/bin/bash
# Auto-import latest GVM scan report into Django
# Usage: Add to crontab for scheduled imports
#   0 2 * * * /home/jong2/openvas-report/scripts/auto_import.sh
#
# Prerequisites: gvm-cli installed and configured

set -euo pipefail

PROJECT_DIR="/home/jong2/openvas-report"
EXPORT_DIR="/tmp/gvm_exports"
LOG_FILE="${PROJECT_DIR}/logs/auto_import.log"
DJANGO_MANAGE="${PROJECT_DIR}/manage.py"

mkdir -p "${EXPORT_DIR}" "$(dirname "${LOG_FILE}")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

log "Starting auto-import..."

# Method 1: Using gvm-cli (if available)
if command -v gvm-cli &> /dev/null; then
    EXPORT_FILE="${EXPORT_DIR}/scan_$(date +%Y%m%d_%H%M%S).xml"

    # Get the latest report ID
    REPORT_ID=$(gvm-cli --gmp-username admin --gmp-password admin \
        socket --socketpath /run/gvmd/gvmd.sock \
        --xml '<get_reports filter="sort-reverse=date first=1 rows=1"/>' \
        2>/dev/null | python3 -c "
import sys
from lxml import etree
tree = etree.parse(sys.stdin)
reports = tree.findall('.//report')
if reports:
    print(reports[0].get('id', ''))
" 2>/dev/null || true)

    if [ -n "${REPORT_ID}" ]; then
        log "Exporting report ${REPORT_ID}..."
        gvm-cli --gmp-username admin --gmp-password admin \
            socket --socketpath /run/gvmd/gvmd.sock \
            --xml "<get_reports report_id=\"${REPORT_ID}\" format_id=\"a994b278-1f62-11e1-96ac-406186ea4fc5\"/>" \
            > "${EXPORT_FILE}" 2>/dev/null

        if [ -s "${EXPORT_FILE}" ]; then
            log "Importing ${EXPORT_FILE}..."
            python3 "${DJANGO_MANAGE}" import_scan "${EXPORT_FILE}" 2>&1 | tee -a "${LOG_FILE}"
            log "Import complete."
        else
            log "ERROR: Export file is empty."
        fi
    else
        log "No reports found to export."
    fi

# Method 2: Using Django API with curl (if gvm-cli not available)
elif [ -f "$1" ] 2>/dev/null; then
    log "Importing file via management command: $1"
    python3 "${DJANGO_MANAGE}" import_scan "$1" 2>&1 | tee -a "${LOG_FILE}"

else
    log "gvm-cli not found. Pass an XML file as argument: $0 /path/to/report.xml"
    exit 1
fi

log "Done."
