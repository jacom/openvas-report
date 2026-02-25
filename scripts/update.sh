#!/bin/bash
# OpenVAS Report — Self-Update Script
# Usage: bash scripts/update.sh
set -e

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$APP_DIR/venv"
SERVICE_NAME="openvas-report"
GITHUB_REPO="${GITHUB_REPO:-OWNER/openvas-report}"

echo "============================================"
echo " OpenVAS Report Updater"
echo "============================================"
echo "App dir : $APP_DIR"
echo "Repo    : $GITHUB_REPO"

# ─── 1. Read current version ────────────────────────────────────────────────
CURRENT=$(cat "$APP_DIR/VERSION" 2>/dev/null || echo "0.0.0")
echo "Current : v$CURRENT"

# ─── 2. Fetch latest release from GitHub ────────────────────────────────────
API_URL="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
echo ""
echo "[1/6] Checking GitHub for latest release..."
RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github+json" "$API_URL")

LATEST=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")
TARBALL_URL=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['tarball_url'])")

echo "Latest  : v$LATEST"

if [ "$CURRENT" = "$LATEST" ]; then
    echo ""
    echo "✓ Already up to date (v$CURRENT)"
    exit 0
fi

echo ""
echo "  Update available: v$CURRENT → v$LATEST"

# ─── 3. Download release tarball ────────────────────────────────────────────
echo ""
echo "[2/6] Downloading v$LATEST..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL -L "$TARBALL_URL" -o "$TMPDIR/release.tar.gz"
tar -xzf "$TMPDIR/release.tar.gz" -C "$TMPDIR"
EXTRACTED=$(ls "$TMPDIR" | grep -v release.tar.gz | head -1)
SRC="$TMPDIR/$EXTRACTED"

echo "  Extracted to: $TMPDIR/$EXTRACTED"

# ─── 4. Install apt packages if listed ──────────────────────────────────────
if [ -f "$SRC/apt-requirements.txt" ]; then
    echo ""
    echo "[3/6] Installing apt packages..."
    apt-get update -qq
    xargs -a "$SRC/apt-requirements.txt" apt-get install -y -qq
else
    echo "[3/6] No apt-requirements.txt — skipping apt install"
fi

# ─── 5. Copy updated files (keep venv, media, .env, local db) ───────────────
echo ""
echo "[4/6] Copying updated files..."
rsync -a --delete \
    --exclude='venv/' \
    --exclude='media/' \
    --exclude='.env' \
    --exclude='*.sqlite3' \
    --exclude='staticfiles/' \
    "$SRC/" "$APP_DIR/"

# ─── 6. pip install ─────────────────────────────────────────────────────────
echo ""
echo "[5/6] Installing Python packages..."
source "$VENV/bin/activate"
pip install -q -r "$APP_DIR/requirements.txt"

# ─── 7. Django migrate + collectstatic ──────────────────────────────────────
echo ""
echo "[6/6] Running database migrations..."
python "$APP_DIR/manage.py" migrate --noinput
python "$APP_DIR/manage.py" collectstatic --noinput --clear -v 0

# ─── 8. Restart service ─────────────────────────────────────────────────────
echo ""
echo "[Done] Restarting service..."
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl restart "$SERVICE_NAME"
    echo "  ✓ Service '$SERVICE_NAME' restarted"
else
    echo "  ⚠ Service '$SERVICE_NAME' not found — please restart manually"
    echo "    (gunicorn, uwsgi, or python manage.py runserver)"
fi

echo ""
echo "============================================"
echo " Updated: v$CURRENT → v$LATEST"
echo "============================================"
