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
    if [ "$(id -u)" -eq 0 ]; then
        APT_CMD=""
    elif command -v sudo &>/dev/null; then
        APT_CMD="sudo"
    else
        echo "  ⚠ Not root and sudo not available — skipping apt install"
        APT_CMD="skip"
    fi
    if [ "$APT_CMD" != "skip" ]; then
        $APT_CMD apt-get update -qq
        xargs -a "$SRC/apt-requirements.txt" $APT_CMD apt-get install -y -qq
    fi
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

# ─── detect Docker mode ──────────────────────────────────────────────────────
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_FILE:-}"
if [ -z "$DOCKER_COMPOSE_FILE" ] && [ -f "$APP_DIR/docker/docker-compose.yml" ]; then
    # ลอง detect จาก INSTALL_DIR ที่อาจมี greenbone-compose.yml
    GREENBONE_COMPOSE="$(dirname "$APP_DIR")/greenbone-compose.yml"
    if [ -f "$GREENBONE_COMPOSE" ] && command -v docker &>/dev/null; then
        DOCKER_COMPOSE_FILE="$GREENBONE_COMPOSE"
    fi
fi

if [ -n "$DOCKER_COMPOSE_FILE" ]; then
    # ─── Docker mode ────────────────────────────────────────────────────────
    ENV_FILE="$(dirname "$APP_DIR")/.env"
    COMPOSE_ARGS="-f $DOCKER_COMPOSE_FILE -f $APP_DIR/docker/docker-compose.yml"
    [ -f "$ENV_FILE" ] && COMPOSE_ARGS="$COMPOSE_ARGS --env-file $ENV_FILE"

    echo ""
    echo "[5/6] Rebuilding Docker image..."
    docker compose $COMPOSE_ARGS build openvas-report

    echo ""
    echo "[6/6] Running database migrations..."
    docker compose $COMPOSE_ARGS run --rm openvas-report python manage.py migrate --noinput
    docker compose $COMPOSE_ARGS run --rm openvas-report python manage.py collectstatic --noinput --clear -v 0

    echo ""
    echo "[Done] Restarting container..."
    docker compose $COMPOSE_ARGS up -d openvas-report
    echo "  ✓ Container 'openvas-report' restarted"
else
    # ─── Systemd mode ───────────────────────────────────────────────────────
    echo ""
    echo "[5/6] Installing Python packages..."
    source "$VENV/bin/activate"
    pip install -q -r "$APP_DIR/requirements.txt"

    echo ""
    echo "[6/6] Running database migrations..."
    python "$APP_DIR/manage.py" migrate --noinput
    python "$APP_DIR/manage.py" collectstatic --noinput --clear -v 0

    echo ""
    echo "[Done] Restarting service..."
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl restart "$SERVICE_NAME"
        echo "  ✓ Service '$SERVICE_NAME' restarted"
    else
        echo "  ⚠ Service '$SERVICE_NAME' not found — please restart manually"
    fi
fi

echo ""
echo "============================================"
echo " Updated: v$CURRENT → v$LATEST"
echo "============================================"
