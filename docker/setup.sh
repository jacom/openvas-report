#!/bin/bash
# OpenVAS + openvas-report Docker Setup Script
# รองรับ Ubuntu 22.04 / Debian 12
set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/openvas-docker}"
REPORT_DIR="$INSTALL_DIR/openvas-report"
GITHUB_REPO="jacom/openvas-report"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo "============================================"
echo " OpenVAS + openvas-report Docker Setup"
echo "============================================"
echo ""

# ─── 1. Check root ───────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || error "กรุณารันด้วย sudo หรือ root"

# ─── 2. Install Docker ───────────────────────────────────────────────────────
info "[1/7] ตรวจสอบ Docker..."
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    info "Docker installed"
else
    info "Docker $(docker --version | cut -d' ' -f3) — OK"
fi

# ─── 3. Create install directory ─────────────────────────────────────────────
info "[2/7] สร้าง directory $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# ─── 4. Download Greenbone Community Edition ─────────────────────────────────
info "[3/7] ดาวน์โหลด Greenbone Community Edition..."
if [ ! -f "$INSTALL_DIR/greenbone-compose.yml" ]; then
    curl -fsSL -o greenbone-compose.yml \
        https://greenbone.github.io/docs/latest/22.4/container/docker-compose.yml
    info "Greenbone compose downloaded"
else
    info "Greenbone compose already exists — ข้าม"
fi

# ─── 5. Download openvas-report ──────────────────────────────────────────────
info "[4/7] ดาวน์โหลด openvas-report..."
API_URL="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github+json" "$API_URL")
TARBALL_URL=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['tarball_url'])")
VERSION=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])")

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
curl -fsSL -L "$TARBALL_URL" -o "$TMPDIR/release.tar.gz"
tar -xzf "$TMPDIR/release.tar.gz" -C "$TMPDIR"
EXTRACTED=$(ls "$TMPDIR" | grep -v release.tar.gz | head -1)
rsync -a --delete \
    --exclude='venv/' --exclude='media/' --exclude='.env' \
    "$TMPDIR/$EXTRACTED/" "$REPORT_DIR/"
info "openvas-report $VERSION downloaded to $REPORT_DIR"

# ─── 6. Generate .env ────────────────────────────────────────────────────────
info "[5/7] สร้าง .env..."
SERVER_IP=$(hostname -I | awk '{print $1}')

if [ ! -f "$INSTALL_DIR/.env" ]; then
    DJANGO_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    REPORT_DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
    GVM_DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")

    cat > "$INSTALL_DIR/.env" << EOF
# openvas-report
SERVER_IP=$SERVER_IP
DJANGO_SECRET_KEY=$DJANGO_SECRET_KEY
REPORT_DB_PASSWORD=$REPORT_DB_PASSWORD
GITHUB_REPO=$GITHUB_REPO

# GVM Database (pg-gvm container)
GVM_DB_USER=gvmd
GVM_DB_PASSWORD=$GVM_DB_PASSWORD
EOF
    chmod 600 "$INSTALL_DIR/.env"
    info ".env created"
else
    info ".env already exists — ข้าม"
    source "$INSTALL_DIR/.env"
    GVM_DB_PASSWORD="${GVM_DB_PASSWORD:-}"
fi
source "$INSTALL_DIR/.env"

# ─── 7. Start Greenbone + openvas-report ─────────────────────────────────────
info "[6/7] Start Docker containers..."
cd "$INSTALL_DIR"
docker compose \
    -f greenbone-compose.yml \
    -f "$REPORT_DIR/docker/docker-compose.yml" \
    --env-file .env \
    up -d --build

info "รอให้ containers พร้อม..."
sleep 15

# ─── 8. Setup gvmd DB user สำหรับ openvas-report ────────────────────────────
info "ตั้งค่า gvmd database access..."
docker compose -f greenbone-compose.yml --env-file .env exec -T pg-gvm \
    psql -U gvmd -d gvmd -c \
    "ALTER USER gvmd WITH PASSWORD '$GVM_DB_PASSWORD';" 2>/dev/null || \
    warn "ไม่สามารถตั้ง gvmd password — อาจต้องตั้งเอง"

# ─── 9. Django setup ─────────────────────────────────────────────────────────
info "[7/7] Django migrate + collectstatic..."
COMPOSE_CMD="docker compose -f greenbone-compose.yml -f $REPORT_DIR/docker/docker-compose.yml --env-file .env"

# รอ report-db พร้อม
for i in $(seq 1 20); do
    $COMPOSE_CMD exec -T report-db pg_isready -U openvas_report &>/dev/null && break
    sleep 3
done

$COMPOSE_CMD exec -T openvas-report python manage.py migrate --noinput
$COMPOSE_CMD exec -T openvas-report python manage.py collectstatic --noinput --clear -v 0

# สร้าง admin user
info "สร้าง Django admin user (admin/admin)..."
$COMPOSE_CMD exec -T openvas-report python manage.py shell -c "
from django.contrib.auth import get_user_model
U = get_user_model()
if not U.objects.filter(username='admin').exists():
    U.objects.create_superuser('admin','admin@localhost','admin')
    print('admin user created')
else:
    print('admin user already exists')
"

echo ""
echo "============================================"
echo " Setup เสร็จสมบูรณ์!"
echo "============================================"
echo ""
echo "  OpenVAS (GSA)    : http://$SERVER_IP:9392"
echo "  openvas-report   : http://$SERVER_IP:8600"
echo ""
echo "  openvas-report login: admin / admin"
echo "  (เปลี่ยนรหัสผ่านหลัง login ครั้งแรก)"
echo ""
echo "  Feed sync (ครั้งแรกอาจใช้เวลา 30-60 นาที):"
echo "  docker compose -f $INSTALL_DIR/greenbone-compose.yml exec -T ospd-openvas greenbone-feed-sync"
echo ""
echo "  หยุด:  docker compose -f $INSTALL_DIR/greenbone-compose.yml -f $REPORT_DIR/docker/docker-compose.yml down"
echo "  Start: docker compose -f $INSTALL_DIR/greenbone-compose.yml -f $REPORT_DIR/docker/docker-compose.yml up -d"
echo "============================================"
