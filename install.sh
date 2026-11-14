#!/usr/bin/env bash
set -euo pipefail

REPO="retro1878/fastly-finder"
BIN_PATH="/usr/local/bin/fastly-finder"
SVC_USER="fastly-finder"
ENV_DIR="/etc/fastly-finder"
ENV_FILE="${ENV_DIR}/env"
TLS_DIR="${ENV_DIR}/tls"
DATA_DIR="/var/lib/fastly-finder"
UNIT_FILE="/etc/systemd/system/fastly-finder.service"
HOOK_FILE="/etc/letsencrypt/renewal-hooks/deploy/fastly-finder-tls.sh"

LISTEN_ADDR="0.0.0.0:8443"
AUTH_CRED=""
VERSION="latest"
LOCAL_BIN=""
USE_CERTBOT=0
CERTBOT_IP=""
CERTBOT_EMAIL=""
UNINSTALL=0

usage() {
  cat <<'EOF'
fastly-finder Linux systemd installer

Usage:
  sudo bash install.sh [options]

Options:
  --addr <host:port>      HTTPS listen address (default: 0.0.0.0:8443)
  --auth <user:pass>      Web login credentials (default: preserve existing or generate random)
  --certbot               Obtain & auto-renew a Let's Encrypt short-lived IP cert (needs port 80 free)
  --certbot-ip <ip>       Explicit public IPv4/IPv6 for --certbot (default: auto-detect)
  --email <email>         Optional email for Certbot notifications (default: no email)
  --version <tag>         Release tag to download (default: latest)
  --binary <path>         Install from a local binary instead of downloading from GitHub
  --uninstall             Stop service and remove binary/unit file (preserves scan data)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --addr) LISTEN_ADDR="$2"; shift 2 ;;
    --auth) AUTH_CRED="$2"; shift 2 ;;
    --certbot) USE_CERTBOT=1; shift ;;
    --certbot-ip) USE_CERTBOT=1; CERTBOT_IP="$2"; shift 2 ;;
    --email) CERTBOT_EMAIL="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --binary) LOCAL_BIN="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] Please run as root (e.g. sudo bash $0)" >&2
  exit 1
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
  systemctl disable --now fastly-finder.service 2>/dev/null || true
  rm -f "$UNIT_FILE" "$BIN_PATH" "$HOOK_FILE"
  systemctl daemon-reload 2>/dev/null || true
  echo "[*] Removed fastly-finder service and binary."
  echo "[*] Config/data kept in ${ENV_DIR} and ${DATA_DIR} (remove manually if unwanted)."
  exit 0
fi

# 1. Detect architecture & install binary.
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "[!] Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP_BIN="$(mktemp)"
trap 'rm -f "$TMP_BIN"' EXIT

if [[ -n "$LOCAL_BIN" ]]; then
  cp -f "$LOCAL_BIN" "$TMP_BIN"
else
  if [[ "$VERSION" == "latest" ]]; then
    URL="https://github.com/${REPO}/releases/latest/download/fastly-finder-linux-${ARCH}"
  else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/fastly-finder-linux-${ARCH}"
  fi
  echo "[*] Downloading ${URL}..."
  curl -fL --retry 3 -o "$TMP_BIN" "$URL"
fi
install -m 0755 "$TMP_BIN" "$BIN_PATH"

# 2. Create service user and directories.
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --home-dir "$DATA_DIR" --shell "$NOLOGIN" "$SVC_USER"
fi

install -d -m 0750 -o root -g "$SVC_USER" "$ENV_DIR" "$TLS_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "${DATA_DIR}/scans" "${DATA_DIR}/cache"

# 3. Resolve or preserve web credentials in /etc/fastly-finder/env.
GENERATED_PASS=""
if [[ -z "$AUTH_CRED" && -f "$ENV_FILE" ]]; then
  EXISTING_LINE="$(grep -E '^FASTLY_FINDER_WEB_AUTH=' "$ENV_FILE" || true)"
  AUTH_CRED="${EXISTING_LINE#FASTLY_FINDER_WEB_AUTH=}"
fi
if [[ -z "$AUTH_CRED" ]]; then
  GENERATED_PASS="$(head -c 18 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
  AUTH_CRED="admin:${GENERATED_PASS}"
fi

# 4. Optional Let's Encrypt short-lived IP certificate via Certbot (>= 5.3 for --ip-address).
ensure_certbot_ip_support() {
  local cb
  cb="$(command -v certbot || true)"
  if [[ -n "$cb" ]] && "$cb" --help all 2>/dev/null | grep -F -- '--ip-address' >/dev/null; then
    echo "$cb"
    return 0
  fi

  if command -v snap >/dev/null 2>&1 && snap list >/dev/null 2>&1; then
    echo "[*] Installing Certbot (>= 5.3 for IP certs) via snap..." >&2
    if dpkg -s certbot >/dev/null 2>&1; then
      apt-get remove -y -qq certbot >/dev/null 2>&1 || true
    fi
    snap install --classic certbot >&2
    ln -sf /snap/bin/certbot /usr/local/bin/certbot
    echo "/snap/bin/certbot"
    return 0
  fi

  echo "[*] Installing Certbot (>= 5.3 for IP certs) in /opt/certbot..." >&2
  if ! python3 -m venv --help >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv >&2
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y python3 >&2
    fi
  fi
  python3 -m venv /opt/certbot >&2
  /opt/certbot/bin/pip install --upgrade --quiet pip certbot >&2
  ln -sf /opt/certbot/bin/certbot /usr/local/bin/certbot
  cat > /etc/systemd/system/fastly-finder-certbot-renew.service <<'UNIT'
[Unit]
Description=Renew Certbot certificates for fastly-finder

[Service]
Type=oneshot
ExecStart=/usr/local/bin/certbot renew -q
UNIT
  cat > /etc/systemd/system/fastly-finder-certbot-renew.timer <<'UNIT'
[Unit]
Description=Twice-daily Certbot renewal timer for fastly-finder

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now fastly-finder-certbot-renew.timer >&2
  echo "/opt/certbot/bin/certbot"
}

CERT_LINE=""
KEY_LINE=""
if [[ "$USE_CERTBOT" -eq 1 ]]; then
  CERTBOT_BIN="$(ensure_certbot_ip_support)"
  if ! "$CERTBOT_BIN" --help all 2>/dev/null | grep -F -- '--ip-address' >/dev/null; then
    echo "[!] Installed certbot ($("$CERTBOT_BIN" --version 2>&1)) does not support --ip-address (requires >= 5.3)." >&2
    exit 1
  fi

  if [[ -z "$CERTBOT_IP" ]]; then
    CERTBOT_IP="$(curl -4 -fsS https://ifconfig.me || curl -fsS https://api.ipify.org || true)"
    if [[ -z "$CERTBOT_IP" ]]; then
      echo "[!] Could not auto-detect public IP; pass --certbot-ip <IP>" >&2
      exit 1
    fi
  fi

  EMAIL_ARGS=(--register-unsafely-without-email)
  if [[ -n "$CERTBOT_EMAIL" ]]; then
    EMAIL_ARGS=(--email "$CERTBOT_EMAIL")
  fi

  echo "[*] Requesting Let's Encrypt short-lived IP certificate for ${CERTBOT_IP} (uses port 80 briefly)..."
  "$CERTBOT_BIN" certonly --non-interactive --agree-tos "${EMAIL_ARGS[@]}" \
    --preferred-profile shortlived --standalone --ip-address "$CERTBOT_IP" \
    --cert-name "fastly-finder-ip"

  LIVE_DIR="/etc/letsencrypt/live/fastly-finder-ip"
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat > "$HOOK_FILE" <<HOOK
#!/usr/bin/env bash
set -euo pipefail
install -m 0644 -o root -g ${SVC_USER} "${LIVE_DIR}/fullchain.pem" "${TLS_DIR}/cert.pem"
install -m 0640 -o root -g ${SVC_USER} "${LIVE_DIR}/privkey.pem" "${TLS_DIR}/key.pem"
HOOK
  chmod 0755 "$HOOK_FILE"
  "$HOOK_FILE"

  systemctl enable --now certbot.timer 2>/dev/null || true
  systemctl enable --now snap.certbot.renew.timer 2>/dev/null || true
  CERT_LINE="FASTLY_FINDER_WEB_CERT=${TLS_DIR}/cert.pem"
  KEY_LINE="FASTLY_FINDER_WEB_KEY=${TLS_DIR}/key.pem"
elif [[ -f "$ENV_FILE" ]]; then
  CERT_LINE="$(grep -E '^FASTLY_FINDER_WEB_CERT=' "$ENV_FILE" || true)"
  KEY_LINE="$(grep -E '^FASTLY_FINDER_WEB_KEY=' "$ENV_FILE" || true)"
fi

{
  printf 'FASTLY_FINDER_WEB_AUTH=%s\n' "$AUTH_CRED"
  [[ -n "$CERT_LINE" ]] && printf '%s\n' "$CERT_LINE"
  [[ -n "$KEY_LINE" ]] && printf '%s\n' "$KEY_LINE"
} > "$ENV_FILE"
chown root:"$SVC_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# 5. Install hardened systemd unit and start service.
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=fastly-finder HTTPS Web Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH} --web ${LISTEN_ADDR} --web-dir ${DATA_DIR}/scans --cache-dir ${DATA_DIR}/cache
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
ReadOnlyPaths=${ENV_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now fastly-finder.service
systemctl restart fastly-finder.service

AUTH_USER="${AUTH_CRED%%:*}"
AUTH_PASS="${AUTH_CRED#*:}"
HOST_HINT="$CERTBOT_IP"
if [[ -z "$HOST_HINT" ]]; then
  HOST_HINT="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
PORT_PART="${LISTEN_ADDR##*:}"

echo ""
echo "[+] fastly-finder service is active!"
echo "    URL:      https://${HOST_HINT:-127.0.0.1}:${PORT_PART}"
echo "    User:     ${AUTH_USER}"
if [[ -n "$GENERATED_PASS" ]]; then
  echo "    Password: ${AUTH_PASS}"
else
  echo "    Password: (kept from --auth or existing ${ENV_FILE})"
fi
echo "    Scans:    ${DATA_DIR}/scans"
echo "    Logs:     journalctl -u fastly-finder -f"
