#!/usr/bin/env bash
# add-user — Generate cert + TOTP + .ovpn for a new user.
# Usage: docker exec -it openvpn add-user <username> [--server-ip <IP>]
set -euo pipefail

DATA_DIR="/etc/openvpn/data"
PKI_DIR="$DATA_DIR/pki"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }
ok()   { echo "[OK]    $*"; }

USERNAME="${1:-}"
SERVER_IP="${OPENVPN_SERVER_IP:-}"
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in --server-ip) SERVER_IP="$2"; shift 2 ;; *) die "Unknown: $1" ;; esac
done

[[ -z "$USERNAME" ]] && die "Usage: add-user <username> [--server-ip <IP>]"
[[ "$USERNAME" =~ ^[a-zA-Z0-9_-]+$ ]] || die "Username: letters, digits, _ and - only"
[[ -f "$PKI_DIR/ca.crt" ]] || die "PKI not initialised. Run: init-pki"
[[ -f "$PKI_DIR/issued/$USERNAME.crt" ]] && die "User '$USERNAME' already exists"

USER_DIR="$DATA_DIR/users/$USERNAME"
mkdir -p "$USER_DIR"
chmod 700 "$USER_DIR"

export EASYRSA_PKI="$PKI_DIR"
export EASYRSA_BATCH=1
export EASYRSA_CERT_EXPIRE="${EASYRSA_CERT_EXPIRE:-825}"

info "Generating certificate..."
easyrsa gen-req "$USERNAME" nopass
easyrsa sign-req client "$USERNAME"

info "Generating TOTP secret..."
GA_FILE="$USER_DIR/.google_authenticator"
google-authenticator --time-based --disallow-reuse --force \
    --rate-limit=3 --rate-time=30 --window-size=3 \
    --no-confirm --qr-mode=NONE --secret="$GA_FILE" > /dev/null 2>&1
chmod 600 "$GA_FILE"
TOTP_SECRET=$(head -1 "$GA_FILE")

# Detect server IP
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP=$(curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
fi

# Build .ovpn
CLIENT_CONF="$DATA_DIR/clients/$USERNAME.ovpn"
CA_CERT=$(cat "$PKI_DIR/ca.crt")
CLIENT_CERT=$(openssl x509 -in "$PKI_DIR/issued/$USERNAME.crt" 2>/dev/null)
CLIENT_KEY=$(cat "$PKI_DIR/private/$USERNAME.key")
TA_KEY=$(cat "$PKI_DIR/ta.key")

cat > "$CLIENT_CONF" <<OVPN
# OpenVPN client profile: $USERNAME
client
dev tun
proto ${OPENVPN_PROTO:-udp}
remote $SERVER_IP ${OPENVPN_PORT:-1194}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
auth-user-pass
key-direction 1
verb 3
<ca>
$CA_CERT
</ca>
<cert>
$CLIENT_CERT
</cert>
<key>
$CLIENT_KEY
</key>
<tls-auth>
$TA_KEY
</tls-auth>
OVPN
chmod 600 "$CLIENT_CONF"

OTP_URI="otpauth://totp/OpenVPN:${USERNAME}?secret=${TOTP_SECRET}&issuer=OpenVPN&algorithm=SHA1&digits=6&period=30"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  User '$USERNAME' created"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Scan QR code (or use the web UI):"
qrencode -t ANSI256 "$OTP_URI"
echo ""
echo "  Manual secret: $TOTP_SECRET"
echo "  Profile:       $CLIENT_CONF"
echo ""
ok "Done. Import the .ovpn and scan QR code in Google Authenticator."
