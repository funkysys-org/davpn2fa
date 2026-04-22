#!/usr/bin/env bash
# show-qr — Re-display the TOTP QR code for an existing user.
# Usage: docker exec -it openvpn show-qr <username>
set -euo pipefail

DATA_DIR="/etc/openvpn/data"
USERNAME="${1:-}"
[[ -z "$USERNAME" ]] && { echo "[ERROR] Usage: show-qr <username>"; exit 1; }

GA_FILE="$DATA_DIR/users/$USERNAME/.google_authenticator"
[[ -f "$GA_FILE" ]] || { echo "[ERROR] No TOTP secret for '$USERNAME'"; exit 1; }

SECRET=$(head -1 "$GA_FILE")
URI="otpauth://totp/OpenVPN:${USERNAME}?secret=${SECRET}&issuer=OpenVPN&algorithm=SHA1&digits=6&period=30"

echo ""
echo "  TOTP QR code for: $USERNAME"
echo ""
qrencode -t ANSI256 "$URI"
echo ""
echo "  Secret: $SECRET"
echo ""
