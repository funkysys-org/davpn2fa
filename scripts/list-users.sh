#!/usr/bin/env bash
# list-users — Show all VPN users with cert and TOTP status.
set -euo pipefail

DATA_DIR="/etc/openvpn/data"
PKI_DIR="$DATA_DIR/pki"
INDEX="$PKI_DIR/index.txt"

[[ -f "$INDEX" ]] || { echo "No certificates issued yet."; exit 0; }

echo ""
printf "  %-20s %-10s %-12s %-20s\n" "USERNAME" "CERT" "TOTP" "EXPIRES"
echo "  $(printf '%.0s─' {1..64})"

while IFS=$'\t' read -r status expiry _ _ subject; do
    cn=$(echo "$subject" | sed 's/.*CN=//' | sed 's/\/.*//')
    [[ "$cn" =~ ^(OpenVPN-CA|server|Easy-RSA CA)$ ]] && continue
    expiry_fmt="20${expiry:0:2}-${expiry:2:2}-${expiry:4:2}"
    cert_status=$(case "$status" in V) echo valid;; R) echo revoked;; E) echo expired;; *) echo "$status";; esac)
    totp_status=$([[ -f "$DATA_DIR/users/$cn/.google_authenticator" ]] && echo configured || echo missing)
    printf "  %-20s %-10s %-12s %-20s\n" "$cn" "$cert_status" "$totp_status" "$expiry_fmt"
done < "$INDEX"
echo ""
