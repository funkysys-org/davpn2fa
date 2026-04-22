#!/usr/bin/env bash
# revoke-user — Revoke certificate, update CRL, remove TOTP secret.
# Usage: docker exec -it openvpn revoke-user <username>
set -euo pipefail

DATA_DIR="/etc/openvpn/data"
PKI_DIR="$DATA_DIR/pki"

USERNAME="${1:-}"
[[ -z "$USERNAME" ]] && { echo "[ERROR] Usage: revoke-user <username>"; exit 1; }
[[ -f "$PKI_DIR/issued/$USERNAME.crt" ]] || { echo "[ERROR] User '$USERNAME' not found"; exit 1; }

read -rp "Permanently revoke '$USERNAME'? [y/N] " ans
[[ "${ans,,}" == "y" ]] || { echo "Aborted."; exit 0; }

export EASYRSA_PKI="$PKI_DIR"
export EASYRSA_BATCH=1

easyrsa revoke "$USERNAME"
easyrsa gen-crl

rm -f "$DATA_DIR/clients/$USERNAME.ovpn"
rm -rf "$DATA_DIR/users/$USERNAME"

echo "[OK] '$USERNAME' revoked. CRL updated."
