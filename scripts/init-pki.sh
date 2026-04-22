#!/usr/bin/env bash
# init-pki — Initialise CA, server cert, DH params, TLS auth key, and server.conf.
# Run once: docker exec -it openvpn init-pki
set -euo pipefail

DATA_DIR="/etc/openvpn/data"
PKI_DIR="$DATA_DIR/pki"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }
ok()   { echo "[OK]    $*"; }

if [[ -f "$PKI_DIR/ca.crt" ]]; then
    read -rp "[WARN] PKI already exists. Re-initialise (destroys all certs)? [y/N] " ans
    [[ "${ans,,}" == "y" ]] || { echo "Aborted."; exit 0; }
    rm -rf "$PKI_DIR"
fi

export EASYRSA_PKI="$PKI_DIR"
export EASYRSA_BATCH=1
export EASYRSA_KEY_SIZE="${EASYRSA_KEY_SIZE:-4096}"
export EASYRSA_CA_EXPIRE="${EASYRSA_CA_EXPIRE:-3650}"
export EASYRSA_CERT_EXPIRE="${EASYRSA_CERT_EXPIRE:-825}"

mkdir -p "$DATA_DIR/users" "$DATA_DIR/clients"

info "Initialising PKI..."
easyrsa init-pki

info "Building CA..."
EASYRSA_REQ_CN="OpenVPN-CA" easyrsa build-ca nopass

info "Generating server certificate..."
# CN must be "server" so clients can verify with: verify-x509-name server name
easyrsa gen-req server nopass
easyrsa sign-req server server

info "Generating DH parameters (${EASYRSA_KEY_SIZE}-bit) — this takes a while..."
easyrsa gen-dh

info "Generating CRL..."
easyrsa gen-crl

info "Generating TLS auth key..."
openvpn --genkey secret "$PKI_DIR/ta.key"

# Write server.conf
PLUGIN_PATH=$(find /usr/lib -name "openvpn-plugin-auth-pam.so" 2>/dev/null | head -1)
[[ -z "$PLUGIN_PATH" ]] && die "openvpn-plugin-auth-pam.so not found"

SERVER_CONF="$DATA_DIR/server.conf"
cp /usr/local/share/openvpn/server.conf.tpl "$SERVER_CONF"
sed -i "s|OPENVPN_PORT|${OPENVPN_PORT:-1194}|g"               "$SERVER_CONF"
sed -i "s|OPENVPN_PROTO|${OPENVPN_PROTO:-udp}|g"             "$SERVER_CONF"
sed -i "s|OPENVPN_NETWORK|${OPENVPN_NETWORK:-10.8.0.0}|g"    "$SERVER_CONF"
sed -i "s|OPENVPN_NETMASK|${OPENVPN_NETMASK:-255.255.255.0}|g" "$SERVER_CONF"
sed -i "s|OPENVPN_DNS1|${OPENVPN_DNS1:-1.1.1.1}|g"           "$SERVER_CONF"
sed -i "s|OPENVPN_DNS2|${OPENVPN_DNS2:-8.8.8.8}|g"           "$SERVER_CONF"
sed -i "s|OPENVPN_PAM_PLUGIN|$PLUGIN_PATH|g"                  "$SERVER_CONF"

ok "PKI initialised."
echo ""
echo "Next steps:"
echo "  1. Restart:         docker compose restart openvpn"
echo "  2. Add first user:  docker exec -it openvpn add-user <username>"
echo "  3. Or use the web UI at http://localhost:8080"
echo ""
