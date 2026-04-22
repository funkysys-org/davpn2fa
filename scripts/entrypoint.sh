#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="/etc/openvpn/data"
SERVER_CONF="$DATA_DIR/server.conf"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

# Locate PAM plugin
PLUGIN_PATH=$(cat /etc/openvpn/plugin-auth-pam.path 2>/dev/null || true)
if [[ -z "$PLUGIN_PATH" ]]; then
    PLUGIN_PATH=$(find /usr/lib -name "openvpn-plugin-auth-pam.so" 2>/dev/null | head -1)
fi
[[ -z "$PLUGIN_PATH" ]] && die "openvpn-plugin-auth-pam.so not found"
info "PAM plugin: $PLUGIN_PATH"

# Wait for PKI
if [[ ! -f "$DATA_DIR/pki/ca.crt" ]]; then
    echo "[WARN] PKI not initialised. Run: docker exec -it openvpn init-pki"
    exec sleep infinity
fi

# Generate server.conf from template if missing
if [[ ! -f "$SERVER_CONF" ]]; then
    info "Generating server.conf..."
    cp /usr/local/share/openvpn/server.conf.tpl "$SERVER_CONF"
    sed -i "s|OPENVPN_PORT|${OPENVPN_PORT:-1194}|g"           "$SERVER_CONF"
    sed -i "s|OPENVPN_PROTO|${OPENVPN_PROTO:-udp}|g"         "$SERVER_CONF"
    sed -i "s|OPENVPN_NETWORK|${OPENVPN_NETWORK:-10.8.0.0}|g" "$SERVER_CONF"
    sed -i "s|OPENVPN_NETMASK|${OPENVPN_NETMASK:-255.255.255.0}|g" "$SERVER_CONF"
    sed -i "s|OPENVPN_DNS1|${OPENVPN_DNS1:-1.1.1.1}|g"       "$SERVER_CONF"
    sed -i "s|OPENVPN_DNS2|${OPENVPN_DNS2:-8.8.8.8}|g"       "$SERVER_CONF"
    sed -i "s|OPENVPN_PAM_PLUGIN|$PLUGIN_PATH|g"              "$SERVER_CONF"
fi

# Ensure CRL exists
if [[ ! -f "$DATA_DIR/pki/crl.pem" ]]; then
    info "Generating initial CRL..."
    EASYRSA_PKI="$DATA_DIR/pki" EASYRSA_BATCH=1 easyrsa gen-crl
fi

mkdir -p "$DATA_DIR/users" "$DATA_DIR/clients"

# iptables NAT
IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
IFACE="${IFACE:-eth0}"
info "Masquerading via $IFACE"
iptables -t nat -C POSTROUTING -s "${OPENVPN_NETWORK:-10.8.0.0}/24" -o "$IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${OPENVPN_NETWORK:-10.8.0.0}/24" -o "$IFACE" -j MASQUERADE

info "Starting OpenVPN..."
exec openvpn --config "$SERVER_CONF"
