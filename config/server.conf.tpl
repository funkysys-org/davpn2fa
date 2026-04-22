port OPENVPN_PORT
proto OPENVPN_PROTO
dev tun

ca   /etc/openvpn/data/pki/ca.crt
cert /etc/openvpn/data/pki/issued/server.crt
key  /etc/openvpn/data/pki/private/server.key
dh   /etc/openvpn/data/pki/dh.pem

crl-verify /etc/openvpn/data/pki/crl.pem
tls-auth   /etc/openvpn/data/pki/ta.key 0

server OPENVPN_NETWORK OPENVPN_NETMASK

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS OPENVPN_DNS1"
push "dhcp-option DNS OPENVPN_DNS2"

keepalive 10 120

cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# Dual-factor: valid certificate AND TOTP password both required
verify-client-cert require
plugin OPENVPN_PAM_PLUGIN openvpn

persist-key
persist-tun
user nobody
group nogroup

status     /etc/openvpn/data/openvpn-status.log
log-append /etc/openvpn/data/openvpn.log
verb 3
mute 20

client-to-client
duplicate-cn
explicit-exit-notify 1
