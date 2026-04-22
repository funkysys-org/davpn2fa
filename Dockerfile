FROM debian:bookworm-slim

LABEL maintainer="openvpn-2fa"
LABEL description="OpenVPN with client certificate + Google Authenticator 2FA"

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn \
    easy-rsa \
    libpam-google-authenticator \
    qrencode \
    iptables \
    iproute2 \
    openssl \
    ca-certificates \
    libpam-runtime \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Locate PAM plugin at build time
RUN mkdir -p /etc/openvpn && \
    find /usr/lib -name "openvpn-plugin-auth-pam.so" 2>/dev/null | head -1 \
    > /etc/openvpn/plugin-auth-pam.path

RUN ln -sf /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa

COPY config/pam.d/openvpn /etc/pam.d/openvpn

RUN mkdir -p /usr/local/share/openvpn
COPY config/server.conf.tpl /usr/local/share/openvpn/server.conf.tpl

COPY scripts/entrypoint.sh  /entrypoint.sh
COPY scripts/init-pki.sh    /usr/local/bin/init-pki
COPY scripts/add-user.sh    /usr/local/bin/add-user
COPY scripts/revoke-user.sh /usr/local/bin/revoke-user
COPY scripts/list-users.sh  /usr/local/bin/list-users
COPY scripts/show-qr.sh     /usr/local/bin/show-qr

RUN chmod +x /entrypoint.sh \
    /usr/local/bin/init-pki \
    /usr/local/bin/add-user \
    /usr/local/bin/revoke-user \
    /usr/local/bin/list-users \
    /usr/local/bin/show-qr

VOLUME ["/etc/openvpn/data"]
EXPOSE 1194/udp
ENTRYPOINT ["/entrypoint.sh"]
