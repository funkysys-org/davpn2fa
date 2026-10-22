OpenVPN 2FA — Docker Compose Stack
====================================

PURPOSE
-------
This project runs a self-hosted OpenVPN server with mandatory two-factor
authentication (client certificate + Google Authenticator TOTP) alongside a
Flask-based web management UI. Administrators can create and revoke VPN users,
download .ovpn profiles, and scan TOTP QR codes — all from a browser.
Administrative actions (successful logins, user additions, revocations,
profile downloads, QR views) are recorded to a local SQLite audit log
stored on the same volume as the PKI.

TOTP ENFORCEMENT (IMPORTANT)
----------------------------
The TOTP factor is ENFORCED at the VPN layer via PAM:

  - Users created with a TOTP secret MUST present a valid code.
    Wrong or missing codes are REJECTED — there is no fallback.
  - Users created with require_totp=false (certificate-only) are
    authenticated by their client certificate alone (TLS layer).
  - The PAM stack is `pam_google_authenticator` with `required`
    control + a helper (scripts/vpn-pam-helper.sh) that distinguishes
    the two user classes. A damaged state (secret file missing while
    the user directory exists) fails CLOSED.

ARCHITECTURE
------------
Two Docker containers share a named volume (openvpn-data):

  openvpn     Debian-based OpenVPN server with EasyRSA PKI and
              libpam-google-authenticator for TOTP enforcement.
              Listens on UDP 1194 (configurable).

  webapp      Python/Flask web UI for VPN administration.
              Listens on TCP 8080 (configurable), proxied internally
              to Flask on port 5000. Bound to 127.0.0.1 by default —
              front it with a TLS reverse proxy.

Both containers read from and write to the shared /etc/openvpn/data volume
which holds the PKI, user certificates, per-user TOTP secrets, and the
audit log (audit_log.db).


PREREQUISITES
-------------
  - Docker Engine 20.10+ and Docker Compose v2
  - A public IP address or hostname that VPN clients can reach
  - A TLS reverse proxy (nginx, Caddy) if the web UI needs remote access

QUICK START
-----------
1. Copy the example environment file:

       cp .env.example .env

2. Edit .env and set at minimum:

       OPENVPN_SERVER_IP     Your server's public IP or hostname

   Then generate the admin credentials:

       # Admin password hash (web UI login)
       python -c "from werkzeug.security import generate_password_hash as g; print(g('YOUR-PASSWORD'))"
       -> ADMIN_PASSWORD_HASH

       # API bearer token (/api/v1)
       python -c "import secrets; print(secrets.token_hex(32))"
       -> API_TOKEN

       # Flask session signing key
       python -c "import secrets; print(secrets.token_hex(32))"
       -> FLASK_SECRET_KEY

   Authentication is ON by default (AUTH_DISABLED=0): the webapp refuses
   to boot without the credentials above. If you cannot use local auth and
   the UI is reachable ONLY from a trusted private network (or behind a
   reverse proxy with its own auth), you may explicitly set
   AUTH_DISABLED=1 to skip login.

3. Build and start the stack:

       docker compose up -d --build

4. Initialise the PKI (required once on first run):

       docker exec -it openvpn init-pki

   The openvpn container sleeps indefinitely until the PKI exists.
   After init-pki completes, restart the container:

       docker compose restart openvpn

5. Open the web UI (via your reverse proxy, or on the host at
   http://127.0.0.1:8080) and log in with ADMIN_EMAIL + your password.


ENVIRONMENT VARIABLES
---------------------
Variable                Default             Description
----------------------  ------------------  ----------------------------------
OPENVPN_SERVER_IP       (auto-detect)       Public IP/hostname for .ovpn files
OPENVPN_PORT            1194                UDP port the VPN listens on
OPENVPN_PROTO           udp                 Transport protocol (udp or tcp)
OPENVPN_NETWORK         10.8.0.0            VPN subnet
OPENVPN_NETMASK         255.255.255.0       VPN subnet mask
OPENVPN_DNS1            1.1.1.1             Primary DNS pushed to clients
OPENVPN_DNS2            8.8.8.8             Secondary DNS pushed to clients
OPENVPN_STATIC_ROUTES   (empty)             Comma-separated CIDR networks for
                                            split-tunnel routing (see below)
EASYRSA_KEY_SIZE        4096                RSA key size for PKI
EASYRSA_CA_EXPIRE       3650                CA certificate lifetime (days)
EASYRSA_CERT_EXPIRE     825                 User certificate lifetime (days)
WEBAPP_PORT             8080                Host port for the web UI
                                            (bound to 127.0.0.1)
ADMIN_EMAIL             admin               Login id / label for the admin
ADMIN_PASSWORD_HASH     (required)          Werkzeug password hash (scrypt)
API_TOKEN               (required)          Static bearer token for /api/v1
FLASK_SECRET_KEY        (required)          Flask session signing key —
                                            the app refuses to boot on an
                                            empty, weak, or default key
FLASK_DEBUG             0                   Set to 1 for development only
AUTH_DISABLED           0                   1 disables login — ONLY for
                                            trusted-network deployments


STATIC ROUTES (OPENVPN_STATIC_ROUTES)
-------------------------------------
By default, all client traffic is routed through the VPN (redirect-gateway).
If you only need specific networks to be reachable over the VPN while the
rest of the client's traffic uses their normal internet connection, set
OPENVPN_STATIC_ROUTES to a comma-separated list of CIDR networks.

Example — route only two networks through the VPN:

    OPENVPN_STATIC_ROUTES=80.50.43.0/24,192.168.1.0/24

This adds "push route" directives to the OpenVPN server config for each
network. Supported CIDR prefixes: /8, /16, /24, /25, /26, /27, /28, /29,
/30, /31, /32. Invalid or unsupported entries are skipped with a warning
in the container log.

When OPENVPN_STATIC_ROUTES is set, the server config REMOVES the
redirect-gateway directive: split-tunnel. Only the listed networks route
through the VPN; all other client traffic follows the client's own
default gateway.

When OPENVPN_STATIC_ROUTES is empty (the default), the VPN routes all
client traffic as usual (redirect-gateway).


MANAGING VPN USERS
------------------
Via the web UI (recommended):
  - Add user, list users, download .ovpn profiles, revoke — from the
    Users page. Each new user gets a TOTP QR code to scan with Google
    Authenticator or any compatible app (Authy, Aegis, etc.).

Via the command line:
  - Add a user:
        docker exec -it openvpn add-user <username>

  - List users:
        docker exec -it openvpn list-users

  - Revoke a user:
        docker exec -it openvpn revoke-user <username>

  - Show TOTP QR code in terminal:
        docker exec -it openvpn show-qr <username>


CLIENT SETUP
------------
1. Install an OpenVPN client (OpenVPN Connect, Tunnelblick, network-manager-openvpn, etc.).
2. Download the .ovpn profile from the web UI (Users -> user detail -> Download).
3. Import the profile into the client.
4. When connecting, enter the TOTP code from the authenticator app as the password.
   The client certificate handles the "something you have" factor automatically.


API (v1)
--------
REST API under /api/v1 (interactive docs at /api/docs). Authenticate with:

       Authorization: Bearer <API_TOKEN>

Endpoints: GET /status, GET/POST /users, GET /users/<name>,
POST /users/<name>/revoke, GET /users/<name>/profile,
GET /users/<name>/totp. All endpoints write to the audit log.


AUDIT LOG
---------
Every administrative action (user_added, user_revoked, profile_downloaded,
qr_viewed) is appended to a local SQLite database at
/etc/openvpn/data/audit_log.db — same volume as the PKI, included in the
volume backup. The dashboard shows the 10 most recent events. Audit
recording works in ALL modes, including AUTH_DISABLED=1 (with the actor
recorded as "unknown"/"anonymous").

DATA PERSISTENCE
----------------
All PKI certificates, keys, user TOTP secrets, and the audit log are
stored in the Docker named volume "openvpn-data". Back up this volume
regularly.

To back up:
    docker run --rm -v openvpn-data:/data -v $(pwd):/backup \
        alpine tar czf /backup/openvpn-data-backup.tar.gz /data

To restore:
    docker run --rm -v openvpn-data:/data -v $(pwd):/backup \
        alpine tar xzf /backup/openvpn-data-backup.tar.gz -C /

Note: the backup tarball contains the CA private key and all TOTP
secrets in plaintext — store it encrypted and restrict access.


AUTHENTICATION (LOCAL ADMIN)
----------------------------
Authentication is ON by default (AUTH_DISABLED=0). On boot the webapp
REFUSES to start if:
  - ADMIN_PASSWORD_HASH, API_TOKEN, or FLASK_SECRET_KEY is missing,
    weak, or a known default.

This is deliberate: a VPN admin console holding the CA, client keys, and
TOTP seeds must never silently fall back to "no auth".

If you cannot use local auth and the web UI is reachable ONLY from a
trusted internal network or behind a reverse proxy/firewall that
enforces its own access controls, set AUTH_DISABLED=1 explicitly.

When AUTH_DISABLED=1:
  - No login page is shown; all routes are immediately accessible.
  - The sidebar displays an "Auth disabled" badge as a visual reminder.
  - The sign-out button is hidden.
  - Audit entries are recorded with the admin email set to "unknown".

NEVER leave AUTH_DISABLED=1 on a host that is publicly reachable.


SECURITY NOTES
--------------
  - The openvpn container requires NET_ADMIN and NET_RAW capabilities and
    direct access to /dev/net/tun. Do not run on shared/untrusted hosts.
  - The web UI port is bound to 127.0.0.1 by default. Use a TLS reverse
    proxy (nginx, Caddy) with access controls for remote access.
  - Always set a strong, random FLASK_SECRET_KEY — with auth enabled the
    webapp refuses to boot without one.
  - Never set FLASK_DEBUG=1 in production.
  - Rotate user certificates before EASYRSA_CERT_EXPIRE days elapse.
  - The web UI has no rate limiting by default; the reverse proxy in front
    of it should provide TLS, rate limiting, and access controls.
  - TOTP is ENFORCED at the VPN layer: users with a TOTP secret must
    present a valid code (PAM `required`, no fallback). Users created
    with require_totp=false authenticate with certificate only.
  - When OPENVPN_SERVER_IP is unset, add-user auto-detects the public IP
    via api.ipify.org (an outbound query to a third party). Set
    OPENVPN_SERVER_IP to avoid it.


STOPPING AND REMOVING
---------------------
Stop the stack:
    docker compose down

Stop and remove all data (irreversible):
    docker compose down -v
