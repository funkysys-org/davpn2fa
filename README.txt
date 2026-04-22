OpenVPN 2FA — Docker Compose Stack
====================================

PURPOSE
-------
This project runs a self-hosted OpenVPN server with mandatory two-factor
authentication (client certificate + Google Authenticator TOTP) alongside a
Flask-based web management UI. Administrators can create and revoke VPN users,
download .ovpn profiles, and scan TOTP QR codes — all from a browser. Audit
events (logins, user additions, revocations, profile downloads) are optionally
logged to a Supabase database.


ARCHITECTURE
------------
Two Docker containers share a named volume (openvpn-data):

  openvpn     Debian-based OpenVPN server with EasyRSA PKI and
              libpam-google-authenticator for TOTP enforcement.
              Listens on UDP 1194 (configurable).

  webapp      Python/Flask web UI for VPN administration.
              Listens on TCP 8080 (configurable), proxied internally
              to Flask on port 5000.

Both containers read from and write to the shared /etc/openvpn/data volume
which holds the PKI, user certificates, and per-user TOTP secrets.


PREREQUISITES
-------------
  - Docker Engine 20.10+ and Docker Compose v2
  - A public IP address or hostname that VPN clients can reach
  - (Optional) A Supabase project for admin authentication and audit logging


QUICK START
-----------
1. Copy the example environment file:

       cp .env.example .env

2. Edit .env and set at minimum:

       OPENVPN_SERVER_IP   Your server's public IP or hostname
       FLASK_SECRET_KEY    A random 64-character hex string (see comment in .env)

   To enable authenticated login and audit logging, also set:

       SUPABASE_URL        Your Supabase project URL
       SUPABASE_ANON_KEY   Your Supabase anon/public key

   Without Supabase, the web UI accepts any email and skips authentication
   (development/testing only — not suitable for production).

3. Build and start the stack:

       docker compose up -d --build

4. Initialise the PKI (required once on first run):

       docker exec -it openvpn init-pki

   The openvpn container sleeps indefinitely until the PKI exists.
   After init-pki completes, restart the container:

       docker compose restart openvpn

5. Open the web UI at http://<server-ip>:8080 and log in.


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
EASYRSA_KEY_SIZE        4096                RSA key size for PKI
EASYRSA_CA_EXPIRE       3650                CA certificate lifetime (days)
EASYRSA_CERT_EXPIRE     825                 User certificate lifetime (days)
WEBAPP_PORT             8080                Host port for the web UI
FLASK_SECRET_KEY        change-me-in-prod   Flask session signing key
FLASK_DEBUG             0                   Set to 1 for development only
AUTH_DISABLED           0                   Set to 1 to bypass login (trusted networks only)
SUPABASE_URL            (empty)             Supabase project URL
SUPABASE_ANON_KEY       (empty)             Supabase anon key


MANAGING VPN USERS
------------------
Via the web UI (recommended):
  - Dashboard: http://<server>:8080/
  - Add user:  http://<server>:8080/users/add
  - List users and download .ovpn profiles from the Users page.
  - Each new user gets a TOTP QR code to scan with Google Authenticator
    or any compatible app (Authy, Aegis, etc.).

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


DATA PERSISTENCE
----------------
All PKI certificates, keys, and user TOTP secrets are stored in the Docker
named volume "openvpn-data". Back up this volume regularly.

To back up:
    docker run --rm -v openvpn-data:/data -v $(pwd):/backup \
        alpine tar czf /backup/openvpn-data-backup.tar.gz /data

To restore:
    docker run --rm -v openvpn-data:/data -v $(pwd):/backup \
        alpine tar xzf /backup/openvpn-data-backup.tar.gz -C /


SUPABASE SETUP (OPTIONAL)
--------------------------
If SUPABASE_URL and SUPABASE_ANON_KEY are configured, the web UI:
  - Requires admins to log in with Supabase email/password authentication.
  - Writes every administrative action to an "audit_log" table.

The required Supabase migration is in:
    supabase/migrations/20260422175931_create_audit_log.sql

Apply it via the Supabase dashboard SQL editor or the Supabase CLI.
Create admin accounts through the Supabase Authentication dashboard.


UNAUTHENTICATED ACCESS (AUTH_DISABLED)
--------------------------------------
Set AUTH_DISABLED=1 in .env to skip the login screen entirely. This is
appropriate when the web UI is accessible only from a trusted internal network
or behind a reverse proxy/firewall that enforces its own access controls.

When AUTH_DISABLED=1:
  - No login page is shown; all routes are immediately accessible.
  - The sidebar displays an "Auth disabled" badge as a visual reminder.
  - The sign-out button is hidden.
  - Audit log entries (if Supabase is configured) are written with the
    admin email set to "unknown".

NEVER set AUTH_DISABLED=1 on a host that is publicly reachable.


SECURITY NOTES
--------------
  - The openvpn container requires NET_ADMIN and NET_RAW capabilities and
    direct access to /dev/net/tun. Do not run on shared/untrusted hosts.
  - Always set a strong, random FLASK_SECRET_KEY in production.
  - Never set FLASK_DEBUG=1 in production.
  - Rotate user certificates before EASYRSA_CERT_EXPIRE days elapse.
  - The web UI has no rate limiting by default; place it behind a reverse
    proxy (nginx, Caddy) with TLS and access controls in production.
  - Without Supabase and without AUTH_DISABLED, the web UI has no
    authentication — restrict access by network/firewall rules.


STOPPING AND REMOVING
---------------------
Stop the stack:
    docker compose down

Stop and remove all data (irreversible):
    docker compose down -v
