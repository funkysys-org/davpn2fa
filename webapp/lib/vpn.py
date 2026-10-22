import base64
import io
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

DATA_DIR = os.environ.get("OPENVPN_DATA_DIR", "/etc/openvpn/data")
PKI_DIR = f"{DATA_DIR}/pki"


def pki_initialized():
    return os.path.exists(f"{PKI_DIR}/ca.crt")


def _easyrsa_env():
    return {
        **os.environ,
        "EASYRSA_PKI": PKI_DIR,
        "EASYRSA_BATCH": "1",
        "EASYRSA_CERT_EXPIRE": os.environ.get("EASYRSA_CERT_EXPIRE", "825"),
    }


def list_users():
    index = f"{PKI_DIR}/index.txt"
    if not os.path.exists(index):
        return []
    users = []
    with open(index) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue
            status = parts[0]
            expiry_raw = parts[1] if status != "R" else parts[2]
            subject = parts[-1]
            cn_match = re.search(r"CN=([^/\n]+)", subject)
            if not cn_match:
                continue
            cn = cn_match.group(1).strip()
            if cn in ("OpenVPN-CA", "server", "Easy-RSA CA"):
                continue
            try:
                expiry = datetime.strptime(expiry_raw[:12], "%y%m%d%H%M%S")
            except Exception:
                expiry = None
            users.append(
                {
                    "username": cn,
                    "cert_status": {"V": "valid", "R": "revoked", "E": "expired"}.get(
                        status, status
                    ),
                    "expiry": expiry,
                    "has_totp": os.path.exists(
                        f"{DATA_DIR}/users/{cn}/.google_authenticator"
                    ),
                    "has_profile": os.path.exists(f"{DATA_DIR}/clients/{cn}.ovpn"),
                }
            )
    return users


def add_user(username, server_ip=None, require_totp=True):
    if os.path.exists(f"{PKI_DIR}/issued/{username}.crt"):
        raise FileExistsError(
            f"User '{username}' already exists. Revoke the existing certificate first."
        )

    # The user dir is created ONLY when TOTP is enabled. The PAM helper
    # (scripts/vpn-pam-helper.sh, has-secret mode) uses this invariant:
    #   dir ABSENT                     -> cert-only user -> allow (TLS-only)
    #   dir present + secret present   -> TOTP user       -> GA required
    #   dir present + secret MISSING   -> damaged state   -> deny (fail closed)
    user_dir = f"{DATA_DIR}/users/{username}"
    if require_totp:
        os.makedirs(user_dir, mode=0o700, exist_ok=True)
    env = _easyrsa_env()

    subprocess.run(
        ["easyrsa", "gen-req", username, "nopass"],
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["easyrsa", "sign-req", "client", username],
        env=env,
        check=True,
        capture_output=True,
    )

    if require_totp:
        ga_file = f"{user_dir}/.google_authenticator"
        subprocess.run(
            [
                "google-authenticator",
                "--time-based",
                "--disallow-reuse",
                "--force",
                "--rate-limit=3",
                "--rate-time=30",
                "--window-size=3",
                "--no-confirm",
                "--qr-mode=NONE",
                f"--secret={ga_file}",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(ga_file, 0o600)

    _build_client_profile(username, server_ip)
    return get_totp_uri(username)


def revoke_user(username):
    env = _easyrsa_env()
    subprocess.run(
        ["easyrsa", "revoke", username],
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["easyrsa", "gen-crl"],
        env=env,
        check=True,
        capture_output=True,
    )
    profile = f"{DATA_DIR}/clients/{username}.ovpn"
    if os.path.exists(profile):
        os.remove(profile)
    user_dir = f"{DATA_DIR}/users/{username}"
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)


def get_totp_uri(username):
    ga_file = f"{DATA_DIR}/users/{username}/.google_authenticator"
    if not os.path.exists(ga_file):
        return None
    with open(ga_file) as f:
        secret = f.readline().strip()
    return (
        f"otpauth://totp/OpenVPN:{username}"
        f"?secret={secret}&issuer=OpenVPN&algorithm=SHA1&digits=6&period=30"
    )


def get_totp_qr_base64(username):
    uri = get_totp_uri(username)
    if not uri:
        return None
    try:
        import qrcode

        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None


def get_connected_clients():
    status_log = f"{DATA_DIR}/openvpn-status.log"
    if not os.path.exists(status_log):
        return []
    clients = []
    with open(status_log) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("CLIENT_LIST"):
                continue
            sep = "," if "," in line else "\t"
            parts = line.split(sep)
            if len(parts) < 5 or parts[1] == "Common Name":
                continue
            clients.append(
                {
                    "username": parts[1],
                    "real_address": parts[2],
                    "virtual_address": parts[3],
                    "bytes_rx": parts[4] if len(parts) > 4 else "-",
                    "bytes_tx": parts[5] if len(parts) > 5 else "-",
                    "connected_since": parts[7] if len(parts) > 7 else parts[-1],
                }
            )
    return clients


def get_client_profile(username):
    if not os.path.exists(f"{PKI_DIR}/issued/{username}.crt"):
        return None
    _build_client_profile(username)
    profile_path = f"{DATA_DIR}/clients/{username}.ovpn"
    if os.path.exists(profile_path):
        return Path(profile_path).read_text()
    return None


def get_user_cert_info(username):
    cert_path = f"{PKI_DIR}/issued/{username}.crt"
    if not os.path.exists(cert_path):
        return {}
    try:
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                cert_path,
                "-noout",
                "-subject",
                "-issuer",
                "-startdate",
                "-enddate",
                "-fingerprint",
                "-sha256",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        info = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                info[key.strip()] = val.strip()
        return info
    except Exception:
        return {}


def _build_client_profile(username, server_ip=None):
    server_ip = server_ip or os.environ.get("OPENVPN_SERVER_IP", "")
    if not server_ip:
        # Refuse to emit a silently-broken profile: an .ovpn pointing at
        # "YOUR_SERVER_IP" connects to nothing and confuses the user.
        raise ValueError(
            "No server IP available for the client profile. Set "
            "OPENVPN_SERVER_IP or pass server_ip explicitly."
        )
    port = os.environ.get("OPENVPN_PORT", "1194")
    proto = os.environ.get("OPENVPN_PROTO", "udp")

    ca = Path(f"{PKI_DIR}/ca.crt").read_text().strip()
    cert_raw = Path(f"{PKI_DIR}/issued/{username}.crt").read_text()
    cert_match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        cert_raw,
        re.DOTALL,
    )
    cert = cert_match.group(1).strip() if cert_match else cert_raw.strip()
    key = Path(f"{PKI_DIR}/private/{username}.key").read_text().strip()
    ta = Path(f"{PKI_DIR}/ta.key").read_text().strip()

    has_totp = os.path.exists(f"{DATA_DIR}/users/{username}/.google_authenticator")
    totp_comment = "# Password prompt = current 6-digit Google Authenticator code\n" if has_totp else "# No TOTP configured — enter any value when prompted for a password\n"

    profile = (
        f"# OpenVPN client profile for: {username}\n"
        f"# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"{totp_comment}\n"
        f"client\ndev tun\nproto {proto}\n"
        f"remote {server_ip} {port}\n"
        f"resolv-retry infinite\nnobind\npersist-key\npersist-tun\n\n"
        f"remote-cert-tls server\nverify-x509-name server name\n\n"
        f"cipher AES-256-GCM\nauth SHA256\ntls-version-min 1.2\n\n"
        f"auth-user-pass\nauth-nocache\nkey-direction 1\nverb 3\n\n"
        f"<ca>\n{ca}\n</ca>\n\n"
        f"<cert>\n{cert}\n</cert>\n\n"
        f"<key>\n{key}\n</key>\n\n"
        f"<tls-auth>\n{ta}\n</tls-auth>\n"
    )

    os.makedirs(f"{DATA_DIR}/clients", exist_ok=True)
    profile_path = f"{DATA_DIR}/clients/{username}.ovpn"
    Path(profile_path).write_text(profile)
    os.chmod(profile_path, 0o600)
