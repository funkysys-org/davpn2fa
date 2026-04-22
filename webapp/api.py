import os
import re
import subprocess
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

from lib.vpn import (
    add_user,
    get_client_profile,
    get_connected_clients,
    get_totp_qr_base64,
    get_totp_uri,
    get_user_cert_info,
    list_users,
    pki_initialized,
    revoke_user,
)

api = Blueprint("api", __name__, url_prefix="/api/v1")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _auth_disabled():
    return current_app.config.get("AUTH_DISABLED", False)


def _supabase():
    return current_app.config.get("SUPABASE_BASE")


def _api_error(message, status=400):
    return jsonify({"error": message}), status


def require_api_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if _auth_disabled():
            g.api_user = "anonymous"
            return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return _api_error("Missing or invalid Authorization header", 401)

        token = auth_header[len("Bearer "):]
        sb = _supabase()
        if not sb:
            # No Supabase configured — accept any bearer token and record it
            g.api_user = "api-user"
            return f(*args, **kwargs)

        try:
            user_resp = sb.auth.get_user(token)
            g.api_user = user_resp.user.email
        except Exception:
            return _api_error("Invalid or expired token", 401)

        return f(*args, **kwargs)

    return decorated


def _log(action, target_user=None, details=None):
    sb = _supabase()
    if not sb:
        return
    try:
        sb.table("audit_log").insert(
            {
                "admin_email": getattr(g, "api_user", "api"),
                "action": action,
                "target_user": target_user,
                "details": details or {},
            }
        ).execute()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@api.route("/status", methods=["GET"])
@require_api_auth
def status():
    """Overall VPN status: PKI state, user counts, connected clients."""
    initialized = pki_initialized()
    users = list_users() if initialized else []
    connected = get_connected_clients() if initialized else []
    return jsonify(
        {
            "pki_initialized": initialized,
            "stats": {
                "total": len(users),
                "valid": sum(1 for u in users if u["cert_status"] == "valid"),
                "revoked": sum(1 for u in users if u["cert_status"] == "revoked"),
                "expired": sum(1 for u in users if u["cert_status"] == "expired"),
                "connected": len(connected),
            },
            "connected_clients": connected,
        }
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@api.route("/users", methods=["GET"])
@require_api_auth
def api_list_users():
    """List all VPN users. Optional query params: q (search), status (valid|revoked|expired)."""
    if not pki_initialized():
        return jsonify({"users": []})

    users = list_users()
    search = request.args.get("q", "").lower()
    status_filter = request.args.get("status", "")

    if search:
        users = [u for u in users if search in u["username"].lower()]
    if status_filter:
        users = [u for u in users if u["cert_status"] == status_filter]

    # Serialize datetime fields
    for u in users:
        if u.get("expiry"):
            u["expiry"] = u["expiry"].isoformat()

    return jsonify({"users": users})


@api.route("/users", methods=["POST"])
@require_api_auth
def api_add_user():
    """Create a new VPN user. Body: {"username": "...", "server_ip": "..."} (server_ip optional)."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    server_ip = (body.get("server_ip") or os.environ.get("OPENVPN_SERVER_IP", "") or "").strip() or None

    if not USERNAME_RE.match(username):
        return _api_error("username must be 1–64 chars: letters, digits, _ and - only")

    if not pki_initialized():
        return _api_error("PKI is not initialised. Run init-pki on the openvpn container first.", 503)

    try:
        totp_uri = add_user(username, server_ip)
        qr_b64 = get_totp_qr_base64(username)
        _log("user_added", target_user=username, details={"server_ip": server_ip, "source": "api"})
        return jsonify(
            {
                "username": username,
                "totp_uri": totp_uri,
                "totp_qr_png_base64": qr_b64,
            }
        ), 201
    except FileExistsError as e:
        return _api_error(str(e), 409)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
        return _api_error(f"PKI command failed: {stderr}", 500)
    except Exception as e:
        return _api_error(str(e), 500)


@api.route("/users/<username>", methods=["GET"])
@require_api_auth
def api_get_user(username):
    """Get details for a single user including cert info and TOTP URI."""
    users = list_users()
    user = next((u for u in users if u["username"] == username), None)
    if not user:
        return _api_error(f"User '{username}' not found", 404)

    if user.get("expiry"):
        user["expiry"] = user["expiry"].isoformat()

    user["cert_info"] = get_user_cert_info(username)
    user["totp_uri"] = get_totp_uri(username) if user["has_totp"] else None
    user["totp_qr_png_base64"] = get_totp_qr_base64(username) if user["has_totp"] else None

    return jsonify(user)


@api.route("/users/<username>/revoke", methods=["POST"])
@require_api_auth
def api_revoke_user(username):
    """Revoke a user's certificate."""
    users = list_users()
    user = next((u for u in users if u["username"] == username), None)
    if not user:
        return _api_error(f"User '{username}' not found", 404)
    if user["cert_status"] == "revoked":
        return _api_error(f"User '{username}' is already revoked", 409)

    try:
        revoke_user(username)
        _log("user_revoked", target_user=username, details={"source": "api"})
        return jsonify({"username": username, "status": "revoked"})
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
        return _api_error(f"PKI command failed: {stderr}", 500)
    except Exception as e:
        return _api_error(str(e), 500)


@api.route("/users/<username>/profile", methods=["GET"])
@require_api_auth
def api_download_profile(username):
    """Download the .ovpn client profile as plain text."""
    profile = get_client_profile(username)
    if not profile:
        return _api_error(f"No profile found for '{username}'. Certificate may not exist.", 404)

    _log("profile_downloaded", target_user=username, details={"source": "api"})
    return current_app.response_class(
        profile,
        mimetype="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{username}.ovpn"'},
    )


@api.route("/users/<username>/totp", methods=["GET"])
@require_api_auth
def api_get_totp(username):
    """Return TOTP URI and QR code (base64 PNG) for a user."""
    users = list_users()
    user = next((u for u in users if u["username"] == username), None)
    if not user:
        return _api_error(f"User '{username}' not found", 404)
    if not user["has_totp"]:
        return _api_error(f"No TOTP secret found for '{username}'", 404)

    totp_uri = get_totp_uri(username)
    qr_b64 = get_totp_qr_base64(username)
    _log("qr_viewed", target_user=username, details={"source": "api"})
    return jsonify({"username": username, "totp_uri": totp_uri, "totp_qr_png_base64": qr_b64})
