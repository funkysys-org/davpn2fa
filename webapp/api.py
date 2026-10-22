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


def _api_token():
    return current_app.config.get("API_TOKEN", "")


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
        expected = _api_token()
        if not expected:
            # Fail CLOSED: no API token configured in auth-enabled mode is
            # a boot-time configuration error (app.py refuses to start) —
            # never let the API silently fall back to accepting arbitrary
            # tokens.
            return _api_error(
                "Auth is enabled but the API token is not configured — "
                "refusing to authenticate. Check API_TOKEN.",
                503,
            )

        import hmac as _hmac

        if not _hmac.compare_digest(token, expected):
            return _api_error("Invalid or expired token", 401)

        g.api_user = "api-token"
        return f(*args, **kwargs)

    return decorated


def _log(action, target_user=None, details=None):
    from lib import audit

    audit.log_event(
        action,
        target_user=target_user,
        details=details,
        admin_email=getattr(g, "api_user", "api"),
    )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@api.route("/status", methods=["GET"])
@require_api_auth
def status():
    """
    Get overall VPN status.
    ---
    tags:
      - Status
    summary: VPN status overview
    description: Returns PKI initialisation state, user counts by certificate status, and connected clients.
    security:
      - Bearer: []
    responses:
      200:
        description: Status retrieved successfully.
        schema:
          type: object
          properties:
            pki_initialized:
              type: boolean
              example: true
            stats:
              type: object
              properties:
                total:
                  type: integer
                  example: 5
                valid:
                  type: integer
                  example: 4
                revoked:
                  type: integer
                  example: 1
                expired:
                  type: integer
                  example: 0
                connected:
                  type: integer
                  example: 2
            connected_clients:
              type: array
              items:
                type: object
                properties:
                  username:
                    type: string
                    example: alice
                  real_address:
                    type: string
                    example: "1.2.3.4:12345"
                  virtual_address:
                    type: string
                    example: "10.8.0.2"
                  bytes_rx:
                    type: string
                    example: "12345"
                  bytes_tx:
                    type: string
                    example: "67890"
                  connected_since:
                    type: string
                    example: "2026-04-22 10:00:00"
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    """
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
    """
    List VPN users.
    ---
    tags:
      - Users
    summary: List all VPN users
    description: Returns all users from the PKI index. Supports optional substring search and status filtering.
    security:
      - Bearer: []
    parameters:
      - name: q
        in: query
        type: string
        required: false
        description: Substring to search in usernames.
      - name: status
        in: query
        type: string
        required: false
        enum: [valid, revoked, expired]
        description: Filter by certificate status.
    responses:
      200:
        description: List of users.
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                $ref: '#/definitions/UserSummary'
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    """
    if not pki_initialized():
        return jsonify({"users": []})

    users = list_users()
    search = request.args.get("q", "").lower()
    status_filter = request.args.get("status", "")

    if search:
        users = [u for u in users if search in u["username"].lower()]
    if status_filter:
        users = [u for u in users if u["cert_status"] == status_filter]

    for u in users:
        if u.get("expiry"):
            u["expiry"] = u["expiry"].isoformat()

    return jsonify({"users": users})


@api.route("/users", methods=["POST"])
@require_api_auth
def api_add_user():
    """
    Create a new VPN user.
    ---
    tags:
      - Users
    summary: Create a VPN user
    description: >
      Generates a client certificate signed by the CA, optionally creates a TOTP secret,
      and builds a ready-to-use .ovpn profile. When `require_totp` is true (default),
      returns the TOTP URI and a base64-encoded QR code PNG. When false, both fields
      are null and the profile will not prompt for a password on connect.
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
          properties:
            username:
              type: string
              description: "Letters, digits, _ and - only. Max 64 characters."
              example: alice
            server_ip:
              type: string
              description: "Public IP or hostname to embed in the profile. Falls back to OPENVPN_SERVER_IP."
              example: "1.2.3.4"
            require_totp:
              type: boolean
              description: "Whether to generate a TOTP secret for Google Authenticator. Defaults to true."
              example: true
    responses:
      201:
        description: User created successfully.
        schema:
          type: object
          properties:
            username:
              type: string
              example: alice
            totp_uri:
              type: string
              nullable: true
              example: "otpauth://totp/OpenVPN:alice?secret=ABCDEFGH&issuer=OpenVPN"
            totp_qr_png_base64:
              type: string
              nullable: true
              description: Base64-encoded PNG of the TOTP QR code. Null when require_totp is false.
      400:
        description: Invalid username format.
        schema:
          $ref: '#/definitions/Error'
      409:
        description: Username already exists.
        schema:
          $ref: '#/definitions/Error'
      503:
        description: PKI not yet initialised.
        schema:
          $ref: '#/definitions/Error'
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    """
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    server_ip = (body.get("server_ip") or os.environ.get("OPENVPN_SERVER_IP", "") or "").strip() or None
    require_totp = body.get("require_totp", True)
    if not isinstance(require_totp, bool):
        require_totp = True

    if not USERNAME_RE.match(username):
        return _api_error("username must be 1–64 chars: letters, digits, _ and - only")

    if not pki_initialized():
        return _api_error("PKI is not initialised. Run init-pki on the openvpn container first.", 503)

    try:
        totp_uri = add_user(username, server_ip, require_totp=require_totp)
        qr_b64 = get_totp_qr_base64(username)
        _log("user_added", target_user=username, details={"server_ip": server_ip, "totp": require_totp, "source": "api"})
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
    """
    Get user details.
    ---
    tags:
      - Users
    summary: Get a single VPN user
    description: Returns certificate metadata, TOTP URI, and base64 QR code for the given user.
    security:
      - Bearer: []
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: VPN username.
        example: alice
    responses:
      200:
        description: User detail.
        schema:
          $ref: '#/definitions/UserDetail'
      404:
        description: User not found.
        schema:
          $ref: '#/definitions/Error'
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    """
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
    """
    Revoke a user's certificate.
    ---
    tags:
      - Users
    summary: Revoke a VPN user
    description: Revokes the user's certificate, regenerates the CRL, and removes their profile and TOTP secret.
    security:
      - Bearer: []
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: VPN username to revoke.
        example: alice
    responses:
      200:
        description: User revoked.
        schema:
          type: object
          properties:
            username:
              type: string
              example: alice
            status:
              type: string
              example: revoked
      404:
        description: User not found.
        schema:
          $ref: '#/definitions/Error'
      409:
        description: User already revoked.
        schema:
          $ref: '#/definitions/Error'
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    """
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
    """
    Download .ovpn profile.
    ---
    tags:
      - Users
    summary: Download client profile
    description: Returns the .ovpn client configuration file as a downloadable attachment.
    security:
      - Bearer: []
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: VPN username.
        example: alice
    produces:
      - application/x-openvpn-profile
    responses:
      200:
        description: The .ovpn file content.
        headers:
          Content-Disposition:
            type: string
            description: "attachment; filename=\"alice.ovpn\""
      404:
        description: Profile not found.
        schema:
          $ref: '#/definitions/Error'
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    """
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
    """
    Get TOTP details.
    ---
    tags:
      - Users
    summary: Get TOTP URI and QR code
    description: Returns the otpauth URI and a base64-encoded PNG of the QR code for the user's TOTP secret.
    security:
      - Bearer: []
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: VPN username.
        example: alice
    responses:
      200:
        description: TOTP details.
        schema:
          type: object
          properties:
            username:
              type: string
              example: alice
            totp_uri:
              type: string
              example: "otpauth://totp/OpenVPN:alice?secret=ABCDEFGH&issuer=OpenVPN"
            totp_qr_png_base64:
              type: string
              description: Base64-encoded PNG of the TOTP QR code.
      404:
        description: User not found, or user has no TOTP secret.
        schema:
          $ref: '#/definitions/Error'
      401:
        description: Missing or invalid auth token.
        schema:
          $ref: '#/definitions/Error'
    definitions:
      Error:
        type: object
        properties:
          error:
            type: string
            example: "User 'alice' not found"
      UserSummary:
        type: object
        properties:
          username:
            type: string
            example: alice
          cert_status:
            type: string
            enum: [valid, revoked, expired]
            example: valid
          expiry:
            type: string
            format: date-time
            example: "2028-07-25T12:00:00"
          has_totp:
            type: boolean
            example: true
          has_profile:
            type: boolean
            example: true
      UserDetail:
        allOf:
          - $ref: '#/definitions/UserSummary'
          - type: object
            properties:
              cert_info:
                type: object
                description: Raw certificate metadata.
              totp_uri:
                type: string
                example: "otpauth://totp/OpenVPN:alice?secret=ABCDEFGH&issuer=OpenVPN"
              totp_qr_png_base64:
                type: string
                description: Base64-encoded PNG of the TOTP QR code.
    """
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
