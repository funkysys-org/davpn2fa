import io
import os
import re
import subprocess
from functools import wraps

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

import hmac

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
from lib import audit

app = Flask(__name__)

AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "0") == "1"
app.config["AUTH_DISABLED"] = AUTH_DISABLED

# ── Local admin credentials (replaces the former Supabase auth) ─────────────
# ADMIN_EMAIL: any identifier for the single admin account (email-like or
#              a plain name — it is only used as a label + login id).
# ADMIN_PASSWORD_HASH: Werkzeug `generate_password_hash` output (scrypt).
#              Generate with:
#                python -c "from werkzeug.security import generate_password_hash as g; print(g('YOUR-PASSWORD'))"
# API_TOKEN:   bearer token for /api/v1 (constant-time compared).
#              Generate with: python -c "import secrets; print(secrets.token_hex(32))"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
API_TOKEN = os.environ.get("API_TOKEN", "")
app.config["API_TOKEN"] = API_TOKEN

if not AUTH_DISABLED:
    missing = [
        name
        for name, val in (
            ("ADMIN_PASSWORD_HASH", ADMIN_PASSWORD_HASH),
            ("API_TOKEN", API_TOKEN),
        )
        if not val
    ]
    if missing:
        raise RuntimeError(
            "Authentication is enabled (AUTH_DISABLED=0) but not configured: "
            f"missing {', '.join(missing)}. Set them in .env, or — ONLY if "
            "the UI is unreachable from untrusted networks — set "
            "AUTH_DISABLED=1."
        )

    # Werkzeug hashes look like 'scrypt:32768:8:1$salt$hash'. A value with
    # no '$' is almost certainly corrupted by docker-compose interpolation:
    # compose treats $VAR sequences inside .env values as variable
    # references and substitutes them with an empty string. That mangled
    # hash would make EVERY login fail with a misleading "Invalid email
    # or password" — refuse to boot instead, with the actual cause.
    import re as _re

    if not _re.match(r"^[A-Za-z0-9]+(?::[0-9A-Za-z]+)*\$", ADMIN_PASSWORD_HASH):
        raise RuntimeError(
            "ADMIN_PASSWORD_HASH does not look like a Werkzeug password hash "
            "(expected something like 'scrypt:32768:8:1$salt$hash' — it must "
            "contain '$' separators). Most likely cause: docker-compose "
            "interpolated the '$...' parts of the hash inside your .env "
            "value. FIX: single-quote the value in .env — "
            "ADMIN_PASSWORD_HASH='scrypt:32768:8:1$...$...'"
        )

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")
_WEAK_SECRET = (
    not app.secret_key
    or app.secret_key in ("change-me-in-production", "change-me-in-prod")
    or len(app.secret_key) < 32
)
if _WEAK_SECRET:
    if AUTH_DISABLED:
        # Trusted-network mode: the session key only signs flash messages,
        # so fall back to an ephemeral key with a loud warning (sessions
        # will not survive restarts).
        import secrets as _secrets

        app.logger.warning(
            "FLASK_SECRET_KEY is empty/weak/known — generating an ephemeral "
            "key. Sessions will not survive restarts; set a strong key "
            '(python -c "import secrets; print(secrets.token_hex(32))").'
        )
        app.secret_key = _secrets.token_urlsafe(48)
    else:
        # Sessions ARE the admin credential when auth is on — a weak or
        # missing key makes them forgeable. Refuse to boot.
        raise RuntimeError(
            "FLASK_SECRET_KEY is missing, weak, or a known default — with "
            "auth enabled this makes admin sessions forgeable. Generate "
            'one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

from flasgger import Swagger  # noqa: E402
from api import api as api_blueprint  # noqa: E402

app.register_blueprint(api_blueprint)

Swagger(app, config={
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/api/v1/apispec.json",
            "rule_filter": lambda rule: rule.rule.startswith("/api/v1"),
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api/docs",
}, template={
    "info": {
        "title": "OpenVPN Manager API",
        "description": (
            "REST API for the OpenVPN 2FA management webapp.\n\n"
            "**Authentication:** include the API token as `Authorization: Bearer <API_TOKEN>`. "
            "When `AUTH_DISABLED=1` the header is not required."
        ),
        "version": "1.0.0",
        "contact": {"name": "OpenVPN Manager"},
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Static API token — format: `Bearer <token>`",
        }
    },
    "security": [{"Bearer": []}],
    "consumes": ["application/json"],
    "produces": ["application/json"],
})


@app.context_processor
def inject_globals():
    return {"auth_disabled": AUTH_DISABLED}


def _log(action, target_user=None, details=None):
    audit.log_event(
        action,
        target_user=target_user,
        details=details,
        admin_email=session.get("user_email", "unknown"),
    )


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if AUTH_DISABLED:
            return f(*args, **kwargs)
        if "user_email" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)

    return decorated


# ─── Auth ──────────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    if AUTH_DISABLED or "user_email" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if AUTH_DISABLED or "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        from werkzeug.security import check_password_hash

        try:
            password_ok = check_password_hash(ADMIN_PASSWORD_HASH, password)
        except Exception:
            password_ok = False
        try:
            email_ok = hmac.compare_digest(
                email.encode("utf-8", "surrogatepass"),
                ADMIN_EMAIL.encode("utf-8", "surrogatepass"),
            )
        except Exception:
            email_ok = False
        if email_ok and password_ok:
            session["user_email"] = ADMIN_EMAIL
            audit.log_event("login_success", admin_email=ADMIN_EMAIL)
            next_url = request.args.get("next") or url_for("dashboard")
            if (
                not next_url.startswith("/")
                or next_url.startswith("//")
                or next_url.startswith("/\\")
                or ":" in next_url.split("?", 1)[0].split("#", 1)[0]
            ):
                # Only allow same-site relative redirects. Rejects absolute
                # (https://evil.com), protocol-relative (//evil.com), and
                # backslash tricks (/\evil.com) — open-redirect phishing.
                next_url = url_for("dashboard")
            return redirect(next_url)
        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if AUTH_DISABLED:
        return redirect(url_for("dashboard"))
    session.clear()
    return redirect(url_for("login"))


# ─── Dashboard ────────────────────────────────────────────────────────────────


@app.route("/dashboard")
@require_auth
def dashboard():
    initialized = pki_initialized()
    users = list_users() if initialized else []
    connected = get_connected_clients() if initialized else []
    stats = {
        "total": len(users),
        "valid": sum(1 for u in users if u["cert_status"] == "valid"),
        "revoked": sum(1 for u in users if u["cert_status"] == "revoked"),
        "expired": sum(1 for u in users if u["cert_status"] == "expired"),
        "connected": len(connected),
    }
    recent_actions = audit.recent_events(limit=10)

    return render_template(
        "dashboard.html",
        stats=stats,
        connected=connected,
        recent_actions=recent_actions,
        initialized=initialized,
    )


# ─── Users ────────────────────────────────────────────────────────────────────


@app.route("/users")
@require_auth
def users():
    initialized = pki_initialized()
    all_users = list_users() if initialized else []
    search = request.args.get("q", "").lower()
    status_filter = request.args.get("status", "")
    if search:
        all_users = [u for u in all_users if search in u["username"].lower()]
    if status_filter:
        all_users = [u for u in all_users if u["cert_status"] == status_filter]
    return render_template(
        "users.html",
        users=all_users,
        search=search,
        status_filter=status_filter,
        initialized=initialized,
    )


@app.route("/users/add", methods=["GET", "POST"])
@require_auth
def add_user_route():
    default_ip = os.environ.get("OPENVPN_SERVER_IP", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        server_ip = request.form.get("server_ip", "").strip() or default_ip or None
        require_totp = request.form.get("require_totp") == "1"

        if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", username):
            flash(
                "Username must be 1–64 characters using only letters, digits, _ and -.",
                "error",
            )
            return render_template("add_user.html", default_server_ip=default_ip)

        try:
            totp_uri = add_user(username, server_ip, require_totp=require_totp)
            qr_b64 = get_totp_qr_base64(username)
            _log("user_added", target_user=username, details={"server_ip": server_ip, "totp": require_totp})
            flash(f"User '{username}' created successfully.", "success")
            return render_template(
                "user_created.html",
                username=username,
                totp_uri=totp_uri,
                qr_b64=qr_b64,
            )
        except FileExistsError as e:
            flash(str(e), "error")
        except subprocess.CalledProcessError as e:
            flash(f"PKI command failed: {e.stderr.decode() if e.stderr else e}", "error")
        except Exception as e:
            flash(f"Failed to create user: {e}", "error")

    return render_template("add_user.html", default_server_ip=default_ip)


@app.route("/users/<username>")
@require_auth
def user_detail(username):
    all_users = list_users()
    user = next((u for u in all_users if u["username"] == username), None)
    if not user:
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("users"))

    qr_b64 = get_totp_qr_base64(username) if user["has_totp"] else None
    cert_info = get_user_cert_info(username)
    totp_uri = get_totp_uri(username) if user["has_totp"] else None

    return render_template(
        "user_detail.html",
        user=user,
        qr_b64=qr_b64,
        cert_info=cert_info,
        totp_uri=totp_uri,
    )


@app.route("/users/<username>/revoke", methods=["POST"])
@require_auth
def revoke_user_route(username):
    try:
        revoke_user(username)
        _log("user_revoked", target_user=username)
        flash(f"User '{username}' has been revoked.", "success")
    except Exception as e:
        flash(f"Failed to revoke user: {e}", "error")
    return redirect(url_for("users"))


@app.route("/users/<username>/download")
@require_auth
def download_profile(username):
    profile = get_client_profile(username)
    if not profile:
        flash("No profile found. The certificate may not exist.", "error")
        return redirect(url_for("user_detail", username=username))
    _log("profile_downloaded", target_user=username)
    return send_file(
        io.BytesIO(profile.encode("utf-8")),
        as_attachment=True,
        download_name=f"{username}.ovpn",
        mimetype="application/x-openvpn-profile",
    )


@app.route("/users/<username>/qr")
@require_auth
def show_qr(username):
    qr_b64 = get_totp_qr_base64(username)
    if not qr_b64:
        flash(f"No TOTP secret found for '{username}'.", "error")
        return redirect(url_for("user_detail", username=username))
    _log("qr_viewed", target_user=username)
    totp_uri = get_totp_uri(username)
    return render_template("qr_page.html", username=username, qr_b64=qr_b64, totp_uri=totp_uri)


# ─── Health ───────────────────────────────────────────────────────────────────


@app.route("/health")
def health():
    return jsonify({"status": "ok", "pki_initialized": pki_initialized()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
