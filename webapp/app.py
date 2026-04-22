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

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "0") == "1"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
_supabase_base = None

if SUPABASE_URL and SUPABASE_ANON_KEY:
    try:
        from supabase import create_client

        _supabase_base = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    except Exception:
        pass


@app.context_processor
def inject_globals():
    return {"auth_disabled": AUTH_DISABLED}


def _get_authed_client():
    if not _supabase_base:
        return None
    if "access_token" not in session:
        return _supabase_base
    try:
        from supabase import create_client

        client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        client.auth.set_session(
            session["access_token"], session.get("refresh_token", "")
        )
        return client
    except Exception:
        return _supabase_base


def _log(action, target_user=None, details=None):
    client = _get_authed_client()
    if not client:
        return
    try:
        client.table("audit_log").insert(
            {
                "admin_email": session.get("user_email", "unknown"),
                "action": action,
                "target_user": target_user,
                "details": details or {},
            }
        ).execute()
    except Exception:
        pass


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

        if not _supabase_base:
            session["user_email"] = email or "admin"
            flash(
                "Supabase not configured — authentication is disabled. "
                "Set SUPABASE_URL and SUPABASE_ANON_KEY for secure login.",
                "warning",
            )
            return redirect(url_for("dashboard"))

        try:
            resp = _supabase_base.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            session["user_email"] = email
            session["access_token"] = resp.session.access_token
            session["refresh_token"] = resp.session.refresh_token
            return redirect(request.args.get("next") or url_for("dashboard"))
        except Exception:
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if AUTH_DISABLED:
        return redirect(url_for("dashboard"))
    try:
        if _supabase_base and "access_token" in session:
            _supabase_base.auth.sign_out()
    except Exception:
        pass
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
    recent_actions = []
    client = _get_authed_client()
    if client:
        try:
            result = (
                client.table("audit_log")
                .select("*")
                .order("created_at", desc=True)
                .limit(10)
                .execute()
            )
            recent_actions = result.data or []
        except Exception:
            pass

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

        if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", username):
            flash(
                "Username must be 1–64 characters using only letters, digits, _ and -.",
                "error",
            )
            return render_template("add_user.html", default_server_ip=default_ip)

        try:
            totp_uri = add_user(username, server_ip)
            qr_b64 = get_totp_qr_base64(username)
            _log("user_added", target_user=username, details={"server_ip": server_ip})
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
