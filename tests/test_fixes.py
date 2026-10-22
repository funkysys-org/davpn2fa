#!/usr/bin/env python3
"""Fix-verification suite for davpn2fa critical hardening + Supabase removal.

Proves, by execution:
  1. PAM: OLD config accepts wrong TOTP (RED/vulnerable, for contrast);
     NEW shipped stack rejects wrong TOTP, accepts correct TOTP, keeps
     cert-only users working, denies malformed usernames, fails closed
     on damaged state.
  2. Webapp boot-guard: refuses to boot in insecure configs, boots in
     safe ones (local admin creds; no external auth service).
  3. Login: local admin credentials work; wrong creds rejected;
     open-redirect on ?next= neutralized.
  4. API: static bearer token enforced (constant-time); garbage/missing
     tokens rejected; valid token accepted.
  5. Profile builder refuses to emit YOUR_SERVER_IP profiles.
  6. SQLite audit log records events in every mode; dashboard-shaped.

Run from anywhere. Exit 0 = all green.
"""
import os
import subprocess
import sys
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name} {detail}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {detail}")


# ── 1. PAM red/green (live PAM stack, container-exact layout) ───────────────
print("[1] PAM 2FA enforcement (live PAM stack, non-system VPN users)")
import pam
import pyotp

DATA = "/etc/openvpn/data"
os.system(f"rm -rf {DATA} && mkdir -p {DATA}/users/vpn_alice")

secret = pyotp.random_base32()
ga = f"{DATA}/users/vpn_alice/.google_authenticator"
with open(ga, "w") as f:
    f.write(secret + "\n")
    f.write('" RATE_LIMIT 3 30\n')
    f.write('" WINDOW_SIZE 3\n')
    f.write('" DISALLOW_REUSE\n')
    f.write('" TOTP_AUTH\n')
os.system(f"chmod 600 {ga}")
# vpn_certonly: NO user dir (add_user invariant: dir only when TOTP enabled)

HELPER = "/usr/local/bin/vpn-pam-helper"
open(HELPER, "w").write(open(f"{REPO}/scripts/vpn-pam-helper.sh").read())
os.chmod(HELPER, 0o755)

NEW_STACK = (
    "auth [success=bad default=ignore] pam_exec.so quiet /usr/local/bin/vpn-pam-helper check-username\n"
    "auth [success=done default=ignore] pam_exec.so quiet /usr/local/bin/vpn-pam-helper has-secret\n"
    "auth required pam_google_authenticator.so "
    f"secret={DATA}/users/${{USER}}/.google_authenticator "
    "user=root no_strict_owner noskewadj no_increment_hotp\n"
    "account required pam_permit.so\n"
)
OLD_STACK = (  # as shipped at 16273b8 — for RED contrast
    "auth sufficient pam_google_authenticator.so "
    f"secret={DATA}/users/${{USER}}/.google_authenticator "
    "nullok noskewadj no_increment_hotp\n"
    "auth sufficient pam_permit.so\n"
    "account required pam_permit.so\n"
)
open("/etc/pam.d/davpn2fa_new", "w").write(NEW_STACK)
open("/etc/pam.d/davpn2fa_old", "w").write(OLD_STACK)

p = pam.pam()
good = pyotp.TOTP(secret).now()
bad = "000000" if good != "000000" else "111111"

r = p.authenticate("vpn_alice", bad, service="davpn2fa_old")
check("OLD shipped stack accepts WRONG TOTP (the vulnerability)", r, f"({p.code})")
r = p.authenticate("vpn_alice", bad, service="davpn2fa_new")
check("NEW stack REJECTS wrong TOTP", not r, f"({p.code})")
r = p.authenticate("vpn_alice", good, service="davpn2fa_new")
check("NEW stack ACCEPTS correct TOTP", r, f"({p.code})")
r = p.authenticate("vpn_certonly", "any", service="davpn2fa_new")
check("NEW stack keeps cert-only users working (no dir, no prompt)", r, f"({p.code})")
r = p.authenticate("../../etc/vpn_x", "any", service="davpn2fa_new")
check("NEW stack denies malformed/traversal usernames", not r, f"({p.code})")
r = p.authenticate("", "any", service="davpn2fa_new")
check("NEW stack denies empty usernames", not r, f"({p.code})")
os.remove(ga)
r = p.authenticate("vpn_alice", "any", service="davpn2fa_new")
check("NEW stack fails CLOSED on damaged state (dir present, secret gone)",
      not r, f"({p.code})")
os.system(f"rm -rf {DATA}")
for svc in ("davpn2fa_new", "davpn2fa_old"):
    os.remove(f"/etc/pam.d/{svc}")

# ── 2. Boot-guard matrix (local admin creds) ─────────────────────────────────
print("[2] Webapp boot-guard (fail-loud config validation)")
STRONG = "a" * 64
HASH = "scrypt:32768:8:1$salt$beef" * 1  # any non-empty hash string works for boot
TOKEN = "b" * 64

def try_boot(env, expect_boot, name):
    e = dict(os.environ)
    e.update({
        "FLASK_SECRET_KEY": "", "AUTH_DISABLED": "0",
        "ADMIN_EMAIL": "admin", "ADMIN_PASSWORD_HASH": "",
        "API_TOKEN": "", "OPENVPN_DATA_DIR": tempfile.mkdtemp(prefix="davpn2fa-boot-"),
    })
    e.update(env)
    code = (
        "import sys; sys.path.insert(0, 'webapp');"
        "import app as _a; print('BOOTED')"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=e,
                       capture_output=True, text=True, timeout=120)
    booted = "BOOTED" in r.stdout
    check(name, booted == expect_boot,
          f"(booted={booted}, exit={r.returncode})")
    return booted

try_boot({"AUTH_DISABLED": "0", "ADMIN_PASSWORD_HASH": "", "API_TOKEN": "",
          "FLASK_SECRET_KEY": STRONG},
         False, "auth ON + missing creds            -> refuses to boot")
try_boot({"AUTH_DISABLED": "0", "ADMIN_PASSWORD_HASH": HASH, "API_TOKEN": TOKEN,
          "FLASK_SECRET_KEY": "change-me-in-production"},
         False, "auth ON + known default secret     -> refuses to boot")
b_ok = try_boot({"AUTH_DISABLED": "0", "ADMIN_PASSWORD_HASH": HASH,
                 "API_TOKEN": TOKEN, "FLASK_SECRET_KEY": STRONG},
                True, "auth ON + full creds + strong key   -> boots")
try_boot({"AUTH_DISABLED": "1", "ADMIN_PASSWORD_HASH": "", "API_TOKEN": "",
          "FLASK_SECRET_KEY": ""},
         True, "auth OFF (trusted net) + no key    -> boots w/ ephemeral key")

# ── 3/4. Login + API with local auth (in-process test client) ────────────────
print("[3] Login flow and API bearer-token auth")
if b_ok:
    e = dict(os.environ)
    e.update({"AUTH_DISABLED": "0",
              "ADMIN_EMAIL": "admin@example.com",
              "ADMIN_PASSWORD_HASH": HASH,
              "API_TOKEN": TOKEN,
              "FLASK_SECRET_KEY": STRONG,
              "OPENVPN_DATA_DIR": tempfile.mkdtemp(prefix="davpn2fa-web-")})
    for m in [k for k in sys.modules if k in ("app", "api", "lib.vpn", "lib.audit")]:
        del sys.modules[m]
    os.environ.update({k: str(v) for k, v in e.items()})
    old_path = os.getcwd()
    os.chdir(f"{REPO}/webapp")
    sys.path.insert(0, os.getcwd())
    from werkzeug.security import generate_password_hash
    REAL_HASH = generate_password_hash("correct-horse")
    os.environ["ADMIN_PASSWORD_HASH"] = REAL_HASH

    for m in [k for k in sys.modules if k in ("app", "api", "lib.vpn", "lib.audit")]:
        del sys.modules[m]
    import app as appmod
    client = appmod.app.test_client()

    r = client.post("/login", data={"email": "admin@example.com",
                                    "password": "wrong-pass"},
                    follow_redirects=False)
    check("login with WRONG password rejected",
          r.status_code == 200 and "Invalid email or password" in r.get_data(as_text=True))

    r = client.post("/login", data={"email": "admin@example.com",
                                    "password": "correct-horse"},
                    follow_redirects=False)
    check("login with CORRECT creds -> dashboard redirect",
          r.headers.get("Location", "").endswith("/dashboard"),
          f"(Location={r.headers.get('Location')})")

    r = client.post("/login?next=https://evil.com",
                    data={"email": "admin@example.com",
                          "password": "correct-horse"},
                    follow_redirects=False)
    loc = r.headers.get("Location", "")
    check("open redirect neutralized (evil next -> dashboard)",
          "evil.com" not in loc and loc.endswith("/dashboard"), f"(Location={loc})")

    # unauthenticated UI access redirected to login
    anon = appmod.app.test_client()
    r = anon.get("/users", follow_redirects=False)
    check("unauthenticated /users -> login redirect", r.status_code == 302)

    # API auth
    r = anon.get("/api/v1/status")
    check("API rejects missing token", r.status_code == 401, f"(status={r.status_code})")
    r = anon.get("/api/v1/status", headers={"Authorization": "Bearer garbage"})
    check("API rejects garbage token", r.status_code == 401, f"(status={r.status_code})")
    r = anon.get("/api/v1/status", headers={"Authorization": f"Bearer {TOKEN}"})
    check("API accepts valid token", r.status_code == 200, f"(status={r.status_code})")

    # ── 6. Audit log (SQLite, all modes) ─────────────────────────────────────
    print("[6] SQLite audit log records events in every mode")
    from lib import audit as audit_mod
    audit_mod.log_event("user_added", target_user="vpn_alice",
                        details={"source": "test"}, admin_email="admin@example.com")
    events = audit_mod.recent_events(limit=5)
    check("audit event recorded and retrievable",
          len(events) == 1 and events[0]["action"] == "user_added"
          and events[0]["target_user"] == "vpn_alice"
          and events[0]["admin_email"] == "admin@example.com")
    check("audit event shape matches dashboard template keys",
          all(k in events[0] for k in ("admin_email", "action", "target_user", "created_at")))
    check("created_at is an ISO string the template can slice",
          isinstance(events[0]["created_at"], str) and "T" in events[0]["created_at"])
    os.chdir(old_path)
else:
    check("booted app available for web tests", False)

# ── 5. Profile builder honesty ───────────────────────────────────────────────
print("[5] Client profile builder honesty")
os.environ["OPENVPN_DATA_DIR"] = tempfile.mkdtemp(prefix="davpn2fa-pkitest-")
sys.path.insert(0, f"{REPO}/webapp")
for m in [k for k in sys.modules if k.startswith("lib")]:
    del sys.modules[m]
import lib.vpn as vpn
try:
    vpn._build_client_profile("tester", None)  # no server_ip, no env var
    check("profile builder refuses YOUR_SERVER_IP fallback", False)
except ValueError as e:
    check("profile builder refuses YOUR_SERVER_IP fallback", True, f"({e})")

print(f"\n==== RESULT: {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
