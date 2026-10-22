#!/bin/sh
# vpn-pam-helper — PAM helper for davpn2fa (called via pam_exec.so).
#
# pam_exec maps: exit 0 -> PAM_SUCCESS, exit !=0 -> PAM_SYSTEM_ERR.
# The PAM control flags in config/pam.d/openvpn therefore give each mode
# a two-way contract:
#
#   vpn-pam-helper check-username
#     exit 0  username INVALID (empty, traversal, bad chars) -> PAM stack DENIES
#     exit 1  username valid                   -> continue to next module
#
#   vpn-pam-helper has-secret
#     exit 0  user is CERT-ONLY: no user dir at all (created only when
#             TOTP is enabled by add_user) -> ALLOW now (TLS already
#             authenticated the client certificate)
#     exit 1  TOTP user (secret file present) OR damaged state (user dir
#             present but secret file missing) OR invalid username OR
#             internal error -> continue to the REQUIRED
#             pam_google_authenticator line, which enforces the code and
#             fails closed for damaged state (no nullok)
#
# NOTE: pam_exec provides the child with the PAM environment + PAM_USER —
# NOT the calling process's environment. The data dir is therefore
# HARDCODED to the fixed container path (it matches the secret= path in
# config/pam.d/openvpn; do not change one without the other).
set -u

DATA_DIR="/etc/openvpn/data"
MODE="${1:-}"
USER_NAME="${PAM_USER:-}"

valid_username() {
    case "$USER_NAME" in
        *[!a-zA-Z0-9_-]*|'') return 1 ;;
        *) [ ${#USER_NAME} -ge 1 ] && [ ${#USER_NAME} -le 64 ] && return 0 ;;
    esac
    return 1
}

case "$MODE" in
    check-username)
        if valid_username; then
            exit 1   # valid -> continue down the stack
        fi
        exit 0       # invalid -> PAM stack denies (success=bad)
        ;;
    has-secret)
        valid_username || exit 1          # invalid -> let GA fail closed
        # Invariant (add_user in webapp/lib/vpn.py): users/<name>/ exists
        # ONLY for TOTP users. dir present + secret missing = damaged
        # state -> fall through to GA, which fails closed (no nullok).
        [ -d "$DATA_DIR/users/$USER_NAME" ] && exit 1
        [ -f "$DATA_DIR/users/$USER_NAME/.google_authenticator" ] && exit 1
        exit 0                            # no user dir -> cert-only: allow
        ;;
    *)
        exit 1                           # unknown mode -> fail closed
        ;;
esac
