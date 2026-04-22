/*
  # Create audit_log table for OpenVPN management app

  ## Purpose
  Tracks every administrative action performed via the web UI — user creation,
  revocation, profile downloads, QR code views — so there is a durable record
  of who did what and when.

  ## New Tables
  - `audit_log`
    - `id`          (uuid, PK)           — unique row identifier
    - `admin_email` (text, NOT NULL)     — email of the admin who acted
    - `action`      (text, NOT NULL)     — one of: user_added, user_revoked,
                                           profile_downloaded, qr_viewed
    - `target_user` (text)               — VPN username affected (null for non-user actions)
    - `details`     (jsonb)              — optional extra context (e.g. server_ip used)
    - `created_at`  (timestamptz)        — when the action occurred

  ## Security
  - RLS enabled — table locked down by default
  - Authenticated users can insert their own audit events (Flask backend uses
    the calling user's JWT, so auth.uid() must be non-null)
  - Authenticated users can read all audit events (admin visibility)
*/

CREATE TABLE IF NOT EXISTS audit_log (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_email text        NOT NULL DEFAULT '',
    action      text        NOT NULL DEFAULT '',
    target_user text,
    details     jsonb       NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated admins can insert audit events"
    ON audit_log
    FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "Authenticated admins can view all audit events"
    ON audit_log
    FOR SELECT
    TO authenticated
    USING (auth.uid() IS NOT NULL);

-- Index for the most common query: recent events ordered by time
CREATE INDEX IF NOT EXISTS audit_log_created_at_idx
    ON audit_log (created_at DESC);

-- Index for filtering by target user
CREATE INDEX IF NOT EXISTS audit_log_target_user_idx
    ON audit_log (target_user);
