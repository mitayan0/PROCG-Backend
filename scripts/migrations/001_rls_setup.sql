-- =============================================================================
-- 001_rls_setup.sql
-- Multi-Tenancy Row-Level Security (RLS) — PROCG Backend
-- Run as: postgres (superuser) against the PRO_CG database
-- =============================================================================
-- INSTRUCTIONS:
--   1. Run this script as the `postgres` superuser:
--        psql -U postgres -d PRO_CG -f scripts/migrations/001_rls_setup.sql
--        (Idempotent: safe to re-run. Re-running picks up policy hardening
--        and re-backfills tenant_id for rows created before the app stamped it.)
--   2. After running, update your .env:
--        DATABASE_URL="postgresql://app_user:<password>@localhost:5431/PRO_CG"
--   3. Set RLS_ENABLED=true in your .env to activate the Flask hooks (see rls/__init__.py)
-- =============================================================================
-- ROLE MODEL:
--   Super Admin  →  is_superadmin=true  Cross-tenant. Reads+writes ALL rows in ALL tenants.
--   Admin        →  is_admin=true       Own tenant only. Reads+writes ALL rows in own tenant.
--   Auditor      →  is_auditor=true     Own tenant only. READS all rows. NO writes (DB-enforced).
--   User         →  is_user=true        Own tenant only. Reads+writes OWN rows only.
--
-- POLICY TIERS:
--   Tier 1   (tenant-scoped shared tables)  : superadmin | tenant users (USING); superadmin | admin+user (WITH CHECK)
--   Tier 1c  (admin-only tables)            : superadmin | admin+auditor (USING); superadmin | admin (WITH CHECK)
--   Tier 1b  (user-owned tables, 3-level)   : superadmin | admin+auditor | own-user (USING); superadmin | admin | own-user (WITH CHECK)
-- =============================================================================
-- NOTES:
--   * Every policy has USING + WITH CHECK (reads AND writes are guarded).
--   * WITH CHECK excludes is_auditor → auditors cannot INSERT/UPDATE/DELETE at DB level.
--   * The app stamps tenant_id on every insert (see utils.auth.resolve_tenant_id).
--     No DB auto-fill triggers: the WITH CHECK policy rejects any row whose
--     tenant does not match the caller, so a missing tenant fails loudly.
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 1: Create the non-superuser application role
--         app_user connects to the DB but is NOT a superuser -> RLS applies to it
-- ─────────────────────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'procg_app') THEN
        CREATE ROLE procg_app WITH LOGIN PASSWORD 'app';
        RAISE NOTICE 'Role procg_app created.';
    ELSE
        RAISE NOTICE 'Role procg_app already exists, skipping creation.';
    END IF;
END $$;

GRANT CONNECT ON DATABASE "PRO_CG" TO procg_app;

GRANT USAGE ON SCHEMA apps   TO procg_app;
GRANT USAGE ON SCHEMA public TO procg_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA apps   TO procg_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO procg_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA apps
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO procg_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO procg_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA apps   TO procg_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO procg_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA apps
    GRANT USAGE, SELECT ON SEQUENCES TO procg_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO procg_app;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA apps TO procg_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA apps
    GRANT EXECUTE ON FUNCTIONS TO procg_app;


-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 2: Helper functions (SECURITY DEFINER so app_user can call them)
--
-- Context readers:
--   rls_tenant_id()  → integer tenant_id of the current session (NULL = not set)
--   rls_user_id()    → integer user_id of the current session
--
-- Role boolean helpers (exactly one is true per session):
--   is_superadmin()  → Super Admin: cross-tenant, all rows
--   is_admin()       → Admin: own tenant, all rows
--   is_auditor()     → Auditor: own tenant, read-only (WITH CHECK blocks writes)
--   is_user()        → User: own tenant, own rows only
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION apps.rls_tenant_id() RETURNS integer AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant_id', TRUE), '')::integer;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION apps.rls_user_id() RETURNS integer AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', TRUE), '')::integer;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION apps.is_superadmin() RETURNS boolean AS $$
    SELECT current_setting('app.is_superadmin', TRUE) = 'true'
$$ LANGUAGE sql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION apps.is_admin() RETURNS boolean AS $$
    SELECT current_setting('app.is_admin', TRUE) = 'true'
$$ LANGUAGE sql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION apps.is_auditor() RETURNS boolean AS $$
    SELECT current_setting('app.is_auditor', TRUE) = 'true'
$$ LANGUAGE sql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION apps.is_user() RETURNS boolean AS $$
    SELECT current_setting('app.is_user', TRUE) = 'true'
$$ LANGUAGE sql STABLE SECURITY DEFINER;



-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 3: Tier 1 — TENANT-SCOPED tables (already have tenant_id)
--   USING    : superadmin | any tenant user (admin + auditor + user can read)
--   WITH CHECK: superadmin | admin or user (auditor CANNOT write)
--   EXCEPTION: apps.def_users — plain Users (is_user) see ONLY their own row;
--              admins/auditors still read all rows of their tenant.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE apps.def_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_users;
-- NOTE: plain Users see ONLY their own row (admins/auditors see all tenant rows).
CREATE POLICY tenant_isolation ON apps.def_users
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id()
            AND (NOT apps.is_user() OR user_id = apps.rls_user_id()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id()
            AND NOT apps.is_auditor()
            AND (NOT apps.is_user() OR user_id = apps.rls_user_id()))
    );

ALTER TABLE apps.def_job_titles ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_job_titles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_job_titles;
CREATE POLICY tenant_isolation ON apps.def_job_titles
    USING (
        apps.is_superadmin()
        OR tenant_id = apps.rls_tenant_id()
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor())
    );

ALTER TABLE apps.def_tenant_enterprise_setup ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_tenant_enterprise_setup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_tenant_enterprise_setup;
CREATE POLICY tenant_isolation ON apps.def_tenant_enterprise_setup
    USING (
        apps.is_superadmin()
        OR tenant_id = apps.rls_tenant_id()
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor())
    );


-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 3.1: Tier 1c — ADMIN-ONLY tables (already have tenant_id)
--   Admins and Auditors can READ; only Admins (and Superadmin) can WRITE
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE apps.def_webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_webhooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_isolation ON apps.def_webhooks;
CREATE POLICY admin_isolation ON apps.def_webhooks
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
    );

ALTER TABLE apps.def_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_webhook_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_isolation ON apps.def_webhook_events;
CREATE POLICY admin_isolation ON apps.def_webhook_events
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
    );

ALTER TABLE apps.def_webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_webhook_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_isolation ON apps.def_webhook_subscriptions;
CREATE POLICY admin_isolation ON apps.def_webhook_subscriptions
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
    );

ALTER TABLE apps.log_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.log_webhook_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_isolation ON apps.log_webhook_deliveries;
CREATE POLICY admin_isolation ON apps.log_webhook_deliveries
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
    );


-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 4: Tier 2 — USER-LINKED tables (add tenant_id + backfill + tenant policy)
--   USING    : superadmin | same tenant (all roles)
--   WITH CHECK: superadmin | same tenant AND NOT auditor
--   EXCEPTIONS (own-row-only for plain Users, like apps.def_users):
--     apps.def_persons, apps.def_access_profiles — every row belongs to
--     exactly one user (keyed by user_id), so is_user sees only their own.
-- ─────────────────────────────────────────────────────────────────────────────

-- 4.1 apps.def_persons
-- NOTE: plain Users (is_user) see ONLY their own person row (one row per
-- user, keyed by user_id) — same rule as apps.def_users.
ALTER TABLE apps.def_persons
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_persons p
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = p.user_id)
    WHERE p.tenant_id IS NULL;
ALTER TABLE apps.def_persons ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_persons FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_persons;
CREATE POLICY tenant_isolation ON apps.def_persons
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id()
            AND (NOT apps.is_user() OR user_id = apps.rls_user_id()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id()
            AND NOT apps.is_auditor()
            AND (NOT apps.is_user() OR user_id = apps.rls_user_id()))
    );

-- 4.2 apps.def_user_credentials
ALTER TABLE apps.def_user_credentials
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_user_credentials uc
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = uc.user_id)
    WHERE uc.tenant_id IS NULL;
ALTER TABLE apps.def_user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_user_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_user_credentials;
CREATE POLICY tenant_isolation ON apps.def_user_credentials
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.3 apps.def_access_profiles
-- NOTE: plain Users (is_user) see ONLY their own profile rows (keyed by
-- user_id) — same rule as apps.def_users. Login's profile lookup runs as
-- superadmin (public allowlist) and is unaffected.
ALTER TABLE apps.def_access_profiles
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_access_profiles ap
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = ap.user_id)
    WHERE ap.tenant_id IS NULL;
ALTER TABLE apps.def_access_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_profiles;
CREATE POLICY tenant_isolation ON apps.def_access_profiles
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id()
            AND (NOT apps.is_user() OR user_id = apps.rls_user_id()))
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id()
            AND NOT apps.is_auditor()
            AND (NOT apps.is_user() OR user_id = apps.rls_user_id()))
    );

-- 4.4 apps.def_user_granted_roles
ALTER TABLE apps.def_user_granted_roles
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_user_granted_roles gr
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = gr.user_id)
    WHERE gr.tenant_id IS NULL;
ALTER TABLE apps.def_user_granted_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_user_granted_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_user_granted_roles;
CREATE POLICY tenant_isolation ON apps.def_user_granted_roles
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.5 apps.def_user_granted_privileges
ALTER TABLE apps.def_user_granted_privileges
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_user_granted_privileges gp
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = gp.user_id)
    WHERE gp.tenant_id IS NULL;
ALTER TABLE apps.def_user_granted_privileges ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_user_granted_privileges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_user_granted_privileges;
CREATE POLICY tenant_isolation ON apps.def_user_granted_privileges
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.6 apps.def_new_user_invitations (link via invited_by)
ALTER TABLE apps.def_new_user_invitations
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_new_user_invitations ni
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = ni.invited_by)
    WHERE ni.tenant_id IS NULL;
ALTER TABLE apps.def_new_user_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_new_user_invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_new_user_invitations;
CREATE POLICY tenant_isolation ON apps.def_new_user_invitations
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.7 apps.def_notification_holders
ALTER TABLE apps.def_notification_holders
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_notification_holders nh
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = nh.user_id)
    WHERE nh.tenant_id IS NULL;
ALTER TABLE apps.def_notification_holders ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_notification_holders FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_notification_holders;
CREATE POLICY tenant_isolation ON apps.def_notification_holders
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.8 apps.def_forgot_password_requests (link via request_by)
ALTER TABLE apps.def_forgot_password_requests
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_forgot_password_requests fp
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = fp.request_by)
    WHERE fp.tenant_id IS NULL;
ALTER TABLE apps.def_forgot_password_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_forgot_password_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_forgot_password_requests;
CREATE POLICY tenant_isolation ON apps.def_forgot_password_requests
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.9 apps.def_action_item_assignments
ALTER TABLE apps.def_action_item_assignments
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_action_item_assignments ai
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = ai.user_id)
    WHERE ai.tenant_id IS NULL;
ALTER TABLE apps.def_action_item_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_action_item_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_action_item_assignments;
CREATE POLICY tenant_isolation ON apps.def_action_item_assignments
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- 4.10 apps.def_alert_recepients
ALTER TABLE apps.def_alert_recepients
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_alert_recepients ar
    SET tenant_id = (SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = ar.user_id)
    WHERE ar.tenant_id IS NULL;
ALTER TABLE apps.def_alert_recepients ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_alert_recepients FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_alert_recepients;
CREATE POLICY tenant_isolation ON apps.def_alert_recepients
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));



-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 4B: Additional Tier 2 — USER-LINKED tables
-- ─────────────────────────────────────────────────────────────────────────────

-- apps.def_alerts
ALTER TABLE apps.def_alerts
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_alerts;
CREATE POLICY tenant_isolation ON apps.def_alerts
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_controls
ALTER TABLE apps.def_controls
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_controls FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_controls;
CREATE POLICY tenant_isolation ON apps.def_controls
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_control_environments
ALTER TABLE apps.def_control_environments
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_control_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_control_environments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_control_environments;
CREATE POLICY tenant_isolation ON apps.def_control_environments
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_data_sources
ALTER TABLE apps.def_data_sources
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_data_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_data_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_data_sources;
CREATE POLICY tenant_isolation ON apps.def_data_sources
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_data_source_connections
ALTER TABLE apps.def_data_source_connections
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_data_source_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_data_source_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_data_source_connections;
CREATE POLICY tenant_isolation ON apps.def_data_source_connections
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_access_models
ALTER TABLE apps.def_access_models
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_access_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_models FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_models;
CREATE POLICY tenant_isolation ON apps.def_access_models
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_access_model_logics
ALTER TABLE apps.def_access_model_logics
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_access_model_logics ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_model_logics FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_model_logics;
CREATE POLICY tenant_isolation ON apps.def_access_model_logics
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_access_model_logic_attributes
ALTER TABLE apps.def_access_model_logic_attributes
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_access_model_logic_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_model_logic_attributes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_model_logic_attributes;
CREATE POLICY tenant_isolation ON apps.def_access_model_logic_attributes
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_access_points
ALTER TABLE apps.def_access_points
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_access_points ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_points FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_points;
CREATE POLICY tenant_isolation ON apps.def_access_points
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_access_entitlements
ALTER TABLE apps.def_access_entitlements
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_access_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_entitlements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_entitlements;
CREATE POLICY tenant_isolation ON apps.def_access_entitlements
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_access_entitlement_elements
ALTER TABLE apps.def_access_entitlement_elements
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_access_entitlement_elements ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_entitlement_elements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_entitlement_elements;
CREATE POLICY tenant_isolation ON apps.def_access_entitlement_elements
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_action_items
ALTER TABLE apps.def_action_items
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_action_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_action_items FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_action_items;
CREATE POLICY tenant_isolation ON apps.def_action_items
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.def_notifications
ALTER TABLE apps.def_notifications
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.def_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_notifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.def_notifications;
CREATE POLICY tenant_isolation ON apps.def_notifications
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- apps.messages
ALTER TABLE apps.messages
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);

ALTER TABLE apps.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.messages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON apps.messages;
CREATE POLICY tenant_isolation ON apps.messages
    USING (apps.is_superadmin() OR tenant_id = apps.rls_tenant_id())
    WITH CHECK (apps.is_superadmin() OR (tenant_id = apps.rls_tenant_id() AND NOT apps.is_auditor()));

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 5: Tier 1b — USER-OWNED tables (3-level policy)
--   USING    : superadmin | admin+auditor (all tenant rows) | user (own rows)
--   WITH CHECK: superadmin | admin (all tenant rows)        | user (own rows)
--              Auditor is in USING but NOT in WITH CHECK → read-only enforced at DB
-- ─────────────────────────────────────────────────────────────────────────────

-- 5.1 public.def_async_task_schedules
ALTER TABLE def_async_task_schedules
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE def_async_task_schedules s
    SET tenant_id = (
        SELECT u.tenant_id FROM apps.def_users u
        WHERE u.user_id = s.created_by::integer
    )
    WHERE s.created_by IS NOT NULL AND s.tenant_id IS NULL;
ALTER TABLE def_async_task_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE def_async_task_schedules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_owned_isolation ON def_async_task_schedules;
CREATE POLICY user_owned_isolation ON def_async_task_schedules
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by::integer = apps.rls_user_id())
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by::integer = apps.rls_user_id())
    );

-- 5.2 public.def_async_task_requests
ALTER TABLE def_async_task_requests
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE def_async_task_requests r
    SET tenant_id = (
        SELECT u.tenant_id FROM apps.def_users u
        WHERE u.user_id = r.created_by::integer
    )
    WHERE r.created_by IS NOT NULL AND r.tenant_id IS NULL;
ALTER TABLE def_async_task_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE def_async_task_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_owned_isolation ON def_async_task_requests;
CREATE POLICY user_owned_isolation ON def_async_task_requests
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by::integer = apps.rls_user_id())
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by::integer = apps.rls_user_id())
    );

-- 5.3 apps.def_process_executions
ALTER TABLE apps.def_process_executions
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_process_executions pe
    SET tenant_id = (
        SELECT u.tenant_id FROM apps.def_users u WHERE u.user_id = pe.created_by
    )
    WHERE pe.created_by IS NOT NULL AND pe.tenant_id IS NULL;
ALTER TABLE apps.def_process_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_process_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_owned_isolation ON apps.def_process_executions;
CREATE POLICY user_owned_isolation ON apps.def_process_executions
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by = apps.rls_user_id())
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by = apps.rls_user_id())
    );

-- 5.4 apps.def_process_execution_steps (inherit tenant from parent)
ALTER TABLE apps.def_process_execution_steps
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_process_execution_steps s
    SET tenant_id = (
        SELECT pe.tenant_id FROM apps.def_process_executions pe
        WHERE pe.def_process_execution_id = s.def_process_execution_id
    )
    WHERE s.tenant_id IS NULL;
ALTER TABLE apps.def_process_execution_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_process_execution_steps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_owned_isolation ON apps.def_process_execution_steps;
CREATE POLICY user_owned_isolation ON apps.def_process_execution_steps
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by = apps.rls_user_id())
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by = apps.rls_user_id())
    );

-- 5.5 apps.def_execution_action_items (inherit tenant from parent)
ALTER TABLE apps.def_execution_action_items
    ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES apps.def_tenants(tenant_id);
UPDATE apps.def_execution_action_items ei
    SET tenant_id = (
        SELECT pe.tenant_id FROM apps.def_process_executions pe
        WHERE pe.def_process_execution_id = ei.execution_id
    )
    WHERE ei.tenant_id IS NULL;
ALTER TABLE apps.def_execution_action_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_execution_action_items FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_owned_isolation ON apps.def_execution_action_items;
CREATE POLICY user_owned_isolation ON apps.def_execution_action_items
    USING (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND (apps.is_admin() OR apps.is_auditor()))
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by = apps.rls_user_id())
    )
    WITH CHECK (
        apps.is_superadmin()
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_admin())
        OR (tenant_id = apps.rls_tenant_id() AND apps.is_user()
            AND created_by = apps.rls_user_id())
    );


-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 6: Orphan triage — rows whose tenant still cannot be attributed
-- ─────────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    n int;
BEGIN
    SELECT count(*) INTO n FROM apps.def_persons WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_persons tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_user_credentials WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_user_credentials tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_access_profiles WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_access_profiles tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_user_granted_roles WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_user_granted_roles tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_user_granted_privileges WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_user_granted_privileges tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_new_user_invitations WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_new_user_invitations tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_notification_holders WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_notification_holders tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_forgot_password_requests WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_forgot_password_requests tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_action_item_assignments WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_action_item_assignments tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_alert_recepients WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_alert_recepients tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM def_async_task_schedules WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN def_async_task_schedules tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM def_async_task_requests WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN def_async_task_requests tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_process_executions WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_process_executions tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_process_execution_steps WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_process_execution_steps tenant_id NULL: % rows', n; END IF;
    SELECT count(*) INTO n FROM apps.def_execution_action_items WHERE tenant_id IS NULL;
    IF n > 0 THEN RAISE NOTICE 'ORPHAN apps.def_execution_action_items tenant_id NULL: % rows', n; END IF;
END $$;


-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 7: Views over RLS-protected tables must enforce RLS too
--   Views run with the OWNER's rights by default (postgres = superuser =
--   RLS bypass), so endpoints reading a view silently see ALL tenants.
--   security_invoker=true makes the view run as the CALLER (procg_app),
--   so the table policies above filter its rows automatically.
--   No policies on views themselves — tables stay the single source of truth.
--   Covers all 9 views over RLS-protected tables. The remaining views
--   (def_api_endpoint_roles_v, vw_lookup_with_values, def_async_tasks_v) sit
--   over shared tables with no RLS and need nothing.
--   Idempotent: safe to re-run. Requires PostgreSQL 15+.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER VIEW public.def_async_task_schedules_v        SET (security_invoker = true);
ALTER VIEW apps.def_users_v                         SET (security_invoker = true);
ALTER VIEW apps.def_tenant_enterprise_setup_v       SET (security_invoker = true);
ALTER VIEW apps.def_webhook_subscriptions_v         SET (security_invoker = true);
ALTER VIEW apps.def_user_granted_roles_privileges_v SET (security_invoker = true);
ALTER VIEW apps.def_access_points_v                 SET (security_invoker = true);
ALTER VIEW apps.def_action_items_v                  SET (security_invoker = true);
ALTER VIEW apps.def_alerts_v                        SET (security_invoker = true);
ALTER VIEW apps.def_notifications_v                 SET (security_invoker = true);


-- ─────────────────────────────────────────────────────────────────────────────
-- VERIFICATION QUERIES (run as app_user to test)
-- ─────────────────────────────────────────────────────────────────────────────

-- Test 1: Super Admin sees everything
-- SET app.is_superadmin = 'true';
-- SET app.is_admin      = 'false';
-- SET app.is_auditor    = 'false';
-- SET app.is_user       = 'false';
-- SELECT count(*) FROM def_async_task_requests;  -- all rows across all tenants

-- Test 2: Admin sees all of own tenant
-- SET app.current_tenant_id = '1';
-- SET app.current_user_id   = '55';
-- SET app.is_superadmin     = 'false';
-- SET app.is_admin          = 'true';
-- SET app.is_auditor        = 'false';
-- SET app.is_user           = 'false';
-- SELECT count(*) FROM def_async_task_requests;  -- all tenant 1 rows

-- Test 3: Auditor reads all tenant rows but cannot write
-- SET app.current_tenant_id = '1';
-- SET app.current_user_id   = '77';
-- SET app.is_superadmin     = 'false';
-- SET app.is_admin          = 'false';
-- SET app.is_auditor        = 'true';
-- SET app.is_user           = 'false';
-- SELECT count(*) FROM def_async_task_requests;  -- all tenant 1 rows (read OK)
-- INSERT INTO def_async_task_requests (...) VALUES (...);  -- must FAIL (WITH CHECK)

-- Test 4: User sees only own rows
-- SET app.current_tenant_id = '1';
-- SET app.current_user_id   = '101';
-- SET app.is_superadmin     = 'false';
-- SET app.is_admin          = 'false';
-- SET app.is_auditor        = 'false';
-- SET app.is_user           = 'true';
-- SELECT count(*) FROM def_async_task_requests;  -- only user 101's rows

-- Test 5: No session vars = must see 0 rows (fail-closed)
-- RESET app.current_tenant_id;
-- RESET app.current_user_id;
-- RESET app.is_superadmin;
-- RESET app.is_admin;
-- RESET app.is_auditor;
-- RESET app.is_user;
-- SELECT count(*) FROM def_async_task_requests;  -- must be 0

SELECT 'RLS setup complete.' AS status;
