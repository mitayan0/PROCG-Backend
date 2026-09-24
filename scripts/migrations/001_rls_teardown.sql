-- =============================================================================
-- 001_rls_teardown.sql
-- ROLLBACK all RLS changes made by 001_rls_setup.sql
-- Run as: psql -U postgres -d PRO_CG -f scripts/migrations/001_rls_teardown.sql
-- =============================================================================
-- WARNING: This REMOVES all RLS policies and drops the tenant_id columns
--          added to Tier 1b and Tier 2 tables. Run ONLY to undo the setup.
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 1b — Drop policies and disable RLS (remove tenant_id columns too)
-- ─────────────────────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS user_owned_isolation ON def_async_task_schedules;
ALTER TABLE def_async_task_schedules DISABLE ROW LEVEL SECURITY;
ALTER TABLE def_async_task_schedules DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS user_owned_isolation ON def_async_task_requests;
ALTER TABLE def_async_task_requests DISABLE ROW LEVEL SECURITY;
ALTER TABLE def_async_task_requests DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS user_owned_isolation ON apps.def_process_executions;
ALTER TABLE apps.def_process_executions DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_process_executions DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS user_owned_isolation ON apps.def_process_execution_steps;
ALTER TABLE apps.def_process_execution_steps DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_process_execution_steps DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS user_owned_isolation ON apps.def_execution_action_items;
ALTER TABLE apps.def_execution_action_items DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_execution_action_items DROP COLUMN IF EXISTS tenant_id;


-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 2 — Drop policies, disable RLS, drop tenant_id columns
-- ─────────────────────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS tenant_isolation ON apps.def_persons;
ALTER TABLE apps.def_persons DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_persons DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_user_credentials;
ALTER TABLE apps.def_user_credentials DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_user_credentials DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_profiles;
ALTER TABLE apps.def_access_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_profiles DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_user_granted_roles;
ALTER TABLE apps.def_user_granted_roles DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_user_granted_roles DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_user_granted_privileges;
ALTER TABLE apps.def_user_granted_privileges DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_user_granted_privileges DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_new_user_invitations;
ALTER TABLE apps.def_new_user_invitations DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_new_user_invitations DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_notification_holders;
ALTER TABLE apps.def_notification_holders DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_notification_holders DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_forgot_password_requests;
ALTER TABLE apps.def_forgot_password_requests DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_forgot_password_requests DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_action_item_assignments;
ALTER TABLE apps.def_action_item_assignments DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_action_item_assignments DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_alert_recepients;
ALTER TABLE apps.def_alert_recepients DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_alerts;
ALTER TABLE apps.def_alerts DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_alerts DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_controls;
ALTER TABLE apps.def_controls DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_controls DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_control_environments;
ALTER TABLE apps.def_control_environments DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_control_environments DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_data_sources;
ALTER TABLE apps.def_data_sources DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_data_sources DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_data_source_connections;
ALTER TABLE apps.def_data_source_connections DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_data_source_connections DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_models;
ALTER TABLE apps.def_access_models DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_models DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_model_logics;
ALTER TABLE apps.def_access_model_logics DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_model_logics DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_model_logic_attributes;
ALTER TABLE apps.def_access_model_logic_attributes DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_model_logic_attributes DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_points;
ALTER TABLE apps.def_access_points DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_points DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_entitlements;
ALTER TABLE apps.def_access_entitlements DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_entitlements DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_access_entitlement_elements;
ALTER TABLE apps.def_access_entitlement_elements DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_access_entitlement_elements DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_action_items;
ALTER TABLE apps.def_action_items DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_action_items DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_notifications;
ALTER TABLE apps.def_notifications DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.def_notifications DROP COLUMN IF EXISTS tenant_id;

DROP POLICY IF EXISTS tenant_isolation ON apps.messages;
ALTER TABLE apps.messages DISABLE ROW LEVEL SECURITY;
ALTER TABLE apps.messages DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE apps.def_alert_recepients DROP COLUMN IF EXISTS tenant_id;


-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 1c — Drop admin-only policies, disable RLS
-- ─────────────────────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS admin_isolation ON apps.def_webhooks;
ALTER TABLE apps.def_webhooks DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS admin_isolation ON apps.def_webhook_events;
ALTER TABLE apps.def_webhook_events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS admin_isolation ON apps.def_webhook_subscriptions;
ALTER TABLE apps.def_webhook_subscriptions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS admin_isolation ON apps.log_webhook_deliveries;
ALTER TABLE apps.log_webhook_deliveries DISABLE ROW LEVEL SECURITY;


-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 1 — Drop tenant policies, disable RLS
-- ─────────────────────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS tenant_isolation ON apps.def_users;
ALTER TABLE apps.def_users DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_job_titles;
ALTER TABLE apps.def_job_titles DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON apps.def_tenant_enterprise_setup;
ALTER TABLE apps.def_tenant_enterprise_setup DISABLE ROW LEVEL SECURITY;


-- ─────────────────────────────────────────────────────────────────────────────
-- Views — reset security_invoker to the default (owner's rights),
-- undoing STEP 7 of 001_rls_setup.sql
-- ─────────────────────────────────────────────────────────────────────────────

ALTER VIEW public.def_async_task_schedules_v        RESET (security_invoker);
ALTER VIEW apps.def_users_v                         RESET (security_invoker);
ALTER VIEW apps.def_tenant_enterprise_setup_v       RESET (security_invoker);
ALTER VIEW apps.def_webhook_subscriptions_v         RESET (security_invoker);
ALTER VIEW apps.def_user_granted_roles_privileges_v RESET (security_invoker);
ALTER VIEW apps.def_access_points_v                 RESET (security_invoker);
ALTER VIEW apps.def_action_items_v                  RESET (security_invoker);
ALTER VIEW apps.def_alerts_v                        RESET (security_invoker);
ALTER VIEW apps.def_notifications_v                 RESET (security_invoker);


-- ─────────────────────────────────────────────────────────────────────────────
-- Helper Functions — drop all (new names + old names for safety)
-- ─────────────────────────────────────────────────────────────────────────────

-- New functions
DROP FUNCTION IF EXISTS apps.is_superadmin();
DROP FUNCTION IF EXISTS apps.is_admin();
DROP FUNCTION IF EXISTS apps.is_auditor();
DROP FUNCTION IF EXISTS apps.is_user();
DROP FUNCTION IF EXISTS apps.rls_tenant_id();
DROP FUNCTION IF EXISTS apps.rls_user_id();

-- Old function names (in case this is run against a pre-refactor DB)
DROP FUNCTION IF EXISTS apps.rls_is_superadmin();
DROP FUNCTION IF EXISTS apps.rls_is_admin();


-- ─────────────────────────────────────────────────────────────────────────────
-- NOTE: We do NOT revoke app_user permissions or drop the role here.
--       app_user can remain for future use. To fully remove:
--         REASSIGN OWNED BY app_user TO postgres;
--         DROP OWNED BY app_user;
--         DROP ROLE app_user;
-- ─────────────────────────────────────────────────────────────────────────────

SELECT 'RLS teardown complete. All policies and helper functions removed.' AS status;
