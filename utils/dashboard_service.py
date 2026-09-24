"""Dashboard data service — scoped counts and recent items.

Catalog tables (def_async_tasks, def_processes, def_async_execution_methods)
are shared across tenants and unfiltered. Everything user-owned (schedules,
workflow runs, users, tenants, enterprises) is scoped by caller role:
    superadmin → all | admin/auditor → own tenant | user → own rows only.

Scope resolution lives in utils.execution_utils (single source of truth);
this module only adds the dashboard's SQL fragments and queries.
"""

from sqlalchemy import text

from executors.extensions import db
from utils.execution_utils import ExecutionScope


# ExecutionScope is a str-enum, so these tuples also match plain strings
# ("tenant", "audit", "all") if a caller ever passes those.
TENANT_READ_SCOPES = (ExecutionScope.TENANT, ExecutionScope.AUDIT)

SCHEDULE_BASE = "(schedule_type != 'IMMEDIATE' OR schedule_type IS NULL)"


def schedule_filter(scope, params):
    """Build WHERE fragment + bind params for def_async_task_schedules scoping.

    Tenant scope resolves via created_by -> apps.def_users.tenant_id so it
    works whether or not the tenant_id backfill column exists. created_by is
    cast to text because some rows store it as varchar.
    """
    if scope == ExecutionScope.ALL:
        return SCHEDULE_BASE, params
    if scope in TENANT_READ_SCOPES:
        params["tid"] = int(params["tid"])
        return (
            f"{SCHEDULE_BASE} AND ("
            "CAST(created_by AS TEXT) IN "
            "(SELECT CAST(user_id AS TEXT) FROM apps.def_users WHERE tenant_id = :tid))",
            params,
        )
    params["uid"] = str(params.get("uid"))
    return f"{SCHEDULE_BASE} AND CAST(created_by AS TEXT) = CAST(:uid AS TEXT)", params


def execution_filter(scope, params):
    """Build WHERE fragment + bind params for apps.def_process_executions.

    Same visibility rule as schedules: superadmin sees all | admin/auditor
    sees the tenant's runs | user sees only runs they started (created_by).

    Columns are qualified with `e.` because fetch_items joins executions `e`
    to processes `p` (both have created_by/tenant_id). Callers querying the
    table without a join must alias it as `e`.
    """
    if scope == ExecutionScope.ALL:
        return "TRUE", params
    if scope in TENANT_READ_SCOPES:
        params["tid"] = int(params["tid"])
        return (
            "(e.tenant_id = :tid OR CAST(e.created_by AS TEXT) IN "
            "(SELECT CAST(user_id AS TEXT) FROM apps.def_users WHERE tenant_id = :tid))",
            params,
        )
    params["uid"] = str(params.get("uid"))
    return "CAST(e.created_by AS TEXT) = CAST(:uid AS TEXT)", params


def fetch_counts(scope, uid, tid):
    """One round-trip for every dashboard counter."""
    sched_where, sched_params = schedule_filter(scope, {"uid": uid, "tid": tid})
    exec_where, exec_params = execution_filter(scope, {"uid": uid, "tid": tid})
    user_where, user_params = ("", {})
    if scope in TENANT_READ_SCOPES:
        user_where, user_params = "WHERE tenant_id = :tid", {"tid": int(tid)}
    elif scope != ExecutionScope.ALL:
        user_where, user_params = "WHERE user_id = :uid", {"uid": int(uid)}

    tenant_where, tenant_params = ("", {})
    enterprise_where, enterprise_params = ("", {})
    if scope == ExecutionScope.ALL:
        pass
    elif scope in TENANT_READ_SCOPES:
        tenant_where, tenant_params = "WHERE tenant_id = :tid", {"tid": int(tid)}
        enterprise_where, enterprise_params = "WHERE tenant_id = :tid", {"tid": int(tid)}
    else:  # normal user: no tenant/enterprise visibility (matches /def_tenants, /get_enterprises -> 403)
        tenant_where, tenant_params = "WHERE 1 = 0", {}
        enterprise_where, enterprise_params = "WHERE 1 = 0", {}

    row = db.session.execute(
        text(f"""
            SELECT
                (SELECT COUNT(*) FROM apps.def_processes) AS workflows,
                (SELECT COUNT(*) FROM def_async_tasks) AS tasks_total,
                (SELECT COUNT(*) FROM def_async_tasks WHERE cancelled_yn = 'N') AS tasks_active,
                (SELECT COUNT(*) FROM def_async_tasks WHERE cancelled_yn = 'Y') AS tasks_inactive,
                (SELECT COUNT(*) FROM def_async_tasks WHERE srs = 'Y') AS tasks_srs,
                (SELECT COUNT(*) FROM def_async_tasks WHERE sf = 'Y') AS tasks_sf,
                (SELECT COUNT(*) FROM def_async_task_schedules WHERE {sched_where}) AS schedules_total,
                (SELECT COUNT(*) FROM def_async_task_schedules WHERE cancelled_yn = 'N' AND ({sched_where})) AS schedules_scheduled,
                (SELECT COUNT(*) FROM def_async_task_schedules WHERE cancelled_yn = 'Y' AND ({sched_where})) AS schedules_cancelled,
                (SELECT COUNT(*) FROM def_async_execution_methods) AS executors,
                (SELECT COUNT(*) FROM apps.def_process_executions e WHERE {exec_where}) AS runs_total,
                (SELECT COUNT(*) FROM apps.def_process_executions e WHERE e.execution_status = 'RUNNING' AND ({exec_where})) AS runs_running,
                (SELECT COUNT(*) FROM apps.def_process_executions e WHERE e.execution_status = 'COMPLETED' AND ({exec_where})) AS runs_completed,
                (SELECT COUNT(*) FROM apps.def_process_executions e WHERE e.execution_status = 'FAILED' AND ({exec_where})) AS runs_failed,
                (SELECT COUNT(*) FROM apps.def_process_executions e WHERE e.execution_status = 'WAITING_ON_TASK' AND ({exec_where})) AS runs_waiting,
                (SELECT COUNT(*) FROM apps.def_users {user_where}) AS users,
                (SELECT COUNT(*) FROM apps.def_tenants {tenant_where}) AS tenants,
                (SELECT COUNT(*) FROM apps.def_tenant_enterprise_setup {enterprise_where}) AS enterprises
        """),
        {**sched_params, **exec_params, **user_params, **tenant_params, **enterprise_params},
    ).first()
    return row


def fetch_items(scope, uid, tid, limit=4):
    """Latest items per section, same scoping as the counters."""
    sched_where, sched_params = schedule_filter(scope, {"uid": uid, "tid": tid})
    exec_where, exec_params = execution_filter(scope, {"uid": uid, "tid": tid})
    user_where, user_params = ("", {})
    if scope in TENANT_READ_SCOPES:
        user_where, user_params = "WHERE tenant_id = :tid", {"tid": int(tid)}
    elif scope != ExecutionScope.ALL:
        user_where, user_params = "WHERE user_id = :uid", {"uid": int(uid)}

    if scope == ExecutionScope.ALL:
        tenant_where, enterprise_where = "", ""
        extra = {}
    elif scope in TENANT_READ_SCOPES:
        tenant_where, enterprise_where = "WHERE tenant_id = :tid", "WHERE tenant_id = :tid"
        extra = {"tid": int(tid)}
    else:
        tenant_where, enterprise_where = "WHERE 1 = 0", "WHERE 1 = 0"
        extra = {}

    rows = db.session.execute(
        text(f"""
            SELECT * FROM (
                SELECT 'workflow' AS section, CAST(process_id AS VARCHAR) AS id,
                       process_name AS name, creation_date
                FROM apps.def_processes
                ORDER BY creation_date DESC LIMIT :limit
            ) w
            UNION ALL
            SELECT * FROM (
                SELECT 'async_task' AS section, CAST(def_task_id AS VARCHAR) AS id,
                       user_task_name AS name, creation_date
                FROM def_async_tasks
                ORDER BY creation_date DESC LIMIT :limit
            ) at
            UNION ALL
            SELECT * FROM (
                SELECT 'schedule' AS section, CAST(def_task_sche_id AS VARCHAR) AS id,
                       user_schedule_name AS name, creation_date
                FROM def_async_task_schedules
                WHERE cancelled_yn = 'N' AND ({sched_where})
                ORDER BY creation_date DESC LIMIT :limit
            ) s
            UNION ALL
            SELECT * FROM (
                SELECT 'run' AS section, CAST(e.def_process_execution_id AS VARCHAR) AS id,
                       COALESCE(p.process_name, 'Ad-hoc run') AS name, e.creation_date
                FROM apps.def_process_executions e
                LEFT JOIN apps.def_processes p ON p.process_id = e.process_id
                WHERE {exec_where}
                ORDER BY e.creation_date DESC LIMIT :limit
            ) r
            UNION ALL
            SELECT * FROM (
                SELECT 'executor' AS section, CAST(internal_execution_method AS VARCHAR) AS id,
                       execution_method AS name, creation_date
                FROM def_async_execution_methods
                ORDER BY creation_date DESC LIMIT :limit
            ) e
            UNION ALL
            SELECT * FROM (
                SELECT 'user' AS section, CAST(user_id AS VARCHAR) AS id,
                       user_name AS name, creation_date
                FROM apps.def_users {user_where}
                ORDER BY creation_date DESC LIMIT :limit
            ) u
            UNION ALL
            SELECT * FROM (
                SELECT 'tenant' AS section, CAST(tenant_id AS VARCHAR) AS id,
                       tenant_name AS name, creation_date
                FROM apps.def_tenants {tenant_where}
                ORDER BY creation_date DESC LIMIT :limit
            ) t
            UNION ALL
            SELECT * FROM (
                SELECT 'enterprise' AS section, CAST(tenant_id AS VARCHAR) AS id,
                       enterprise_name AS name, creation_date
                FROM apps.def_tenant_enterprise_setup {enterprise_where}
                ORDER BY creation_date DESC LIMIT :limit
            ) en
        """),
        {**sched_params, **exec_params, **user_params, **extra, "limit": limit},
    ).fetchall()

    result = {k: [] for k in ['workflow', 'async_task', 'schedule', 'run', 'executor', 'user', 'tenant', 'enterprise']}
    for row in rows:
        result[row.section].append({
            "id": row.id,
            "name": row.name,
            "creation_date": row.creation_date,
        })
    return result
